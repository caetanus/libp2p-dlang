/**
 * OpenSSL-backed TlsProvider for the WebSocket transport's `/tls` (wss) layer.
 *
 * It pumps bytes over a libp2p `Stream` through OpenSSL memory BIOs, so no socket
 * ownership is assumed and the same code works over any inner stream. Compiled
 * only under `-version=LibP2P_OpensslTls`, so libp2p-core pulls no TLS stack by
 * default; the Android build turns it on (P2P_TLS=1) and links libssl/libcrypto.
 *
 * In libp2p the security layer is Noise (it authenticates the peer's public key),
 * NOT TLS — the wss TLS is transport-level compatibility with browser-oriented
 * relays. So the client defaults to `verifyPeer = false`: it sends SNI (public
 * relays like libp2p.direct need it to select the cert) but does not verify the
 * returned certificate, which avoids shipping a trust store. Construct with
 * `verifyPeer = true` for strict verification (a CA store must be configured).
 */
module libp2p.transport.ws_tls_openssl;

version (LibP2P_OpensslTls):

import std.algorithm.comparison : min;
import std.string : toStringz;

import deimos.openssl.bio;
import deimos.openssl.ssl;
import deimos.openssl.tls1;

import libp2p.core.ending : ConnClosed, EndOfStream;
import libp2p.core.stream : Stream;
import libp2p.transport.ws : TlsProvider;

/// A TlsProvider using OpenSSL. `verifyPeer` defaults to false (see the module
/// note: Noise is libp2p's security, so the wss cert is not verified by default).
final class OpensslTlsProvider : TlsProvider
{
	private bool verifyPeer;

	this(bool verifyPeer = false)
	{
		this.verifyPeer = verifyPeer;
	}

	Stream connect(Stream inner, string sniHost)
	{
		return new OpensslStream(inner, false, sniHost, verifyPeer);
	}

	Stream accept(Stream inner)
	{
		return new OpensslStream(inner, true, null, verifyPeer);
	}
}

private final class OpensslStream : Stream
{
	private Stream inner;
	private SSL_CTX* ctx;
	private SSL* ssl;
	private BIO* rbio; // OpenSSL reads from here; we feed it inbound bytes
	private BIO* wbio; // OpenSSL writes here; we drain it to `inner`
	private bool closed;

	this(Stream inner, bool server, string sni, bool verify)
	{
		// Server-side wss would need a certificate + key; our use is the client
		// dialing relays. Listening happens over plain /ws or /tcp, so accept()
		// isn't exercised — fail clearly rather than half-work.
		if (server)
			throw new ConnClosed("tls: server-side wss needs a certificate (not configured)");

		this.inner = inner;
		ctx = SSL_CTX_new(TLS_client_method());
		if (ctx is null)
			throw new ConnClosed("tls: SSL_CTX_new failed");
		SSL_CTX_set_verify(ctx, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, null);

		ssl = SSL_new(ctx);
		if (ssl is null)
		{
			SSL_CTX_free(ctx);
			throw new ConnClosed("tls: SSL_new failed");
		}
		rbio = BIO_new(BIO_s_mem());
		wbio = BIO_new(BIO_s_mem());
		SSL_set_bio(ssl, rbio, wbio); // SSL takes ownership; SSL_free releases them
		if (sni.length)
			SSL_set_tlsext_host_name(ssl, sni.toStringz);
		SSL_set_connect_state(ssl);
		handshake();
	}

	// Drain everything OpenSSL has produced (wbio) out to the inner stream.
	private void drainOut()
	{
		ubyte[4096] b;
		while (true)
		{
			immutable n = BIO_read(wbio, cast(void*) b.ptr, cast(int) b.length);
			if (n <= 0)
				break;
			inner.write(b[0 .. n]);
		}
	}

	// Read one chunk from the inner stream into OpenSSL's input (rbio).
	private void feedIn()
	{
		ubyte[4096] b;
		immutable n = inner.read(b[]); // ≥1 byte or throws EndOfStream
		BIO_write(rbio, cast(void*) b.ptr, cast(int) n);
	}

	private void handshake()
	{
		while (true)
		{
			immutable r = SSL_do_handshake(ssl);
			drainOut(); // flush any handshake output OpenSSL produced
			if (r == 1)
				return;
			immutable e = SSL_get_error(ssl, r);
			if (e == SSL_ERROR_WANT_READ)
				feedIn();
			else if (e != SSL_ERROR_WANT_WRITE)
				throw new ConnClosed("tls: handshake failed");
		}
	}

	size_t read(ubyte[] buf)
	{
		if (buf.length == 0)
			return 0;
		if (closed)
			throw new ConnClosed("tls: closed locally");
		while (true)
		{
			immutable r = SSL_read(ssl, cast(void*) buf.ptr, cast(int) min(buf.length, int.max));
			if (r > 0)
				return r;
			immutable e = SSL_get_error(ssl, r);
			if (e == SSL_ERROR_WANT_READ)
			{
				drainOut();
				feedIn();
				continue;
			}
			if (e == SSL_ERROR_ZERO_RETURN)
				throw new EndOfStream("tls: peer closed the connection");
			throw new ConnClosed("tls: read failed");
		}
	}

	void write(const(ubyte)[] data)
	{
		if (closed)
			throw new ConnClosed("tls: closed locally");
		size_t off;
		while (off < data.length)
		{
			immutable r = SSL_write(ssl, cast(const(void)*)(data.ptr + off),
				cast(int) min(data.length - off, int.max));
			if (r > 0)
			{
				off += r;
				drainOut();
				continue;
			}
			immutable e = SSL_get_error(ssl, r);
			if (e == SSL_ERROR_WANT_READ)
			{
				drainOut();
				feedIn();
				continue;
			}
			if (e == SSL_ERROR_WANT_WRITE)
			{
				drainOut();
				continue;
			}
			throw new ConnClosed("tls: write failed");
		}
	}

	void close() nothrow
	{
		if (closed)
			return;
		closed = true;
		try
		{
			SSL_shutdown(ssl);
			drainOut();
		}
		catch (Exception)
		{
		}
		try
			inner.close();
		catch (Exception)
		{
		}
		freeSsl();
	}

	void reset() nothrow
	{
		if (closed)
			return;
		closed = true;
		try
			inner.reset();
		catch (Exception)
		{
		}
		freeSsl();
	}

	private void freeSsl() nothrow
	{
		if (ssl !is null)
			SSL_free(ssl); // also frees rbio/wbio
		if (ctx !is null)
			SSL_CTX_free(ctx);
		ssl = null;
		ctx = null;
	}
}
