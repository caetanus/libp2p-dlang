//! The other end of the wire: a real rust-libp2p node, so that "interoperates"
//! stops being a hypothesis.
//!
//! Everything else in this repository checks libp2p-dlang against itself or
//! against byte vectors. Both are useful and neither can catch the class of bug
//! that matters most here — a shared misreading. If the same author writes the
//! dialer, the listener and the vectors, a protocol detail understood wrongly is
//! understood wrongly consistently, and every test agrees.
//!
//! Two modes, because the two directions exercise different code. `listen`
//! prints its address and waits to be dialed; `dial` connects to an address and
//! reports what it found. In both cases the transport is the real default TCP
//! stack: TCP -> Noise XX -> yamux, with ping and identify on top.
//!
//! Output is line-oriented and meant to be parsed by `interop/run-interop.sh`:
//!   LISTEN <multiaddr>       — ready, this is where to reach me
//!   PING <peer> <micros>     — a ping round trip completed
//!   IDENTIFY <peer> <agent>  — the peer told us who it is
//!   ERROR <what>             — something went wrong; the exit code says so too

use std::error::Error;
use std::time::Duration;

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, identity, noise, ping, tcp, yamux, Multiaddr, SwarmBuilder, Transport};
use libp2p_webrtc as webrtc;

#[derive(libp2p::swarm::NetworkBehaviour)]
struct Behaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("listen");

    let keypair = identity::Keypair::generate_ed25519();
    let local_peer = keypair.public().to_peer_id();

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        // webrtc-direct beside TCP: it secures and multiplexes itself.
        .with_other_transport(|id| {
            let cert = webrtc::tokio::Certificate::generate(&mut rand::thread_rng())?;
            Ok(webrtc::tokio::Transport::new(id.clone(), cert)
                .map(|(peer, conn), _| (peer, libp2p::core::muxing::StreamMuxerBox::new(conn))))
        })?
        .with_dns()?
        .with_websocket(noise::Config::new, yamux::Config::default)
        .await?
        .with_behaviour(|key| Behaviour {
            // Ping often enough that a short test does not have to wait for it.
            ping: ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_millis(200)),
            ),
            identify: identify::Behaviour::new(identify::Config::new(
                "/interop/1.0.0".into(),
                key.public(),
            )),
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();

    // LISTEN_HOST overrides the bind address (default loopback for run-interop.sh;
    // set 0.0.0.0 for cross-network conformance).
    let lh = std::env::var("LISTEN_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    match mode {
        "listen" => {
            swarm.listen_on(format!("/ip4/{lh}/tcp/0").parse()?)?;
        }
        "listen-ws" => {
            swarm.listen_on(format!("/ip4/{lh}/tcp/0/ws").parse()?)?;
        }
        "listen-quic" => {
            swarm.listen_on(format!("/ip4/{lh}/udp/0/quic-v1").parse()?)?;
        }
        "listen-webrtc" => {
            swarm.listen_on(format!("/ip4/{lh}/udp/0/webrtc-direct").parse()?)?;
        }
        "dial" => {
            let addr: Multiaddr = args
                .get(2)
                .ok_or("dial needs a multiaddr")?
                .parse()
                .map_err(|e| format!("bad multiaddr: {e}"))?;
            // webrtc-direct dials from a listening socket: the transport wants
            // one before it will dial.
            if addr.to_string().contains("/webrtc-direct/") {
                swarm.listen_on("/ip4/127.0.0.1/udp/0/webrtc-direct".parse()?)?;
            }
            swarm.dial(addr)?;
        }
        other => return Err(format!("unknown mode: {other}").into()),
    }

    // A deadline rather than a "run forever": a hung interop test that a CI job
    // eventually kills tells you nothing about which side hung.
    let deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(deadline);

    let mut pings = 0usize;
    let mut identified = false;

    loop {
        tokio::select! {
            _ = &mut deadline => {
                println!("ERROR timed out after 30s (pings={pings}, identified={identified})");
                std::process::exit(1);
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("LISTEN {address}/p2p/{local_peer}");
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("CONNECTED {peer_id}");
                }
                SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event {
                    peer,
                    result: Ok(rtt),
                    ..
                })) => {
                    println!("PING {peer} {}", rtt.as_micros());
                    pings += 1;
                }
                SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event {
                    peer,
                    result: Err(e),
                    ..
                })) => {
                    println!("ERROR ping to {peer} failed: {e}");
                    std::process::exit(1);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                    peer_id,
                    info,
                    ..
                })) => {
                    println!("IDENTIFY {peer_id} {}", info.agent_version);
                    identified = true;
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    println!("ERROR outgoing connection: {error}");
                    std::process::exit(1);
                }
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    println!("CLOSED {peer_id} {cause:?}");
                    // Either way the run is over: whether it succeeded is decided
                    // by what was seen before the peer left.
                    break;
                }
                _ => {}
            }
        }

        // In dial mode this side drives, so having seen a round trip and an
        // identify is the whole job. In listen mode it is NOT: the peer that
        // dialed is still using the connection, and leaving as soon as our own
        // ping came back tears it down under them — which made this check fail
        // about one run in eight, on the dialer's side, for no reason of theirs.
        // A listener leaves when the peer does, or when the deadline says so.
        if mode == "dial" && pings >= 1 && identified {
            break;
        }
    }

    if pings == 0 {
        println!("ERROR no ping round trip completed");
        std::process::exit(1);
    }
    println!("OK pings={pings} identified={identified}");
    Ok(())
}
