// go-libp2p interop peer: same CLI contract as the D and rust peers.
//   go-peer listen              -> prints "LISTEN <multiaddr>/p2p/<id>", serves ping+identify
//   go-peer dial <multiaddr>    -> connects, verifies ping AND reads the peer's identify, exit 0
// Stack: TCP -> Noise -> Yamux -> ping / identify (go-libp2p defaults).
package main

import (
	"context"
	"strings"
	"fmt"
	"os"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	tcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ws "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"
)

func die(f string, a ...interface{}) { fmt.Fprintf(os.Stderr, "FAIL "+f+"\n", a...); os.Exit(1) }

func main() {
	mode := "listen"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	lh := os.Getenv("LISTEN_HOST")
	if lh == "" {
		lh = "0.0.0.0"
	}
	listenAddr := "/ip4/" + lh + "/tcp/0"
	switch mode {
	case "listen-ws":
		listenAddr = "/ip4/" + lh + "/tcp/0/ws"
	case "listen-quic":
		listenAddr = "/ip4/" + lh + "/udp/0/quic-v1"
	}
	h, err := libp2p.New(
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Transport(quic.NewTransport),
		libp2p.Transport(ws.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Muxer(yamux.ID, yamux.DefaultTransport),
		libp2p.ListenAddrStrings(listenAddr),
	)
	if err != nil {
		die("host: %v", err)
	}
	identify.NewIDService(h) // ensure identify is served
	ps := ping.NewPingService(h)
	ctx := context.Background()

	if len(mode) >= 6 && mode[:6] == "listen" {
		// pick the addr matching the requested transport
		var chosen ma.Multiaddr
		want := "/tcp/"
		if mode == "listen-quic" {
			want = "/quic"
		}
		for _, a := range h.Addrs() {
			s := a.String()
			if mode == "listen-ws" {
				if strings.Contains(s, "/ws") {
					chosen = a
					break
				}
			} else if mode == "listen-quic" {
				if strings.Contains(s, "/quic") {
					chosen = a
					break
				}
			} else if strings.Contains(s, want) && !strings.Contains(s, "/ws") && !strings.Contains(s, "/quic") {
				chosen = a
				break
			}
		}
		if chosen == nil {
			chosen = h.Addrs()[0]
		}
		fmt.Printf("LISTEN %s/p2p/%s\n", chosen, h.ID())
		select {}
	}

	// dial
	if len(os.Args) < 3 {
		die("dial needs a multiaddr")
	}
	maddr, err := ma.NewMultiaddr(os.Args[2])
	if err != nil {
		die("multiaddr: %v", err)
	}
	ai, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		die("addrinfo: %v", err)
	}
	// subscribe to identify-completed BEFORE connecting, so we prove we read theirs
	sub, err := h.EventBus().Subscribe(new(event.EvtPeerIdentificationCompleted))
	if err != nil {
		die("subscribe: %v", err)
	}
	defer sub.Close()

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := h.Connect(cctx, *ai); err != nil {
		die("connect: %v", err)
	}

	// ping
	pctx, pcancel := context.WithTimeout(ctx, 10*time.Second)
	defer pcancel()
	select {
	case r := <-ps.Ping(pctx, ai.ID):
		if r.Error != nil {
			die("ping: %v", r.Error)
		}
		fmt.Printf("PING ok rtt=%v\n", r.RTT)
	case <-pctx.Done():
		die("ping timeout")
	}

	// identify (must actually read the peer's)
	ictx, icancel := context.WithTimeout(ctx, 10*time.Second)
	defer icancel()
	for {
		select {
		case e := <-sub.Out():
			ev := e.(event.EvtPeerIdentificationCompleted)
			if ev.Peer == ai.ID {
				fmt.Printf("IDENTIFY ok agent=%q protocols=%d\n", ev.AgentVersion, len(ev.Protocols))
				fmt.Println("OK both verified")
				os.Exit(0)
			}
		case <-ictx.Done():
			die("identify timeout")
		}
	}
}
