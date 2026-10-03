# Xray-core OpenConnect

## Motivation

There are two different stories/baselines: 
1. `Xray`
2. `ocserv`

`Xray` has server-side routing/filtering (via gVisor) and hardly detectable protocols.

`OpenConnect` was focused on implementing Cisco Anyconnect compatible enterprise-level protocol. It has important differencies from VLESS: 
- Client-side split-routing where routes are provided from server;
- L3 level communication between clients;
- UDP/TCP communication with fallback to TCP (DTLS).

The primary usecase for OpenConnect is home routers many of which has OC-client in the stock bundle and "additive routing policy". Instead of routing ALL traffic into VPN the server (where it's filtered by gVisor) the router sends only packets to VPN by server's ip routing list (client side split routing).

But the native `ocserv` is written in C which is hardly extensible. My benchmark showed that `ocserv` on clients count > 15 uses more RAM than `Xray` because each client spawns dedicated worker.

It appeared that implementing Cisco Anyconnect protocol in `Xray` is easier than implementing worker pool in `ocserv`.
Also there's ready gVisor's features to filter traffic on the server.

## Android clients

1. [SeldorGate](https://seldor.ru) - Advanced OpenClient Android client 
2. [OpenConnect for Android](https://gitlab.com/openconnect/ics-openconnect) - free opensource without ads 

## Features in details

This fork adds an **OpenConnect / Cisco AnyConnect inbound** — a drop-in, ocserv-compatible VPN server, so standard OpenConnect clients (Linux, Android, iOS, macOS) connect to Xray natively:

- **Control channel** — TLS 1.2/1.3 with ocserv-compatible HTTP auth forms (single-round username/password for mobile clients), cookie & resume
- **Data channel** — CSTP over the control TLS connection, carrying a gVisor userspace TCP/UDP/ICMP stack. The DTLS channel was measured against the TCP path and removed: on the tested links CSTP was the cheaper one, and it needs no fallback negotiation on CGNAT or UDP-throttling carriers
- **Multi-frame downlink coalescing** — several CSTP frames in one TLS write, negotiated by the `X-CSTP-Multi-Frame-Capability` header. This is a fork extension, not an ocserv option: only clients built against this fork send it, stock openconnect keeps one frame per TLS record
- **ocserv parity** — camouflage (`camouflageSecret` / `camouflageRealm`, byte-compatible 401/404), MTU 1500, per-user and per-group split routing (`X-CSTP-Split-Include` / `X-CSTP-Split-Exclude`)
- **Addressing is IPv4-only** — the virtual IP pool, `X-CSTP-Address` / `X-CSTP-Netmask` and the split routes are IPv4; the tunnel carries no IPv6
- Virtual IP pool, DPD/keepalive, MTU discovery, per-user traffic stats, client-to-client L3 relay. `maxClients` bounds live tunnels, not session records: a client inside its resume window holds an address, not a slot

Also in this fork:

- **Router: `failover` balancing strategy** — traffic sticks to the highest-priority outbound and fails over only after N consecutive failed observatory probes, with automatic failback (set `fallbackTag` on the balancing rule for the all-down case)
- **Strict egress socket options** — dialing fails (instead of silently leaking to the host's default route) when outbound socket options such as `interface` cannot be applied

Full config [example](https://github.com/kryoz/Xray-core-openconnect/wiki/OpenConnect-example-config).

Upgrading from a config that predates the DTLS removal: `dtls`, `dtlsPort`,
`cipher` and the per-user / per-group `dtls` overrides no longer exist. Old
configs still load — the JSON layer ignores unknown keys — but those fields do
nothing now.

User management:

```bash
xray openconnect hash [<password>]
xray openconnect add    -c cfg.json [-in tag] [-ip 10.66.0.5] <name> <password>
xray openconnect list   -c cfg.json [-in tag]
xray openconnect passwd -c cfg.json <name> <password>
xray openconnect rm     -c cfg.json <name>
```

# Disclaimer

The project was created for research purposes. 
Use according to the laws of your country — responsibility of the user.