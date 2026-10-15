# Xray-core OpenConnect

## Motivation

There are two different stories/baselines: 
1. `Xray`
2. `ocserv`

`Xray` has server-side routing/filtering (via gVisor) and hardly detectable protocols.

`OpenConnect` was focused on implementing Cisco Anyconnect compatible enterprise-level protocol. It has important differencies from VLESS: 
- Client-side split-routing where routes are provided from server;
- L3 level communication between clients;
- Broad support in various devices.

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
- Virtual IP pool, DPD/keepalive, MTU discovery, per-user traffic stats, client-to-client L3 relay. `maxClients` bounds live tunnels, not session records: a client inside its resume window holds an address, not a slot. It is enforced at authentication: a client that still holds a valid cookie resumes without re-checking it. `maxSessionsPerUser` (0 = unlimited) does the same accounting per account and also re-checks at CONNECT, where cookie holders skip auth; settable on the inbound (default), a group, and a user — the most specific set value wins

Also in this fork:

- **Router: `failover` balancing strategy** — traffic sticks to the highest-priority outbound and fails over only after N consecutive failed observatory probes, with automatic failback (set `fallbackTag` on the balancing rule for the all-down case)
- **Strict egress socket options** — dialing fails (instead of silently leaking to the host's default route) when outbound socket options such as `interface` cannot be applied
- **VLESS inbound: `maxSessionsPerUser`** — bounds live flows of one account per inbound (0 = unlimited). A session is a live TCP/UDP flow, so tune it in flows, not devices: a browser alone opens several at once. An XTLS/vision flow and a whole MUX bundle each take one slot; excess flows get a closed connection, live flows are never cut

Full config [example](https://github.com/kryoz/Xray-core-openconnect/wiki/OpenConnect-example-config).

Upgrading from a config that predates the DTLS removal: `dtls`, `dtlsPort`,
`cipher` and the per-user / per-group `dtls` overrides no longer exist. Old
configs still load — the JSON layer ignores unknown keys — but those fields do
nothing now.

### User management

Offline — edit a config file, applied on the next start:

```bash
xray openconnect hash [<password>]
xray openconnect add    -c cfg.json [-in tag] [-ip 10.66.0.5] <name> <password>
xray openconnect list   -c cfg.json [-in tag]
xray openconnect passwd -c cfg.json <name> <password>
xray openconnect rm     -c cfg.json <name>
xray openconnect block  -c cfg.json [-in tag] <name>
xray openconnect unblock -c cfg.json [-in tag] <name>
```

Online — applied to the running process, no restart:

```bash
xray openconnect add   -s 127.0.0.1:8080 -in oc <name> <password>
xray openconnect list  -s 127.0.0.1:8080 -in oc
xray openconnect rm    -s 127.0.0.1:8080 -in oc <name>
xray openconnect block -s 127.0.0.1:8080 -in oc <name>   # or unblock
xray api adu -tag=oc users.json      # add users of any supported inbound
xray api bu  -tag=oc <email>         # block; -unblock restores
xray api rmu -tag=oc <email>         # remove
```

Blocking keeps the account — its credential, static address and stats key — and
takes away its access: a blocked user cannot authenticate, cannot resume on a
session cookie it still holds, and loses the tunnels it has up within a second.
VLESS behaves the same way: a blocked account is refused exactly like an unknown
UUID, and its live flows are closed. `xray openconnect passwd` is offline-only —
rotating a password online would mean deleting and re-adding the account, which
cannot be rolled back half-way.

To make runtime changes survive a restart, give the inbound a `usersFile`:

```json
{ "tag": "oc", "protocol": "openconnect", "settings": { "usersFile": "/etc/xray/oc-users.json", "users": [ … ] } }
```

The file is seeded from `users` on the first start and is the source of accounts
from then on: every add, block and remove is written to it atomically (0600,
temp + rename), while the config file itself is never rewritten. Without
`usersFile` the behavior is unchanged — runtime changes last until the next
restart. VLESS inbounds take the same `settings.usersFile`.

> **The management API is not authenticated.** Whoever can reach the commander
> address (`-s`, the `commander`/stats inbound, default `127.0.0.1:8080`) can
> create, block and delete users of every inbound and read their accounts —
> root-equivalent on a proxy that routes your traffic. Bind it to loopback or a
> unix socket (`@xray-api`) only. `xray api lu`/`ListInbounds` still returns
> inbound settings verbatim, credentials included; `api ru`/`GetInboundUsers`
> masks the `password` of every account it lists.

# Disclaimer

The project was created for research purposes. 
Use according to the laws of your country — responsibility of the user.
