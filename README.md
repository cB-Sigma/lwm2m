# lwm2m

OMA LightweightM2M 1.0 to 1.2 in pure Go: every content format (OMA TLV, plain text, opaque, CBOR, SenML JSON and CBOR, LwM2M JSON and LwM2M CBOR), and the client, server and bootstrap server roles over CoAP/UDP and DTLS; not affiliated with OMA SpecWorks.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/lwm2m.svg)](https://pkg.go.dev/github.com/cB-Sigma/lwm2m) [![test](https://github.com/cB-Sigma/lwm2m/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/lwm2m/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.26-00ADD8.svg)](go.mod)

The module root is the codec layer: decode what a device sends in any
format, encode reads, writes and notifications in any format, type
values with the object model (TLV carries no types), and read Register
payloads; it needs only fxamacker/cbor and brings no CoAP stack, so it
fits any CoAP library. Since v0.2.0 the roles are packages of their own
on go-coap and pion/dtls: `client` (a device: registration, bootstrap,
every device management and reporting operation), `server` (an LwM2M
server: registrations, operations on registered clients, observations,
Send) and its `BootstrapServer`. No cgo. It was written for SigmaM2M, a
oneM2M platform, whose LwM2M server uses the codecs; it has no
dependency on it.

## Features

| Feature | Status |
|---|---|
| OMA TLV (11542), every data type of Core appendix C, objects, instances, multiple resources | decode and encode (`DecodeTLV`, `EncodeTLV`) |
| Plain text (0), opaque (42), CBOR single values (60, epoch time as tag 1) | decode and encode |
| SenML JSON (110) and CBOR (112): base name and time, relative times | decode and encode |
| SenML FETCH/PATCH name packs (320, 322) for the composite operations | encode (`EncodePaths`) and decode (`DecodeSenMLNames`) |
| LwM2M JSON (11543, LwM2M 1.0) | decode and encode |
| LwM2M CBOR (11544, LwM2M 1.2) | decode and encode |
| `Encode` and `Decode` by Content-Format number | yes |
| Float resources stay CBOR floats when whole (`EncodeSenMLCBORModel`, `EncodeLwM2MCBORModel`) | yes |
| Notes on input accepted though not well formed (`*Lax`) | yes |
| Object model | objects 0, 1, 3, 4, 5, 9, 21, 25, 26 and 3303 built in (from the OMNA registry); more through a `Model` |
| Register payload (CoRE link format, alternate path) | `ParseRegistration`, `ParseLinks` |
| LwM2M client role: Register, Update at half the lifetime, De-register, client-initiated bootstrap; Read, Discover, Write (replace and partial), Write-Attributes, Execute, Create, Delete, Read- and Write-Composite, Observe (and composite), Cancel, Notify, Send, in every format; CoAP/UDP and DTLS with a PSK or an X.509 certificate (`client.New`) | yes (since v0.2.0; was lwm2m-sim's) |
| LwM2M server role: Register, Update (the client's new address taken), De-register, lifetime expiry, an admission hook given the PSK identity or certificate name; Read, Discover, Write, Write-Attributes, Execute, Create, Delete, Read- and Write-Composite, Observe and Cancel towards a registered client; Send; CoAP/UDP and DTLS with PSK or X.509 (`server.New`, `Registration`) | yes (since v0.2.0) |
| Bootstrap server role: client-initiated bootstrap, Bootstrap-Delete, Bootstrap-Write of Security and Server instances (PSK, certificate or no security) in TLV or SenML, Bootstrap-Finish (`server.NewBootstrap`, `Account`) | yes (since v0.2.0) |
| DTLS raw public keys (security mode 1, RFC 7250) | no: pion/dtls has no RFC 7250 (see Not yet) |
| Queue mode, SMS binding, CoAP over TCP, LwM2M gateway (1.2) | no (see Not yet) |
| Reading OMA DDF object definition files into a `Model` (`ParseDDF`, `Model.Merge`) | yes (since v0.2.0) |

## Choosing a Go LwM2M library

Compared from each project's source at the version named, on
2026-10-11. Check the projects themselves before relying on a row.

| | this module | zourva/lwm2m v0.2.0 (2024-04) | yplam/lwm2m v0.1.0 (2023-06) | zubairhamed/betwixt (2016-11 commit) |
|---|---|---|---|---|
| What it is | content formats and object model; client, server and bootstrap server roles (since v0.2.0) | client and server | server for edge routers | client and server, LwM2M 1.0 |
| TLV | yes | partly (encoder helpers) | yes | yes |
| Plain text, opaque, CBOR | yes | no | no (its README) | text |
| SenML JSON / CBOR | yes | no | no (its README) | no |
| LwM2M JSON / CBOR | yes | no | no | JSON (1.0 draft) |
| Bootstrap server | yes | no | no | no |
| CoAP, DTLS | go-coap v3, pion/dtls v3: PSK and X.509 (the codecs take any stack) | go-coap, pion/dtls v2 | go-coap, DTLS PSK | go-coap of 2016 |
| Interop evidence | Leshan 2.0.0-M18 client, server and bootstrap server against our roles and codecs (below) | none stated | none stated | none stated |
| Status | v0.x, maintained | "will be changed dramatically" (its README) | v0.1.0 | unmaintained since 2016 |
| Go version | 1.26 | 1.20 | 1.18 | GOPATH |
| Licence | Apache-2.0 | MIT | Apache-2.0 | Apache-2.0 |

Pick this module for an LwM2M client, server or bootstrap server in Go
that needs every content format right, or take only its codecs under
your own CoAP stack. Pick yplam/lwm2m for a small TLV-only server that
is ready to run. Outside Go, Eclipse Leshan 2.0.0-M18 (Java) and
Wakaama and Anjay (C) are more complete: raw public keys, queue mode,
SMS and TCP bindings, OSCORE and (Anjay) LwM2M gateway are there and
not here yet; pick them when you need those.

## Install

```
go get github.com/cB-Sigma/lwm2m@latest
```

Requires Go 1.26 or later.

## Quick start

```go
import "github.com/cB-Sigma/lwm2m"

// Decode a read answer, whatever format the device chose.
base, _ := lwm2m.ParsePath("/3303/0")
vals, err := lwm2m.Decode(int(contentFormat), nil, base, payload)
// vals[i].Path is /3303/0/5700, vals[i].V is 21.5

// Encode a write of a float resource in SenML CBOR.
p, _ := lwm2m.ParsePath("/3303/0/5603")
b, err := lwm2m.Encode(lwm2m.CFSenMLCBOR, nil, p, []lwm2m.Value{{Path: p, V: -40.0}})
```

The runnable versions are the `Example` tests.

The roles (v0.2.0):

```go
srv := server.New(server.Config{
	Security:   server.Security{PSK: keyOf},
	OnRegister: func(r *server.Registration) { go watch(r) },
})
srv.Listen("coaps", ":5684")

func watch(r *server.Registration) {
	vals, _ := r.Read(ctx, "/3/0", lwm2m.CFSenMLCBOR)
	r.Observe(ctx, "/3303/0/5700", 0, func(v []lwm2m.Value) { store(r.Endpoint, v) })
}

dev := client.New(client.Config{Endpoint: "meter-7", Bootstrap: "coaps://bs.example", PSKIdentity: id, PSK: key})
dev.Start(ctx)
dev.Set("/3303/0/5700", 22.5) // notifies the observers
```

`TestServerOperations` (server/server_test.go) runs this, both roles
in process.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/lwm2m

| Package | What it does |
|---|---|
| `lwm2m` (module root) | `Path`, `Value`, `TimedValue`; `Encode`, `Decode`; TLV (`DecodeTLV`, `EncodeTLV`, `EncodeScalar`, `EncodeResourceTLV`, `EncodeInstanceTLV`, `AppendTLV`); SenML JSON and CBOR; LwM2M JSON and CBOR; `EncodeText`, `DecodeText`, `EncodeCBORValue`, `DecodeCBORValue`; `ParseRegistration`, `ParseLinks`; `EncodePaths`, `DecodeSenMLNames`; `Model`, `ResourceDef`, `Objects`, `ParseDDF`, the `CF*` Content-Format numbers and `T*` data types |
| `client` | the client role: `New`, `Config`, `Client` (`Start`, `Stop`, `Update`, `Set`, `Send`, `OnExecute`, `Objects`), `Objects`, `Default` |
| `server` | the server role: `New`, `Config`, `Security`, `Server` (`Listen`, `Registration`, `Registrations`, `Close`), `Registration` (`Read`, `Discover`, `Write`, `WriteAttributes`, `Execute`, `Create`, `Delete`, `ReadComposite`, `WriteComposite`, `Observe`), `CodeError`; the bootstrap server: `NewBootstrap`, `BootstrapConfig`, `Account` |
| `interop` (nested module, tests only) | the codecs and the server and bootstrap server roles against Eclipse Leshan's demo client, in a container |

Changes per version are in [CHANGELOG.md](CHANGELOG.md).

## Testing

```
go test -race ./...
cd interop && SIGMA_LWM2M_INTEROP=1 go test -v ./...   # needs Docker
```

The unit tests check each format against byte examples of the
specification (clause numbers in the tests) and round trips. Tests carry
`// Covers: SIG-...` comments: requirement IDs of the SigmaM2M project's
compliance report, with no meaning outside it; tests added for v0.1.0
carry none.

`interop/` is a nested module with its own go.mod. Its tests build an
image from `interop/peer` (eclipse-temurin:21-jre-alpine with Leshan's
demo jars 2.0.0-M18 from Maven Central, checked by SHA-256) and are
skipped unless `SIGMA_LWM2M_INTEROP=1` is set and Docker answers.

### Interop tested against

- Eclipse Leshan 2.0.0-M18 demo client (2026-10-11, Docker Desktop on
  arm64; `interop`). A minimal LwM2M server in the test (go-coap)
  registered it and decoded with this module everything Leshan encoded:
  the Register payload; `/3/0` in TLV, SenML JSON, SenML CBOR and LwM2M
  JSON, which decode to the same values; single resources in TLV, plain
  text and CBOR, which agree; `/3303` as an object in TLV and SenML CBOR;
  Discover answers of an object, an instance and a resource; and three
  notifications of an observation of `/3303/0/5700` and of `/3303/0` in
  each of those formats. The other way, Leshan decoded writes this module
  encoded of a string, an integer and a boolean in TLV, SenML JSON,
  SenML CBOR, LwM2M JSON, plain text and CBOR, and each read back
  unchanged. Write-Attributes and Execute were accepted.
- Eclipse Leshan 2.0.0-M18 demo client against the roles (2026-10-12,
  Docker Desktop on arm64; `interop/roles_test.go`). Over plain CoAP the
  `server` package registered it (lifetime, binding UT, object links
  read), read `/3/0` in TLV, SenML JSON, SenML CBOR and LwM2M JSON
  (LwM2M CBOR answered 4.06), discovered `/3303/0`, set notification
  attributes, wrote `/3/0/14` in SenML CBOR and read it back, observed
  `/3303/0/5700` through three notifications, cancelled, and executed a
  reboot. Over DTLS with a PSK the identity reached `Authorize` and a TLV
  read passed. The `BootstrapServer` bootstrapped it, with its writes in
  TLV and in SenML CBOR, onto the `server` package, where it then
  registered with the provisioned lifetime. Passed. The SenML CBOR
  bootstrap found a defect, fixed in v0.2.0: an empty opaque value (an
  unused key) was written as a SenML CBOR record with no value field,
  which Leshan refuses; it is now an empty byte string
  (`TestEmptyOpaqueKeepsItsValue`).
- LwM2M CBOR (11544) could not be checked against Leshan: its client
  does not offer it (4.06 to reads, 4.15 to writes). This format is
  checked only against the byte examples of Core 1.2 clause 7.5.4.
- [lwm2m-sim](https://github.com/cB-Sigma/lwm2m-sim) runs Leshan's demo
  server and bootstrap server against the `client` package (the
  simulator is built on it since v0.2.0), which checks the client role
  and the encoders against Leshan's decoders for reads and
  notifications in every format.
- The X.509 mode of both roles is tested in process only
  (`TestServerX509`), not yet against Leshan.
- Found by these runs and fixed in v0.1.0: a Float resource holding a
  whole number was written as a CBOR integer in SenML CBOR and LwM2M
  CBOR; Leshan refuses that (`TestCBORFloatResourcesStayFloats`).
- Not yet: Wakaama, Anjay, a real device.

## Not yet

| What | Why |
|---|---|
| LwM2M CBOR against an independent peer | Leshan 2.0.0-M18 does not implement it; Anjay does, and its demo client builds from C source in Docker: next release |
| DTLS raw public keys (security mode 1) | pion/dtls v3 has no RFC 7250; SigmaM2M's fork of it (dtlsx) has, and these roles move to it once it is published as a module |
| Queue mode (holding requests until the client wakes), SMS and non-IP bindings, CoAP over TCP and WebSockets, OSCORE, the 1.2 gateway objects, the bootstrap server reading the client's configuration before writing (Bootstrap-Discover and -Read) | not in this release; each is a feature of the roles, planned in this order |
| X.509 against Leshan | tested in process only so far |

## Related repositories

- [lwm2m-sim](https://github.com/cB-Sigma/lwm2m-sim): a simulated LwM2M
  client device built on this module, over CoAP/UDP and DTLS.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam. The built-in object model holds facts from the OMNA
LwM2M registry (BSD-3-Clause, Open Mobile Alliance); see NOTICE.
LightweightM2M and LwM2M are names of OMA SpecWorks, used only to say
what this module implements.
