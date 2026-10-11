# lwm2m

The content formats of OMA LightweightM2M 1.0 to 1.2 in pure Go: OMA TLV, plain text, opaque, CBOR, SenML JSON and CBOR, LwM2M JSON and LwM2M CBOR, with LwM2M paths, registration payloads and a built-in object model; not affiliated with OMA SpecWorks.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/lwm2m.svg)](https://pkg.go.dev/github.com/cB-Sigma/lwm2m) [![test](https://github.com/cB-Sigma/lwm2m/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/lwm2m/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.26-00ADD8.svg)](go.mod)

It is the codec layer for an LwM2M server or client: decode what a
device sends in any format, encode reads, writes and notifications in
any format, type values with the object model (TLV carries no types),
and read Register payloads. It brings no CoAP stack: use it with the
CoAP library you already have. One dependency, fxamacker/cbor; no cgo.
It was written for SigmaM2M, a oneM2M platform, whose LwM2M server is
built on it; it has no dependency on it.

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
| A CoAP stack, DTLS, an LwM2M server or client | no: this is the codec layer; [lwm2m-sim](https://github.com/cB-Sigma/lwm2m-sim) is a client built on it |
| Reading OMA DDF object definition files | no (pass a `Model`) |

## Choosing a Go LwM2M library

Compared from each project's source at the version named, on
2026-10-11. Check the projects themselves before relying on a row.

| | this module | zourva/lwm2m v0.2.0 (2024-04) | yplam/lwm2m v0.1.0 (2023-06) | zubairhamed/betwixt (2016-11 commit) |
|---|---|---|---|---|
| What it is | content formats and object model | client and server | server for edge routers | client and server, LwM2M 1.0 |
| TLV | yes | partly (encoder helpers) | yes | yes |
| Plain text, opaque, CBOR | yes | no | no (its README) | text |
| SenML JSON / CBOR | yes | no | no (its README) | no |
| LwM2M JSON / CBOR | yes | no | no | JSON (1.0 draft) |
| CoAP, DTLS, operations | bring your own (go-coap works) | go-coap, pion/dtls v2 | go-coap, DTLS PSK | go-coap of 2016 |
| Interop evidence | Leshan 2.0.0-M18, every format both ways (below) | none stated | none stated | none stated |
| Status | v0.x, maintained | "will be changed dramatically" (its README) | v0.1.0 | unmaintained since 2016 |
| Go version | 1.26 | 1.20 | 1.18 | GOPATH |
| Licence | Apache-2.0 | MIT | Apache-2.0 | Apache-2.0 |

Pick this module when you have, or want to choose, your own CoAP stack
and need every content format right, or when you are writing a client
or a test device. Pick yplam/lwm2m for a small TLV-only server that is
ready to run, or zourva/lwm2m for a client and server in one place if
TLV is enough for your devices. Outside Go, Eclipse Leshan (Java),
Wakaama and Anjay (C) are complete implementations with servers,
clients and bootstrap.

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

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/lwm2m

| Package | What it does |
|---|---|
| `lwm2m` (module root) | `Path`, `Value`, `TimedValue`; `Encode`, `Decode`; TLV (`DecodeTLV`, `EncodeTLV`, `EncodeScalar`, `EncodeResourceTLV`, `EncodeInstanceTLV`, `AppendTLV`); SenML JSON and CBOR; LwM2M JSON and CBOR; `EncodeText`, `DecodeText`, `EncodeCBORValue`, `DecodeCBORValue`; `ParseRegistration`, `ParseLinks`; `EncodePaths`, `DecodeSenMLNames`; `Model`, `ResourceDef`, `Objects`, the `CF*` Content-Format numbers and `T*` data types |
| `interop` (nested module, tests only) | the codecs against Eclipse Leshan's demo client, in a container |

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
- LwM2M CBOR (11544) could not be checked against Leshan: its client
  does not offer it (4.06 to reads, 4.15 to writes). This format is
  checked only against the byte examples of Core 1.2 clause 7.5.4.
- [lwm2m-sim](https://github.com/cB-Sigma/lwm2m-sim) runs Leshan's demo
  server against a client built on this module, which checks the
  encoders against Leshan's decoders for reads and notifications in
  every format.
- Found by these runs and fixed in v0.1.0: a Float resource holding a
  whole number was written as a CBOR integer in SenML CBOR and LwM2M
  CBOR; Leshan refuses that (`TestCBORFloatResourcesStayFloats`).
- Not yet: Wakaama, Anjay, a real device.

## Not yet

| What | Why |
|---|---|
| Reading OMA DDF XML object definitions into a `Model` | out of scope so far; pass a `Model` built from them |
| LwM2M CBOR against an independent peer | Leshan does not implement it; Anjay does and is next |

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
