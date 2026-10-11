# Provenance

## How the code was written

Written in Go from the specifications below, for SigmaM2M, a oneM2M
platform. No code was ported or copied from another LwM2M implementation
(Leshan, Wakaama, Anjay and the Go projects named in the README were not
used as sources; Leshan is used only as a test peer, in a container).
The codecs came with SigmaM2M's first commit (2026-09-27) as part of its
LwM2M server and were moved into this module on 2026-10-06; `exported.go`
exports the helpers that server calls and `EncodePaths` was moved in
from its composite operations. For the first public release (v0.1.0,
2026-10-11) `encode.go` added the encoders a client needs (TLV of any
depth, plain text, CBOR, LwM2M JSON), `Encode`, `Decode` and
`DecodeSenMLNames`, and the CBOR encoders started to take the object
model into account (see CHANGELOG.md).

## Sources

| Area (files) | Followed |
|---|---|
| Paths, TLV, plain text, opaque, CBOR single value, LwM2M 1.0 JSON (codec.go, encode.go) | OMA-TS-LightweightM2M_Core V1.1.1 clause 7.4 and appendix C; Core 1.2.2 for the changes since |
| SenML JSON and CBOR (codec.go) | RFC 8428 (with the integer labels of its table 6), RFC 8790 for the FETCH/PATCH formats, Core clause 7.4.4 and 7.4.5 |
| LwM2M CBOR (lwm2mcbor.go) | Core 1.2.2 clause 7.5.4 (its byte examples are test vectors); RFC 8949 |
| Registration payload, alternate path (codec.go) | RFC 6690 link format; Transport 1.1.1 clause 6.4.1 |
| Object model (model.go) | OMNA LwM2M registry, facts only (see NOTICE) |

Where the documents leave something open, the code says what it does in
a comment: opaque values in JSON formats are read in either base64
alphabet, with or without padding (LwM2M names base64, SenML base64url);
TLV integers of 3, 5, 6 or 7 bytes and booleans other than 0 and 1 are
read and reported through the `*Lax` notes.

## Passages to review before publication

No passage is known to be copied. Doc comments cite clause numbers in our
own words; a search for normative wording (MUST, SHALL, SHOULD) in the
module finds none.

## Test data

Every device value in the tests is made up, or is a byte example of the
specification used as a test vector. The interop tests compare with
values Leshan's demo client reports about itself ("Leshan Demo Device",
"Model 500"), which are that program's own demo values.
