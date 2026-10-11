# Changelog

All notable changes to this module. Versions follow semantic versioning;
before v1 the API may change in minor versions.

## v0.2.0 (2026-10-12)

The LwM2M roles as library packages. Only additions to the root
package's API; the roles bring go-coap v3 and pion/dtls v3 into go.mod,
which code importing only the codecs does not compile.

- `client`: the LwM2M client role (registration, updates,
  de-registration, client-initiated bootstrap, every device management
  and reporting operation in every format, Notify, Send), moved from
  lwm2m-sim's simulator, which is now built on it; new: DTLS certificate
  mode (`Config.Certificate`, `RootCAs`, `ServerName`).
- `server`: the LwM2M server role over CoAP/UDP and DTLS (PSK, X.509):
  registrations with lifetime expiry and an admission hook, Read,
  Discover, Write, Write-Attributes, Execute, Create, Delete, Read- and
  Write-Composite, Observe and Cancel, Send; and the bootstrap server
  role (`NewBootstrap`): Bootstrap-Delete, Bootstrap-Write of the
  configured accounts in TLV or SenML, Bootstrap-Finish.
- `ParseDDF` reads OMA object definition (DDF) files into a `Model`;
  `Model.Merge`. Closes the v0.1.0 "Not yet" row.
- Fixed: an empty opaque value in SenML CBOR was a record with no value
  field, which Leshan refuses (found bootstrapping Leshan's client in
  SenML CBOR); it is now an empty byte string
  (`TestEmptyOpaqueKeepsItsValue`).
- Interop: Leshan 2.0.0-M18's demo client against the server role (plain
  CoAP and DTLS PSK) and the bootstrap server role (TLV and SenML CBOR
  writes).

## v0.1.0 (2026-10-11)

First public release, as github.com/cB-Sigma/lwm2m.

- Every content format decodes and encodes: OMA TLV, plain text, opaque,
  CBOR, SenML JSON and CBOR, LwM2M JSON (encoding is new) and LwM2M CBOR.
- New: `Encode` and `Decode` by Content-Format number; `EncodeTLV` for an
  object, an instance, a resource or a resource instance with multiple
  resources; `EncodeText`, `EncodeCBORValue`, `EncodeLwM2MJSON`;
  `DecodeSenMLNames` for composite requests; `ErrNotSingle`;
  `EncodeSenMLCBORModel` and `EncodeLwM2MCBORModel`.
- Fixed: a Float resource holding a whole number (say -40) was written
  as a CBOR integer in SenML CBOR and LwM2M CBOR; Eclipse Leshan refuses
  that. `EncodeSenMLCBOR`, `EncodeLwM2MCBOR` and `EncodeSenML` now write
  Float resources of the model as CBOR floats; other numbers are written
  as before. Regression test `TestCBORFloatResourcesStayFloats`.
- Interop tests against Eclipse Leshan 2.0.0-M18's demo client in a
  nested test-only module, `interop`.
