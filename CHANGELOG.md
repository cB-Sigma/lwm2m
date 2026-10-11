# Changelog

All notable changes to this module. Versions follow semantic versioning;
before v1 the API may change in minor versions.

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
