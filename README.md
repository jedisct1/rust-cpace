[![Documentation](https://docs.rs/pake-cpace/badge.svg)](https://docs.rs/pake-cpace)

# CPace-Ristretto255, a balanced PAKE

A CPace implementation for Rust.

This is a port of the [CPace implementation for libsodium](https://github.com/jedisct1/cpace).

## Blurb

[CPace](https://tools.ietf.org/id/draft-haase-cpace-01.html) is a protocol for two parties that share a low-entropy secret (password) to derive a strong shared key without disclosing the secret to offline dictionary attacks.

CPace is a balanced PAKE, meaning that both parties must know the low-entropy secret.

Applications include pairing IoT and mobile applications using ephemeral pin codes, QR-codes, serial numbers, etc.

## Usage

The CPace protocol requires a single round trip.

It returns a set of two 256-bit (`SHARED_KEY_BYTES` bytes) keys that can be used to communicate in both directions.

```rust
use pake_cpace::CPace;

// client-side
let client = CPace::step1("password", "client", "server", Some("ad")).unwrap();

// server-side
let step2 = CPace::step2(&client.packet(), "password", "client", "server", Some("ad")).unwrap();

// client-side
let shared_keys = client.step3(&step2.packet()).unwrap();

// both parties now have the same set of shared keys
assert_eq!(shared_keys.k1, step2.shared_keys().k1);
assert_eq!(shared_keys.k2, step2.shared_keys().k2);
```

## Notes

- This implementation uses the Ristretto255 group and SHA-512 as the hash function, so it is compatible with the C implementation and can trivially be ported to [wasm-crypto](https://github.com/jedisct1/wasm-crypto).
- Client and server identifiers have a maximum size of 255 bytes.
- `no_std` compatible, WebAssembly compatible.
