# Strata

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache-blue.svg)](https://opensource.org/licenses/apache-2-0)
[![ci](https://github.com/alpenlabs/bitcoin-bosd/actions/workflows/lint.yml/badge.svg?event=push)](https://github.com/alpenlabs/bitcoin-bosd/actions)
[![docs](https://img.shields.io/badge/docs-bosd-orange)](https://docs.rs/bitcoin-bosd)

## Features

- Compact binary representation of standard Bitcoin output types.
- Zero-copy parsing and validation.
- Support for P2PKH, P2SH, P2WPKH, P2WSH, P2TR, and `OP_RETURN` outputs.
- Implements [`serde`](https://serde.rs) and [`borsh`](https://borsh.io) serialization.
- Strict validation of Bitcoin addresses and output formats.
- Direct conversion to `bitcoin::ScriptBuf`.

## Specification

BOSD uses a simple binary format consisting of
a 1-byte type tag followed by a cryptographic payload.
The format is designed to be compact
and efficiently represent standard Bitcoin output types:

| Type | Payload Len | Payload Interpretation |
| ---- | ----------- | ---------------------- |
| 0    | ..=80       | `OP_RETURN` payload    |
| 1    | 20          | P2PKH hash             |
| 2    | 20          | P2SH hash              |
| 3    | 20          | P2WPKH hash            |
| 3    | 32          | P2WSH hash             |
| 4    | 32          | P2TR X-only PubKey     |

## Usage

```rust
use bitcoin::Network;
use bosd::Descriptor;

// Parse from binary
let desc = Descriptor::from_bytes(&[0x04, /* 32 bytes of pubkey */])?;

// Convert to Address
let address = desc.to_address(Network::Mainnet)?;

// Convert to ScriptBuf
let script = desc.to_script()?;

// Serialize/deserialize
let json = serde_json::to_string(&amp)?;
let borsh_bytes = borsh::to_vec(&amp)?;
```

## Contributing

Contributions are generally welcome.
If you intend to make larger changes please discuss them in an issue
before opening a PR to avoid duplicate work and architectural mismatches.

For more information please see [`CONTRIBUTING.md`](/CONTRIBUTING.md).

## License

This work is dual-licensed under MIT and Apache 2.0.
You can choose between one of them if you use this work.
