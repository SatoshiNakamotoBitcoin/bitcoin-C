# Bitcoin Echo

A complete, ossified implementation of the Bitcoin protocol in pure C.

*Build once. Build right. Stop.*

## Status

**Phase 3: Consensus Data Structures** — Complete (175 tests passing)

| Component | Tests |
|-----------|-------|
| SHA-256 | 9/9 |
| RIPEMD-160 | 17/17 |
| secp256k1 Field | 19/19 |
| secp256k1 Group | 15/15 |
| ECDSA Verification | 17/17 |
| Schnorr (BIP-340) | 20/20 |
| Signature Interface | 13/13 |
| Varint Encoding | 50/50 |
| Transactions | 15/15 |
| Blocks | 14/14 |
| Merkle Trees | 15/15 |

Next: Phase 4 — Transaction Validation (Script Interpreter)

## Building

### POSIX (Linux, macOS, BSD)

```sh
make
./echo
```

### Windows

```cmd
build.bat
echo.exe
```

## Testing

```sh
make test
```

Runs all unit tests for cryptographic primitives.

## Requirements

- C11 compiler (GCC, Clang, or MSVC)
- No external dependencies

## Documentation

Documentation lives in the [`bitcoinecho-org`](https://github.com/bitcoinecho/bitcoinecho-org) repository:

- [Whitepaper](https://github.com/bitcoinecho/bitcoinecho-org/blob/main/bitcoin-echo-whitepaper.md) — Technical specification
- [Manifesto](https://github.com/bitcoinecho/bitcoinecho-org/blob/main/bitcoin-echo-manifesto.md) — Philosophical foundation
- [Roadmap](https://github.com/bitcoinecho/bitcoinecho-org/blob/main/ROADMAP.md) — Implementation progress

## License

MIT License — see [LICENSE](LICENSE)
