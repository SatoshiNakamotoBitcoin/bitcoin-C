# Bitcoin-C

A complete, ossified implementation of the Bitcoin protocol in pure C.

*Build once. Build right. Stop.*

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

Runs all unit tests for cryptographic primitives, data structures, and script execution.

## Requirements

- C11 compiler (GCC, Clang, or MSVC)
- No external dependencies

## License

MIT License — see [LICENSE](LICENSE)
