# cargo-unsafe-surface

> **Status: early development.** The README is completed alongside the
> implementation; see `docs/` for the design documents that already exist.

`cargo-unsafe-surface` is a Cargo subcommand that determines which unsafe
operations are reachable from selected entry points in a Rust program. It
goes beyond counting `unsafe` blocks: it builds an approximate call graph
from source code and reports the unsafe and foreign-code exposure of an
application or library, together with the call paths that lead there.

```console
cargo unsafe-surface --bin server
cargo unsafe-surface --lib --format json
```

The tool provides an **approximation**. It must not be treated as formal
proof that a program is safe. See `docs/analysis-model.md` and
`docs/threat-model.md` (added in later commits) for details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
