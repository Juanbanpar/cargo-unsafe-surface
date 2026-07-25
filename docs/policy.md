# Policy reference

A policy file encodes organisational rules over analysis results. It is
evaluated after the analysis with `--policy policy.toml`. Unknown keys
are configuration errors (exit 1); violations exit with code 2.

```toml
[policy]
deny_reachable_inline_assembly = true
deny_reachable_mutable_statics = true
maximum_reachable_ffi_calls = 10
require_safety_comments = true

[dependencies]
deny = ["deprecated-native-wrapper"]
allow_unsafe = ["libc", "socket2"]
```

## `[policy]` rules

| Key | Type | Effect |
| --- | --- | --- |
| `deny_reachable_inline_assembly` | bool | Violation per reachable `asm!`/`global_asm!`/`naked_asm!` finding. |
| `deny_reachable_mutable_statics` | bool | Violation per reachable `static mut` access. |
| `deny_reachable_transmutes` | bool | Violation per reachable `transmute`/`transmute_copy`. |
| `deny_reachable_unsafe_code` | bool | Single violation when any reachable unsafe operation exists (strict mode). |
| `maximum_reachable_ffi_calls` | int | Violation when reachable FFI calls exceed the maximum. |
| `maximum_reachable_unsafe_operations` | int | Violation when total reachable unsafe operations exceed the maximum. |
| `maximum_unresolved_calls` | int | Violation (marked *uncertainty*) when unresolved calls exceed the budget. |
| `require_safety_comments` | bool | Violation per reachable finding without a `SAFETY:` comment. |
| `fail_on_unresolved_calls` | bool | Violation (marked *uncertainty*) when any non-std call is unresolved. |

## `[dependencies]` rules

| Key | Type | Effect |
| --- | --- | --- |
| `deny` | array of names | Violation when a denied package appears in the analysis universe. |
| `allow_unsafe` | array of names | Allow-list of third-party packages (registry/git/path origin) that may contribute reachable unsafe code. When non-empty, reachable findings from any other third-party package are violations. Workspace packages are first-party and never flagged by this rule. |

## Violations vs uncertainty

Evaluation distinguishes:

* **policy violations** — a rule denies something the analysis found;
* **uncertainty violations** — unresolved calls exceed tolerance. They
  fail the command identically (exit 2) but are printed with an
  `[uncertainty]` marker, because they reflect analysis limits rather
  than confirmed unsafe code;
* **configuration errors** — malformed TOML or unknown keys (exit 1).

Unresolved calls are never treated as safe: use
`fail_on_unresolved_calls` or a `maximum_unresolved_calls` budget in
strict environments.

## Example workflows

Gate CI on FFI growth in the networking stack:

```toml
[policy]
maximum_reachable_ffi_calls = 3
```

Forbid new dependencies with unsafe code except the audited set:

```toml
[dependencies]
allow_unsafe = ["libc", "socket2"]
```

Require justifications everywhere unsafe is reachable:

```toml
[policy]
require_safety_comments = true
```
