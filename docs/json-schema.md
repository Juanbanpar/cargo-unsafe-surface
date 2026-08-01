# JSON report schema (version 1)

`cargo unsafe-surface --format json` emits a single JSON object: the
serialized `ReportModel` from `unsafe-surface-core`. The schema is
versioned by the top-level `schema_version` field (currently `1`).
Within a schema version, changes are additive only; consumers should
ignore unknown fields.

## Top-level object

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | `1` | Schema version. |
| `tool` | object | `{name, version}` of the tool. |
| `configuration` | object | Analysis configuration (see below). |
| `packages` | array | Analysed packages, sorted by name. |
| `entry_points` | array | Resolved entry points, sorted by path. |
| `summary` | object | Aggregate counts. |
| `findings` | array | All findings (reachable and unreachable). |
| `structural_findings` | array | Module-level unsafe constructs. |
| `unresolved_calls` | array | Listed unresolved calls (capped). |
| `unresolved_calls_total` | integer | Total unresolved calls before capping. |
| `diagnostics` | array | Analysis diagnostics. |
| `limitations` | array of strings | Analysis limitations applying to this report. |

## `configuration`

`packages` (array of strings), `include_dependencies` (bool),
`include_dev_dependencies` (bool), `explicit_entries` (array of
strings), `features` (array of strings), `all_features` (bool),
`no_default_features` (bool), `target` (string|null).

## Packages

`{id: {name, version, origin}, root, sources_available}` where `origin`
is one of `workspace`, `path`, `registry`, `git`, `unknown`.

## Entry points

`{item, kind}` where `item` is `{krate, segments}` and `kind` is a
tagged object: `{kind: "binary_main", target}`, `{kind: "library_api",
target}` or `{kind: "explicit"}`.

## Findings

```json
{
  "id": 0,
  "operation": {
    "kind": "ffi_call",
    "location": {"file": "ffiwrap/src/lib.rs", "line": 10, "column": 18},
    "confidence": "confirmed",
    "justification": "present",
    "detail": "ffiwrap::socket"
  },
  "enclosing_item": {"krate": "ffiwrap", "segments": ["create_socket"]},
  "package": {"name": "ffiwrap", "version": "0.3.0", "origin": "workspace"},
  "reachability": "reachable",
  "path": [
    {"item": {"krate": "server", "segments": ["main"]},
     "call_site": {"file": "server/src/main.rs", "line": 10, "column": 5},
     "edge_confidence": "confirmed"}
  ]
}
```

* `operation.kind` is one of the snake_case `UnsafeOpKind` values:
  `unsafe_block`, `unsafe_fn`, `unsafe_fn_call`, `unsafe_trait`,
  `unsafe_trait_impl`, `send_impl`, `sync_impl`, `foreign_function`,
  `extern_block`, `ffi_call`, `raw_pointer_deref`, `transmute`,
  `inline_assembly`, `union_field_access`, `mutable_static_access`,
  `mutable_static_definition`, `maybe_uninit_use`, `unchecked_call`.
* `reachability`: `reachable` | `unreachable` | `structural`.
* `path` is `null` for unreachable findings; otherwise the steps from an
  entry point to the enclosing function. `call_site`/`edge_confidence`
  of a step describe the edge to the *next* step (`null` on the last).
* `confidence`: `confirmed` | `inferred`. `justification`: `present` |
  `absent` (a `SAFETY:` comment was found).

## Structural findings

`{kind, package, location, detail, justification}`: same value
vocabularies as findings.

## Unresolved calls

`{caller, callee_text, location, reason}` where `reason` is a tagged
object: `{kind: "unknown_name"}`, `{kind: "ambiguous_method",
candidates}`, `{kind: "dynamic_dispatch"}`, `{kind: "function_pointer"}`,
`{kind: "macro_expansion"}`, `{kind: "standard_library"}`,
`{kind: "dependency_sources_unavailable", krate}`,
`{kind: "unsupported_construct"}`. Standard-library calls are excluded
from the list and noted in `limitations`.

## Diagnostics

`{severity, message, location?}` where `severity` is `info` | `warning`
| `error`.

## Summary

`reachable_unsafe_operations`, `reachable_unsafe_functions`,
`reachable_ffi_calls`, `manual_send_sync_impls`,
`inline_assembly_sites`, `transmutes`, `raw_pointer_dereferences`,
`unreachable_unsafe_operations`, `unresolved_calls` (integers) and
`reachable_by_kind` (map from op kind to count). Summary counts always
reflect the full analysis, even when lists are capped by limits.
