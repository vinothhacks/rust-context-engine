<!--
SPDX-License-Identifier: Apache-2.0
Provenance: Generated and verified via `user-rust-anything` MCP (v3.1.0) from
isolated deterministic unit `headroom_port/classifier_json_reducer.py`, adapted from
`chopratejas/headroom` @ commit `ce0460cfa8598dc939243dbc7aec4b2d35f4e44a` (Apache-2.0,
Copyright 2025 Headroom Contributors).
-->

## `classifier-json-reducer-rs` in Rust

![classifier-json-reducer-rs report card](card.svg)

| | |
| --- | --- |
| Upstream Source | `chopratejas/headroom` @ `ce0460cfa8598dc939243dbc7aec4b2d35f4e44a` (`Apache-2.0`) |
| Isolated Unit | `headroom_port/classifier_json_reducer.py` (Python 3.11.15, stdlib-only) |
| Recorded cases matched (`diff`) | 1180 / 1180 (`0` mismatches, `0` errors) |
| Differential fuzz cases matched (`fuzz`) | 2748 / 2748 (`seed=20261122`, `2` rounds, `0` mismatches) |
| Definition-of-done `gate` | **PASSED** (`12 / 12` checks: `fmt`, `clippy -D warnings`, `cargo test`, `#![forbid(unsafe_code)]`, `lockfile`, `ported`, `size`, `error cases`, `panics`, `build`, `api`, `behavior`) |
| Speedup, FFI call included (`report`) | **6.94x** geometric mean (`7.19x` standalone `bench` run) |
| Fallback to the original | 0.0% (0 of 1180 cases) |
| Switched on | off (pure Rust `port.rs` exported to `research/evidence/port.rs` for native integration into `crates/context-reducers`) |

| Function | Cases | Original per call (`report`) | Rust per call (`report`) | Speedup (`report` / `bench`) |
| --- | ---: | ---: | ---: | ---: |
| `scan_json_spans` | 226 | 1952.5 ns (2.0 µs) | 437.0 ns | **4.47x** / 4.58x |
| `normalize_concatenated_json` | 232 | 614.0 ns | 250.0 ns | **2.46x** / 2.75x |
| `carries_record_array` | 227 | 5663.8 ns (5.7 µs) | 332.1 ns | **17.05x** / 15.39x |
| `classify_content` | 245 | 23096.8 ns (23.1 µs) | 2349.9 ns (2.3 µs) | **9.83x** / 9.24x |
| `reduce_json_structure` | 250 | 6675.8 ns (6.7 µs) | 761.2 ns | **8.77x** / 10.75x |

Measured with `rust-anything report` and `rust-anything bench` on `x86_64, 12 cores, Windows`: `diff` replays every recorded case (including 138 Unicode/BOM/numeric traps and Context Engine tool-output fixtures), `fuzz` generates 2,748 fresh unseen cases from `seed=20261122`, and `gate` enforces formatting, zero clippy warnings, unit tests, zero `unsafe`, and 100% behavioral parity.
