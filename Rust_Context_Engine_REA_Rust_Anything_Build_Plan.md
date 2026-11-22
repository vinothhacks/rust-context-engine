# Rust Context Engine: Build Plan with REA MCP and Rust Anything MCP

**Date:** 22 November 2026  
**Status:** Proposed implementation; not yet built or validated  
**Objective:** Deliver a self-hosted Rust context-optimization layer that preserves recoverable evidence while reducing the amount of tool output exposed to coding agents.

## 1. Executive decision

Build **one native Rust core** with three product interfaces: a CLI, an MCP server, and narrowly scoped agent adapters. Use **REA MCP** to investigate behavior and gather evidence and **Rust Anything MCP** to verify selected ports of actual legacy code. Do **not** chain Context Mode, RTK, Headroom, and Caveman as runtime dependencies. Do **not** require REA or Rust Anything for normal operation.

The reference projects inspire the following capabilities:

| Reference | Feature to learn | Implementation decision |
| --- | --- | --- |
| Context Mode | Local indexing, hooks, exact recovery, session state | Independent Rust implementation of the relevant contract; audit license before reuse |
| RTK | Deterministic command-output reducers | Native Rust reducers; study existing Rust techniques rather than redundantly porting Rust |
| Headroom | Content-aware reduction and original recovery | Rust classification and policy routing; optional semantic reduction only later |
| Caveman | Concise interactions and recoverability | Optional agent response guidance; do not rewrite user input |

**Definition of value:** Task success must remain non-inferior to baseline and overall session tokens/cost must fall after accounting for evidence retrieval overhead. Output byte reduction alone is insufficient.

## 2. Boundaries and product surfaces

```text
  Developer / agent (OpenCode, Claude Code, Cursor)
             |
   +---------+---------------------------+
   |                                     |
   v                                     v
 Agent-specific hooks               Explicit MCP calls
 native result capture              context_run/index/search/get
   |                                     |
   +-----------------+-------------------+
                     |
                     v
             Rust context-core
       [trust check -> capture -> policy]
                     |
    [classify -> deterministic reducer -> view]
                     |
     +---------------+------------------+
     |               |                  |
 protected blob   SQLite FTS5      session journal
 originals        search/index     and checkpoints
     +---------------+------------------+
                     |
         compact view + provenance
          + exact recovery handle

 Development only: REA MCP <-> coding agent <-> Rust Anything MCP
```

MCP alone does **not** transparently intercept an agent's native shell, edit, or file-read tools. Native interception is possible only through a compatible host plugin/hook with demonstrated replacement semantics; otherwise the agent must explicitly use the context engine's MCP/CLI tools.

### Must-have (V1)

- Local processing; no remote summarizer or remote vector service.
- Capture terminal outputs and supplied documents with explicit scope and provenance.
- Deterministic reduction for build/test/Git/log/JSON/search results.
- Recover original captured bytes, or clearly state when exact originals are unavailable.
- Separate stdout and stderr, exit status, timestamps, encoding and truncation markers.
- Scoped lexical search, bounded range retrieval, session checkpoint and restore.
- CLI, MCP stdio transport, one proven agent adapter.
- Explicit permissions, no secret indexing, secure retention, and audited command execution.
- Reproducible comparison against uncached baseline tasks.

### Non-goals (V1)

- No LLM-based summarization, embeddings, cross-project hosted memory, provider proxy, browser automation, or automatic installation by an agent.
- No direct database access, unrestricted execution, or destructive shell privileges by default.
- No claim of transparent support for every coding agent.

## 3. Development MCP setup

The upstream `.mcp.json` for Rust Anything registers `rust-anything mcp`; REA's upstream `mcp.json` registers `npx -y rea-agents@6.10.1 mcp`. Both are **development MCP servers**. This example is for an MCP client that accepts `mcpServers` (such as Claude-style `.mcp.json`); other clients require different configuration shapes.

```json
{
  "mcpServers": {
    "rea": {
      "command": "npx",
      "args": ["-y", "rea-agents@6.10.1", "mcp"]
    },
    "rust-anything": {
      "command": "rust-anything",
      "args": ["mcp"]
    }
  }
}
```

Prerequisites: supported Rust toolchain, Cargo, Node/npm, installed/vetted `rust-anything` binary on PATH, local copies of permitted reference repositories, and an MCP-aware agent. Use the upstream `npx rea-agents setup` and `rust-anything setup` only after reviewing their proposed changes. Prefer pinned binaries/package versions, integrity checks, and installation in an online staging environment; do not rely on npm downloads in an offline runtime.

**Verification:** Restart the client, inspect its discovered tool list, confirm REA and Rust Anything separately, and invoke only read-only diagnostic tools first. A successful shell command does not prove that a desktop agent inherited the right PATH.

**After the engine is built**, its own MCP registration should be independent, for example `context-engine mcp --workspace /absolute/path/to/project` (to be implemented in Phase 4). Scope the workspace server-side, not by trusting an arbitrary tool argument.

## 4. How to use the two MCPs correctly

### REA MCP: investigate references, not author the Rust

1. Pin a source revision/tag and record the relevant license before studying behavior.
2. Inspect normal source first: entry points, middleware/hooks, reducers, capture and persistence, search, error and retention paths.
3. Use REA where source analysis is insufficient: packaged distributions, dynamically composed behavior, runtime call paths, and native code boundaries.
4. Capture reproducible, attributed evidence: revision, path, line/function or trace, fixture, observed output, inferred hypothesis, unresolved question.
5. Convert evidence into a *behavioral specification*, including failure and edge cases.
6. Repeat the investigation after unexpected discrepancies; do not accept AI-generated conclusions without corroboration.

REA's investigation findings and pseudocode are evidence, not proof that an implementation is correct. REA's analysis runs locally, but its tool results can still be sent to the agent's model provider. Use an approved private/local model for confidential work.

### Rust Anything MCP: port when there is an actual original unit

For a real TypeScript/Python/etc. function selected for behavioral compatibility:

```bash
rust-anything analyze /path/to/pinned-reference --json
# Choose a unit from the analyze result. Work in a disposable licensed source copy.
rust-anything bridge /path/to/pinned-reference <UNIT_ID>
# Implement the generated src/port.rs in Rust.
rust-anything record <GENERATED_CRATE_DIR>
rust-anything build <GENERATED_CRATE_DIR>
rust-anything diff <GENERATED_CRATE_DIR>
rust-anything fuzz <GENERATED_CRATE_DIR>
rust-anything bench <GENERATED_CRATE_DIR>
rust-anything gate <GENERATED_CRATE_DIR>
```

The corresponding MCP tool names include `analyze`, `bridge`, `record`, `build`, `diff`, `fuzz`, `bench`, `gate`; `app_record`, `app_replay`, `app_front_door`, `app_wire`, `app_lift` support suitable whole-app migration paths.

**Limits:** Rust Anything does not automatically translate source code. Its behavior-gate only tests recorded cases and may miss unrecorded inputs. Use it for a specific existing source component (e.g., an approved JSON reducer or Python content classifier), not as a substitute for writing and testing a brand-new Rust architecture. RTK is already Rust: review or integrate relevant permitted code instead of 'porting' it with a tool designed for source-language migrations. Do not require byte-for-byte equivalence when a deliberately improved new output contract differs; compare the relevant invariants and documented compatibility surface.

**Safety:** `record`, `diff`, `fuzz`, `app record` and related operations can execute original code repeatedly. Run in a disposable sandbox with fixture data, test services, no production secrets, and denied outbound network. For nondeterministic input, pin clocks or use explicitly reviewed normalizers; never normalize away meaningful errors.

## 5. Proposed Rust workspace

```text
context-engine/
  Cargo.toml                       # workspace, dependency pins, lint policy
  Cargo.lock
  crates/
    context-core/                 # types, result contract, budget, policy decisions
    context-capture/              # bounded stdout/stderr capture, ingestion
    context-reducers/             # build/test/git/log/json reducers
    context-store/                # content-addressed protected blob storage
    context-search/               # SQLite FTS5, excerpts, retrieval ranking
    context-journal/              # session checkpoint and event log
    context-execution/            # explicit allowlist, approvals, sandbox backends
    context-mcp/                  # MCP tools over stdio
    context-cli/                  # executable: run, index, search, get, doctor
  adapters/
    opencode/                     # one host first; verified hooks only
    claude-code/                  # deferred until after V1 validation
    cursor/                       # deferred
  research/
    provenance-and-licenses.md
    capability-matrix.md
    observed-behavior.md
    open-questions.md
    evidence/
  fixtures/
    commands/
    documents/
    adversarial/
  evals/
    tasks.jsonl
    run-baseline.sh
    run-engine.sh
    reports/
  docs/
    adrs/
    threat-model.md
    api-contract.md
    security-and-retention.md
    operations.md
```

### Recommended dependencies (evaluate and pin)

- `tokio`: async process capture, bounded channels, cancellation, task deadlines.
- `clap`: CLI arguments and subcommands.
- `serde` / `serde_json`: contracts and JSON parsing.
- `rusqlite` with SQLite FTS5/WAL support: metadata, search index, journal.
- `sha2`: SHA-256 integrity verification of exact originals; `zstd` optional compression.
- `regex`, `ignore`, `tracing`: reducers, path filtering and structured diagnostics.
- An established Rust MCP SDK compatible with the target MCP protocol version; assess current API/maintenance before pinning.
- `proptest`/`cargo-fuzz`, `tempfile`, integration fixtures and `criterion` as appropriate.

Avoid choosing 20 crates or a complex plugin ABI before there is one successful vertical slice.

## 6. Core contracts

### Artifact envelope (proposed schema)

```json
{
  "schema_version": 1,
  "artifact_id": "a_<opaque-id>",
  "project_scope": "<server-bound-scope>",
  "session_id": "<session-id>",
  "source": {
    "kind": "command",
    "argv": ["cargo", "test"],
    "cwd_relative": ".",
    "exit_code": 101,
    "captured_at": "<ISO-8601>"
  },
  "capture": {
    "stdout_sha256": "<digest>",
    "stderr_sha256": "<digest>",
    "stdout_bytes": 123456,
    "stderr_bytes": 32768,
    "complete": true,
    "encoding": "utf-8",
    "originals_available": true
  },
  "view": {
    "kind": "test_summary",
    "reducer_version": "1",
    "omitted": true,
    "safe_excerpt": "2 tests failed",
    "transformations": ["strip_ansi@1", "cargo_test@1"]
  },
  "recovery": {
    "tool": "context_get",
    "artifact_id": "a_<opaque-id>",
    "bounded": true
  }
}
```

IDs must be opaque, generated by the server, and always resolved through the session's bound principal/project. Source-supplied `project_id` is not authorization. Store stdout/stderr independently. Preserve original non-UTF-8 bytes and permit byte-offset retrieval; UTF-8 line views are a separate derived representation.

### CLI contract

```text
context-engine run -- cargo test
context-engine index ./test-output.log
context-engine search "assertion failed" --session <id>
context-engine get <artifact-id> --stream stderr --lines 10:70
context-engine stats --session <id>
context-engine doctor
context-engine mcp --workspace /absolute/project/path
```

These are **planned commands** (not currently implemented). `run` must support an argv vector without invoking a shell by default. Preserve exit status and command outcomes, even when the summary is compact. Do not rerun a command merely to recover evidence.

### MCP tools

| Tool | Contract | Authority |
| --- | --- | --- |
| `context_run` | approved argv/cwd/timeouts; compact summary + original handle | capability-gated and approval-required where needed |
| `context_index` | index allowed workspace file or supplied text | scoped file-read only |
| `context_search` | bounded ranked excerpts and provenance | current project/session only |
| `context_get` | original stream by byte offset or line range, paginated | authenticated, authorized scope, max bytes |
| `context_resume` | journal checkpoint + referenced artifact handles | same principal/project |
| `context_stats` | capture, compression, retrieval and cost metrics | non-sensitive aggregate |
| `context_doctor` | config, local storage, permissions, integrations | read-only |

Never expose arbitrary SQL execution, unbounded dump retrieval, general network access or destructive purge through the initial MCP catalog. `context_run` must require a strict executable policy, canonical cwd confinement, timeouts and cancellation; a shell or high-risk command is a separate explicitly approved capability.

## 7. Processing pipeline

1. **Authorize:** Bind principal, workspace and requested operation before reading or executing.
2. **Capture:** Stream output in bounded chunks; record stdout/stderr separately, process exit status, and observed truncation/errors.
3. **Protect:** Check sensitive data policy before writing, displaying or indexing. Route secrets to deny/quarantine/redact-only policy as configured.
4. **Persist:** Write allowed originals to a private content-addressed store atomically and verify SHA-256. If the exact original cannot be stored, explicitly mark recovery unavailable.
5. **Classify:** Identify test/compiler/Git/log/JSON/search/plain/binary by reliable shape and source metadata; fail safely on unknown data.
6. **Reduce once:** Apply one policy-selected reducer; track transformation provenance so adapters do not re-compress already reduced results.
7. **Index:** Index selected *sanitized* text only, with pointers to originals, provenance and confidentiality boundaries.
8. **Respond:** Return status, key errors and counts, omitted marker, and bounded retrieval handle. Include enough immediate evidence to choose the next action.
9. **Journal:** Save event and checkpoint state without logging secret payloads or broad credential-bearing context.

For failures in any step: never report success falsely. Security controls fail closed; reduction errors degrade to a bounded safe view with explicit `reduction_error`, `capture_complete` and `originals_available` status. Do not dump arbitrary original content into an agent's context as an error fallback.

### Reducer priorities

| Class | Compact response | Always preserve |
| --- | --- | --- |
| Cargo / pytest / test runners | passed/failed/ignored counts, failing tests, essential stack traces | exit status; failed identifiers; assertion evidence; artifacts |
| Rust compiler / build | unique errors, first causal diagnostics, file:line, warning counts | diagnostic code, location and distinct errors |
| Git status/diff | staged vs unstaged, path lists, diff summary | precise paths and states; exact diff accessible |
| Logs | severity counts, deduplicated templates and bounded context | timestamps, unique error messages, contextual ranges |
| JSON/structured | type/schema overview and selected fields | keys, structure, relevant values; original pointer |
| Search | relevant bounded snippets | filename, line range, stable source and ranked order |
| Unknown/binary | type, size, hash, safe preview if allowed | mark omitted/unparsed; exact byte recovery where permitted |

Do not silently discard errors or source lines that are necessary for an edit. Keep source outlines distinct from exact code excerpts. Avoid general-purpose semantic rewriting in V1.

## 8. Storage and security architecture

### Metadata and original storage

- One SQLite database per local workspace/principal or a database with enforced scoped identities. Use WAL and migrations; do not infer that SQLite alone provides encryption or row-level access control.
- Immutable content-addressed blobs, private directory permissions, atomic temp file + rename, checksum validation, optional zstd and per-workspace quotas.
- Only sanitized, authorized text enters FTS5; otherwise sensitive strings leak through search even if summaries were redacted.
- Tiered retention: session lifecycle, TTL, per-workspace size caps, explicit administrative prune. Remove index rows and blobs consistently; validate crash recovery.
- Optional at-rest encryption (and key management) for sensitive or multi-user deployments; OS permissions are not enough for all threat models.

### Security gates

- Canonical path and symlink containment; check TOCTOU risks around path resolution.
- Deny `.env`, private keys, tokens and unrelated credential directories by default. Avoid indexing secret-bearing stdout or log bodies.
- Treat tool outputs as untrusted data, including prompt-injection-looking text.
- Do not run repository-provided install hooks or networked scripts without review.
- Separate permissions: read, execute, write, network, destructive command, admin purge. Require explicit human approval and environment confinement for dangerous operations.
- Default to no network on execution sandbox; use local test services and stubbed dependencies.
- Verify no outbound traffic during an offline acceptance test using host/firewall monitoring. **Local MCP transport alone is not a no-egress guarantee:** a hosted coding model may still receive tool results.
- Prevent project A/session A from retrieving project B/session B output even with forged artifact IDs.
- Include supply-chain checks, pinned versions, dependency vulnerability review, SBOM and license provenance before distribution.

### Licensing gate

REA and Rust Anything currently declare MIT licenses. Context Mode's repository declares Elastic License 2.0, including restrictions for certain third-party hosted/managed offerings. Caveman currently publishes Apache-2.0. Verify the exact pinned upstream versions and files, plus Headroom and RTK license terms, before copying or modifying implementation code. Independently specifying behavior does not automatically resolve every legal question; get legal review before commercial distribution or hosted service operation.

## 9. Phased delivery with acceptance gates

| Phase | Deliverables | Exit criterion |
| --- | --- | --- |
| **0 - Evidence and design** | pinned refs, license inventory, threat model, capability matrix, fixtures, decisions | every V1 requirement has an evidence source or is clearly new design; no unresolved license blocker |
| **1 - Rust skeleton** | Cargo workspace, core types, CLI `doctor`, lint/test/CI | reproducible builds on target OS, no warnings, unit testing scaffold operational |
| **2 - Capture/recover** | bounded process capture, store, hashes, `run`/`get` | byte-exact stdout/stderr round trip across normal/non-UTF-8/large/crash inputs; exit status correct |
| **3 - Deterministic reducers** | Cargo/test/compiler/Git/log/JSON reducers, classifier | fixtures retain all required failures; unknown formats degrade safely; one reduction per artifact |
| **4 - MCP and one adapter** | `context_*` MCP stdio tools, OpenCode adapter after host-hook validation | live agent can run tests, read summary and recover exact diagnostics; without hooks explicit MCP works |
| **5 - Search and continuity** | SQLite FTS5, bounded retrieval, journal/resume | authorized project/session search and resume return valid evidence; cross-scope leakage denied |
| **6 - Security and evaluation** | adversarial fixtures, offline egress test, benchmark harness, runbooks | documented non-inferior task quality, measured token/cost savings, no critical security failure |
| **Later** | other host adapters, embeddings/semantic routing, optional provider proxy | each addition individually benchmarks and passes security/compatibility review |

**Recommended first PR series:**

- PR-01: Workspace, configuration schema and tests.
- PR-02: Capture -> protected blob store -> SHA verification -> range retrieval.
- PR-03: Cargo test reducer, golden fixtures, raw-vs-compact comparison.
- PR-04: MCP stdio `context_run` and `context_get`, tool schema tests.
- PR-05: Host adapter only after actual hook semantics are confirmed.
- PR-06: Search, journal, retention, security tests.
- PR-07: End-to-end evaluations and distribution artifacts.

## 10. First vertical slice (build this before anything else)

```text
agent -> context_run { argv: ["cargo", "test"] }
      -> approved isolated command execution once
      -> persist stdout, stderr, exit code, SHA-256
      -> parse Cargo test output
      -> compact summary (counts + failed test identifiers + error excerpt)
      -> context_get {artifact_id, stream:"stderr", lines:{start:1,end:80}}
      -> exact recovered evidence
```

**Three mandatory fixtures:**

1. Failing test with multi-line assertion and nonzero exit; preserve failure location and evidence.
2. Successful test with large, repetitive output; return concise success and a valid recovery pointer.
3. Unknown/non-UTF-8 output; return a safe bounded view, mark format uncertainty and permit byte-accurate retrieval.

Before adding more reducers, show that these fixtures work via both CLI and MCP, and that `cargo test` was not inadvertently run twice. Capture command results even when the reducer fails, subject to the data-security policy.

## 11. Verification and benchmark plan

### Regression, property and security tests

- Unit tests for every reducer with real and synthetic fixtures, empty output, ANSI escapes, colors, carriage returns, CRLF, malformed encodings, partial lines and terminal control codes.
- Golden tests and property tests for totals, errors, status, stable artifact references and transformation ledgers.
- Long-output streaming, backpressure, cancellation, process timeout, command spawn failure, disk full, corrupted blob, interrupted atomic writes and concurrent readers/writers.
- MCP `initialize`, `tools/list`, schema-validated arguments, pagination, cancellation, error contracts and tool-result size checks using a real client harness.
- Symlink escape, traversal, path swap, forged project ID, artifact enumeration, log injection, prompt injection, malicious JSON and oversized retrieval attempts.
- Secret leakage simulation: tokens in stdout, files and stack traces must not enter summaries, index or non-authorized MCP responses.
- Cross-platform build/run tests, at least Linux and Windows, before claiming support.

### Evaluation dataset

- Start with 20 representative coding tasks and 20 output fixtures. Include Rust compiler errors, failing tests, Git state, noisy logs and JSON, plus cases where the agent needs original source context.
- Run baseline agent vs same agent/model/permissions with engine. Repeat with controlled variance; compare paired tasks and use model/provider token usage wherever available.
- Measure task success, regression tests, total input/output tokens, retrieval calls/tokens, provider cost and cache usage, wall time, tool-visible byte savings, startup time, p95 tool latency, CPU, memory, disk, error rate and data egress.
- Check whether the agent can make the same debugging decision using compact evidence, and how often follow-up retrieval is necessary.

**Suggested V1 acceptance targets (proposals, not measurements):**

| Measure | Proposed bar |
| --- | --- |
| Exact recovery | 100% match for every fully captured authorized fixture, including binary bytes |
| Failure evidence | 100% of distinct failure identifiers and exit codes retained in supported parser fixtures |
| Tool-output reduction | >= 40% median reduction on target noisy fixtures (not claimed as token/cost savings) |
| End-to-end token reduction | >= 25% median lower total usage on paired target tasks, including retrieval overhead |
| Task effectiveness | No material regression in successful completions; review any new failures |
| Security | Zero unauthorized cross-project retrievals and no observed external connections during designated offline run |
| Safety | All unsupported/failed reductions explicitly marked; no fabricated success; destructive actions blocked without approval |

These thresholds should be approved before evaluation and adjusted only with an explicit documented decision, not after seeing performance results. A small task set cannot establish broad statistical non-inferiority; enlarge it before broad rollout.

## 12. Operational and rollout decisions

- Package one local binary with CLI and MCP subcommands; keep adapter installations explicit, opt-in and separately versioned.
- Default to single-user/per-workspace isolation for V1. Multi-tenant daemon requires separate identity/authentication, encryption, quotas, process isolation and threat-model review.
- Use feature flags for each reducer and agent adapter; allow rollback to untouched output where data policy permits, otherwise return a clear safe error.
- Provide `doctor` checks for storage permissions, schema migrations, command policy, MCP transport, host hooks and network policy.
- Monitor output size and token estimates, retrieval usage, crash rate, queue/backpressure, disk usage, DB health, and security denial counts without logging raw secrets.
- Any cloud-provider proxy or general semantic compression is a new independently threat-modeled phase, not part of V1.

## 13. Immediate next steps for the coding agent

1. Create `research/provenance-and-licenses.md` with pinned upstream revisions and obligations; do not copy upstream implementation until cleared.
2. Connect REA and Rust Anything, verify `tools/list`, and produce `research/capability-matrix.md` plus the first four fixture families.
3. Draft and approve ADRs for artifact identity/scope, storage policy, command permissions, truncation limits, retention and security failure behavior.
4. Scaffold the Rust workspace. Implement the first vertical slice: `cargo test` capture, compact summary, exact range retrieval.
5. Test through CLI and local MCP client. Publish baseline comparisons, then move to more reducers and agent hooks.

### Definition of done for initial PoC

One real local coding agent runs a failing Rust test suite through the new MCP tool, receives a bounded summary, retrieves the exact failed assertion from its original stdout/stderr artifact, and fixes the underlying code. Provenance, scope, command exit status and original integrity are verified. The equivalent baseline task is run under the same conditions and compared for quality and total token usage. No external network connection is required by the engine during the demonstration.

## Sources verified on 22 November 2026

- Original design supplied in this conversation: `Pasted text(20261122-061138).txt`.
- Rust Anything `.mcp.json`: https://github.com/erkamyaman/rust-anything/blob/main/.mcp.json
- Rust Anything verified MCP tools: https://github.com/erkamyaman/rust-anything/blob/main/docs/tools.md
- Rust Anything how it works and limits: https://github.com/erkamyaman/rust-anything/blob/main/docs/how-it-works.md
- Rust Anything whole-app warnings: https://github.com/erkamyaman/rust-anything/blob/main/docs/whole-apps.md
- REA `mcp.json`: https://github.com/morluto/rea/blob/main/mcp.json
- REA installation: https://github.com/morluto/rea/blob/main/docs/getting-started/installation.md
- REA client configuration: https://github.com/morluto/rea/blob/main/docs/getting-started/client-configuration.md
- Context Mode license: https://github.com/mksglu/context-mode/blob/main/LICENSE
- Caveman license: https://github.com/JuliusBrussee/caveman/blob/main/LICENSE

**Confidence:** Architecture and phase ordering 0.93; upstream MCP registration details 0.97; performance targets 0.55 pending measurements. **Key caveat:** This is an implementation plan and has not been run in the user's environment; specific agent hook compatibility, licenses of pinned versions and end-to-end savings require testing.
