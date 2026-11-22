//! Unified CLI entrypoint stub for `context-engine` (implemented in Phase 5).

fn main() {
    println!(
        "context-engine {} (schema v{})",
        env!("CARGO_PKG_VERSION"),
        context_core::ARTIFACT_SCHEMA_VERSION
    );
}
