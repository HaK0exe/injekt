# injekt task runner (https://just.systems)
# Usage: `just`, `just check`, `just test`, `just scan TARGET="https://example.com/?id=1"`

default:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --all-targets -- -D warnings

check: fmt-check clippy
    cargo check --all-targets

test:
    cargo test --all-targets

doc-test:
    cargo test --doc

completions SHELL="bash":
    cargo run -q -- --no-banner completions {{SHELL}}

man:
    cargo run -q -- --no-banner man

init PROFILE="balanced":
    cargo run -q -- --no-banner init --preset {{PROFILE}}

# OPSEC-safe: no request sent, prints the execution plan.
dry-run TARGET="https://example.com/?id=1":
    cargo run -q -- --no-banner --target "{{TARGET}}" --dry-run

auto TARGET="https://example.com/?id=1":
    cargo run -q -- --no-banner auto --target "{{TARGET}}"
