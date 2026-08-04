default: check

check: fmt-check lint test

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

lint:
    cargo clippy --all-targets -- -D warnings

test:
    cargo nextest run

coverage:
    cargo llvm-cov nextest

coverage-html:
    cargo llvm-cov nextest --open
