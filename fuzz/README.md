# Fuzz Targets

This directory contains 23 libFuzzer targets covering signature verification, public input assembly, commitment operations, protocol message handling, and deserialisation paths across the provii-crypto workspace.

## Running

```bash
# Single target
cargo +nightly fuzz run fuzz_sig_verify

# All targets (time-boxed)
cargo +nightly fuzz run <target> -- -max_total_time=300
```

Corpus files are stored in `corpus/<target>/`. The `oss-fuzz/` directory at the repository root contains the OSS-Fuzz integration harness.
