# FLUX Fuzzer — Bytecode Generation + Crash Detection

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
Generate random valid FLUX bytecodes and find VM edge cases.

## Features
- Random valid instruction generation from 20 templates
- 6 built-in edge cases (div-by-zero, stack underflow, overflow, etc.)
- Crash/timeout/infinite-loop detection
- Unique crash fingerprinting (MD5 of bytecode)
- Opcode coverage tracking
- Deterministic seeding for reproducibility

## Usage
```python
from fuzzer import FluxFuzzer
f = FluxFuzzer(seed=42)
report = f.fuzz(n=100, seed=42)
print(report.to_markdown())
```

9 tests passing.
