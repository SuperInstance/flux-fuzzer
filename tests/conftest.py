"""Pytest configuration for flux-fuzzer."""
import sys
from pathlib import Path

# Ensure the repo root is on sys.path so `import fuzzer` works
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
