"""Enables `python -m k8smatrixwarden ...`."""
from .cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
