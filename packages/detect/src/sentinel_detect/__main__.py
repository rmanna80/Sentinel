"""``python -m sentinel_detect <stream.jsonl>`` — the same entry point as the ``sentinel-detect`` command."""

from __future__ import annotations

import sys

from .replay import main

if __name__ == "__main__":
    sys.exit(main())
