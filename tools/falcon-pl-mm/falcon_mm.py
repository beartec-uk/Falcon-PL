#!/usr/bin/env python3
# Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
"""falcon-mm entrypoint. Usage: falcon_mm.py /etc/falcon-mm/config.json [--once]"""
from __future__ import annotations

import sys

from falcon_mm.config import load_config
from falcon_mm.service import run_forever


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    once = False
    if "--once" in argv:
        once = True
        argv.remove("--once")
    if not argv:
        print("usage: falcon_mm.py /path/to/config.json [--once]", file=sys.stderr)
        return 2
    cfg = load_config(argv[0])
    run_forever(cfg, once=once)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
