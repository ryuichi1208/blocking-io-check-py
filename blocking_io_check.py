#!/usr/bin/env python3
"""後方互換のシム。

`sudo uv run blocking_io_check.py` という従来の起動方法を保つためのもの。
実装は blockingio パッケージにある。新しくは `blocking-io-check` コマンド、
または `python -m blockingio` を使う。
"""

import sys

from blockingio.cli import main

if __name__ == "__main__":
    sys.exit(main())
