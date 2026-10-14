"""允许从项目根运行 python -m utils.deobf_bench。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from .cli import main

raise SystemExit(main())
