"""Run MAIN source for an offline demo; never load private configuration."""

import importlib.util
import os
import runpy
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location(
    "sentinelx",
    ROOT / "packages/__init__.py",
    submodule_search_locations=[str(ROOT / "packages")],
)
module = importlib.util.module_from_spec(spec)
sys.modules["sentinelx"] = module
spec.loader.exec_module(module)
for name in list(os.environ):
    if any(word in name.upper() for word in ("API_KEY", "API_TOKEN")):
        os.environ.pop(name, None)
os.environ["DOTENV_DISABLED"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
# All network activity in these captures must stay on loopback.
original_connect = socket.socket.connect


def local_connect(sock, address):
    if isinstance(address, tuple) and address[0] not in ("127.0.0.1", "::1", "localhost"):
        raise RuntimeError("demo forbids non-loopback network access")
    return original_connect(sock, address)


socket.socket.connect = local_connect
kind, target, *args = sys.argv[1:]
sys.argv = [target, *args]
if kind == "module":
    runpy.run_module(target, run_name="__main__")
else:
    runpy.run_path(str(ROOT / target), run_name="__main__")
