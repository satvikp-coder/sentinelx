from apps import labctl
import psutil
from pathlib import Path
import time

labctl.up('vibe_notes_node')
time.sleep(2)

pf = Path('labs/vibe_notes_node/.lab.pid')
if pf.exists():
    pid = int(pf.read_text().strip())
    print(f"PID file: {pid}")
    try:
        proc = psutil.Process(pid)
        print(f"Process: {proc.name()}")
        conns = proc.net_connections(kind="inet")
        print(f"Total connections: {len(conns)}")
        for c in conns:
            laddr = c.laddr
            raddr = c.raddr
            laddr_str = f"{laddr[0]}:{laddr[1]}" if laddr else "?"
            raddr_str = f"{raddr[0]}:{raddr[1]}" if raddr else "()"
            print(f"  {laddr_str} -> {raddr_str} status={c.status}")
    except Exception as e:
        print(f"Error: {e}")

labctl.down('vibe_notes_node')
