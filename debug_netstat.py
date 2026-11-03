from apps import labctl
import subprocess
import time

labctl.up('vibe_notes_node')
time.sleep(2)

r = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
print("=== Lines with 18081 or LISTEN ===")
for line in r.stdout.splitlines():
    if '18081' in line or 'LISTEN' in line.upper():
        print(line)

print("\n=== All TCP lines ===")
for line in r.stdout.splitlines():
    if 'TCP' in line:
        print(line)

labctl.down('vibe_notes_node')
