import os
import re
from utils.memory_scanner_strategy import MemoryScannerStrategy

class LinuxMemoryScanner(MemoryScannerStrategy):
    def list_processes(self):
        return [(int(pid), open(f"/proc/{pid}/comm").read().strip())
                for pid in os.listdir("/proc") if pid.isdigit()]

    def scan_process_memory(self, pid, target_value: bytes):
        matches = []
        maps_path = f"/proc/{pid}/maps"
        mem_path = f"/proc/{pid}/mem"

        with open(maps_path, 'r') as maps, open(mem_path, 'rb', 0) as mem:
            for line in maps:
                m = re.match(r"([0-9A-Fa-f]+)-([0-9A-Fa-f]+)", line)
                if m:
                    start, end = [int(x, 16) for x in m.groups()]
                    try:
                        mem.seek(start)
                        chunk = mem.read(end - start)
                        for i in range(len(chunk) - len(target_value)):
                            if chunk[i:i+len(target_value)] == target_value:
                                matches.append(hex(start + i))
                    except Exception:
                        continue
        return matches