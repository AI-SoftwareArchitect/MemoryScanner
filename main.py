import platform
from Windows.windows_memory_scanner import WindowsMemoryScanner
from Linux.linux_memory_scanner import LinuxMemoryScanner
from utils.pattern_parser_util import parse_pattern

def get_strategy():
    if platform.system() == "Windows":
        return WindowsMemoryScanner()
    elif platform.system() == "Linux":
        return LinuxMemoryScanner()
    else:
        raise NotImplementedError("Unsupported OS")

if __name__ == "__main__":
    scanner = get_strategy()

    pname = input("Process name: ")
    pid = scanner.get_pid_by_name(pname)
    print(f"PID: {pid}")

    pattern_str = input("Enter byte pattern (e.g., 'FF ?? AB ?? 12'): ")
    pattern, wildcard = parse_pattern(pattern_str)

    print("Searching pattern in memory...")
    matches = scanner.search_pattern(pid, pattern, wildcard)

    for addr in matches:
        print(f"Found at: {hex(addr)}")
