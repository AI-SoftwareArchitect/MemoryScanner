import ctypes, psutil, win32api, win32con, win32process
from utils.memory_scanner_strategy import MemoryScannerStrategy

class WindowsMemoryScanner(MemoryScannerStrategy):
    def get_pid_by_name(self, process_name: str) -> int:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == process_name:
                return proc.pid
        raise Exception("Process not found")

    def read_memory(self, pid: int, address: int, size: int) -> bytes:
        PROCESS_ALL_ACCESS = 0x1F0FFF
        handle = win32api.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        data = ctypes.create_string_buffer(size)
        bytesRead = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(handle.handle, address, data, size, ctypes.byref(bytesRead))
        return data.raw

    def write_memory(self, pid: int, address: int, data: bytes) -> None:
        PROCESS_ALL_ACCESS = 0x1F0FFF
        handle = win32api.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        bytesWritten = ctypes.c_size_t()
        ctypes.windll.kernel32.WriteProcessMemory(handle.handle, address, data, len(data), ctypes.byref(bytesWritten))

    def search_pattern(self, pid: int, pattern: bytes, wildcard: bytes = b'\x00') -> list:
        # Basic scan: Tüm bellekte pattern arama (wildcard desteği eklenecek)
        # Daha sonra burayı optimize edebiliriz
        return []
