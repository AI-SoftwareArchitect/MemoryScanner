from abc import ABC, abstractmethod

class MemoryScannerStrategy(ABC):
    @abstractmethod
    def get_pid_by_name(self, process_name: str) -> int: pass

    @abstractmethod
    def read_memory(self, pid: int, address: int, size: int) -> bytes: pass

    @abstractmethod
    def write_memory(self, pid: int, address: int, data: bytes) -> None: pass

    @abstractmethod
    def search_pattern(self, pid: int, pattern: bytes, wildcard: bytes) -> list: pass
