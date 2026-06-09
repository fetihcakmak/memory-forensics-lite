"""
Process Analyzer - Pure Python memory mapping and reading via ctypes (Windows)
"""
import sys
import ctypes
from ctypes import wintypes
from typing import List, Tuple, Optional

# Windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

def get_process_memory_regions(pid: int) -> List[Tuple[int, int, int]]:
    """Returns a list of readable memory regions for a given PID. (BaseAddress, RegionSize, Protect)"""
    if sys.platform != 'win32':
        return []
        
    kernel32 = ctypes.windll.kernel32
    process_handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    
    if not process_handle:
        return []

    regions = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    
    while kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if mbi.State == MEM_COMMIT and mbi.Protect in (PAGE_READWRITE, PAGE_EXECUTE_READWRITE):
            regions.append((mbi.BaseAddress, mbi.RegionSize, mbi.Protect))
        address += mbi.RegionSize

    kernel32.CloseHandle(process_handle)
    return regions

def read_process_memory(pid: int, address: int, size: int) -> Optional[bytes]:
    """Reads a specific memory region of a process."""
    if sys.platform != 'win32':
        return None
        
    kernel32 = ctypes.windll.kernel32
    process_handle = kernel32.OpenProcess(PROCESS_VM_READ, False, pid)
    
    if not process_handle:
        return None

    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()

    success = kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read)
    )

    kernel32.CloseHandle(process_handle)
    
    if success:
        return buffer.raw[:bytes_read.value]
    return None
