"""
Injection Detector - Identifies suspicious memory regions (e.g. RWX memory)
"""
from typing import List, Tuple
from .process_analyzer import PAGE_EXECUTE_READWRITE

def detect_rwx_regions(regions: List[Tuple[int, int, int]]) -> List[Tuple[int, int]]:
    """
    Scans memory regions and returns those that have RWX (Read/Write/Execute) permissions.
    Malware and shellcode often allocate RWX memory.
    Returns list of (BaseAddress, RegionSize)
    """
    suspicious = []
    for base_addr, size, protect in regions:
        if protect == PAGE_EXECUTE_READWRITE:
            suspicious.append((base_addr, size))
    return suspicious
