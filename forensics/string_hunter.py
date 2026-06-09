"""
String Hunter - Scans byte arrays for IOCs (URLs, IPs, Suspicious APIs)
"""
import re
from typing import List, Dict

IOC_PATTERNS = {
    "IPv4": rb"(?:[0-9]{1,3}\.){3}[0-9]{1,3}",
    "URL": rb"https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9\-\._\?\,\'/\\\+&%\$#\=~]*)?",
    "Email": rb"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Windows_API": rb"(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|LoadLibraryA|GetProcAddress|SetWindowsHookEx)",
}

def extract_ascii_strings(data: bytes, min_length: int = 5) -> List[str]:
    """Extracts printable ASCII strings from binary data."""
    strings = []
    current_string = ""
    for b in data:
        if 32 <= b <= 126:
            current_string += chr(b)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""
            
    if len(current_string) >= min_length:
        strings.append(current_string)
        
    return strings

def scan_for_iocs(data: bytes) -> Dict[str, List[str]]:
    """Scans binary data for specific Indicators of Compromise (IOCs)."""
    findings = {key: [] for key in IOC_PATTERNS}
    
    for key, pattern in IOC_PATTERNS.items():
        matches = re.finditer(pattern, data)
        for match in matches:
            try:
                decoded = match.group().decode('ascii')
                if decoded not in findings[key]:
                    findings[key].append(decoded)
            except UnicodeDecodeError:
                continue
                
    # Filter out empty lists
    return {k: v for k, v in findings.items() if v}
