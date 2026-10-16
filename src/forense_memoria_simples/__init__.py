"""forense-memoria-simples: forense volátil (strings + IOC)."""

from .ioc import IOC, scan_iocs
from .report import Report, build_report
from .strings import ExtractedString, extract_strings, extract_strings_from_file

__all__ = [
    "IOC",
    "ExtractedString",
    "Report",
    "build_report",
    "extract_strings",
    "extract_strings_from_file",
    "scan_iocs",
]

__version__ = "0.1.0"
