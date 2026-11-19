"""Nemr Cyber Harden Core Package (v3.0.0)."""

__version__ = "3.0.0"

from core.server_hardener import ServerHardener
from core.source_patcher import SourcePatcher, PatchResult
from core.secret_scanner import SecretScanner
from core.headers_auditor import HeadersAuditor
from core.dependency_auditor import DependencyAuditor
from core.csp_builder import CspBuilder

__all__ = [
    "__version__",
    "ServerHardener",
    "SourcePatcher",
    "PatchResult",
    "SecretScanner",
    "HeadersAuditor",
    "DependencyAuditor",
    "CspBuilder",
]
