"""
Layer 2: Runtime Application Self-Protection (RASP)
====================================================
CrowdStrike Paradigm: Inline interceptors for SQL injection, RCE,
Deserialization attacks, SSRF, and other runtime threats.
"""

from __future__ import annotations

import ast
import re
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional
from functools import wraps
import inspect


class RASPThreatType(str, Enum):
    """Types of RASP-detected threats."""
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    CODE_INJECTION = "code_injection"
    DESERIALIZATION_ATTACK = "deserialization_attack"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    XSS = "xss"
    TEMPLATE_INJECTION = "template_injection"


class RASPAction(str, Enum):
    """RASP response actions."""
    LOG = "log"
    BLOCK = "block"
    SANITIZE = "sanitize"
    QUARANTINE = "quarantine"
    TERMINATE = "terminate"


@dataclass
class RASPEvent:
    """RASP detection event."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    threat_type: RASPThreatType = RASPThreatType.SQL_INJECTION
    action_taken: RASPAction = RASPAction.LOG
    location: str = ""  # Function/module where detected
    payload: str = ""  # The malicious payload (truncated)
    context: dict[str, Any] = field(default_factory=dict)
    stack_trace: list[str] = field(default_factory=list)
    severity: float = 0.0  # 0.0 - 1.0


class RASPInterceptor(ABC):
    """Abstract RASP interceptor."""

    @abstractmethod
    def intercept(self, *args, **kwargs) -> Any:
        """Intercept and analyze call."""
        pass

    @abstractmethod
    def get_threat_type(self) -> RASPThreatType:
        """Get threat type this interceptor handles."""
        pass


class SQLInjectionInterceptor(RASPInterceptor):
    """Detect SQL injection attempts."""

    # Common SQL injection patterns
    SQL_PATTERNS = [
        r"(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
        r"(--|#|/\*|\*/)",
        r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
        r"('|\")\s*(OR|AND)\s*\1",
        r"(;|\|\|)\s*(\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b)",
        r"(\b(WAITFOR|DELAY|SLEEP)\s*\()",
        r"(\b(INTO|OUTFILE|DUMPFILE)\s+\w+)",
        r"(\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)\b)",
    ]

    def __init__(self, action: RASPAction = RASPAction.BLOCK) -> None:
        self.action = action
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.SQL_PATTERNS]

    def intercept(self, query: str, params: tuple = (), **kwargs) -> Any:
        """Intercept SQL query execution."""
        # Check raw query
        if self._is_malicious(query):
            self._report_threat(query, "raw_query")
            if self.action == RASPAction.BLOCK:
                raise RuntimeError("SQL injection attempt blocked by RASP")

        # Check parameters
        for param in params:
            if isinstance(param, str) and self._is_malicious(param):
                self._report_threat(param, "query_parameter")
                if self.action == RASPAction.BLOCK:
                    raise RuntimeError("SQL injection attempt blocked by RASP")

        # Allow execution to proceed
        return {"allowed": True, "sanitized": False}

    def _is_malicious(self, text: str) -> bool:
        """Check if text contains SQL injection patterns."""
        for pattern in self._compiled_patterns:
            if pattern.search(text):
                return True
        return False

    def _report_threat(self, payload: str, location: str) -> None:
        """Report detected threat."""
        event = RASPEvent(
            threat_type=RASPThreatType.SQL_INJECTION,
            action_taken=self.action,
            location=location,
            payload=payload[:500],  # Truncate
            severity=0.9,
            stack_trace=inspect.stack()[1:5],
        )
        # In production, send to telemetry/SIEM
        print(f"[RASP] SQL Injection detected: {event}")

    def get_threat_type(self) -> RASPThreatType:
        return RASPThreatType.SQL_INJECTION


class CommandInjectionInterceptor(RASPInterceptor):
    """Detect command injection attempts."""

    CMD_PATTERNS = [
        r"[;&|$`]\s*\w+",
        r"\b(cat|ls|ps|netstat|ifconfig|id|whoami|pwd|uname)\b",
        r"\b(curl|wget|nc|ncat|telnet|ssh)\b",
        r"\b(chmod|chown|chgrp)\s+\d+",
        r"(/bin/|/usr/bin/|/sbin/|/usr/sbin/)\w+",
        r"\$\{.*\}",
        r"`.*`",
        r"\$(\(|\{)",
    ]

    def __init__(self, action: RASPAction = RASPAction.BLOCK) -> None:
        self.action = action
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.CMD_PATTERNS]

    def intercept(self, command: str, args: list = [], **kwargs) -> Any:
        """Intercept command execution."""
        full_cmd = " ".join([command] + [str(a) for a in args])

        if self._is_malicious(full_cmd):
            self._report_threat(full_cmd, "command_execution")
            if self.action == RASPAction.BLOCK:
                raise RuntimeError("Command injection attempt blocked by RASP")

        return {"allowed": True}

    def _is_malicious(self, text: str) -> bool:
        for pattern in self._compiled_patterns:
            if pattern.search(text):
                return True
        return False

    def _report_threat(self, payload: str, location: str) -> None:
        event = RASPEvent(
            threat_type=RASPThreatType.COMMAND_INJECTION,
            action_taken=self.action,
            location=location,
            payload=payload[:500],
            severity=0.95,
            stack_trace=inspect.stack()[1:5],
        )
        print(f"[RASP] Command Injection detected: {event}")

    def get_threat_type(self) -> RASPThreatType:
        return RASPThreatType.COMMAND_INJECTION


class DeserializationInterceptor(RASPInterceptor):
    """Detect unsafe deserialization attempts."""

    UNSAFE_MODULES = {
        "pickle", "cPickle", "marshal", "shelve",
        "yaml", "jsonpickle", "dill", "cloudpickle",
    }

    UNSAFE_FUNCTIONS = {
        "pickle.loads", "pickle.load",
        "cPickle.loads", "cPickle.load",
        "marshal.loads", "marshal.load",
        "yaml.load", "yaml.unsafe_load",
        "jsonpickle.decode",
        "dill.loads", "dill.load",
        "cloudpickle.loads", "cloudpickle.load",
    }

    def __init__(self, action: RASPAction = RASPAction.BLOCK) -> None:
        self.action = action

    def intercept(self, module_name: str, function_name: str, data: bytes, **kwargs) -> Any:
        """Intercept deserialization call."""
        full_name = f"{module_name}.{function_name}"

        if full_name in self.UNSAFE_FUNCTIONS or module_name in self.UNSAFE_MODULES:
            # Check for malicious patterns in data
            if self._is_malicious_pickle(data):
                self._report_threat(data, full_name)
                if self.action == RASPAction.BLOCK:
                    raise RuntimeError("Unsafe deserialization blocked by RASP")

        return {"allowed": True}

    def _is_malicious_pickle(self, data: bytes) -> bool:
        """Check for malicious pickle patterns."""
        # Look for __reduce__, __reduce_ex__, eval, exec, etc.
        dangerous = [
            b"__reduce__", b"__reduce_ex__", b"__getstate__", b"__setstate__",
            b"eval", b"exec", b"compile", b"__import__",
            b"subprocess", b"os.system", b"os.popen",
            b"builtins", b"__builtins__",
        ]
        for pattern in dangerous:
            if pattern in data:
                return True
        return False

    def _report_threat(self, payload: bytes, location: str) -> None:
        event = RASPEvent(
            threat_type=RASPThreatType.DESERIALIZATION_ATTACK,
            action_taken=self.action,
            location=location,
            payload=payload[:500].decode(errors="ignore"),
            severity=0.95,
            stack_trace=inspect.stack()[1:5],
        )
        print(f"[RASP] Deserialization Attack detected: {event}")

    def get_threat_type(self) -> RASPThreatType:
        return RASPThreatType.DESERIALIZATION_ATTACK


class SSRFInterceptor(RASPInterceptor):
    """Detect Server-Side Request Forgery attempts."""

    PRIVATE_IP_PATTERNS = [
        r"^127\.",
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"^192\.168\.",
        r"^169\.254\.",
        r"^::1$",
        r"^fe80::",
        r"^fc00::",
        r"^fd00::",
    ]

    BLOCKED_SCHEMES = {"file", "ftp", "gopher", "dict", "ldap", "ldaps", "tftp"}

    def __init__(self, action: RASPAction = RASPAction.BLOCK, allow_private: bool = False) -> None:
        self.action = action
        self.allow_private = allow_private
        self._ip_patterns = [re.compile(p) for p in self.PRIVATE_IP_PATTERNS]

    def intercept(self, url: str, **kwargs) -> Any:
        """Intercept outbound HTTP request."""
        if self._is_malicious(url):
            self._report_threat(url, "outbound_request")
            if self.action == RASPAction.BLOCK:
                raise RuntimeError("SSRF attempt blocked by RASP")

        return {"allowed": True}

    def _is_malicious(self, url: str) -> bool:
        """Check for SSRF indicators."""
        from urllib.parse import urlparse

        try:
            parsed = urlparse(url)

            # Check scheme
            if parsed.scheme.lower() in self.BLOCKED_SCHEMES:
                return True

            # Check for private IPs
            if not self.allow_private:
                hostname = parsed.hostname or ""
                for pattern in self._ip_patterns:
                    if pattern.match(hostname):
                        return True

            # Check for localhost variations
            if parsed.hostname and parsed.hostname.lower() in ["localhost", "localhost.localdomain"]:
                return True

            # Check for metadata service endpoints
            metadata_hosts = [
                "169.254.169.254",  # AWS
                "metadata.google.internal",  # GCP
                "169.254.169.254",  # Azure
                "metadata",  # Generic
            ]
            if parsed.hostname in metadata_hosts:
                return True

        except Exception:
            return True  # Malformed URL is suspicious

        return False

    def _report_threat(self, payload: str, location: str) -> None:
        event = RASPEvent(
            threat_type=RASPThreatType.SSRF,
            action_taken=self.action,
            location=location,
            payload=payload[:500],
            severity=0.85,
            stack_trace=inspect.stack()[1:5],
        )
        print(f"[RASP] SSRF detected: {event}")

    def get_threat_type(self) -> RASPThreatType:
        return RASPThreatType.SSRF


class PathTraversalInterceptor(RASPInterceptor):
    """Detect path traversal attempts."""

    TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r"\.\.%2f",
        r"\.\.%5c",
        r"\.\.%c0%af",
        r"\.\.%c1%9c",
    ]

    def __init__(self, action: RASPAction = RASPAction.BLOCK) -> None:
        self.action = action
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.TRAVERSAL_PATTERNS]

    def intercept(self, path: str, **kwargs) -> Any:
        """Intercept file path access."""
        if self._is_malicious(path):
            self._report_threat(path, "file_access")
            if self.action == RASPAction.BLOCK:
                raise RuntimeError("Path traversal attempt blocked by RASP")

        return {"allowed": True}

    def _is_malicious(self, path: str) -> bool:
        for pattern in self._compiled_patterns:
            if pattern.search(path):
                return True
        return False

    def _report_threat(self, payload: str, location: str) -> None:
        event = RASPEvent(
            threat_type=RASPThreatType.PATH_TRAVERSAL,
            action_taken=self.action,
            location=location,
            payload=payload[:500],
            severity=0.8,
            stack_trace=inspect.stack()[1:5],
        )
        print(f"[RASP] Path Traversal detected: {event}")

    def get_threat_type(self) -> RASPThreatType:
        return RASPThreatType.PATH_TRAVERSAL


class CodeInjectionInterceptor(RASPInterceptor):
    """Detect code injection via eval/exec/ast parsing."""

    DANGEROUS_NODES = {
        ast.Call,  # Function calls
        ast.Import, ast.ImportFrom,
    }

    DANGEROUS_NAMES = {
        "eval", "exec", "compile", "__import__",
        "open", "file", "input", "raw_input",
        "os.system", "os.popen", "subprocess.call",
        "subprocess.run", "subprocess.Popen",
    }

    def __init__(self, action: RASPAction = RASPAction.BLOCK) -> None:
        self.action = action

    def intercept(self, code: str, **kwargs) -> Any:
        """Intercept code execution."""
        if self._is_malicious(code):
            self._report_threat(code, "code_execution")
            if self.action == RASPAction.BLOCK:
                raise RuntimeError("Code injection attempt blocked by RASP")

        return {"allowed": True}

    def _is_malicious(self, code: str) -> bool:
        """Analyze AST for dangerous patterns."""
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in self.DANGEROUS_NAMES:
                            return True
                    elif isinstance(node.func, ast.Attribute):
                        full_name = self._get_full_name(node.func)
                        if full_name in self.DANGEROUS_NAMES:
                            return True
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        if alias.name.split(".")[0] in ["os", "subprocess", "sys", "shutil"]:
                            return True
        except SyntaxError:
            return True  # Invalid syntax is suspicious
        return False

    def _get_full_name(self, node: ast.Attribute) -> str:
        """Get full attribute name."""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    def _report_threat(self, payload: str, location: str) -> None:
        event = RASPEvent(
            threat_type=RASPThreatType.CODE_INJECTION,
            action_taken=self.action,
            location=location,
            payload=payload[:500],
            severity=0.95,
            stack_trace=inspect.stack()[1:5],
        )
        print(f"[RASP] Code Injection detected: {event}")

    def get_threat_type(self) -> RASPThreatType:
        return RASPThreatType.CODE_INJECTION


class RASPEngine:
    """
    Central RASP Engine managing all interceptors.
    Provides decorator-based protection for functions.
    """

    def __init__(self) -> None:
        self._interceptors: list[RASPInterceptor] = []
        self._events: list[RASPEvent] = []
        self._enabled = True

        # Register default interceptors
        self.register(SQLInjectionInterceptor())
        self.register(CommandInjectionInterceptor())
        self.register(DeserializationInterceptor())
        self.register(SSRFInterceptor())
        self.register(PathTraversalInterceptor())
        self.register(CodeInjectionInterceptor())

    def register(self, interceptor: RASPInterceptor) -> None:
        """Register a RASP interceptor."""
        self._interceptors.append(interceptor)

    def unregister(self, threat_type: RASPThreatType) -> None:
        """Unregister interceptor by threat type."""
        self._interceptors = [
            i for i in self._interceptors
            if i.get_threat_type() != threat_type
        ]

    def set_action(self, threat_type: RASPThreatType, action: RASPAction) -> None:
        """Set action for threat type."""
        for interceptor in self._interceptors:
            if interceptor.get_threat_type() == threat_type:
                interceptor.action = action

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    def protect_sql(self, func: Callable) -> Callable:
        """Decorator to protect SQL execution."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not self._enabled:
                return func(*args, **kwargs)

            # Extract query and params
            query = args[0] if args else kwargs.get("query", "")
            params = args[1] if len(args) > 1 else kwargs.get("params", ())

            for interceptor in self._interceptors:
                if interceptor.get_threat_type() == RASPThreatType.SQL_INJECTION:
                    interceptor.intercept(query, params)

            return func(*args, **kwargs)
        return wrapper

    def protect_command(self, func: Callable) -> Callable:
        """Decorator to protect command execution."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not self._enabled:
                return func(*args, **kwargs)

            command = args[0] if args else kwargs.get("command", "")
            cmd_args = args[1] if len(args) > 1 else kwargs.get("args", [])

            for interceptor in self._interceptors:
                if interceptor.get_threat_type() == RASPThreatType.COMMAND_INJECTION:
                    interceptor.intercept(command, cmd_args)

            return func(*args, **kwargs)
        return wrapper

    def protect_deserialization(self, func: Callable) -> Callable:
        """Decorator to protect deserialization."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not self._enabled:
                return func(*args, **kwargs)

            # Extract module, function, data
            module = args[0] if args else kwargs.get("module", "")
            function = args[1] if len(args) > 1 else kwargs.get("function", "")
            data = args[2] if len(args) > 2 else kwargs.get("data", b"")

            for interceptor in self._interceptors:
                if interceptor.get_threat_type() == RASPThreatType.DESERIALIZATION_ATTACK:
                    interceptor.intercept(module, function, data)

            return func(*args, **kwargs)
        return wrapper

    def protect_http_request(self, func: Callable) -> Callable:
        """Decorator to protect outbound HTTP requests."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not self._enabled:
                return func(*args, **kwargs)

            url = args[0] if args else kwargs.get("url", "")

            for interceptor in self._interceptors:
                if interceptor.get_threat_type() == RASPThreatType.SSRF:
                    interceptor.intercept(url)

            return func(*args, **kwargs)
        return wrapper

    def protect_file_access(self, func: Callable) -> Callable:
        """Decorator to protect file access."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not self._enabled:
                return func(*args, **kwargs)

            path = args[0] if args else kwargs.get("path", "")

            for interceptor in self._interceptors:
                if interceptor.get_threat_type() == RASPThreatType.PATH_TRAVERSAL:
                    interceptor.intercept(path)

            return func(*args, **kwargs)
        return wrapper

    def protect_code_execution(self, func: Callable) -> Callable:
        """Decorator to protect eval/exec."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not self._enabled:
                return func(*args, **kwargs)

            code = args[0] if args else kwargs.get("code", "")

            for interceptor in self._interceptors:
                if interceptor.get_threat_type() == RASPThreatType.CODE_INJECTION:
                    interceptor.intercept(code)

            return func(*args, **kwargs)
        return wrapper

    def get_events(self, limit: int = 100) -> list[RASPEvent]:
        """Get recent RASP events."""
        return self._events[-limit:]

    def clear_events(self) -> None:
        """Clear event history."""
        self._events.clear()


# Global RASP engine
rasp_engine = RASPEngine()