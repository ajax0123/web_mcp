"""
Layer 3: Next-Generation WAF & Deep Content Inspection
=======================================================
Palo Alto Paradigm: Deep packet inspection, malicious pattern detection,
protocol anomaly detection, known exploit signatures.
"""

from __future__ import annotations

import re
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional
from collections import defaultdict
import hashlib


class WAFRuleType(str, Enum):
    """WAF rule categories."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    KNOWN_EXPLOIT = "known_exploit"
    BOT_DETECTION = "bot_detection"
    RATE_LIMIT = "rate_limit"
    GEO_BLOCK = "geo_block"
    CUSTOM = "custom"


class WAFAction(str, Enum):
    """WAF response actions."""
    ALLOW = "allow"
    LOG = "log"
    BLOCK = "block"
    CHALLENGE = "challenge"  # CAPTCHA, MFA
    RATE_LIMIT = "rate_limit"
    SANITIZE = "sanitize"


@dataclass
class WAFRule:
    """WAF rule definition."""
    rule_id: str
    name: str
    rule_type: WAFRuleType
    pattern: str  # Regex pattern
    action: WAFAction = WAFAction.BLOCK
    severity: int = 5  # 1-10
    enabled: bool = True
    description: str = ""
    tags: list[str] = field(default_factory=list)
    # For rate limiting
    rate_limit: Optional[int] = None
    rate_window_seconds: int = 60


@dataclass
class WAFMatch:
    """WAF rule match result."""
    rule: WAFRule
    matched_content: str
    location: str  # header, body, query, path
    confidence: float


@dataclass
class WAFRequest:
    """HTTP request for WAF inspection."""
    method: str
    path: str
    query_params: dict[str, list[str]]
    headers: dict[str, str]
    body: str
    client_ip: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class WAFResult:
    """WAF inspection result."""
    request_id: str
    allowed: bool
    action: WAFAction
    matches: list[WAFMatch] = field(default_factory=list)
    risk_score: float = 0.0
    processing_time_ms: float = 0.0


class WAFEngine:
    """
    Next-Generation Web Application Firewall.
    Deep content inspection with signature-based and behavioral detection.
    """

    def __init__(self) -> None:
        self._rules: list[WAFRule] = []
        self._compiled_rules: list[tuple[WAFRule, re.Pattern]] = []
        self._rate_limit_buckets: dict[str, list[float]] = defaultdict(list)
        self._blocked_ips: set[str] = set()
        self._geo_block_list: set[str] = set()
        self._initialize_default_rules()

    def _initialize_default_rules(self) -> None:
        """Initialize default WAF rules (OWASP Top 10 + more)."""
        rules = [
            # SQL Injection
            WAFRule(
                rule_id="waf-sqli-001",
                name="SQL Injection - Union Select",
                rule_type=WAFRuleType.SQL_INJECTION,
                pattern=r"(?i)\bunion\s+select\b",
                severity=9,
                description="Detects UNION SELECT injection attempts",
            ),
            WAFRule(
                rule_id="waf-sqli-002",
                name="SQL Injection - Comment Terminators",
                rule_type=WAFRuleType.SQL_INJECTION,
                pattern=r"(--|#|/\*|\*/)",
                severity=8,
                description="Detects SQL comment terminators",
            ),
            WAFRule(
                rule_id="waf-sqli-003",
                name="SQL Injection - Boolean Based",
                rule_type=WAFRuleType.SQL_INJECTION,
                pattern=r"(?i)\b(or|and)\s+\d+\s*=\s*\d+",
                severity=8,
                description="Detects boolean-based SQL injection",
            ),
            WAFRule(
                rule_id="waf-sqli-004",
                name="SQL Injection - Time Based",
                rule_type=WAFRuleType.SQL_INJECTION,
                pattern=r"(?i)\b(waitfor|delay|sleep|benchmark)\s*\(",
                severity=9,
                description="Detects time-based blind SQL injection",
            ),
            WAFRule(
                rule_id="waf-sqli-005",
                name="SQL Injection - Data Exfiltration",
                rule_type=WAFRuleType.SQL_INJECTION,
                pattern=r"(?i)\b(into\s+(outfile|dumpfile)|load_file)\b",
                severity=10,
                description="Detects data exfiltration attempts",
            ),

            # XSS
            WAFRule(
                rule_id="waf-xss-001",
                name="XSS - Script Tag",
                rule_type=WAFRuleType.XSS,
                pattern=r"(?i)<script[^>]*>.*?</script>",
                severity=9,
                description="Detects script tag injection",
            ),
            WAFRule(
                rule_id="waf-xss-002",
                name="XSS - Event Handlers",
                rule_type=WAFRuleType.XSS,
                pattern=r"(?i)\bon\w+\s*=",
                severity=8,
                description="Detects inline event handlers",
            ),
            WAFRule(
                rule_id="waf-xss-003",
                name="XSS - JavaScript Protocol",
                rule_type=WAFRuleType.XSS,
                pattern=r"(?i)javascript:",
                severity=8,
                description="Detects javascript: protocol usage",
            ),
            WAFRule(
                rule_id="waf-xss-004",
                name="XSS - Data URI",
                rule_type=WAFRuleType.XSS,
                pattern=r"(?i)data:text/html",
                severity=7,
                description="Detects data URI XSS vectors",
            ),

            # Command Injection
            WAFRule(
                rule_id="waf-cmd-001",
                name="Command Injection - Shell Metacharacters",
                rule_type=WAFRuleType.COMMAND_INJECTION,
                pattern=r"[;&|$`]",
                severity=9,
                description="Detects shell command separators",
            ),
            WAFRule(
                rule_id="waf-cmd-002",
                name="Command Injection - Subshell",
                rule_type=WAFRuleType.COMMAND_INJECTION,
                pattern=r"\$\(",
                severity=9,
                description="Detects subshell execution",
            ),
            WAFRule(
                rule_id="waf-cmd-003",
                name="Command Injection - Backticks",
                rule_type=WAFRuleType.COMMAND_INJECTION,
                pattern=r"`.*`",
                severity=9,
                description="Detects backtick command substitution",
            ),

            # Path Traversal
            WAFRule(
                rule_id="waf-path-001",
                name="Path Traversal - Dot Dot Slash",
                rule_type=WAFRuleType.PATH_TRAVERSAL,
                pattern=r"\.\./",
                severity=8,
                description="Detects directory traversal",
            ),
            WAFRule(
                rule_id="waf-path-002",
                name="Path Traversal - URL Encoded",
                rule_type=WAFRuleType.PATH_TRAVERSAL,
                pattern=r"%2e%2e%2f",
                severity=8,
                description="Detects URL-encoded traversal",
            ),
            WAFRule(
                rule_id="waf-path-003",
                name="Path Traversal - Double Encoded",
                rule_type=WAFRuleType.PATH_TRAVERSAL,
                pattern=r"%252e%252e%252f",
                severity=8,
                description="Detects double-encoded traversal",
            ),

            # Protocol Anomalies
            WAFRule(
                rule_id="waf-proto-001",
                name="Protocol Anomaly - Null Byte",
                rule_type=WAFRuleType.PROTOCOL_ANOMALY,
                pattern=r"%00",
                severity=7,
                description="Detects null byte injection",
            ),
            WAFRule(
                rule_id="waf-proto-002",
                name="Protocol Anomaly - CRLF Injection",
                rule_type=WAFRuleType.PROTOCOL_ANOMALY,
                pattern=r"(%0d%0a|%0a%0d|\r\n|\n\r)",
                severity=8,
                description="Detects CRLF injection",
            ),

            # Known Exploits
            WAFRule(
                rule_id="waf-exploit-001",
                name="Exploit - Log4j JNDI",
                rule_type=WAFRuleType.KNOWN_EXPLOIT,
                pattern=r"\$\{jndi:",
                severity=10,
                description="Detects Log4Shell exploitation attempts",
            ),
            WAFRule(
                rule_id="waf-exploit-002",
                name="Exploit - Spring4Shell",
                rule_type=WAFRuleType.KNOWN_EXPLOIT,
                pattern=r"class\.module\.classLoader",
                severity=10,
                description="Detects Spring4Shell exploitation",
            ),

            # Bot Detection
            WAFRule(
                rule_id="waf-bot-001",
                name="Bot - SQLMap User Agent",
                rule_type=WAFRuleType.BOT_DETECTION,
                pattern=r"(?i)sqlmap",
                severity=9,
                description="Detects SQLMap scanner",
            ),
            WAFRule(
                rule_id="waf-bot-002",
                name="Bot - Nikto Scanner",
                rule_type=WAFRuleType.BOT_DETECTION,
                pattern=r"(?i)nikto",
                severity=8,
                description="Detects Nikto scanner",
            ),
            WAFRule(
                rule_id="waf-bot-003",
                name="Bot - Generic Scanner",
                rule_type=WAFRuleType.BOT_DETECTION,
                pattern=r"(?i)(nmap|masscan|zmap|shodan|censys)",
                severity=7,
                description="Detects common scanner user agents",
            ),
        ]

        for rule in rules:
            self.add_rule(rule)

    def add_rule(self, rule: WAFRule) -> None:
        """Add WAF rule."""
        self._rules.append(rule)
        if rule.enabled:
            self._compiled_rules.append((rule, re.compile(rule.pattern)))

    def remove_rule(self, rule_id: str) -> bool:
        """Remove WAF rule."""
        self._rules = [r for r in self._rules if r.rule_id != rule_id]
        self._compiled_rules = [(r, p) for r, p in self._compiled_rules if r.rule_id != rule_id]
        return True

    def enable_rule(self, rule_id: str) -> bool:
        """Enable WAF rule."""
        for rule in self._rules:
            if rule.rule_id == rule_id:
                rule.enabled = True
                self._compiled_rules.append((rule, re.compile(rule.pattern)))
                return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable WAF rule."""
        for rule in self._rules:
            if rule.rule_id == rule_id:
                rule.enabled = False
                self._compiled_rules = [(r, p) for r, p in self._compiled_rules if r.rule_id != rule_id]
                return True
        return False

    def inspect(self, request: WAFRequest) -> WAFResult:
        """Inspect request against all WAF rules."""
        start_time = datetime.now(timezone.utc)
        matches = []
        max_severity = 0
        final_action = WAFAction.ALLOW

        # Check blocked IPs
        if request.client_ip in self._blocked_ips:
            return WAFResult(
                request_id=request.request_id,
                allowed=False,
                action=WAFAction.BLOCK,
                risk_score=1.0,
            )

        # Check geo blocking
        if request.client_ip in self._geo_block_list:
            return WAFResult(
                request_id=request.request_id,
                allowed=False,
                action=WAFAction.BLOCK,
                risk_score=1.0,
            )

        # Prepare content for inspection
        content_sources = {
            "path": request.path,
            "query": "&".join(f"{k}={v}" for k, vals in request.query_params.items() for v in vals),
            "headers": "\n".join(f"{k}: {v}" for k, v in request.headers.items()),
            "body": request.body,
        }

        # Inspect each content source
        for location, content in content_sources.items():
            if not content:
                continue

            for rule, pattern in self._compiled_rules:
                match = pattern.search(content)
                if match:
                    waf_match = WAFMatch(
                        rule=rule,
                        matched_content=match.group()[:200],
                        location=location,
                        confidence=0.9,
                    )
                    matches.append(waf_match)
                    max_severity = max(max_severity, rule.severity)

                    # Determine action (most restrictive wins)
                    if rule.action == WAFAction.BLOCK:
                        final_action = WAFAction.BLOCK
                    elif rule.action == WAFAction.CHALLENGE and final_action != WAFAction.BLOCK:
                        final_action = WAFAction.CHALLENGE
                    elif rule.action == WAFAction.RATE_LIMIT and final_action == WAFAction.ALLOW:
                        final_action = WAFAction.RATE_LIMIT
                    elif rule.action == WAFAction.LOG and final_action == WAFAction.ALLOW:
                        final_action = WAFAction.LOG

        # Check rate limiting
        if self._check_rate_limit(request):
            final_action = WAFAction.RATE_LIMIT
            matches.append(WAFMatch(
                rule=WAFRule(
                    rule_id="waf-ratelimit",
                    name="Rate Limit Exceeded",
                    rule_type=WAFRuleType.RATE_LIMIT,
                    pattern="",
                    action=WAFAction.RATE_LIMIT,
                ),
                matched_content="",
                location="rate_limit",
                confidence=1.0,
            ))

        # Calculate risk score
        risk_score = min(1.0, max_severity / 10.0 + len(matches) * 0.05)

        processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        return WAFResult(
            request_id=request.request_id,
            allowed=final_action in [WAFAction.ALLOW, WAFAction.LOG, WAFAction.RATE_LIMIT],
            action=final_action,
            matches=matches,
            risk_score=risk_score,
            processing_time_ms=processing_time,
        )

    def _check_rate_limit(self, request: WAFRequest) -> bool:
        """Check rate limit for client IP."""
        now = datetime.now(timezone.utc).timestamp()
        window_start = now - 60  # 1 minute window

        # Clean old entries
        self._rate_limit_buckets[request.client_ip] = [
            ts for ts in self._rate_limit_buckets[request.client_ip]
            if ts > window_start
        ]

        # Add current request
        self._rate_limit_buckets[request.client_ip].append(now)

        # Check limit (default 100 req/min)
        return len(self._rate_limit_buckets[request.client_ip]) > 100

    def block_ip(self, ip: str) -> None:
        """Block IP address."""
        self._blocked_ips.add(ip)

    def unblock_ip(self, ip: str) -> None:
        """Unblock IP address."""
        self._blocked_ips.discard(ip)

    def block_geo(self, country_code: str) -> None:
        """Block country (simplified - would use GeoIP in production)."""
        self._geo_block_list.add(country_code.upper())

    def get_stats(self) -> dict[str, Any]:
        """Get WAF statistics."""
        return {
            "total_rules": len(self._rules),
            "enabled_rules": len([r for r in self._rules if r.enabled]),
            "blocked_ips": len(self._blocked_ips),
            "blocked_countries": len(self._geo_block_list),
            "rate_limit_buckets": len(self._rate_limit_buckets),
        }


# Global WAF engine
waf_engine = WAFEngine()