"""
Layer 2: Behavioral Bot Detection & Fingerprinting
===================================================
Client-side & environmental fingerprinting, challenge-response orchestration,
request entropy & heuristic analysis.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import secrets


class BotSignal(str, Enum):
    """Bot detection signals."""
    HEADLESS_BROWSER = "headless_browser"
    AUTOMATION_FRAMEWORK = "automation_framework"
    MISSING_HEADERS = "missing_headers"
    INCONSISTENT_HEADERS = "inconsistent_headers"
    UNNATURAL_TIMING = "unnatural_timing"
    LOW_ENTROPY = "low_entropy"
    KEYSTROKE_ANOMALY = "keystroke_anomaly"
    MOUSE_ANOMALY = "mouse_anomaly"
    CANVAS_FINGERPRINT_MISMATCH = "canvas_fingerprint_mismatch"
    WEBGL_FINGERPRINT_MISMATCH = "webgl_fingerprint_mismatch"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    KNOWN_BOT_ASN = "known_bot_asn"
    DATA_CENTER_IP = "data_center_ip"
    TOR_EXIT_NODE = "tor_exit_node"
    RESIDENTIAL_PROXY = "residential_proxy"


class ChallengeType(str, Enum):
    """Challenge types for bot mitigation."""
    PROOF_OF_WORK = "proof_of_work"
    INVISIBLE_CAPTCHA = "invisible_captcha"
    SLIDER_CAPTCHA = "slider_captcha"
    IMAGE_SELECTION = "image_selection"
    CRYPTOGRAPHIC_ATTESTATION = "cryptographic_attestation"
    BEHAVIORAL_CHALLENGE = "behavioral_challenge"


@dataclass
class FingerprintComponents:
    """Components of a device fingerprint."""
    # Passive (from headers)
    user_agent: str = ""
    accept: str = ""
    accept_language: str = ""
    accept_encoding: str = ""
    connection: str = ""
    upgrade_insecure_requests: str = ""
    sec_fetch_site: str = ""
    sec_fetch_mode: str = ""
    sec_fetch_dest: str = ""
    sec_fetch_user: str = ""
    sec_ch_ua: str = ""
    sec_ch_ua_mobile: str = ""
    sec_ch_ua_platform: str = ""
    sec_ch_ua_full_version_list: str = ""
    cookie: str = ""
    referer: str = ""
    origin: str = ""
    x_forwarded_for: str = ""
    x_real_ip: str = ""
    cf_connecting_ip: str = ""
    true_client_ip: str = ""

    # Active (from JavaScript)
    screen_width: int = 0
    screen_height: int = 0
    screen_color_depth: int = 0
    timezone: str = ""
    timezone_offset: int = 0
    language: str = ""
    languages: list[str] = field(default_factory=list)
    platform: str = ""
    hardware_concurrency: int = 0
    device_memory: int = 0
    touch_points: int = 0
    cookie_enabled: bool = True
    js_enabled: bool = True
    local_storage: bool = True
    session_storage: bool = True
    indexed_db: bool = True
    webgl_vendor: str = ""
    webgl_renderer: str = ""
    canvas_hash: str = ""
    audio_hash: str = ""
    fonts: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    mime_types: list[str] = field(default_factory=list)
    battery: dict[str, Any] = field(default_factory=dict)
    media_devices: list[str] = field(default_factory=list)
    permissions: dict[str, str] = field(default_factory=dict)

    # Behavioral
    keystroke_timings: list[int] = field(default_factory=list)
    mouse_movements: list[dict[str, Any]] = field(default_factory=list)
    scroll_events: list[dict[str, Any]] = field(default_factory=list)
    focus_events: list[dict[str, Any]] = field(default_factory=list)
    paste_events: int = 0
    autocomplete_events: int = 0


@dataclass
class BotAnalysisResult:
    """Result of bot analysis."""
    is_bot: bool = False
    confidence: float = 0.0  # 0.0 - 1.0
    signals: list[BotSignal] = field(default_factory=list)
    risk_score: float = 0.0  # 0.0 - 1.0
    challenge_recommended: ChallengeType = ChallengeType.PROOF_OF_WORK
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Challenge:
    """Bot challenge."""
    challenge_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    challenge_type: ChallengeType = ChallengeType.PROOF_OF_WORK
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    difficulty: int = 4
    data: dict[str, Any] = field(default_factory=dict)
    solution: Optional[str] = None
    verified: bool = False
    verified_at: Optional[datetime] = None


class Fingerprinter:
    """
    Client fingerprinting engine.
    Generates stable fingerprints from passive and active signals.
    """

    def __init__(self) -> None:
        self._known_browsers = {
            "chrome", "firefox", "safari", "edge", "opera", "brave", "vivaldi",
        }
        self._automation_indicators = {
            "webdriver", "selenium", "puppeteer", "playwright", "phantomjs",
            "headless", "automation", "bot", "crawler", "spider", "scraper",
        }

    def generate_fingerprint_id(self, components: FingerprintComponents) -> str:
        """Generate stable fingerprint ID from components."""
        # Create hash from stable components
        stable_parts = [
            components.user_agent,
            components.accept_language,
            components.accept_encoding,
            f"{components.screen_width}x{components.screen_height}x{components.screen_color_depth}",
            components.timezone,
            components.platform,
            str(components.hardware_concurrency),
            str(components.device_memory),
            components.webgl_vendor,
            components.webgl_renderer,
            components.canvas_hash,
            components.audio_hash,
            ",".join(sorted(components.fonts)),
            ",".join(sorted(components.plugins)),
        ]
        content = "|".join(stable_parts)
        return hashlib.sha256(content.encode()).hexdigest()[:32]

    def generate_headers_hash(self, components: FingerprintComponents) -> str:
        """Generate hash from HTTP headers."""
        header_parts = [
            components.user_agent,
            components.accept,
            components.accept_language,
            components.accept_encoding,
            components.connection,
            components.upgrade_insecure_requests,
            components.sec_fetch_site,
            components.sec_fetch_mode,
            components.sec_fetch_dest,
            components.sec_fetch_user,
            components.sec_ch_ua,
            components.sec_ch_ua_mobile,
            components.sec_ch_ua_platform,
        ]
        content = "|".join(header_parts)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def parse_user_agent(self, ua: str) -> dict[str, Any]:
        """Parse user agent string."""
        result = {
            "browser": "unknown",
            "version": "unknown",
            "os": "unknown",
            "device": "desktop",
            "is_mobile": False,
            "is_bot": False,
        }

        ua_lower = ua.lower()

        # Check for bots/crawlers
        for indicator in self._automation_indicators:
            if indicator in ua_lower:
                result["is_bot"] = True
                break

        # Browser detection
        if "edg/" in ua_lower:
            result["browser"] = "edge"
        elif "chrome" in ua_lower and "chromium" not in ua_lower:
            result["browser"] = "chrome"
        elif "firefox" in ua_lower:
            result["browser"] = "firefox"
        elif "safari" in ua_lower and "chrome" not in ua_lower:
            result["browser"] = "safari"
        elif "opera" in ua_lower or "opr/" in ua_lower:
            result["browser"] = "opera"
        elif "brave" in ua_lower:
            result["browser"] = "brave"

        # OS detection
        if "windows" in ua_lower:
            result["os"] = "windows"
        elif "macintosh" in ua_lower or "mac os x" in ua_lower:
            result["os"] = "macos"
        elif "linux" in ua_lower:
            result["os"] = "linux"
        elif "android" in ua_lower:
            result["os"] = "android"
            result["device"] = "mobile"
            result["is_mobile"] = True
        elif "ios" in ua_lower or "iphone" in ua_lower or "ipad" in ua_lower:
            result["os"] = "ios"
            result["device"] = "mobile"
            result["is_mobile"] = True

        return result

    def check_consistency(self, components: FingerprintComponents) -> list[str]:
        """Check for fingerprint inconsistencies."""
        issues = []

        # Check UA vs Sec-CH-UA consistency
        ua_info = self.parse_user_agent(components.user_agent)
        if components.sec_ch_ua:
            # Parse Sec-CH-UA
            sec_ua = components.sec_ch_ua.lower()
            if "chrome" in sec_ua and ua_info["browser"] != "chrome":
                issues.append("ua_sec_ch_ua_mismatch_browser")
            if "firefox" in sec_ua and ua_info["browser"] != "firefox":
                issues.append("ua_sec_ch_ua_mismatch_browser")

        # Check platform consistency
        if components.sec_ch_ua_platform:
            platform = components.sec_ch_ua_platform.strip('"').lower()
            if platform == "windows" and ua_info["os"] != "windows":
                issues.append("platform_mismatch")
            elif platform == "macos" and ua_info["os"] != "macos":
                issues.append("platform_mismatch")
            elif platform == "linux" and ua_info["os"] != "linux":
                issues.append("platform_mismatch")

        # Check mobile consistency
        if components.sec_ch_ua_mobile == "?1" and not ua_info["is_mobile"]:
            issues.append("mobile_mismatch")
        elif components.sec_ch_ua_mobile == "?0" and ua_info["is_mobile"]:
            issues.append("mobile_mismatch")

        # Check hardware concurrency reasonableness
        if components.hardware_concurrency > 128:
            issues.append("unrealistic_hardware_concurrency")
        if components.device_memory > 1024:  # GB
            issues.append("unrealistic_device_memory")

        # Check for missing expected headers
        if not components.sec_fetch_site and "chrome" in ua_info["browser"]:
            issues.append("missing_sec_fetch_headers")

        return issues


class BehavioralAnalyzer:
    """
    Behavioral analysis for bot detection.
    Analyzes keystroke dynamics, mouse movements, timing patterns.
    """

    def __init__(self) -> None:
        self._human_typing_min_interval = 50  # ms
        self._human_typing_max_interval = 500  # ms
        self._human_mouse_variance_threshold = 0.1

    def analyze_keystrokes(self, timings: list[int]) -> dict[str, Any]:
        """Analyze keystroke timing patterns."""
        if len(timings) < 3:
            return {"analyzed": False, "reason": "insufficient_data"}

        intervals = [timings[i+1] - timings[i] for i in range(len(timings)-1)]

        # Check for robotic patterns (exact intervals)
        unique_intervals = len(set(intervals))
        total_intervals = len(intervals)
        interval_diversity = unique_intervals / total_intervals if total_intervals > 0 else 0

        # Check for too-fast typing
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        min_interval = min(intervals) if intervals else 0

        # Check for inhuman consistency
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals) if intervals else 0
        cv = (variance ** 0.5) / avg_interval if avg_interval > 0 else 0  # Coefficient of variation

        is_suspicious = (
            interval_diversity < 0.3 or  # Too consistent
            min_interval < self._human_typing_min_interval or  # Too fast
            cv < 0.05  # Too regular
        )

        return {
            "analyzed": True,
            "interval_count": len(intervals),
            "avg_interval_ms": avg_interval,
            "min_interval_ms": min_interval,
            "interval_diversity": interval_diversity,
            "coefficient_of_variation": cv,
            "is_suspicious": is_suspicious,
            "suspicion_factors": [
                f for f, v in [
                    ("low_diversity", interval_diversity < 0.3),
                    ("too_fast", min_interval < self._human_typing_min_interval),
                    ("too_regular", cv < 0.05),
                ] if v
            ],
        }

    def analyze_mouse_movements(self, movements: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze mouse movement patterns."""
        if len(movements) < 5:
            return {"analyzed": False, "reason": "insufficient_data"}

        # Check for linear/bezier perfection
        straight_lines = 0
        for i in range(len(movements) - 2):
            p1 = movements[i]
            p2 = movements[i+1]
            p3 = movements[i+2]

            # Check if three points are collinear (perfectly straight)
            if self._are_collinear(p1, p2, p3):
                straight_lines += 1

        straight_ratio = straight_lines / max(1, len(movements) - 2)

        # Check velocity patterns
        velocities = []
        for i in range(len(movements) - 1):
            p1 = movements[i]
            p2 = movements[i+1]
            dt = p2.get("t", 0) - p1.get("t", 0)
            if dt > 0:
                dx = p2.get("x", 0) - p1.get("x", 0)
                dy = p2.get("y", 0) - p1.get("y", 0)
                dist = (dx**2 + dy**2)**0.5
                velocities.append(dist / dt)

        avg_velocity = sum(velocities) / len(velocities) if velocities else 0
        velocity_variance = sum((v - avg_velocity)**2 for v in velocities) / len(velocities) if velocities else 0

        is_suspicious = (
            straight_ratio > 0.8 or  # Too many straight lines
            velocity_variance < 0.01 or  # Too constant velocity
            avg_velocity > 5000  # Too fast
        )

        return {
            "analyzed": True,
            "point_count": len(movements),
            "straight_line_ratio": straight_ratio,
            "avg_velocity": avg_velocity,
            "velocity_variance": velocity_variance,
            "is_suspicious": is_suspicious,
            "suspicion_factors": [
                f for f, v in [
                    ("too_linear", straight_ratio > 0.8),
                    ("constant_velocity", velocity_variance < 0.01),
                    ("too_fast", avg_velocity > 5000),
                ] if v
            ],
        }

    def _are_collinear(self, p1: dict, p2: dict, p3: dict, tolerance: float = 1.0) -> bool:
        """Check if three points are collinear."""
        x1, y1 = p1.get("x", 0), p1.get("y", 0)
        x2, y2 = p2.get("x", 0), p2.get("y", 0)
        x3, y3 = p3.get("x", 0), p3.get("y", 0)

        # Area of triangle = 0.5 * |x1(y2-y3) + x2(y3-y1) + x3(y1-y2)|
        area = abs(x1*(y2-y3) + x2*(y3-y1) + x3*(y1-y2)) / 2
        return area < tolerance

    def analyze_timing(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze request timing patterns."""
        if len(events) < 2:
            return {"analyzed": False, "reason": "insufficient_data"}

        intervals = []
        for i in range(len(events) - 1):
            t1 = events[i].get("timestamp", 0)
            t2 = events[i+1].get("timestamp", 0)
            if t2 > t1:
                intervals.append(t2 - t1)

        if not intervals:
            return {"analyzed": False, "reason": "no_valid_intervals"}

        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
        cv = (variance ** 0.5) / avg_interval if avg_interval > 0 else 0

        # Check for periodic patterns (bot-like)
        is_suspicious = cv < 0.01 or avg_interval < 100  # Too regular or too fast

        return {
            "analyzed": True,
            "event_count": len(events),
            "avg_interval_ms": avg_interval,
            "coefficient_of_variation": cv,
            "is_suspicious": is_suspicious,
        }


class EntropyAnalyzer:
    """Request entropy analysis for detecting automated requests."""

    def __init__(self) -> None:
        self._min_entropy_threshold = 2.5  # bits per character

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string."""
        if not data:
            return 0.0

        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1

        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            entropy -= p * (p.bit_length() - 1)  # Approximation

        return entropy

    def analyze_request_entropy(
        self,
        username: str,
        password: str,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """Analyze entropy of authentication request."""
        results = {}

        # Username entropy
        if username:
            results["username_entropy"] = self.calculate_entropy(username)
            results["username_length"] = len(username)

        # Password entropy (without revealing password)
        if password:
            results["password_entropy"] = self.calculate_entropy(password)
            results["password_length"] = len(password)

        # Headers entropy
        header_str = "".join(f"{k}:{v}" for k, v in sorted(headers.items()))
        results["headers_entropy"] = self.calculate_entropy(header_str)

        # Overall entropy
        combined = username + password + header_str
        results["combined_entropy"] = self.calculate_entropy(combined)

        # Low entropy indicator
        results["low_entropy"] = results["combined_entropy"] < self._min_entropy_threshold

        return results


class ProofOfWorkChallenge:
    """Proof-of-work challenge for bot mitigation."""

    def __init__(self, default_difficulty: int = 4) -> None:
        self.default_difficulty = default_difficulty
        self._challenges: dict[str, Challenge] = {}
        self._lock = asyncio.Lock()

    async def create_challenge(
        self,
        challenge_type: ChallengeType = ChallengeType.PROOF_OF_WORK,
        difficulty: Optional[int] = None,
        ttl_seconds: int = 300,
    ) -> Challenge:
        """Create new challenge."""
        diff = difficulty or self.default_difficulty

        if challenge_type == ChallengeType.PROOF_OF_WORK:
            # Generate random challenge string
            challenge_str = secrets.token_hex(16)
            target = "0" * diff

            challenge = Challenge(
                challenge_type=challenge_type,
                difficulty=diff,
                data={
                    "challenge": challenge_str,
                    "target": target,
                    "algorithm": "sha256",
                },
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
            )

        elif challenge_type == ChallengeType.INVISIBLE_CAPTCHA:
            # Invisible CAPTCHA - behavioral token
            token = secrets.token_urlsafe(32)
            challenge = Challenge(
                challenge_type=challenge_type,
                difficulty=1,
                data={
                    "token": token,
                    "action": "verify_human",
                },
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
            )

        else:
            # Generic challenge
            challenge = Challenge(
                challenge_type=challenge_type,
                difficulty=diff or 1,
                data={"nonce": secrets.token_hex(16)},
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
            )

        async with self._lock:
            self._challenges[challenge.challenge_id] = challenge

        return challenge

    async def verify_pow(self, challenge_id: str, nonce: int) -> bool:
        """Verify proof-of-work solution."""
        async with self._lock:
            challenge = self._challenges.get(challenge_id)

        if not challenge or challenge.verified:
            return False

        if datetime.now(timezone.utc) > challenge.expires_at:
            return False

        if challenge.challenge_type != ChallengeType.PROOF_OF_WORK:
            return False

        challenge_str = challenge.data.get("challenge", "")
        target = challenge.data.get("target", "0000")

        # Verify: sha256(challenge + nonce) starts with target
        attempt = hashlib.sha256(f"{challenge_str}{nonce}".encode()).hexdigest()
        if attempt.startswith(target):
            challenge.verified = True
            challenge.verified_at = datetime.now(timezone.utc)
            challenge.solution = str(nonce)
            return True

        return False

    async def verify_invisible_captcha(self, challenge_id: str, token: str, behavior_data: dict) -> bool:
        """Verify invisible CAPTCHA with behavioral data."""
        async with self._lock:
            challenge = self._challenges.get(challenge_id)

        if not challenge or challenge.verified:
            return False

        if datetime.now(timezone.utc) > challenge.expires_at:
            return False

        if challenge.challenge_type != ChallengeType.INVISIBLE_CAPTCHA:
            return False

        expected_token = challenge.data.get("token", "")
        if token != expected_token:
            return False

        # Verify behavioral data indicates human
        analyzer = BehavioralAnalyzer()

        # Check keystrokes
        if behavior_data.get("keystrokes"):
            ks_result = analyzer.analyze_keystrokes(behavior_data["keystrokes"])
            if ks_result.get("is_suspicious"):
                return False

        # Check mouse
        if behavior_data.get("mouse_movements"):
            mouse_result = analyzer.analyze_mouse_movements(behavior_data["mouse_movements"])
            if mouse_result.get("is_suspicious"):
                return False

        challenge.verified = True
        challenge.verified_at = datetime.now(timezone.utc)
        return True

    async def get_challenge(self, challenge_id: str) -> Optional[Challenge]:
        """Get challenge by ID."""
        async with self._lock:
            return self._challenges.get(challenge_id)

    async def cleanup_expired(self) -> int:
        """Remove expired challenges."""
        async with self._lock:
            now = datetime.now(timezone.utc)
            expired = [
                cid for cid, c in self._challenges.items()
                if now > c.expires_at
            ]
            for cid in expired:
                del self._challenges[cid]
            return len(expired)


import asyncio
from datetime import timedelta


class BotDetector:
    """
    Comprehensive bot detection engine.
    Combines fingerprinting, behavioral analysis, entropy analysis, and heuristics.
    """

    def __init__(self) -> None:
        self.fingerprinter = Fingerprinter()
        self.behavioral = BehavioralAnalyzer()
        self.entropy = EntropyAnalyzer()
        self.pow = ProofOfWorkChallenge()

    async def analyze(
        self,
        fingerprint: FingerprintComponents,
        request_data: dict[str, Any],
        behavior_data: dict[str, Any],
    ) -> BotAnalysisResult:
        """Comprehensive bot analysis."""
        signals = []
        risk_factors = []

        # 1. Fingerprint analysis
        fp_issues = self.fingerprinter.check_consistency(fingerprint)
        if fp_issues:
            signals.append(BotSignal.INCONSISTENT_HEADERS)
            risk_factors.append(("fingerprint_inconsistency", len(fp_issues) * 0.15))

        # Check for headless/automation in UA
        ua_info = self.fingerprinter.parse_user_agent(fingerprint.user_agent)
        if ua_info["is_bot"]:
            signals.append(BotSignal.AUTOMATION_FRAMEWORK)
            risk_factors.append(("automation_in_ua", 0.8))

        # Check for missing expected browser features
        if not fingerprint.js_enabled:
            signals.append(BotSignal.MISSING_HEADERS)
            risk_factors.append(("no_javascript", 0.3))

        if fingerprint.hardware_concurrency == 0:
            signals.append(BotSignal.HEADLESS_BROWSER)
            risk_factors.append(("no_hardware_concurrency", 0.4))

        if not fingerprint.canvas_hash and not fingerprint.webgl_vendor:
            signals.append(BotSignal.HEADLESS_BROWSER)
            risk_factors.append(("no_canvas_webgl", 0.3))

        # 2. Behavioral analysis
        if behavior_data.get("keystrokes"):
            ks_result = self.behavioral.analyze_keystrokes(behavior_data["keystrokes"])
            if ks_result.get("is_suspicious"):
                signals.append(BotSignal.KEYSTROKE_ANOMALY)
                risk_factors.append(("keystroke_anomaly", 0.4))

        if behavior_data.get("mouse_movements"):
            mouse_result = self.behavioral.analyze_mouse_movements(behavior_data["mouse_movements"])
            if mouse_result.get("is_suspicious"):
                signals.append(BotSignal.MOUSE_ANOMALY)
                risk_factors.append(("mouse_anomaly", 0.3))

        if behavior_data.get("timing_events"):
            timing_result = self.behavioral.analyze_timing(behavior_data["timing_events"])
            if timing_result.get("is_suspicious"):
                signals.append(BotSignal.UNNATURAL_TIMING)
                risk_factors.append(("timing_anomaly", 0.3))

        # 3. Entropy analysis
        entropy_result = self.entropy.analyze_request_entropy(
            request_data.get("username", ""),
            request_data.get("password", ""),
            request_data.get("headers", {}),
        )
        if entropy_result.get("low_entropy"):
            signals.append(BotSignal.LOW_ENTROPY)
            risk_factors.append(("low_entropy", 0.3))

        # 4. Request pattern analysis
        if request_data.get("paste_events", 0) > 0 and behavior_data.get("keystrokes"):
            # Paste + no keystrokes = suspicious
            if len(behavior_data["keystrokes"]) < 3:
                signals.append(BotSignal.BEHAVIORAL_ANOMALY)
                risk_factors.append(("paste_without_typing", 0.5))

        # Calculate overall risk
        total_risk = min(1.0, sum(score for _, score in risk_factors))
        is_bot = total_risk > 0.6 or len(signals) >= 3

        # Determine challenge type
        if total_risk > 0.8:
            challenge_type = ChallengeType.PROOF_OF_WORK
        elif total_risk > 0.5:
            challenge_type = ChallengeType.INVISIBLE_CAPTCHA
        else:
            challenge_type = ChallengeType.BEHAVIORAL_CHALLENGE

        return BotAnalysisResult(
            is_bot=is_bot,
            confidence=total_risk,
            signals=signals,
            risk_score=total_risk,
            challenge_recommended=challenge_type,
            details={
                "fingerprint_issues": fp_issues,
                "user_agent_info": ua_info,
                "entropy": entropy_result,
                "risk_factors": risk_factors,
            },
        )

    async def generate_challenge(self, fingerprint: FingerprintComponents) -> Challenge:
        """Generate appropriate challenge based on fingerprint."""
        # Analyze fingerprint risk quickly
        ua_info = self.fingerprinter.parse_user_agent(fingerprint.user_agent)
        fp_issues = self.fingerprinter.check_consistency(fingerprint)

        risk = 0.0
        if ua_info["is_bot"]:
            risk += 0.5
        risk += len(fp_issues) * 0.1
        if fingerprint.hardware_concurrency == 0:
            risk += 0.2

        if risk > 0.6:
            return await self.pow.create_challenge(ChallengeType.PROOF_OF_WORK, difficulty=5)
        elif risk > 0.3:
            return await self.pow.create_challenge(ChallengeType.INVISIBLE_CAPTCHA)
        else:
            return await self.pow.create_challenge(ChallengeType.BEHAVIORAL_CHALLENGE)

    async def verify_challenge(self, challenge_id: str, response: dict) -> bool:
        """Verify challenge response."""
        challenge = await self.pow.get_challenge(challenge_id)
        if not challenge:
            return False

        if challenge.challenge_type == ChallengeType.PROOF_OF_WORK:
            nonce = response.get("nonce")
            if isinstance(nonce, int):
                return await self.pow.verify_pow(challenge_id, nonce)

        elif challenge.challenge_type == ChallengeType.INVISIBLE_CAPTCHA:
            token = response.get("token", "")
            behavior = response.get("behavior", {})
            return await self.pow.verify_invisible_captcha(challenge_id, token, behavior)

        return False


# Global bot detector
bot_detector = BotDetector()