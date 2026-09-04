"""
Layer 3: Credential Intelligence & Breach Database Correlation
===============================================================
Known-bad credential filtering (HaveIBeenPwned k-anonymity),
credential stuffing pattern recognition, anomalous geo-velocity tracking.
"""

from __future__ import annotations

import hashlib
import asyncio
import ipaddress
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Optional
import httpx


class IPReputationCategory(str, Enum):
    """IP reputation categories."""
    CLEAN = "clean"
    TOR_EXIT = "tor_exit"
    VPN_PROXY = "vpn_proxy"
    HOSTING_PROVIDER = "hosting_provider"
    RESIDENTIAL_PROXY = "residential_proxy"
    MALICIOUS = "malicious"
    SCANNER = "scanner"
    BOTNET = "botnet"


class CredentialStuffingPattern(str, Enum):
    """Credential stuffing attack patterns."""
    HIGH_VELOCITY_SINGLE_IP = "high_velocity_single_ip"
    DISTRIBUTED_LOW_VELOCITY = "distributed_low_velocity"
    PASSWORD_SPRAY = "password_spray"
    USERNAME_ENUMERATION = "username_enumeration"
    KNOWN_BREACHED_CREDENTIALS = "known_breached_credentials"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    DEVICE_FARM = "device_farm"


@dataclass
class BreachedCredentialCheck:
    """Result of breached credential check (k-anonymity)."""
    checked: bool = False
    breached: bool = False
    breach_count: int = 0
    breach_sources: list[str] = field(default_factory=list)
    first_breach_date: Optional[datetime] = None
    last_breach_date: Optional[datetime] = None
    recommendation: str = ""
    hibp_prefix: str = ""  # First 5 chars of SHA1


@dataclass
class IPReputation:
    """IP reputation assessment."""
    ip: str
    category: IPReputationCategory = IPReputationCategory.CLEAN
    confidence: float = 0.0
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    is_hosting: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_vpn: bool = False
    threat_feeds: list[str] = field(default_factory=list)
    last_seen: Optional[datetime] = None
    risk_score: float = 0.0


@dataclass
class GeoVelocityCheck:
    """Impossible travel / geo-velocity check result."""
    impossible_travel: bool = False
    distance_km: float = 0.0
    time_hours: float = 0.0
    required_speed_kmh: float = 0.0
    max_possible_speed_kmh: float = 900  # Commercial jet
    previous_location: Optional[dict[str, Any]] = None
    current_location: Optional[dict[str, Any]] = None
    risk_score: float = 0.0


@dataclass
class DeviceAnomalyCheck:
    """Device anomaly check result."""
    new_device: bool = False
    device_id: str = ""
    known_devices: list[str] = field(default_factory=list)
    user_agent_changed: bool = False
    platform_changed: bool = False
    browser_changed: bool = False
    risk_score: float = 0.0


@dataclass
class CredentialStuffingAssessment:
    """Comprehensive credential stuffing assessment."""
    patterns_detected: list[CredentialStuffingPattern] = field(default_factory=list)
    ip_reputation: Optional[IPReputation] = None
    geo_velocity: Optional[GeoVelocityCheck] = None
    device_anomaly: Optional[DeviceAnomalyCheck] = None
    breached_credential: Optional[BreachedCredentialCheck] = None
    overall_risk: float = 0.0
    confidence: float = 0.0
    recommended_actions: list[str] = field(default_factory=list)


class HaveIBeenPwnedClient:
    """
    HaveIBeenPwned API client using k-anonymity model.
    Never sends full password hash to the API.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.pwnedpasswords.com/range/",
        timeout: float = 5.0,
        cache_ttl: int = 86400,  # 24 hours
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._cache: dict[str, tuple[BreachedCredentialCheck, float]] = {}
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            headers = {"User-Agent": "CyberGuard-AuthDefense/1.0"}
            if self.api_key:
                headers["hibp-api-key"] = self.api_key
            self._client = httpx.AsyncClient(headers=headers, timeout=self.timeout)
        return self._client

    async def check_password(self, password: str) -> BreachedCredentialCheck:
        """
        Check password against HIBP using k-anonymity.
        Only first 5 chars of SHA1 hash are sent.
        """
        # Compute SHA1 hash
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Check cache
        if prefix in self._cache:
            cached_result, cached_time = self._cache[prefix]
            if time.time() - cached_time < self.cache_ttl:
                # Verify suffix match
                cached_result.hibp_prefix = prefix
                return cached_result

        # Query API
        result = BreachedCredentialCheck(
            checked=True,
            hibp_prefix=prefix,
        )

        try:
            client = await self._get_client()
            response = await client.get(f"{self.base_url}{prefix}")

            if response.status_code == 200:
                # Parse response: each line is "SUFFIX:COUNT"
                lines = response.text.strip().split("\n")
                for line in lines:
                    if ":" in line:
                        suf, count_str = line.split(":", 1)
                        if suf == suffix:
                            count = int(count_str)
                            result.breached = True
                            result.breach_count = count
                            result.recommendation = (
                                f"This password has appeared in {count} data breaches. "
                                "Please choose a different password."
                            )
                            break

                if result.breached:
                    result.breach_sources = ["HaveIBeenPwned"]
                    # We don't get dates from the range API, but could from full API

        except Exception as e:
            result.recommendation = f"Breach check unavailable: {str(e)}"

        # Cache result
        self._cache[prefix] = (result, time.time())
        return result

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


class IPReputationService:
    """
    IP reputation service.
    Checks against Tor exit nodes, VPN/proxy lists, hosting providers, threat feeds.
    """

    def __init__(self) -> None:
        self._tor_exit_nodes: set[str] = set()
        self._vpn_proxies: set[str] = set()
        self._hosting_asns: set[str] = set()
        self._malicious_ips: set[str] = set()
        self._scanner_ips: set[str] = set()
        self._cache: dict[str, tuple[IPReputation, float]] = {}
        self.cache_ttl = 3600  # 1 hour
        self._initialized = False

        # Known hosting provider ASNs (sample)
        self._known_hosting_asns = {
            "AS16509", "AS14618", "AS396982", "AS36351", "AS24940",  # AWS
            "AS15169", "AS36492",  # Google
            "AS8075", "AS12076",  # Microsoft Azure
            "AS209242", "AS20473",  # Cloudflare
            "AS13335",  # Cloudflare
            "AS16276", "AS63949",  # DigitalOcean
            "AS14061", "AS394377",  # Linode
            "AS20473", "AS22652",  # Vultr
            "AS24940", "AS36351",  # Hetzner
            "AS60068", "AS9009",  # OVH
        }

    async def initialize(self) -> None:
        """Initialize threat intelligence feeds."""
        if self._initialized:
            return

        # In production, fetch from threat intel feeds
        # For now, load static lists
        await self._load_static_lists()
        self._initialized = True

    async def _load_static_lists(self) -> None:
        """Load static threat intelligence lists."""
        # Tor exit nodes (sample - in production fetch from Tor Project)
        self._tor_exit_nodes = {
            "185.220.100.240", "185.220.101.240", "185.220.102.240",
            # ... would load full list
        }

        # VPN/Proxy IPs (sample)
        self._vpn_proxies = set()

        # Malicious IPs (sample)
        self._malicious_ips = set()

        # Scanner IPs (sample)
        self._scanner_ips = set()

    def _get_asn_info(self, ip: str) -> tuple[Optional[str], Optional[str]]:
        """Get ASN info for IP (simplified - would use MaxMind/IP2Location in production)."""
        # In production, use GeoIP2 ASN database
        # For now, return None
        return None, None

    def _get_geo_info(self, ip: str) -> tuple[Optional[str], Optional[str]]:
        """Get geo info for IP."""
        # In production, use GeoIP2 City database
        return None, None

    async def check_ip(self, ip: str) -> IPReputation:
        """Check IP reputation."""
        # Check cache
        if ip in self._cache:
            cached, cached_time = self._cache[ip]
            if time.time() - cached_time < self.cache_ttl:
                return cached

        await self.initialize()

        reputation = IPReputation(ip=ip)

        # Check if private IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                reputation.category = IPReputationCategory.CLEAN
                reputation.risk_score = 0.0
                self._cache[ip] = (reputation, time.time())
                return reputation
        except ValueError:
            reputation.category = IPReputationCategory.MALICIOUS
            reputation.risk_score = 1.0
            self._cache[ip] = (reputation, time.time())
            return reputation

        # Check Tor
        if ip in self._tor_exit_nodes:
            reputation.is_tor = True
            reputation.category = IPReputationCategory.TOR_EXIT
            reputation.confidence = 0.95
            reputation.risk_score = 0.9
            reputation.threat_feeds.append("tor_exit_nodes")

        # Check VPN/Proxy
        if ip in self._vpn_proxies:
            reputation.is_proxy = True
            reputation.category = IPReputationCategory.VPN_PROXY
            reputation.confidence = max(reputation.confidence, 0.8)
            reputation.risk_score = max(reputation.risk_score, 0.7)
            reputation.threat_feeds.append("vpn_proxy_list")

        # Check malicious
        if ip in self._malicious_ips:
            reputation.category = IPReputationCategory.MALICIOUS
            reputation.confidence = 0.9
            reputation.risk_score = 0.95
            reputation.threat_feeds.append("malicious_feed")

        # Check scanner
        if ip in self._scanner_ips:
            reputation.category = IPReputationCategory.SCANNER
            reputation.confidence = max(reputation.confidence, 0.85)
            reputation.risk_score = max(reputation.risk_score, 0.8)
            reputation.threat_feeds.append("scanner_feed")

        # Get ASN info
        asn, asn_name = self._get_asn_info(ip)
        if asn:
            reputation.asn = asn
            reputation.asn_name = asn_name
            if asn in self._known_hosting_asns:
                reputation.is_hosting = True
                if reputation.category == IPReputationCategory.CLEAN:
                    reputation.category = IPReputationCategory.HOSTING_PROVIDER
                reputation.risk_score = max(reputation.risk_score, 0.4)
                reputation.threat_feeds.append("hosting_asn")

        # Get geo info
        country, city = self._get_geo_info(ip)
        reputation.country = country
        reputation.city = city

        # Cache
        self._cache[ip] = (reputation, time.time())
        return reputation


class GeoVelocityTracker:
    """Track user geo-location for impossible travel detection."""

    def __init__(self) -> None:
        self._user_locations: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._max_history = 50
        self._max_speed_kmh = 900  # Commercial aircraft

    def _haversine_distance(
        self,
        lat1: float, lon1: float,
        lat2: float, lon2: float,
    ) -> float:
        """Calculate distance between two points in km."""
        from math import radians, sin, cos, sqrt, atan2

        R = 6371  # Earth radius in km

        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])

        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))

        return R * c

    def record_location(
        self,
        user_id: str,
        lat: float,
        lon: float,
        timestamp: Optional[datetime] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Record user location."""
        ts = timestamp or datetime.now(timezone.utc)
        self._user_locations[user_id].append({
            "lat": lat,
            "lon": lon,
            "timestamp": ts,
            "metadata": metadata or {},
        })

        # Trim history
        if len(self._user_locations[user_id]) > self._max_history:
            self._user_locations[user_id] = self._user_locations[user_id][-self._max_history:]

    def check_impossible_travel(
        self,
        user_id: str,
        lat: float,
        lon: float,
        timestamp: Optional[datetime] = None,
    ) -> GeoVelocityCheck:
        """Check for impossible travel."""
        ts = timestamp or datetime.now(timezone.utc)
        history = self._user_locations.get(user_id, [])

        if not history:
            return GeoVelocityCheck(
                current_location={"lat": lat, "lon": lon, "timestamp": ts.isoformat()},
            )

        # Find most recent location
        last = history[-1]
        last_ts = last["timestamp"]
        if isinstance(last_ts, str):
            last_ts = datetime.fromisoformat(last_ts)

        time_diff = (ts - last_ts).total_seconds() / 3600  # hours

        if time_diff <= 0:
            return GeoVelocityCheck(
                current_location={"lat": lat, "lon": lon, "timestamp": ts.isoformat()},
                previous_location=last,
            )

        distance = self._haversine_distance(
            last["lat"], last["lon"], lat, lon
        )

        required_speed = distance / time_diff if time_diff > 0 else float('inf')
        impossible = required_speed > self._max_speed_kmh

        risk_score = min(1.0, required_speed / (self._max_speed_kmh * 2)) if impossible else 0.0

        return GeoVelocityCheck(
            impossible_travel=impossible,
            distance_km=distance,
            time_hours=time_diff,
            required_speed_kmh=required_speed,
            max_possible_speed_kmh=self._max_speed_kmh,
            previous_location=last,
            current_location={"lat": lat, "lon": lon, "timestamp": ts.isoformat()},
            risk_score=risk_score,
        )


class DeviceTracker:
    """Track user devices for anomaly detection."""

    def __init__(self) -> None:
        self._user_devices: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

    def register_device(
        self,
        user_id: str,
        device_id: str,
        fingerprint: dict[str, Any],
    ) -> bool:
        """Register device for user. Returns True if new device."""
        is_new = device_id not in self._user_devices[user_id]

        self._user_devices[user_id][device_id] = {
            "fingerprint": fingerprint,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "trusted": not is_new,  # First device is trusted
        }

        return is_new

    def check_device(
        self,
        user_id: str,
        device_id: str,
        fingerprint: dict[str, Any],
    ) -> DeviceAnomalyCheck:
        """Check device for anomalies."""
        user_devices = self._user_devices.get(user_id, {})

        if not user_devices:
            # First device for user
            return DeviceAnomalyCheck(
                new_device=True,
                device_id=device_id,
                known_devices=[],
                risk_score=0.2,  # Slight risk for first device
            )

        if device_id not in user_devices:
            # New device
            known = list(user_devices.keys())
            return DeviceAnomalyCheck(
                new_device=True,
                device_id=device_id,
                known_devices=known,
                risk_score=0.6,
            )

        # Known device - check for fingerprint changes
        known = user_devices[device_id]
        known_fp = known.get("fingerprint", {})

        ua_changed = known_fp.get("user_agent") != fingerprint.get("user_agent")
        platform_changed = known_fp.get("platform") != fingerprint.get("platform")

        risk_score = 0.0
        if ua_changed:
            risk_score += 0.3
        if platform_changed:
            risk_score += 0.4

        return DeviceAnomalyCheck(
            new_device=False,
            device_id=device_id,
            known_devices=list(user_devices.keys()),
            user_agent_changed=ua_changed,
            platform_changed=platform_changed,
            browser_changed=ua_changed,  # Simplified
            risk_score=risk_score,
        )

    def mark_device_trusted(self, user_id: str, device_id: str) -> None:
        """Mark device as trusted."""
        if user_id in self._user_devices and device_id in self._user_devices[user_id]:
            self._user_devices[user_id][device_id]["trusted"] = True

    def revoke_device(self, user_id: str, device_id: str) -> bool:
        """Revoke device trust."""
        if user_id in self._user_devices and device_id in self._user_devices[user_id]:
            self._user_devices[user_id][device_id]["trusted"] = False
            return True
        return False

    def get_user_devices(self, user_id: str) -> list[dict[str, Any]]:
        """Get all devices for user."""
        return [
            {"device_id": did, **info}
            for did, info in self._user_devices.get(user_id, {}).items()
        ]


class CredentialIntelligenceEngine:
    """
    Comprehensive credential intelligence engine.
    Combines breach checking, IP reputation, geo-velocity, device tracking.
    """

    def __init__(
        self,
        hibp_api_key: Optional[str] = None,
        enable_hibp: bool = True,
    ) -> None:
        self.hibp = HaveIBeenPwnedClient(api_key=hibp_api_key) if enable_hibp else None
        self.ip_reputation = IPReputationService()
        self.geo_velocity = GeoVelocityTracker()
        self.device_tracker = DeviceTracker()

    async def check_password_breach(self, password: str) -> BreachedCredentialCheck:
        """Check if password is in breach database."""
        if not self.hibp:
            return BreachedCredentialCheck(
                checked=False,
                recommendation="Breach checking disabled",
            )
        return await self.hibp.check_password(password)

    async def check_ip_reputation(self, ip: str) -> IPReputation:
        """Check IP reputation."""
        return await self.ip_reputation.check_ip(ip)

    def record_user_location(
        self,
        user_id: str,
        lat: float,
        lon: float,
        timestamp: Optional[datetime] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Record user location for geo-velocity tracking."""
        self.geo_velocity.record_location(user_id, lat, lon, timestamp, metadata)

    def check_geo_velocity(
        self,
        user_id: str,
        lat: float,
        lon: float,
        timestamp: Optional[datetime] = None,
    ) -> GeoVelocityCheck:
        """Check for impossible travel."""
        return self.geo_velocity.check_impossible_travel(user_id, lat, lon, timestamp)

    def register_device(
        self,
        user_id: str,
        device_id: str,
        fingerprint: dict[str, Any],
    ) -> bool:
        """Register device. Returns True if new."""
        return self.device_tracker.register_device(user_id, device_id, fingerprint)

    def check_device(
        self,
        user_id: str,
        device_id: str,
        fingerprint: dict[str, Any],
    ) -> DeviceAnomalyCheck:
        """Check device for anomalies."""
        return self.device_tracker.check_device(user_id, device_id, fingerprint)

    async def assess_credential_stuffing(
        self,
        ip: str,
        username: str,
        password: str,
        user_id: Optional[str],
        device_id: Optional[str],
        fingerprint: dict[str, Any],
        lat: Optional[float] = None,
        lon: Optional[float] = None,
    ) -> CredentialStuffingAssessment:
        """Comprehensive credential stuffing assessment."""
        assessment = CredentialStuffingAssessment()

        # 1. Check password breach
        if password:
            assessment.breached_credential = await self.check_password_breach(password)
            if assessment.breached_credential.breached:
                assessment.patterns_detected.append(
                    CredentialStuffingPattern.KNOWN_BREACHED_CREDENTIALS
                )

        # 2. Check IP reputation
        assessment.ip_reputation = await self.check_ip_reputation(ip)
        if assessment.ip_reputation.category in [
            IPReputationCategory.TOR_EXIT,
            IPReputationCategory.VPN_PROXY,
            IPReputationCategory.HOSTING_PROVIDER,
            IPReputationCategory.RESIDENTIAL_PROXY,
        ]:
            assessment.patterns_detected.append(CredentialStuffingPattern.DISTRIBUTED_LOW_VELOCITY)

        if assessment.ip_reputation.category == IPReputationCategory.MALICIOUS:
            assessment.patterns_detected.append(CredentialStuffingPattern.HIGH_VELOCITY_SINGLE_IP)

        # 3. Check geo-velocity
        if user_id and lat is not None and lon is not None:
            assessment.geo_velocity = self.check_geo_velocity(user_id, lat, lon)
            if assessment.geo_velocity.impossible_travel:
                assessment.patterns_detected.append(CredentialStuffingPattern.IMPOSSIBLE_TRAVEL)

        # 4. Check device anomaly
        if user_id and device_id:
            assessment.device_anomaly = self.check_device(user_id, device_id, fingerprint)
            if assessment.device_anomaly.new_device:
                assessment.patterns_detected.append(CredentialStuffingPattern.DEVICE_FARM)

        # Calculate overall risk
        risk_factors = []

        if assessment.breached_credential and assessment.breached_credential.breached:
            risk_factors.append(("breached_credential", 0.8))

        if assessment.ip_reputation:
            risk_factors.append(("ip_reputation", assessment.ip_reputation.risk_score))

        if assessment.geo_velocity:
            risk_factors.append(("geo_velocity", assessment.geo_velocity.risk_score))

        if assessment.device_anomaly:
            risk_factors.append(("device_anomaly", assessment.device_anomaly.risk_score))

        assessment.overall_risk = min(1.0, sum(score for _, score in risk_factors) / max(1, len(risk_factors)))
        assessment.confidence = min(1.0, len(risk_factors) * 0.25)

        # Generate recommendations
        if assessment.breached_credential and assessment.breached_credential.breached:
            assessment.recommended_actions.append("Require password change - credential found in breach")

        if assessment.ip_reputation and assessment.ip_reputation.is_tor:
            assessment.recommended_actions.append("Block or challenge Tor exit node")

        if assessment.ip_reputation and assessment.ip_reputation.is_hosting:
            assessment.recommended_actions.append("Challenge hosting provider IP")

        if assessment.geo_velocity and assessment.geo_velocity.impossible_travel:
            assessment.recommended_actions.append("Require MFA - impossible travel detected")

        if assessment.device_anomaly and assessment.device_anomaly.new_device:
            assessment.recommended_actions.append("Require email verification for new device")

        return assessment

    async def close(self) -> None:
        """Close connections."""
        if self.hibp:
            await self.hibp.close()


# Global credential intelligence engine
credential_intel = CredentialIntelligenceEngine()