"""
SNMK MAP ?" Geolocation and Coordinate Intelligence Engine
Provides public IP geolocation, decimal-to-DMS coordinate conversion,
forward and reverse geocoding, device geolocation ingestion, and multi-source comparison.
"""

from __future__ import annotations

import ipaddress
import logging
import math
from typing import Any

import httpx

from core.network.models import GeolocationInfo

logger = logging.getLogger("snmk.map.geo")


def decimal_to_dms(deg: float, is_lat: bool) -> str:
    """Converts decimal degrees to Degrees, Minutes, Seconds string (e.g. 17°41'12.5"N)."""
    if deg is None or math.isnan(deg):
        return "N/A"
    direction = ""
    if is_lat:
        direction = "N" if deg >= 0 else "S"
    else:
        direction = "E" if deg >= 0 else "W"

    abs_deg = abs(deg)
    d = int(abs_deg)
    rem_m = (abs_deg - d) * 60
    m = int(rem_m)
    s = (rem_m - m) * 60
    return f"{d}°{m}'{s:.1f}\"{direction}"


def is_private_ip(ip: str) -> bool:
    """Checks whether an IP address is private, loopback, link-local or reserved."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_unspecified
    except ValueError:
        return False


class GeolocationEngine:
    """Multi-source IP Geolocation & Coordinate Engine."""

    def __init__(self):
        self._cache = {}

    async def lookup_ip_geolocation(self, ip: str) -> GeolocationInfo:
        """Geolocates a public IPv4/IPv6 address with fallback providers."""
        ip = ip.strip()
        if ip in self._cache:
            return self._cache[ip]

        # Reject private IP coordinates fabrication
        if is_private_ip(ip):
            return GeolocationInfo(
                ip=ip,
                latitude=None,
                longitude=None,
                lat_dms="N/A (Private Range)",
                lon_dms="N/A (Private Range)",
                city="Local Network / Non-Routable",
                region="Private Subnet",
                country="Internal",
                country_code="LOCAL",
                postal=None,
                timezone="Local",
                accuracy_radius_km=None,
                source_provider="Internal RFC1918 Classifier",
                confidence="Private Network Endpoint",
                physical_caveat="RFC 1918 / Private network addresses have no global geographical routing location."
            )

        import ipaddress
        import urllib.parse

        try:
            ip_obj = ipaddress.ip_address(ip.strip())
            if not ip_obj.is_global:
                return GeolocationInfo(
                    ip=ip,
                    latitude=None,
                    longitude=None,
                    lat_dms="N/A (Private/Local Range)",
                    lon_dms="N/A (Private/Local Range)",
                    city="Non-Public Address",
                    region="Private/Reserved Subnet",
                    country="Internal",
                    country_code="LOCAL",
                    source_provider="Internal RFC Classifier",
                    confidence="Non-Routable IP"
                )
            if ip_obj.version == 4:
                b = ip_obj.packed
                safe_ip = f"{int(b[0])}.{int(b[1])}.{int(b[2])}.{int(b[3])}"
            elif ip_obj.version == 6:
                safe_ip = str(ip_obj.exploded)
            else:
                raise ValueError("Unsupported IP version")
        except ValueError:
            return GeolocationInfo(
                ip=ip,
                latitude=None,
                longitude=None,
                lat_dms="Unavailable",
                lon_dms="Unavailable",
                city="Invalid IP",
                region="Invalid IP",
                country="Invalid IP",
                source_provider="Local Validator",
                confidence="Invalid IP Syntax"
            )

        # 1. Try ipinfo.io
        try:
            async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
                res = await client.get(f"https://ipinfo.io/{safe_ip}/json")
                if res.status_code == 200:
                    data = res.json()
                    loc = data.get("loc", "")
                    lat, lon = None, None
                    if loc and "," in loc:
                        parts = loc.split(",")
                        lat = float(parts[0].strip())
                        lon = float(parts[1].strip())

                    lat_dms = decimal_to_dms(lat, True) if lat is not None else None
                    lon_dms = decimal_to_dms(lon, False) if lon is not None else None

                    res_info = GeolocationInfo(
                        ip=ip,
                        latitude=lat,
                        longitude=lon,
                        lat_dms=lat_dms,
                        lon_dms=lon_dms,
                        city=data.get("city"),
                        region=data.get("region"),
                        country=data.get("country"),
                        country_code=data.get("country"),
                        postal=data.get("postal"),
                        timezone=data.get("timezone"),
                        accuracy_radius_km=25,
                        source_provider="ipinfo.io Geolocation Feed",
                        confidence="Approximate Public Network Geolocation",
                        physical_caveat="IP geolocation represents internet service provider allocation, not physical device or personal location."
                    )
                    self._cache[ip] = res_info
                    return res_info
        except Exception as e:
            logger.debug(f"ipinfo lookup failed for {ip}: {e}")

        # 2. Try ip-api.com fallback
        try:
            async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
                res = await client.get(
                    f"https://ip-api.com/json/{safe_ip}",
                    params={"fields": "status,country,countryCode,regionName,city,zip,lat,lon,timezone,as"}
                )
                if res.status_code == 200:
                    data = res.json()
                    if data.get("status") == "success":
                        lat = float(data.get("lat")) if data.get("lat") is not None else None
                        lon = float(data.get("lon")) if data.get("lon") is not None else None
                        lat_dms = decimal_to_dms(lat, True) if lat is not None else None
                        lon_dms = decimal_to_dms(lon, False) if lon is not None else None

                        res_info = GeolocationInfo(
                            ip=ip,
                            latitude=lat,
                            longitude=lon,
                            lat_dms=lat_dms,
                            lon_dms=lon_dms,
                            city=data.get("city"),
                            region=data.get("regionName"),
                            country=data.get("country"),
                            country_code=data.get("countryCode"),
                            postal=data.get("zip"),
                            timezone=data.get("timezone"),
                            accuracy_radius_km=35,
                            source_provider="ip-api.com Feed",
                            confidence="Approximate Public Network Geolocation"
                        )
                        self._cache[ip] = res_info
                        return res_info
        except Exception as e:
            logger.debug(f"ip-api fallback failed for {ip}: {e}")

        # If lookups fail or offline, return unestablished result
        return GeolocationInfo(
            ip=ip,
            latitude=None,
            longitude=None,
            lat_dms="Unavailable",
            lon_dms="Unavailable",
            city="Unestablished",
            region="Unestablished",
            country="Unestablished",
            source_provider="Local Resolver (Network lookup timed out)",
            confidence="Unavailable"
        )

    async def forward_geocode(self, address_or_place: str) -> dict[str, Any]:
        """Forward geocoding: Place/Address -> Latitude + Longitude."""
        query = address_or_place.strip()
        try:
            async with httpx.AsyncClient(headers={"User-Agent": "SNMK-MAP-Intelligence/2.2"}, timeout=5.0, follow_redirects=False) as client:
                res = await client.get(
                    "https://nominatim.openstreetmap.org/search",
                    params={"q": query, "format": "json", "limit": 1}
                )
                if res.status_code == 200 and res.json():
                    item = res.json()[0]
                    lat = float(item["lat"])
                    lon = float(item["lon"])
                    return {
                        "success": True,
                        "query": query,
                        "display_name": item.get("display_name"),
                        "latitude": lat,
                        "longitude": lon,
                        "lat_dms": decimal_to_dms(lat, True),
                        "lon_dms": decimal_to_dms(lon, False),
                        "source": "OpenStreetMap Nominatim Geocoder"
                    }
        except Exception as e:
            logger.error(f"Forward geocoding error: {e}")

        return {"success": False, "query": query, "message": "Geocoding query could not be resolved."}

    async def reverse_geocode(self, latitude: float, longitude: float) -> dict[str, Any]:
        """Reverse geocoding: Latitude + Longitude -> Geographic Address."""
        try:
            lat_f = float(latitude)
            lon_f = float(longitude)
            async with httpx.AsyncClient(headers={"User-Agent": "SNMK-MAP-Intelligence/2.2"}, timeout=5.0, follow_redirects=False) as client:
                res = await client.get(
                    "https://nominatim.openstreetmap.org/reverse",
                    params={"lat": str(lat_f), "lon": str(lon_f), "format": "json"}
                )
                if res.status_code == 200 and res.json():
                    item = res.json()
                    addr = item.get("address", {})
                    return {
                        "success": True,
                        "latitude": latitude,
                        "longitude": longitude,
                        "display_name": item.get("display_name"),
                        "city": addr.get("city") or addr.get("town") or addr.get("suburb"),
                        "region": addr.get("state") or addr.get("county"),
                        "country": addr.get("country"),
                        "postal": addr.get("postcode"),
                        "source": "OpenStreetMap Nominatim Reverse Geocoder"
                    }
        except Exception as e:
            logger.error(f"Reverse geocoding error: {e}")

        return {"success": False, "latitude": latitude, "longitude": longitude, "message": "Reverse geocoding query failed."}


geo_engine = GeolocationEngine()
