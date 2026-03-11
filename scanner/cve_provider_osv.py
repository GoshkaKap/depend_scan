from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

from .models import Finding, Criticality
from .parser import normalize_package_name


class OsvcveProvider:
    """
    CVE-провайдер через OSV.dev.
    Делает запросы: POST /v1/query (ecosystem=PyPI, name, version)
    и превращает ответ в Finding(risk_type="CVE").
    """

    OSV_QUERY_URL = "https://api.osv.dev/v1/query"

    def __init__(self, timeout_seconds: float = 10.0) -> None:
        self._timeout_seconds = float(timeout_seconds)
        self._cache: Dict[Tuple[str, str], List[Finding]] = {}

    def find_cve_findings(self, package_name: str, package_version: str) -> List[Finding]:
        name = normalize_package_name(package_name)
        version = (package_version or "").strip()

        cache_key = (name, version)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return list(cached)

        vulns = self._query_osv(name=name, version=version)
        findings: List[Finding] = [self._vuln_to_finding(name, version, v) for v in vulns]

        self._cache[cache_key] = list(findings)
        return findings

    def _query_osv(self, name: str, version: str) -> List[dict]:
        payload = {
            "package": {"ecosystem": "PyPI", "name": name},
            "version": version,
        }
        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            self.OSV_QUERY_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self._timeout_seconds) as resp:
                raw = resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            # Если OSV недоступен — не падаем, просто возвращаем пустой список
            return []

        try:
            obj = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return []

        vulns = obj.get("vulns")
        if isinstance(vulns, list):
            return [x for x in vulns if isinstance(x, dict)]
        return []

    def _vuln_to_finding(self, package_name: str, package_version: str, vuln: dict) -> Finding:
        vuln_id = self._safe_str(vuln.get("id"))
        summary = self._safe_str(vuln.get("summary"))
        details = self._safe_str(vuln.get("details"))

        parts: List[str] = []
        if vuln_id:
            parts.append(f"OSV: {vuln_id}")
        if summary:
            parts.append(summary)
        elif details:
            parts.append(details)

        description = " — ".join([p for p in parts if p]) or "Обнаружены уязвимости по данным OSV для указанной версии."
        recommendation = "Обновить пакет до версии без уязвимости."
        criticality = self._extract_criticality(vuln)

        if vuln_id:
            reason = f"OSV вернул vulns (id={vuln_id}) для PyPI: {package_name} {package_version}"
        else:
            reason = f"OSV вернул vulns для PyPI: {package_name} {package_version}"

        return Finding(
            name=package_name,
            version=package_version,
            risk_type="CVE",
            description=description,
            recommendation=recommendation,
            criticality=criticality,
            reason=reason,
        )

    def _extract_criticality(self, vuln: dict) -> Criticality:
        """
        Пытаемся взять severity из данных OSV.
        Если не нашли — ставим Low (чтобы не ломать отчёт).
        """
        dbs = vuln.get("database_specific")
        if isinstance(dbs, dict):
            mapped = self._map_severity_value(dbs.get("severity"))
            if mapped is not None:
                return mapped

        sev_list = vuln.get("severity")
        if isinstance(sev_list, list):
            for item in sev_list:
                if isinstance(item, dict):
                    mapped = self._map_severity_value(item.get("score"))
                    if mapped is not None:
                        return mapped

        return "Low"

    def _map_severity_value(self, value: object) -> Optional[Criticality]:
        if not isinstance(value, str):
            return None
        v = value.strip().upper()

        if v == "CRITICAL":
            return "Critical"
        if v == "HIGH":
            return "High"
        if v in ("MEDIUM", "MODERATE"):
            return "Medium"
        if v in ("LOW", "INFO", "INFORMATIONAL"):
            return "Low"
        return None

    def _safe_str(self, v: object) -> str:
        return v.strip() if isinstance(v, str) else ""