from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import Criticality, Finding
from .parser import normalize_package_name


class SemgrepRulesEngine:
    """
    Сигнатурный анализ зависимости через Semgrep:

    1) Получаем sdist для (package, version) с PyPI
    2) Распаковываем во временную папку
    3) Запускаем semgrep с локальными правилами
    4) results[] -> Finding(risk_type="SIGNATURE")
    """

    PYPI_JSON_URL_TPL = "https://pypi.org/pypi/{name}/{version}/json"

    def __init__(self, download_timeout_seconds: float = 20.0, semgrep_timeout_seconds: float = 60.0) -> None:
        self._download_timeout = float(download_timeout_seconds)
        self._semgrep_timeout = float(semgrep_timeout_seconds)
        self._cache: Dict[Tuple[str, str], List[Finding]] = {}

    def rules_dir(self) -> Path:
        return Path(__file__).resolve().parent / "rules" / "semgrep"

    def scan_package(self, package_name: str, package_version: str) -> List[Finding]:
        name = normalize_package_name(package_name)
        version = (package_version or "").strip()

        cache_key = (name, version)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return list(cached)

        with TemporaryDirectory(prefix="scanner_pypi_") as tmp:
            tmp_path = Path(tmp)

            src_root = self._download_and_extract_sdist(name=name, version=version, tmp_dir=tmp_path)

            findings = self._run_semgrep_and_convert(
                package_name=name,
                package_version=version,
                target_dir=src_root,
            )

        self._cache[cache_key] = list(findings)
        return findings

    # -------- PyPI: download + extract --------
    def _download_and_extract_sdist(self, name: str, version: str, tmp_dir: Path) -> Path:
        sdist_url = self._get_sdist_url_from_pypi(name=name, version=version)

        archive_path = tmp_dir / "sdist_archive"
        self._download_file(url=sdist_url, dst=archive_path)

        extract_dir = tmp_dir / "src"
        extract_dir.mkdir(parents=True, exist_ok=True)

        root = self._extract_archive(archive_path=archive_path, extract_to=extract_dir)

        # Часто внутри архива одна папка вида package-1.2.3/
        children = [p for p in root.iterdir()]
        if len(children) == 1 and children[0].is_dir():
            return children[0]

        return root

    def _get_sdist_url_from_pypi(self, name: str, version: str) -> str:
        url = self.PYPI_JSON_URL_TPL.format(name=name, version=version)
        payload = self._http_get_json(url)

        urls = payload.get("urls")
        if not isinstance(urls, list):
            raise RuntimeError("PyPI JSON: поле 'urls' отсутствует или некорректно.")

        for item in urls:
            if isinstance(item, dict) and item.get("packagetype") == "sdist":
                u = item.get("url")
                if isinstance(u, str) and u:
                    return u

        raise RuntimeError("PyPI JSON: sdist не найден для указанного пакета/версии.")

    def _http_get_json(self, url: str) -> dict:
        req = Request(url, headers={"Accept": "application/json"})
        try:
            with urlopen(req, timeout=self._download_timeout) as resp:
                raw = resp.read()
        except (URLError, HTTPError, TimeoutError) as e:
            raise RuntimeError(f"Не удалось получить данные PyPI: {e}") from e

        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as e:
            raise RuntimeError("PyPI JSON: невалидный JSON.") from e

    def _download_file(self, url: str, dst: Path) -> None:
        req = Request(url, headers={"User-Agent": "scanner/1.0"})
        try:
            with urlopen(req, timeout=self._download_timeout) as resp:
                data = resp.read()
        except (URLError, HTTPError, TimeoutError) as e:
            raise RuntimeError(f"Не удалось скачать sdist: {e}") from e

        dst.write_bytes(data)

    def _extract_archive(self, archive_path: Path, extract_to: Path) -> Path:
        # Сначала пробуем распаковать по расширению, потом — “угадываем” формат.
        lower = archive_path.name.lower()

        if lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
            try:
                with tarfile.open(archive_path, mode="r:*") as tf:
                    tf.extractall(path=extract_to)
                return extract_to
            except tarfile.TarError:
                pass

        if lower.endswith(".zip"):
            try:
                with zipfile.ZipFile(archive_path, mode="r") as zf:
                    zf.extractall(path=extract_to)
                return extract_to
            except zipfile.BadZipFile:
                pass

        try:
            with tarfile.open(archive_path, mode="r:*") as tf:
                tf.extractall(path=extract_to)
            return extract_to
        except tarfile.TarError:
            pass

        try:
            with zipfile.ZipFile(archive_path, mode="r") as zf:
                zf.extractall(path=extract_to)
            return extract_to
        except zipfile.BadZipFile as e:
            raise RuntimeError("Неизвестный формат sdist-архива (tar/zip не распознан).") from e

    # -------- Semgrep: run + parse + convert --------
    def _run_semgrep_and_convert(self, package_name: str, package_version: str, target_dir: Path) -> List[Finding]:
        semgrep = shutil.which("semgrep")
        if not semgrep:
            raise RuntimeError("Semgrep не найден в PATH.")

        rules_path = self._pick_rules_config_path()
        cmd = [
            semgrep,
            "--config", str(rules_path),
            "--json",
            "--quiet",
            "--no-git-ignore",
            str(target_dir),
        ]

        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self._semgrep_timeout,
                check=False,
                text=True,
            )
        except subprocess.TimeoutExpired:
            return []

        try:
            out = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return []

        results = out.get("results")
        if not isinstance(results, list):
            return []

        findings: List[Finding] = []
        for r in results:
            if not isinstance(r, dict):
                continue
            f = self._result_to_finding(
                package_name=package_name,
                package_version=package_version,
                result=r,
                root_dir=target_dir,
            )
            if f is not None:
                findings.append(f)

        return findings

    def _pick_rules_config_path(self) -> Path:
        candidate = self.rules_dir() / "basic.yml"
        if candidate.is_file():
            return candidate
        raise RuntimeError("Не найден встроенный набор правил Semgrep (ожидается scanner/rules/semgrep/basic.yml).")

    def _result_to_finding(self, package_name: str, package_version: str, result: dict, root_dir: Path) -> Optional[Finding]:
        check_id = self._safe_str(result.get("check_id"))
        path_raw = self._safe_str(result.get("path"))
        start = result.get("start")
        extra = result.get("extra")

        line = None
        if isinstance(start, dict):
            ln = start.get("line")
            if isinstance(ln, int):
                line = ln

        rel_path = self._relativize_path(path_raw, root_dir)

        severity_raw = None
        message = None
        if isinstance(extra, dict):
            severity_raw = extra.get("severity")
            message = extra.get("message")

        criticality = self._map_semgrep_severity(severity_raw)

        reason_parts = []
        if check_id:
            reason_parts.append(f"Semgrep check_id={check_id}")
        if isinstance(message, str) and message.strip():
            reason_parts.append(message.strip())
        reason = " — ".join(reason_parts) if reason_parts else "Semgrep result"

        return Finding(
            name=package_name,
            version=package_version,
            risk_type="SIGNATURE",
            description="Сигнатурное срабатывание Semgrep на подозрительный паттерн.",
            recommendation="Проверить срабатывание и при необходимости заменить/удалить зависимость.",
            criticality=criticality,
            reason=reason,
            package=package_name,
            file=rel_path,
            line=line,
        )

    def _relativize_path(self, path_str: str, root_dir: Path) -> str:
        if not path_str:
            return ""
        try:
            p = Path(path_str)
            if p.is_absolute():
                rp = p.resolve()
                rr = root_dir.resolve()
                try:
                    return str(rp.relative_to(rr)).replace("\\", "/")
                except Exception:
                    return str(p.name)
            return path_str.replace("\\", "/")
        except Exception:
            return path_str

    def _map_semgrep_severity(self, severity: object) -> Criticality:
        if isinstance(severity, str):
            s = severity.strip().upper()
            if s == "ERROR":
                return "Critical"
            if s == "WARNING":
                return "High"
            if s == "INFO":
                return "Medium"
        return "Low"

    def _safe_str(self, v: object) -> str:
        return v.strip() if isinstance(v, str) else ""