from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .models import Finding, ASTAnalysisResult


class Reporter:
    """
    Reporter:
      - генерирует JSON и Markdown отчёты
      - включает перечень находок с причиной, критичностью, рекомендацией
      - делает группировку по категориям: CVE / SIGNATURE / UNUSED_DEPENDENCY / UNDECLARED_IMPORT
      - формирует короткую консольную сводку: число зависимостей и количество находок

    По умолчанию пишет отчёты в ./scanner_reports (в текущей директории),
    чтобы не изменять файлы анализируемого проекта.
    """

    DEFAULT_REPORT_DIRNAME = "scanner_reports"

    def default_out_dir(self) -> Path:
        return Path.cwd() / self.DEFAULT_REPORT_DIRNAME

    def write_json_report(
        self,
        findings: List[Finding],
        analysis: ASTAnalysisResult,
        out_dir: Optional[Path] = None,
    ) -> Path:
        out_dir = Path(out_dir) if out_dir is not None else self.default_out_dir()
        out_dir.mkdir(parents=True, exist_ok=True)

        payload = self._build_json_payload(findings=findings)

        path = out_dir / "report.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def write_markdown_report(
        self,
        findings: List[Finding],
        analysis: ASTAnalysisResult,
        out_dir: Optional[Path] = None,
    ) -> Path:
        out_dir = Path(out_dir) if out_dir is not None else self.default_out_dir()
        out_dir.mkdir(parents=True, exist_ok=True)

        grouped = self._group_findings(findings)
        md = self._render_markdown(grouped)

        path = out_dir / "report.md"
        path.write_text(md, encoding="utf-8")
        return path

    def render_console_summary(self, declared_dependency_count: int, findings: List[Finding]) -> str:
        return f"Зависимости: {declared_dependency_count}. Находки: {len(findings)}."

    def _build_json_payload(self, findings: List[Finding]) -> Dict[str, List[dict]]:
        grouped = self._group_findings(findings)
        return {
            "CVE": [self._finding_to_json_dict(f) for f in grouped["CVE"]],
            "SIGNATURE": [self._finding_to_json_dict(f) for f in grouped["SIGNATURE"]],
            "UNUSED_DEPENDENCY": [self._finding_to_json_dict(f) for f in grouped["UNUSED_DEPENDENCY"]],
            "UNDECLARED_IMPORT": [self._finding_to_json_dict(f) for f in grouped["UNDECLARED_IMPORT"]],
        }

    def _finding_to_json_dict(self, f: Finding) -> dict:
        d = {
            "name": f.name,
            "version": f.version,
            "risk_type": f.risk_type,
            "description": f.description,
            "recommendation": f.recommendation,
        }

        if f.criticality is not None:
            d["criticality"] = f.criticality
        if f.reason is not None:
            d["reason"] = f.reason

        if f.risk_type == "SIGNATURE":
            if f.package is not None:
                d["package"] = f.package
            if f.file is not None:
                d["file"] = f.file
            if f.line is not None:
                d["line"] = f.line

        return d

    def _group_findings(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        grouped: Dict[str, List[Finding]] = {
            "CVE": [],
            "SIGNATURE": [],
            "UNUSED_DEPENDENCY": [],
            "UNDECLARED_IMPORT": [],
        }

        for f in findings:
            if f.risk_type == "CVE":
                grouped["CVE"].append(f)
            elif f.risk_type == "SIGNATURE":
                grouped["SIGNATURE"].append(f)
            elif f.risk_type == "UNUSED_DEPENDENCY":
                grouped["UNUSED_DEPENDENCY"].append(f)
            elif f.risk_type == "UNDECLARED_IMPORT":
                grouped["UNDECLARED_IMPORT"].append(f)
            else:
                # иных категорий не ожидаем
                continue

        for k in grouped:
            grouped[k].sort(key=lambda x: (x.name, x.version, (x.file or ""), (x.line or 0)))
        return grouped

    def _render_markdown(self, grouped: Dict[str, List[Finding]]) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total = sum(len(v) for v in grouped.values())

        lines: List[str] = []
        lines.append("# Отчёт анализа зависимостей")
        lines.append("")
        lines.append(f"- Сформировано: {now}")
        lines.append(f"- Всего находок: {total}")
        lines.append("")
        lines.append("## Сводка по категориям")
        lines.append("")
        lines.append("| Категория | Кол-во |")
        lines.append("|---|---:|")
        lines.append(f"| CVE | {len(grouped['CVE'])} |")
        lines.append(f"| Сигнатуры | {len(grouped['SIGNATURE'])} |")
        lines.append(f"| Неиспользуемые зависимости | {len(grouped['UNUSED_DEPENDENCY'])} |")
        lines.append(f"| Импорты без декларации | {len(grouped['UNDECLARED_IMPORT'])} |")
        lines.append("")

        self._render_category_section(lines, "CVE", grouped["CVE"], include_location=False)
        self._render_category_section(lines, "Сигнатуры", grouped["SIGNATURE"], include_location=True)
        self._render_category_section(lines, "Неиспользуемые зависимости", grouped["UNUSED_DEPENDENCY"], include_location=False)
        self._render_category_section(lines, "Импорты без декларации", grouped["UNDECLARED_IMPORT"], include_location=False)

        return "\n".join(lines).rstrip() + "\n"

    def _render_category_section(
        self,
        lines: List[str],
        title: str,
        findings: List[Finding],
        include_location: bool,
    ) -> None:
        lines.append(f"## {title}")
        lines.append("")

        if not findings:
            lines.append("Нет находок.")
            lines.append("")
            return

        if include_location:
            lines.append("| Имя | Версия | Критичность | Пакет | Файл | Строка | Причина | Рекомендация |")
            lines.append("|---|---|---|---|---|---:|---|---|")
        else:
            lines.append("| Имя | Версия | Критичность | Причина | Рекомендация |")
            lines.append("|---|---|---|---|---|")

        for f in findings:
            crit = f.criticality or ""
            reason = self._md_escape(f.reason or "")
            rec = self._md_escape(f.recommendation or "")

            if include_location:
                pkg = self._md_escape(f.package or "")
                fp = self._md_escape(f.file or "")
                ln = "" if f.line is None else str(f.line)
                lines.append(
                    f"| {self._md_escape(f.name)} | {self._md_escape(f.version)} | {crit} | {pkg} | {fp} | {ln} | {reason} | {rec} |"
                )
            else:
                lines.append(
                    f"| {self._md_escape(f.name)} | {self._md_escape(f.version)} | {crit} | {reason} | {rec} |"
                )

        lines.append("")

    def _md_escape(self, s: str) -> str:
        return s.replace("|", "\\|").replace("\n", " ").strip()
