from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Optional

from scanner.parser import Parser
from scanner.ast_engine import ASTEngine
from scanner.cve_provider_osv import OsvcveProvider
from scanner.rules_engine_semgrep import SemgrepRulesEngine
from scanner.reporter import Reporter
from scanner.models import Finding

# Точная версия: ==1.2.3 или ===1.2.3
_EXACT_VERSION_RE = re.compile(r"^(==|===)\s*([0-9A-Za-z][0-9A-Za-z.\-_+]*)\s*$")


def _extract_exact_version(spec: str) -> str:
    """
    Достаём версию только если она указана строго (== или ===).
    Для диапазонов (>=, ~= и т.п.) возвращаем пустую строку.
    """
    s = (spec or "").strip()
    m = _EXACT_VERSION_RE.match(s)
    if not m:
        return ""
    return m.group(2).strip()


def _make_unused_dependency_finding(name: str, version: str) -> Finding:
    """Зависимость указана, но в коде не используется."""
    return Finding(
        name=name,
        version=version,
        risk_type="UNUSED_DEPENDENCY",
        description="Зависимость указана в файле зависимостей, но не используется в коде проекта.",
        recommendation="Удалить зависимость из файла зависимостей, если она действительно не нужна.",
        reason="Зависимость найдена в requirements/pyproject, но отсутствует среди импортов AST.",
    )


def _make_undeclared_import_finding(name: str) -> Finding:
    """Импорт есть в коде, но зависимости нет в requirements/pyproject."""
    return Finding(
        name=name,
        version="",
        risk_type="UNDECLARED_IMPORT",
        description="Импорт используется в коде проекта, но отсутствует в файле зависимостей.",
        recommendation="Добавить зависимость в файл зависимостей, если она действительно необходима.",
        reason="Импорт найден AST-анализом, но отсутствует в requirements/pyproject.",
    )


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Ожидаем ровно один аргумент: путь к проекту
    if len(argv) != 1:
        print("Usage: python scanner.py /path/to/project")
        return 1

    project_path = Path(argv[0]).expanduser().resolve()
    if not project_path.exists() or not project_path.is_dir():
        print("Error: project path must be an existing directory.")
        return 1

    # Инициализация компонентов пайплайна
    parser = Parser()
    ast_engine = ASTEngine()
    cve_provider = OsvcveProvider(timeout_seconds=10.0)
    rules_engine = SemgrepRulesEngine(download_timeout_seconds=20.0, semgrep_timeout_seconds=60.0)
    reporter = Reporter()

    # 1) Читаем заявленные зависимости (requirements/pyproject)
    declared_deps = parser.parse_dependencies(project_path)

    # 2) Анализируем импорты в исходниках проекта через AST
    analysis = ast_engine.analyze_imports(project_path, declared_deps)

    findings: List[Finding] = []

    # 3) Проверяем только реально используемые зависимости
    # Внешние запросы идут по name/version, исходники проекта никуда не отправляются.
    for dep_name in sorted(analysis.used_dependencies):
        spec = declared_deps.get(dep_name, "")
        exact_version = _extract_exact_version(spec)

        # CVE-проверка через OSV.dev
        findings.extend(cve_provider.find_cve_findings(dep_name, exact_version))

        # Semgrep-скан зависимостей делаем только при точной версии
        if exact_version:
            findings.extend(rules_engine.scan_package(dep_name, exact_version))

    # 4) Лишние зависимости (заявлены, но не используются)
    for dep_name in sorted(analysis.unused_declared_dependencies):
        findings.append(_make_unused_dependency_finding(dep_name, declared_deps.get(dep_name, "")))

    # 5) Незадекларированные импорты (используются, но нет в requirements/pyproject)
    for imp in sorted(analysis.undeclared_imports):
        findings.append(_make_undeclared_import_finding(imp))

    # 6) Генерация отчётов
    reporter.write_json_report(findings=findings, analysis=analysis, out_dir=None)
    reporter.write_markdown_report(findings=findings, analysis=analysis, out_dir=None)

    # 7) Краткая сводка в консоль
    print(reporter.render_console_summary(declared_dependency_count=len(declared_deps), findings=findings))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())