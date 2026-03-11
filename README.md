# Dependency Scanner (Контракт v1)

Консольная утилита для анализа Python-проекта:
- выявление реально используемых зависимостей через AST-импорты;
- проверка реально используемых зависимостей по CVE через OSV.dev;
- сигнатурный анализ исходников пакетов (из PyPI) через Semgrep;
- отчёты: Markdown и JSON.

## Требования
- Python 3.8+
- Пакеты Python:
  - `tomli` (нужен для чтения `pyproject.toml` на Python 3.8+)
- Внешний инструмент:
  - `semgrep` (должен быть доступен в `PATH`)

## Установка зависимостей Python
```bash
python -m pip install -U pip
python -m pip install tomli
```

Для запуска тестов:
```bash
python -m pip install pytest
```

## Установка Semgrep
Semgrep ставится отдельным пакетом (внешний инструмент). Пример:
```bash
python -m pip install semgrep
```
Проверьте:
```bash
semgrep --version
```

## Запуск
```bash
python scanner.py /path/to/project
```

## Отчёты
По умолчанию отчёты пишутся в директорию:

- `./scanner_reports/report.json`
- `./scanner_reports/report.md`

TODO (контракт): точный путь/правила именования/перезапись отчётов не специфицированы.

## Важно про read-only и приватность
- Файлы проекта не изменяются (read-only).
- Исходный код проекта не передаётся во внешние сервисы.
- В сеть выполняются запросы только:
  - к OSV.dev API для CVE-проверки по `name/version`;
  - к PyPI для загрузки исходников пакетов (sdist) для сигнатурного анализа.

## Запуск тестов (сценарии A/B/В/Г)
```bash
pytest -q
```

## Traceability (MUST -> реализация)

1) MUST принимать путь к Python-проекту  
   - `scanner.py: main()`

2) MUST находить `requirements.txt` и/или `pyproject.toml`  
   - `scanner/parser.py: Parser.parse_dependencies()`

3) MUST сканировать `.py` и через `ast` определять используемые библиотеки (по импортам)  
   - `scanner/ast_engine.py: ASTEngine.analyze_imports()`  
   - `scanner/ast_engine.py: ASTEngine._extract_top_level_imports()`

4) MUST для каждой реально используемой зависимости выполнять CVE-проверку через открытые базы  
   - `scanner.py: main()` (цикл по `analysis.used_dependencies`)  
   - `scanner/cve_provider_osv.py: OsvcveProvider.find_cve_findings()`

5) MUST для каждой реально используемой зависимости загружать код из PyPI и выполнять сигнатурные проверки  
   - `scanner.py: main()` (вызов `SemgrepRulesEngine.scan_package()` при наличии точной версии)  
   - `scanner/rules_engine_semgrep.py: SemgrepRulesEngine.scan_package()`  
   - `scanner/rules_engine_semgrep.py: SemgrepRulesEngine._download_and_extract_sdist()`

   TODO (контракт): поведение для диапазонов версий/отсутствия точной версии.

6) MUST отдельно выявлять зависимости, указанные в файле, но не используемые  
   - `scanner/ast_engine.py: ASTEngine.analyze_imports()` (поле `unused_declared_dependencies`)  
   - `scanner.py: _make_unused_dependency_finding()`

7) MUST отдельно выявлять импорты без декларации  
   - `scanner/ast_engine.py: ASTEngine.analyze_imports()` (поле `undeclared_imports`, исключая stdlib)  
   - `scanner.py: _make_undeclared_import_finding()`

8) MUST формировать отчёт Markdown и JSON с находками, критичностью, причиной, рекомендацией и агрегацией по категориям  
   - `scanner/reporter.py: Reporter.write_markdown_report()`  
   - `scanner/reporter.py: Reporter.write_json_report()`  
   - `scanner/reporter.py: Reporter._group_findings()`

9) MUST работать в режиме чтения и не изменять файлы проекта  
   - Все модули используют только чтение файлов проекта; запись идёт только в `./scanner_reports`  
   - `scanner/reporter.py: Reporter.default_out_dir()` (вне проекта)

10) MUST запускаться на Python 3.8+ без тяжёлых зависимостей  
   - Код совместим с Python 3.8+ (типизация, `tomli` для pyproject)  
   - Встроенные зависимости минимальны: стандартная библиотека + `tomli`

