# Dependency Scanner 

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
python -m pip install tomli
```

## Установка Semgrep
Semgrep ставится отдельным пакетом (внешний инструмент). Пример:
```bash
python -m pip install semgrep
```

## Запуск
```bash
python scanner.py /path/to/project
```

## Отчёты
По умолчанию отчёты пишутся в директорию:

- `./scanner_reports/report.json`
- `./scanner_reports/report.md`