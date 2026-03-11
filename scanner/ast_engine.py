from __future__ import annotations

import ast
import os
import importlib.util
import sysconfig
from pathlib import Path
from typing import Dict, Iterable, Set

from .models import ASTAnalysisResult
from .parser import normalize_package_name


class ASTEngine:
    """
    Обходит проект, читает все *.py и достаёт импорты через AST.

    Классификация:
      - used_dependencies: заявлены и реально импортируются
      - unused_declared_dependencies: заявлены, но нигде не импортируются
      - undeclared_imports: импортируются, но не заявлены (и это не stdlib и не внутренний модуль)
    """

    def analyze_imports(self, project_path: Path, declared_dependencies: Dict[str, str]) -> ASTAnalysisResult:
        project_path = Path(project_path).resolve()

        declared_norm: Set[str] = {normalize_package_name(k) for k in declared_dependencies.keys()}

        internal_top_levels = self._collect_internal_top_levels(project_path)

        imported_top_levels: Set[str] = set()
        for py_file in self._iter_python_files(project_path):
            imported_top_levels.update(self._extract_top_level_imports(py_file))

        imported_norm: Set[str] = {normalize_package_name(x) for x in imported_top_levels if x}

        used_deps: Set[str] = {dep for dep in declared_norm if dep in imported_norm}
        unused_deps: Set[str] = declared_norm - used_deps

        undeclared: Set[str] = set()
        for imp in imported_top_levels:
            if not imp:
                continue

            imp_norm = normalize_package_name(imp)

            if imp_norm in declared_norm:
                continue
            if imp_norm in internal_top_levels:
                continue
            if self._is_stdlib_module(imp):
                continue

            undeclared.add(imp_norm)

        return ASTAnalysisResult(
            used_dependencies=used_deps,
            unused_declared_dependencies=unused_deps,
            undeclared_imports=undeclared,
        )

    def _iter_python_files(self, project_path: Path) -> Iterable[Path]:
        """Только Python-файлы проекта, без обхода виртуальных окружений и кешей."""
        project_path = Path(project_path).resolve()

        ignore_dirs = {
            ".git", ".hg", ".svn",
            ".idea", ".vscode",
            "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
            ".tox", ".nox",
            ".venv", "venv", "env",
            "site-packages", "dist-packages",
            "build", "dist",
        }

        roots = [project_path]
        src = project_path / "src"
        if src.is_dir():
            roots.append(src)

        for root in roots:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [
                    d for d in dirnames
                    if d not in ignore_dirs and not d.startswith(".")
                ]

                for fn in filenames:
                    if not fn.endswith(".py"):
                        continue

                    p = Path(dirpath) / fn
                    if p.is_symlink():
                        continue
                    yield p

    def _extract_top_level_imports(self, py_file: Path) -> Set[str]:
        """
        Достаёт множество top-level импортов из одного .py файла.
        Например: 'requests.sessions' -> 'requests'.
        """
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return set()

        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            return set()

        imports: Set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = self._top_level(alias.name)
                    if top:
                        imports.add(top)

            elif isinstance(node, ast.ImportFrom):
                if getattr(node, "level", 0) and node.level > 0:
                    continue

                mod = node.module
                if not mod:
                    continue

                top = self._top_level(mod)
                if top:
                    imports.add(top)

        return imports

    def _top_level(self, module_name: str) -> str:
        """Берём только первую часть импорта: a.b.c -> a."""
        module_name = (module_name or "").strip()
        if not module_name:
            return ""
        return module_name.split(".", 1)[0]

    def _collect_internal_top_levels(self, project_path: Path) -> Set[str]:
        """
        Находит внутренние модули проекта:
          - файлы *.py в корне (utils.py -> utils)
          - пакеты-директории с __init__.py (myapp/__init__.py -> myapp)
        Учитывает также структуру src, если она есть.
        """
        project_path = Path(project_path).resolve()

        roots = [project_path]
        src = project_path / "src"
        if src.is_dir():
            roots.append(src)

        ignore_dirs = {
            ".git", ".hg", ".svn",
            ".idea", ".vscode",
            "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
            ".tox", ".nox",
            ".venv", "venv", "env",
            "site-packages", "dist-packages",
            "build", "dist",
        }

        internal: Set[str] = set()

        for root in roots:
            for f in root.glob("*.py"):
                if f.is_file() and not f.is_symlink():
                    internal.add(normalize_package_name(f.stem))

            for d in root.iterdir():
                if not d.is_dir():
                    continue
                if d.name in ignore_dirs or d.name.startswith("."):
                    continue
                if d.is_symlink():
                    continue

                init_py = d / "__init__.py"
                if init_py.is_file():
                    internal.add(normalize_package_name(d.name))

        return internal

    _stdlib_cache: Dict[str, bool] = {}

    def _is_stdlib_module(self, top_level: str) -> bool:
        """Пытается определить, является ли модуль частью стандартной библиотеки Python."""
        key = top_level.strip()
        if not key:
            return False

        cached = self._stdlib_cache.get(key)
        if cached is not None:
            return cached

        is_std = False

        try:
            spec = importlib.util.find_spec(key)
        except Exception:
            spec = None

        if spec is None:
            is_std = False
        else:
            origin = getattr(spec, "origin", None)
            if origin in ("built-in", "frozen"):
                is_std = True
            elif isinstance(origin, str) and origin:
                o = origin.replace("\\", "/").lower()
                if "site-packages" in o or "dist-packages" in o:
                    is_std = False
                else:
                    std_paths = self._stdlib_paths()
                    try:
                        origin_path = Path(origin).resolve()
                        is_std = any(self._is_under(origin_path, p) for p in std_paths)
                    except Exception:
                        is_std = False

        self._stdlib_cache[key] = is_std
        return is_std

    def _stdlib_paths(self) -> Set[Path]:
        """Папки стандартной библиотеки Python (stdlib)."""
        paths: Set[Path] = set()
        try:
            p = sysconfig.get_paths()
            for k in ("stdlib", "platstdlib"):
                v = p.get(k)
                if v:
                    paths.add(Path(v).resolve())
        except Exception:
            pass
        return paths

    def _is_under(self, child: Path, parent: Path) -> bool:
        """Проверка: лежит ли child внутри parent."""
        try:
            child.relative_to(parent)
            return True
        except Exception:
            return False