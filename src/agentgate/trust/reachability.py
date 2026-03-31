from __future__ import annotations

import ast
import re
import shlex
from pathlib import Path

_ENTRYPOINT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\buvicorn\s+([A-Za-z_][\w.]*):"),
    re.compile(r"\bgunicorn\s+([A-Za-z_][\w.]*)\:"),
    re.compile(r"\bpython3?(?:\.\d+)?\s+-m\s+([A-Za-z_][\w.]*)"),
    re.compile(r"\bpython3?(?:\.\d+)?\s+([A-Za-z0-9_./-]+\.py)"),
)
_DYNAMIC_IMPORT_CALLS = {
    "import_module",
    "__import__",
    "entry_points",
    "iter_entry_points",
}
_DYNAMIC_TARGET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"importlib\.import_module\(\s*['\"]([A-Za-z_][\w.]*)['\"]"),
    re.compile(r"__import__\(\s*['\"]([A-Za-z_][\w.]*)['\"]"),
)


def parse_entrypoint_module(entrypoint: str) -> list[str]:
    """Extract Python module names from a Docker CMD/ENTRYPOINT string."""

    modules: list[str] = []
    for command in re.split(r"\s*(?:&&|\|\||;)\s*", entrypoint.strip()):
        if not command:
            continue
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
        if not tokens:
            continue
        for module in _parse_command_tokens(tokens):
            if module and module not in modules:
                modules.append(module)
    return modules


def walk_imports(source_dir: Path, entry_modules: list[str]) -> set[str]:
    """Walk local import chains from the provided entry modules."""

    source_root = source_dir.resolve()
    module_map = _build_module_map(source_root)
    reached: set[str] = set()
    queue = list(entry_modules)

    while queue:
        module_name = queue.pop()
        if module_name in reached:
            continue
        reached.add(module_name)

        path = module_map.get(module_name)
        if path is None:
            continue

        text = _read_text(source_root / path)
        if not text:
            continue

        for imported in _extract_import_targets(text, module_name, path):
            if imported in module_map and imported not in reached:
                queue.append(imported)

    return reached


def build_reachability(source_dir: Path, entrypoint: str) -> dict[Path, str]:
    """Classify all Python files as on_execution_path, not_reached, or unknown."""

    source_root = source_dir.resolve()
    module_map = _build_module_map(source_root)
    entry_modules = parse_entrypoint_module(entrypoint)
    all_paths = sorted(module_map.values())

    if not entry_modules:
        return {path: "unknown" for path in all_paths}

    reached = walk_imports(source_root, entry_modules)
    dynamic_targets = _collect_dynamic_targets(source_root, module_map)
    dynamic_modules = _collect_dynamic_modules(source_root, module_map)

    result: dict[Path, str] = {}
    for module_name, path in module_map.items():
        if module_name in reached:
            result[path] = "on_execution_path"
        elif module_name in dynamic_targets or path in dynamic_modules:
            result[path] = "unknown"
        else:
            result[path] = "not_reached"
    return result


def _parse_command_tokens(tokens: list[str]) -> list[str]:
    modules: list[str] = []
    head = tokens[0]

    if _looks_like_python_command(head):
        module = _parse_python_tokens(tokens)
        if module:
            modules.append(module)
        return modules

    module = _parse_entrypoint_token(tokens)
    if module:
        modules.append(module)
    return modules


def _parse_python_tokens(tokens: list[str]) -> str | None:
    if "-m" in tokens:
        idx = tokens.index("-m")
        if idx + 1 < len(tokens):
            return _normalize_module_name(tokens[idx + 1])

    for token in tokens[1:]:
        if token.startswith("-"):
            continue
        if token.endswith(".py"):
            return _normalize_module_name(token)
    return None


def _parse_entrypoint_token(tokens: list[str]) -> str | None:
    for token in tokens[1:]:
        if token.startswith("-"):
            continue
        if ":" in token:
            module = token.split(":", 1)[0]
            return module.strip() or None
    return None


def _looks_like_python_command(token: str) -> bool:
    return token == "python" or token.startswith("python3")


def _normalize_module_name(value: str) -> str:
    module = value.strip()
    if module.endswith(".py"):
        module = module[:-3].replace("/", ".")
    return module.strip(".")


def _build_module_map(source_root: Path) -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    for path in sorted(source_root.rglob("*.py")):
        if not path.is_file():
            continue
        relative = path.relative_to(source_root)
        if any(part.startswith(".") for part in relative.parts):
            continue
        module_name = _module_name_for_path(relative)
        if module_name and module_name not in mapping:
            mapping[module_name] = relative
    return mapping


def _module_name_for_path(relative_path: Path) -> str | None:
    if relative_path.suffix != ".py":
        return None

    parts = list(relative_path.parts)
    if not parts:
        return None

    if relative_path.name in {"__init__.py", "__main__.py"}:
        parts = parts[:-1]
    else:
        parts[-1] = relative_path.stem

    if not parts:
        return relative_path.stem

    return ".".join(part for part in parts if part)


def _extract_import_targets(text: str, module_name: str, path: Path) -> set[str]:
    targets: set[str] = set()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return targets

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name:
                    targets.add(alias.name)
            continue

        if isinstance(node, ast.ImportFrom):
            base = _resolve_import_from(node, module_name, path)
            if base is None:
                continue
            if node.module:
                targets.add(base)
                continue
            for alias in node.names:
                if alias.name and alias.name != "*":
                    targets.add(f"{base}.{alias.name}" if base else alias.name)

    return targets


def _resolve_import_from(node: ast.ImportFrom, module_name: str, path: Path) -> str | None:
    package_parts = module_name.split(".")
    if path.name != "__init__.py":
        package_parts = package_parts[:-1]

    if node.level:
        if node.level > len(package_parts) + 1:
            return None
        base_parts = package_parts[: len(package_parts) - (node.level - 1)]
    else:
        base_parts = []

    if node.module:
        base_parts = [*base_parts, *node.module.split(".")]

    return ".".join(part for part in base_parts if part)


def _collect_dynamic_targets(source_root: Path, module_map: dict[str, Path]) -> set[str]:
    targets: set[str] = set()
    for path in module_map.values():
        text = _read_text(source_root / path)
        if not text:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = _call_name(node.func)
            if func_name not in _DYNAMIC_IMPORT_CALLS:
                continue
            if not node.args:
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                normalized = arg.value.strip().strip(".")
                if normalized:
                    targets.add(normalized)
    return targets


def _collect_dynamic_modules(source_root: Path, module_map: dict[str, Path]) -> set[Path]:
    dynamic_modules: set[Path] = set()
    for path in module_map.values():
        text = _read_text(source_root / path)
        if text and _has_dynamic_import_signals(text):
            dynamic_modules.add(path)
    return dynamic_modules


def _has_dynamic_import_signals(text: str) -> bool:
    return any(pattern.search(text) for pattern in _DYNAMIC_TARGET_PATTERNS) or any(
        token in text for token in ("importlib.metadata.entry_points", "pkg_resources.iter_entry_points")
    )


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _read_text(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""
