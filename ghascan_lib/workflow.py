"""
Parseo y utilidades sobre workflows de GitHub Actions.

Todo el analisis es estatico y local: no ejecuta nada del workflow.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

try:
    import yaml  # PyYAML
except Exception:  # pragma: no cover - se informa en el CLI
    yaml = None


KEY_RE = re.compile(r'^(\s*)(?:-\s+)?([A-Za-z0-9_.\-]+):\s*(.*)$')
EXPR_RE = re.compile(r'\$\{\{.*?\}\}')
INLINE_EXPR_RE = re.compile(r'\$\{\{\s*([^}]+?)\s*\}\}')
BLOCK_SCALAR_RE = re.compile(r'^[|>][+-]?\d*\s*$')
ENV_INJECT_PAT = re.compile(r'>>\s*"?\$(GITHUB_ENV|GITHUB_PATH)"?')


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(' '))


def is_comment(line: str) -> bool:
    return line.strip().startswith('#')


def build_context_map(lines: List[str]) -> Dict[int, str]:
    """Mapea indice de linea -> contexto ('run', 'script', 'env', 'with', 'name', ...).

    Para las lineas de contenido de un bloque escalar (run: |) devuelve el nombre
    de la clave padre. Para el resto, la clave de la linea o la del ancestro mas
    cercano.
    """
    ctx: Dict[int, str] = {}
    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        m = KEY_RE.match(line)
        if m and m.group(3).strip() and not BLOCK_SCALAR_RE.match(m.group(3).strip()):
            ctx[idx] = m.group(2)
            continue
        if m and BLOCK_SCALAR_RE.match(m.group(3).strip()):
            ctx[idx] = m.group(2)
            continue
        # linea de contenido o item de lista: buscar ancestro por indentacion
        cur_indent = indent_of(line)
        found = None
        for j in range(idx - 1, -1, -1):
            prev = lines[j]
            if not prev.strip():
                continue
            if indent_of(prev) < cur_indent:
                pm = KEY_RE.match(prev)
                if pm:
                    found = pm.group(2)
                    break
                if prev.strip().startswith('- '):
                    # item de lista: seguir subiendo
                    found = found or 'list'
                    continue
                break
        ctx[idx] = found or 'unknown'
    return ctx


def _doc_from_yaml(content: str):
    if yaml is None:
        return None
    try:
        doc = yaml.safe_load(content)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    # YAML 1.1 convierte la clave `on` en True
    if True in doc and 'on' not in doc:
        doc['on'] = doc.pop(True)
    return doc


def parse_triggers(content: str) -> Dict[str, Optional[list]]:
    doc = _doc_from_yaml(content)
    if doc is not None and 'on' in doc:
        on = doc.get('on')
        if isinstance(on, str):
            return {on: None}
        if isinstance(on, list):
            return {str(x): None for x in on}
        if isinstance(on, dict):
            out = {}
            for k, v in on.items():
                if isinstance(v, dict):
                    types = v.get('types')
                    out[str(k)] = list(types) if isinstance(types, list) else None
                elif isinstance(v, list):
                    out[str(k)] = list(v)
                else:
                    out[str(k)] = None
            return out
    # Fallback por regex
    out: Dict[str, Optional[list]] = {}
    m = re.search(r'^on:\s*(\[.*?\]|\S+)\s*$', content, re.M)
    if m:
        raw = m.group(1).strip()
        if raw.startswith('['):
            for t in raw.strip('[]').split(','):
                if t.strip():
                    out[t.strip().strip("'\"")] = None
        else:
            out[raw.strip("'\"")] = None
        return out
    block = re.search(r'^on:\s*\n((?:[ \t]+.*\n)+)', content, re.M)
    if block:
        for line in block.group(1).splitlines():
            km = re.match(r'^  ([A-Za-z0-9_\-]+):', line)
            if km:
                out[km.group(1)] = None
    return out


def parse_permissions(content: str) -> Dict[str, str]:
    doc = _doc_from_yaml(content)
    perms: Dict[str, str] = {}
    if doc is not None:
        raw = doc.get('permissions')
        if raw == 'write-all':
            perms['_workflow'] = 'write-all'
        elif raw == 'read-all':
            perms['_workflow'] = 'read-all'
        elif isinstance(raw, dict):
            for k, v in raw.items():
                perms[str(k)] = str(v)
        return perms
    m = re.search(r'^permissions:\s*(\S+)\s*$', content, re.M)
    if m:
        perms['_workflow'] = m.group(1)
    return perms


def find_secrets(content: str) -> Tuple[List[str], bool]:
    names = set()
    for m in re.finditer(r'secrets\.([A-Za-z_][A-Za-z0-9_]*)', content):
        names.add(m.group(1))
    has_github_token = bool(re.search(r'secrets\.GITHUB_TOKEN', content))
    if re.search(r'secrets:\s*inherit', content):
        names.add('*inherit*')
    # claves definidas en on.workflow_call.secrets
    for m in re.finditer(r'^\s{4,}([A-Za-z_][A-Za-z0-9_]*):\s*\n\s+description:', content, re.M):
        names.add(m.group(1))
    return sorted(names), has_github_token


def job_ranges(lines: List[str]) -> List[Tuple[int, int, str]]:
    """Devuelve [(inicio, fin, nombre)] de cada job."""
    jobs_line = None
    for i, line in enumerate(lines):
        if re.match(r'^jobs:\s*$', line):
            jobs_line = i
            break
    if jobs_line is None:
        return []
    candidates: List[Tuple[int, str, int]] = []
    for i in range(jobs_line + 1, len(lines)):
        line = lines[i]
        if not line.strip() or is_comment(line):
            continue
        if indent_of(line) == 0:
            break
        m = re.match(r'^(\s{2,6})([A-Za-z0-9_.\-]+):\s*(?:#.*)?$', line)
        if m:
            candidates.append((i, m.group(2), len(m.group(1))))
    if not candidates:
        return []
    job_indent = min(c[2] for c in candidates)
    starts = [(i, name) for i, name, ind in candidates if ind == job_indent]
    out = []
    for n, (start, name) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
        out.append((start, end, name))
    return out


def job_for_line(lines: List[str], idx: int) -> Tuple[int, str]:
    best = (-1, '')
    for start, end, name in job_ranges(lines):
        if start <= idx < end and start > best[0]:
            best = (start, name)
    return best


def find_step_for_line(lines: List[str], idx: int) -> int:
    """Indice de la linea que inicia el step que contiene idx (-1 si no hay)."""
    if not (0 <= idx < len(lines)):
        return -1
    cur_indent = indent_of(lines[idx])
    for j in range(idx, -1, -1):
        s = lines[j]
        if re.match(r'^\s*-\s+', s) and indent_of(s) <= cur_indent:
            return j
        if re.match(r'^\s*steps:\s*$', s):
            return -1
    return -1


def step_range(lines: List[str], start_idx: int) -> Tuple[int, int]:
    """Rango del step que empieza en start_idx."""
    start = start_idx
    if start < 0:
        return -1, -1
    base_indent = indent_of(lines[start])
    end = len(lines)
    for j in range(start + 1, len(lines)):
        s = lines[j]
        if not s.strip():
            continue
        if re.match(r'^\s*-\s+', s) and indent_of(s) <= base_indent:
            end = j
            break
    return start, end


def find_env_injections(content: str, lines: List[str],
                        ctx_map: Dict[int, str]) -> List[dict]:
    out = []
    for i, line in enumerate(lines):
        m = ENV_INJECT_PAT.search(line)
        if not m:
            continue
        target = m.group(1)
        expr = None
        for j in range(max(0, i - 6), i + 1):
            em = EXPR_RE.search(lines[j])
            if em:
                expr = em.group(0)
                break
        if not expr:
            continue
        out.append({
            'line': i + 1,
            'target': target,
            'expression': expr,
            'content': line.strip(),
            'context': ctx_map.get(i, 'run'),
        })
    return out


def is_disabled(lines: List[str], start: int, end: int) -> Tuple[bool, str]:
    """True si el job/step tiene un if: que lo desactiva."""
    if start < 0:
        return False, ''
    for i in range(max(0, start), min(len(lines), end)):
        line = lines[i]
        if re.match(r'^\s*(?:-\s+)?if:\s*false\s*$', line, re.I):
            return True, line.strip()
        if re.search(r'if:.*\$\{\{\s*false\s*\}\}', line, re.I):
            return True, line.strip()
        if re.search(r'if:.*always\(\)\s*&&\s*false', line, re.I):
            return True, line.strip()
        if re.search(r'if:.*true\s*&&\s*false', line, re.I):
            return True, line.strip()
        if re.search(r'if:.*false\s*&&', line, re.I):
            return True, line.strip()
    return False, ''


def check_auth_gate(lines: List[str], start: int, end: int) -> List[str]:
    out = []
    for i in range(max(0, start), min(len(lines), end)):
        for pat in _AUTH_PATS:
            if pat.search(lines[i]):
                out.append(lines[i].strip())
                break
    return out

_AUTH_PATS = [
    re.compile(r"author_association\s*(==|!=)\s*'[A-Z_]+'", re.I),
    re.compile(r'get-user-teams-membership', re.I),
    re.compile(r'check-user-membership', re.I),
    re.compile(r"github\.actor\s*==\s*'[^']+'"),
    re.compile(r"github\.triggering_actor\s*==\s*'[^']+'"),
    re.compile(r'slash-command-dispatch', re.I),
    re.compile(r"github\.repository_owner\s*==\s*'[^']+'"),
    re.compile(r"github\.repository\s*==\s*'[^/]+/[^']+'"),
    re.compile(r"contains\(\s*'[^']*'\s*,\s*github\.(actor|triggering_actor)"),
]
