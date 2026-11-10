"""
Motor de analisis estatico de ghascan.

No ejecuta workflows. Aplica reglas de deteccion y de eliminacion de falsos
positivos sobre el texto YAML y devuelve un Finding con veredicto y PoC.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import patterns as P
from . import workflow as W


# --------------------------------------------------------------------------
# Clasificacion de expresiones
# --------------------------------------------------------------------------

def clean_expr(expr: str) -> str:
    e = expr.strip()
    if e.startswith('${{') and e.endswith('}}'):
        e = e[3:-2].strip()
    return e


def _is_boolean(e: str) -> bool:
    if e.startswith('!'):
        return True
    if re.match(r'^(contains|startsWith|endsWith|success|failure|cancelled|always)\s*\(', e):
        return True
    if '==' in e or '!=' in e:
        # comparacion: el resultado es booleano, no se interpola texto
        if not re.search(r'format\s*\(', e):
            return True
    return False


def classify_expression(expr: str) -> str:
    e = clean_expr(expr)
    if not e:
        return 'NO_CONTROL'
    if _is_boolean(e):
        return 'NO_CONTROL'

    has_tojson = 'toJSON(' in e
    tokens = re.findall(r'github\.[A-Za-z0-9_.\[\]]+', e)
    tokens += re.findall(r'\binputs\.[A-Za-z0-9_-]+', e)
    if not tokens and 'github.' not in e and 'inputs.' not in e:
        return 'NO_CONTROL'

    levels: List[str] = []
    for tok in tokens:
        tok = tok.rstrip('.')
        if re.fullmatch(r'github\.event\.inputs\.[\w-]+|inputs\.[\w-]+', tok):
            levels.append('DISPATCH_INPUT')
            continue
        if tok in P.FULL_CONTROL:
            levels.append('FULL_CONTROL')
            continue
        if tok in P.PARENT_FULL_CONTROL:
            levels.append('FULL_CONTROL' if has_tojson else 'UNKNOWN')
            continue
        if tok in P.LIMITED_CONTROL:
            levels.append('LIMITED_CONTROL')
            continue
        if tok in P.NO_CONTROL:
            levels.append('NO_CONTROL')
            continue
        if any(tok.startswith(pref) for pref in P.NO_CONTROL_PREFIXES):
            levels.append('NO_CONTROL')
            continue
        base = tok.rsplit('.', 1)[0]
        if base in P.FULL_CONTROL or any(tok.startswith(fc + '.') for fc in P.FULL_CONTROL):
            levels.append('FULL_CONTROL')
            continue
        if base in P.PARENT_FULL_CONTROL and has_tojson:
            levels.append('FULL_CONTROL')
            continue
        if tok.startswith('github.event.pull_request.head.repo.'):
            levels.append('LIMITED_CONTROL')
            continue
        if tok.startswith('github.event.'):
            levels.append('UNKNOWN')
            continue
        levels.append('NO_CONTROL')

    for level in ('FULL_CONTROL', 'UNKNOWN', 'DISPATCH_INPUT', 'LIMITED_CONTROL'):
        if level in levels:
            return level
    return 'NO_CONTROL'


def trigger_openness(triggers: Dict[str, Optional[list]], expr: str):
    required = None
    e = clean_expr(expr)
    for key, trigs in P.EXPR_TRIGGERS.items():
        if key in e:
            required = trigs
            break
    if required is None:
        required = list(triggers.keys())
    best, best_trigger = 'INTERNAL', ''
    for tn in required:
        if tn not in triggers:
            continue
        types = triggers[tn]
        if not types:
            if tn in P.OPEN_TYPES:
                return 'OPEN', tn
            if tn in P.RESTRICTED_TYPES and best != 'OPEN':
                best, best_trigger = 'RESTRICTED', tn
            elif tn == 'pull_request' and best == 'INTERNAL':
                best, best_trigger = 'PR_FORK', tn
            elif tn == 'workflow_dispatch' and best == 'INTERNAL':
                best, best_trigger = 'DISPATCH', tn
        else:
            ts = set(types)
            if tn in P.OPEN_TYPES and ts & P.OPEN_TYPES[tn]:
                return 'OPEN', tn
            if tn in P.RESTRICTED_TYPES and ts & P.RESTRICTED_TYPES[tn] and best != 'OPEN':
                best, best_trigger = 'RESTRICTED', tn
            if tn == 'pull_request' and best == 'INTERNAL':
                best, best_trigger = 'PR_FORK', tn
    if 'workflow_call' in triggers and best == 'INTERNAL':
        best, best_trigger = 'UNKNOWN_CALLER', 'workflow_call'
    return best, best_trigger


# --------------------------------------------------------------------------
# Escaneo de expresiones en contextos ejecutables
# --------------------------------------------------------------------------

def scan_expressions(content: str) -> List[dict]:
    lines = content.split('\n')
    ctx = W.build_context_map(lines)
    out: List[dict] = []
    seen = set()
    for i, line in enumerate(lines):
        c = ctx.get(i)
        if c not in ('run', 'script'):
            continue
        if W.is_comment(line):
            continue
        for m in W.EXPR_RE.finditer(line):
            expr = m.group(0)
            level = classify_expression(expr)
            if level == 'NO_CONTROL':
                continue
            key = (i, expr)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                'line': i + 1,
                'expression': expr,
                'content': line.strip(),
                'context': c,
                'control': level,
            })
    return out


# --------------------------------------------------------------------------
# Modelo
# --------------------------------------------------------------------------

@dataclass
class ExprVuln:
    line: int
    expression: str
    content: str = ''
    context: str = 'run'
    control: str = 'UNKNOWN'
    status: str = 'ACTIVE'
    rule: str = ''
    reason: str = ''
    heredoc: bool = False
    echo_only: bool = False

    def to_dict(self) -> dict:
        return {
            'line': self.line,
            'expression': self.expression,
            'content': self.content,
            'context': self.context,
            'control': self.control,
            'status': self.status,
            'rule': self.rule,
            'reason': self.reason,
            'heredoc': self.heredoc,
            'echo_only': self.echo_only,
        }


@dataclass
class Finding:
    repo: str
    path: str
    source_url: str = ''
    triggers: Dict[str, Optional[list]] = field(default_factory=dict)
    permissions: Dict[str, str] = field(default_factory=dict)
    secrets: List[str] = field(default_factory=list)
    has_github_token: bool = False
    active: List[ExprVuln] = field(default_factory=list)
    eliminated: List[ExprVuln] = field(default_factory=list)
    env_injections: List[dict] = field(default_factory=list)
    verdict: str = 'FALSE_POSITIVE'
    score: float = 0.0
    trigger_openness: str = 'INTERNAL'
    who_can_trigger: str = ''
    has_auth_gate: bool = False
    auth_details: str = ''
    merged_only: bool = False
    has_write_permissions: bool = False
    explanation: str = ''
    poc: str = ''
    remediation: str = ''
    content_hash: str = ''
    dork_query: str = ''

    def to_dict(self, include_eliminated: bool = True) -> dict:
        d = {
            'repo': self.repo,
            'path': self.path,
            'source_url': self.source_url,
            'verdict': self.verdict,
            'score': self.score,
            'triggers': list(self.triggers.keys()),
            'permissions': self.permissions,
            'secrets': self.secrets,
            'has_github_token': self.has_github_token,
            'trigger_openness': self.trigger_openness,
            'who_can_trigger': self.who_can_trigger,
            'has_auth_gate': self.has_auth_gate,
            'auth_details': self.auth_details,
            'merged_only': self.merged_only,
            'has_write_permissions': self.has_write_permissions,
            'active': [v.to_dict() for v in self.active],
            'env_injections': self.env_injections,
            'explanation': self.explanation,
            'poc': self.poc,
            'remediation': self.remediation,
            'content_hash': self.content_hash,
            'dork_query': self.dork_query,
        }
        if include_eliminated:
            d['eliminated'] = [v.to_dict() for v in self.eliminated]
        return d


# --------------------------------------------------------------------------
# Reglas
# --------------------------------------------------------------------------

def _job_gate(lines: List[str], idx: int) -> List[str]:
    start, _ = W.job_for_line(lines, idx)
    if start < 0:
        return []
    end = len(lines)
    for s, e, _n in W.job_ranges(lines):
        if s == start:
            end = e
            break
    gates = []
    for i in range(start, min(end, start + 40)):
        m = re.match(r'^\s*(?:-\s+)?if:\s*(.+)$', lines[i])
        if m:
            gates.append(m.group(1).strip())
    return gates


def _step_gate(lines: List[str], idx: int) -> List[str]:
    s = W.find_step_for_line(lines, idx)
    if s < 0:
        return []
    _, e = W.step_range(lines, s)
    gates = []
    for i in range(s, min(e, s + 20)):
        m = re.match(r'^\s*(?:-\s+)?if:\s*(.+)$', lines[i])
        if m:
            gates.append(m.group(1).strip())
    return gates


def _exact_match_gate(lines: List[str], idx: int, expr: str) -> Optional[str]:
    """Gate del tipo `if: github.event.label.name == 'safe'`."""
    e = clean_expr(expr)
    keys = re.findall(r'github\.[A-Za-z0-9_.]+', e)
    if not keys:
        return None
    key = keys[0]
    for gate in _job_gate(lines, idx) + _step_gate(lines, idx):
        if key not in gate:
            continue
        if re.search(re.escape(key) + r'\s*(==|!=)\s*[\'\"][^\'\"]+[\'\"]', gate):
            return gate
        if re.search(r'[\'\"][^\'\"]+[\'\"]\s*(==|!=)\s*' + re.escape(key), gate):
            return gate
    return None


def _in_quoted_heredoc(lines: List[str], idx: int) -> bool:
    for j in range(idx, max(-1, idx - 80), -1):
        m = re.search(r'<<-?\s*([\'"]?)([A-Za-z_][A-Za-z0-9_]*)\1', lines[j])
        if not m:
            continue
        delimiter, quoted = m.group(2), bool(m.group(1))
        if any(lines[k].strip() == delimiter for k in range(j + 1, idx)):
            continue
        return quoted
    return False


def _is_echo_only(line: str) -> bool:
    return bool(re.match(r'^\s*(echo|printf|Write-Output|Write-Host)\b', line))


def _merged_only(lines: List[str], idx: int) -> bool:
    for gate in _job_gate(lines, idx) + _step_gate(lines, idx):
        if re.search(r'merged\s*==\s*true|merged\s*==\s*\'true\'', gate, re.I):
            return True
    return False


# --------------------------------------------------------------------------
# PoC
# --------------------------------------------------------------------------

def _payload_for(expr: str, trigger: str, control: str, script: bool) -> str:
    e = clean_expr(expr)
    if script:
        return '");console.log("GHA_POC");//'
    if control == 'LIMITED_CONTROL':
        return 'x$(echo GHA_POC)'
    return '$(echo GHA_POC)'


def _how_to_trigger(trigger: str) -> str:
    table = {
        'issues': 'Abrir un issue (o editar el titulo/cuerpo) en el repositorio.',
        'issue_comment': 'Comentar en un issue o PR del repositorio.',
        'pull_request_target': 'Hacer fork, abrir un PR contra el repo y editar el titulo/cuerpo del PR.',
        'pull_request': 'Hacer fork y abrir un PR (los secrets no estan disponibles en forks).',
        'pull_request_review': 'Enviar un review con un comentario en un PR.',
        'pull_request_review_comment': 'Comentar sobre una linea del diff de un PR.',
        'discussion': 'Crear o editar una discusion.',
        'discussion_comment': 'Comentar en una discusion.',
        'workflow_dispatch': 'Requiere permisos de escritura: ejecutar el workflow a mano.',
        'workflow_call': 'Depende del workflow que llama: revisar el caller.',
    }
    return table.get(trigger, 'Disparar el evento %s con contenido controlado.' % trigger)


def build_poc(f: Finding) -> str:
    if not f.active and not f.env_injections:
        return ''
    trigger = f.active[0].expression if f.active else ''
    trigger_name = next(iter(f.triggers), 'issues')
    lines: List[str] = []
    lines.append('PoC benigno (no exfiltra nada, solo imprime una marca):')
    lines.append('')
    lines.append('1) ' + _how_to_trigger(trigger_name))
    lines.append('')
    if f.env_injections:
        inj = f.env_injections[0]
        lines.append('2) En el contenido controlado incluir una linea como:')
        lines.append('')
        lines.append('   GHA_POC=1')
        lines.append('')
        lines.append('   El workflow escribe ese valor en $%s (linea %d), por lo que' % (inj['target'], inj['line']))
        lines.append('   los pasos siguientes heredan la variable. Impacto: manipulacion de')
        lines.append('   entorno, secuestro de PATH/NODE_OPTIONS y ejecucion en pasos posteriores.')
        return '\n'.join(lines)

    v = f.active[0]
    payload = _payload_for(v.expression, trigger_name, v.control, v.context == 'script')
    lines.append('2) Usar este valor:')
    lines.append('')
    lines.append('   ' + payload)
    lines.append('')
    lines.append('3) El workflow interpola la expresion en un contexto ejecutable:')
    lines.append('')
    lines.append('   linea %d: %s' % (v.line, v.content[:300]))
    lines.append('')
    lines.append('4) Resultado esperado: la salida contiene GHA_POC. En un caso real,')
    lines.append('   el mismo patron permite ejecutar comandos con los permisos del runner')
    lines.append('   y leer los secrets disponibles para el job.')
    if f.merged_only:
        lines.append('')
        lines.append('Nota: el job tiene un gate merged == true. El PoC se dispara despues')
        lines.append('del merge, cuando un maintainer acepta el PR.')
    return '\n'.join(lines)


REMEDIATION = """\
Pasar el dato por una variable de entorno intermedia y citarlo:

  env:
    TITLE: ${{ github.event.issue.title }}
  run: |
    printf '%s\\n' "$TITLE"

Reglas:
  1. Nunca interpolar ${{ github.event.* }} directamente en run: o script:.
  2. Usar env: como frontera y citar siempre la variable ("$TITLE").
  3. Evitar pull_request_target con checkout del codigo del PR.
  4. Aplicar permisos minimos (permissions: contents: read).
  5. Validar el dato con una allowlist antes de usarlo.
"""


# --------------------------------------------------------------------------
# Analisis principal
# --------------------------------------------------------------------------

def analyze_text(content: str, path: str = '', repo: str = '',
                 source_url: str = '', dork_query: str = '') -> Finding:
    f = Finding(repo=repo, path=path, source_url=source_url, dork_query=dork_query)
    lines = content.split('\n')
    f.triggers = W.parse_triggers(content)
    f.permissions = W.parse_permissions(content)
    f.secrets, f.has_github_token = W.find_secrets(content)
    f.content_hash = hashlib.sha256(content.encode('utf-8', 'replace')).hexdigest()[:16]
    f.has_write_permissions = (
        not f.permissions
        or f.permissions.get('_workflow') == 'write-all'
        or any(v == 'write' for k, v in f.permissions.items() if k != '_workflow')
    )

    # Expresiones en run:/script:
    raw = scan_expressions(content)
    for item in raw:
        v = ExprVuln(
            line=item['line'],
            expression=item['expression'],
            content=item['content'],
            context=item['context'],
            control=item['control'],
        )
        idx = v.line - 1

        if W.is_comment(lines[idx]):
            v.status, v.rule, v.reason = 'ELIMINATED', 'R1_COMMENT', 'Linea comentada'
            f.eliminated.append(v)
            continue

        job_start, job_name = W.job_for_line(lines, idx)
        if job_start >= 0:
            job_end = next((e for s, e, _n in W.job_ranges(lines) if s == job_start), len(lines))
            disabled, why = W.is_disabled(lines, job_start, job_end)
            if disabled:
                v.status, v.rule = 'ELIMINATED', 'R2_JOB_DISABLED'
                v.reason = 'Job "%s" desactivado: %s' % (job_name, why)
                f.eliminated.append(v)
                continue

        step_start = W.find_step_for_line(lines, idx)
        if step_start >= 0:
            _s, step_end = W.step_range(lines, step_start)
            disabled, why = W.is_disabled(lines, step_start, step_end)
            if disabled:
                v.status, v.rule = 'ELIMINATED', 'R3_STEP_DISABLED'
                v.reason = 'Step desactivado: %s' % why
                f.eliminated.append(v)
                continue

        required = None
        e = clean_expr(v.expression)
        for key, trigs in P.EXPR_TRIGGERS.items():
            if key in e:
                required = trigs
                break
        if required is not None and 'workflow_call' not in f.triggers:
            if not any(rt in f.triggers for rt in required):
                v.status, v.rule = 'ELIMINATED', 'R4_TRIGGER'
                v.reason = 'Requiere %s y el workflow tiene %s' % (required, list(f.triggers.keys()))
                f.eliminated.append(v)
                continue

        gate = _exact_match_gate(lines, idx, v.expression)
        if gate:
            v.status, v.rule = 'ELIMINATED', 'R7B_EXACT_GATE'
            v.reason = 'Gate de match exacto: %s' % gate
            f.eliminated.append(v)
            continue

        v.heredoc = _in_quoted_heredoc(lines, idx)
        v.echo_only = _is_echo_only(lines[idx])
        if v.heredoc:
            v.status, v.rule = 'ELIMINATED', 'R8_HEREDOC'
            v.reason = 'Dentro de heredoc citado: el shell no expande la expresion'
            f.eliminated.append(v)
            continue

        v.status = 'ACTIVE'
        v.reason = 'Contexto %s alcanzable y sin gate' % v.context
        f.active.append(v)

    # GITHUB_ENV / GITHUB_PATH injection
    for inj in W.find_env_injections(content, lines, W.build_context_map(lines)):
        level = classify_expression(inj['expression'])
        if level in ('FULL_CONTROL', 'LIMITED_CONTROL', 'UNKNOWN'):
            inj['control'] = level
            f.env_injections.append(inj)

    # Gate de autenticacion
    if f.active:
        idx0 = f.active[0].line - 1
        js, _jn = W.job_for_line(lines, idx0)
        je = next((e for s, e, _n in W.job_ranges(lines) if s == js), len(lines))
        gates = W.check_auth_gate(lines, js, je)
        f.has_auth_gate = bool(gates)
        f.auth_details = '; '.join(gates[:3])
        f.merged_only = _merged_only(lines, idx0)

    # Sin hallazgos: falso positivo
    if not f.active and not f.env_injections:
        f.verdict = 'FALSE_POSITIVE'
        if f.eliminated:
            f.explanation = 'Todas las expresiones fueron eliminadas: ' + '; '.join(
                '%s (%s)' % (v.rule, v.reason) for v in f.eliminated[:3])
        else:
            f.explanation = ('Sin expresiones peligrosas en contextos ejecutables '
                             '(run:/script:). Pueden existir en env:, name: o with:, '
                             'donde no se interpolan como codigo.')
        f.poc = ''
        return f

    # Apertura del trigger
    best_open, best_trigger = 'INTERNAL', ''
    for v in f.active:
        o, t = trigger_openness(f.triggers, v.expression)
        if o == 'OPEN':
            best_open, best_trigger = 'OPEN', t
            break
        if o in ('RESTRICTED', 'PR_FORK', 'UNKNOWN_CALLER', 'DISPATCH') and best_open == 'INTERNAL':
            best_open, best_trigger = o, t
    if f.env_injections and not f.active:
        o, t = trigger_openness(f.triggers, f.env_injections[0]['expression'])
        best_open = o
        best_trigger = t
    f.trigger_openness = best_open
    f.who_can_trigger = P.OPENNESS_DESC.get(best_open, '{trigger}').format(
        trigger=best_trigger or next(iter(f.triggers), 'evento'))

    controls = [v.control for v in f.active] or [i['control'] for i in f.env_injections]
    has_full = any(c in ('FULL_CONTROL', 'UNKNOWN') for c in controls)
    has_limited = any(c == 'LIMITED_CONTROL' for c in controls)
    has_dispatch = any(c == 'DISPATCH_INPUT' for c in controls)

    # Verdicto
    if f.env_injections:
        if best_open == 'OPEN' and has_full:
            f.verdict, f.score = 'CRITICAL', 9.1
        elif best_open == 'OPEN':
            f.verdict, f.score = 'HIGH', 8.0
        else:
            f.verdict, f.score = 'MEDIUM', 6.1
    elif has_full:
        if best_open == 'OPEN':
            if f.secrets or f.has_write_permissions:
                f.verdict, f.score = 'CRITICAL', 9.1
            else:
                f.verdict, f.score = 'HIGH', 7.8
        elif best_open in ('RESTRICTED', 'PR_FORK', 'UNKNOWN_CALLER'):
            f.verdict, f.score = ('HIGH', 7.4) if (f.secrets or f.has_write_permissions) else ('MEDIUM', 6.2)
        elif best_open == 'DISPATCH':
            f.verdict, f.score = ('MEDIUM', 5.5) if f.secrets else ('LOW', 3.1)
        else:
            f.verdict, f.score = 'LOW', 2.5
    elif has_limited:
        if best_open == 'OPEN' and (f.secrets or f.has_write_permissions):
            f.verdict, f.score = 'HIGH', 7.5
        else:
            f.verdict, f.score = 'MEDIUM', 5.8
    elif has_dispatch:
        f.verdict, f.score = 'MEDIUM', 5.2
    else:
        f.verdict, f.score = 'LOW', 2.0

    if f.has_auth_gate:
        # No elimina: un gate de actor puede ser bypasseable, pero baja confianza.
        f.score = max(0.0, f.score - 0.8)

    details = []
    if f.active:
        v = f.active[0]
        details.append('Expresion %s (control %s) interpolada en %s:, linea %d%s.' % (
            v.expression, P.ctrl_label(v.control), v.context, v.line,
            ', solo echo' if v.echo_only else ''))
        if v.echo_only:
            details.append('Aunque sea echo, $() se expande antes de ejecutar echo.')
    if f.env_injections:
        details.append('Escritura de contenido controlado en $%s (linea %d).' % (
            f.env_injections[0]['target'], f.env_injections[0]['line']))
    details.append('Disparador: %s.' % f.who_can_trigger)
    if f.secrets:
        details.append('Secrets accesibles: %s.' % ', '.join(f.secrets[:6]))
    if f.has_write_permissions:
        details.append('GITHUB_TOKEN con permisos de escritura.')
    if f.merged_only:
        details.append('Gate merged == true: explotable despues del merge.')
    if f.has_auth_gate:
        details.append('Gate de autenticacion presente (%s); revisar si es bypasseable.' % f.auth_details)
    f.explanation = ' '.join(details)
    f.poc = build_poc(f)
    f.remediation = REMEDIATION
    return f


def analyze_file(path: str, repo: str = '') -> Finding:
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        content = fh.read()
    return analyze_text(content, path=path, repo=repo)
