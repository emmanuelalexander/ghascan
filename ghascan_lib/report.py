"""
Reportes de ghascan: JSON, HTML y PDF (via Chromium/Edge headless).
"""

from __future__ import annotations

import html
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from typing import List, Optional

from . import patterns as P
from .analyze import Finding

SEV_COLORS = {
    'CRITICAL': '#b3001b',
    'HIGH': '#d9480f',
    'MEDIUM': '#b8860b',
    'LOW': '#2b6cb0',
    'AI_INJECTION': '#6b46c1',
    'FALSE_POSITIVE': '#6b7280',
    'INFO': '#4b5563',
}


def summarize(results: List[Finding], stats=None, meta: Optional[dict] = None) -> dict:
    counts = {}
    for f in results:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1
    actionable = [f for f in results if f.verdict not in ('FALSE_POSITIVE', 'INFO')]
    return {
        'generated_at': datetime.now().isoformat(timespec='seconds'),
        'tool': 'ghascan',
        'version': '1.0.0',
        'meta': meta or {},
        'stats': stats.as_dict() if stats is not None else {},
        'counts': counts,
        'total_findings': len(results),
        'actionable': len(actionable),
        'findings': [f.to_dict() for f in results],
    }


def write_json(results: List[Finding], path: str, stats=None, meta=None) -> str:
    data = summarize(results, stats, meta)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    return path


def _e(text) -> str:
    return html.escape(str(text or ''))


CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
       background: #f6f7f9; color: #111827; }
header { background: #0f172a; color: #fff; padding: 28px 32px; }
header h1 { margin: 0 0 6px; font-size: 26px; letter-spacing: .3px; }
header p { margin: 0; color: #cbd5e1; font-size: 13px; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 24px 20px 60px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 22px; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px 16px; }
.card .n { font-size: 26px; font-weight: 700; }
.card .l { font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: .5px; }
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; margin: 18px 0; }
button { border: 1px solid #d1d5db; background: #fff; border-radius: 999px; padding: 7px 14px;
         font-size: 13px; cursor: pointer; }
button.active { background: #0f172a; color: #fff; border-color: #0f172a; }
.finding { background: #fff; border: 1px solid #e5e7eb; border-left: 5px solid #6b7280;
           border-radius: 10px; margin-bottom: 14px; overflow: hidden; }
.finding summary { cursor: pointer; padding: 14px 18px; list-style: none; }
.finding summary::-webkit-details-marker { display: none; }
.row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.sev { color: #fff; font-weight: 700; font-size: 11px; letter-spacing: .6px;
       padding: 4px 9px; border-radius: 999px; text-transform: uppercase; }
.repo { font-weight: 600; font-size: 14px; }
.path { color: #4b5563; font-size: 13px; font-family: ui-monospace, Consolas, monospace; }
.meta { color: #6b7280; font-size: 12px; margin-top: 6px; }
.body { padding: 4px 18px 18px; border-top: 1px solid #f1f5f9; }
h3 { font-size: 13px; text-transform: uppercase; letter-spacing: .6px; color: #374151; margin: 18px 0 8px; }
pre { background: #0f172a; color: #e2e8f0; padding: 14px 16px; border-radius: 8px; overflow-x: auto;
      font-size: 12.5px; line-height: 1.55; white-space: pre-wrap; word-break: break-word; }
code { font-family: ui-monospace, Consolas, monospace; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
td, th { text-align: left; padding: 6px 8px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
th { color: #6b7280; font-weight: 600; font-size: 12px; text-transform: uppercase; }
a { color: #1d4ed8; }
.tag { background: #eef2ff; color: #3730a3; border-radius: 5px; padding: 2px 6px; font-size: 11.5px; }
.fp { opacity: .72; }
footer { color: #6b7280; font-size: 12px; text-align: center; margin-top: 28px; }
"""

JS = """
function filter(sev, btn) {
  document.querySelectorAll('.toolbar button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding').forEach(el => {
    const s = el.getAttribute('data-sev');
    el.style.display = (sev === 'ALL' || s === sev) ? '' : 'none';
  });
}
"""


def _finding_html(f: Finding) -> str:
    color = SEV_COLORS.get(f.verdict, '#6b7280')
    fp_class = ' fp' if f.verdict in ('FALSE_POSITIVE', 'INFO') else ''
    controls = ', '.join(sorted({v.control for v in f.active})) or '-'
    triggers = ', '.join(f.triggers.keys()) or '-'
    secrets = ', '.join(f.secrets[:8]) if f.secrets else '-'
    url = f.source_url or ''
    link = '<a href="%s" target="_blank" rel="noopener">%s</a>' % (_e(url), _e(f.repo + '/' + f.path)) if url else _e(f.repo + '/' + f.path)

    rows = []
    rows.append('<tr><th>Trigger</th><td>%s</td><th>Control</th><td>%s</td></tr>' % (_e(triggers), _e(controls)))
    rows.append('<tr><th>Quien dispara</th><td colspan="3">%s</td></tr>' % _e(f.who_can_trigger))
    rows.append('<tr><th>Secrets</th><td>%s</td><th>Permisos</th><td>%s</td></tr>' % (
        _e(secrets), 'write' if f.has_write_permissions else 'read/none'))
    if f.active:
        v = f.active[0]
        rows.append('<tr><th>Linea</th><td>%d</td><th>Expresion</th><td><code>%s</code></td></tr>' % (
            v.line, _e(v.expression)))
    if f.env_injections:
        inj = f.env_injections[0]
        rows.append('<tr><th>Env inject</th><td colspan="3"><code>$%s</code> linea %d</td></tr>' % (
            _e(inj['target']), inj['line']))
    if f.eliminated:
        reasons = '; '.join('%s: %s' % (v.rule, v.reason) for v in f.eliminated[:5])
        rows.append('<tr><th>FPs eliminados</th><td colspan="3">%s</td></tr>' % _e(reasons))

    return """
<details class="finding%s" data-sev="%s" style="border-left-color:%s">
  <summary>
    <div class="row">
      <span class="sev" style="background:%s">%s</span>
      <span class="repo">%s</span>
      <span class="path">%s</span>
    </div>
    <div class="meta">CVSS aprox %.1f &middot; %s</div>
  </summary>
  <div class="body">
    <h3>Hallazgo</h3>
    <p>%s</p>
    <table>%s</table>
    %s
    %s
    <h3>Remediacion</h3>
    <pre>%s</pre>
  </div>
</details>
""" % (
        fp_class, f.verdict, color, color, f.verdict,
        _e(f.repo), _e(f.path), f.score, link,
        _e(f.explanation), ''.join(rows),
        ('<h3>PoC</h3><pre>%s</pre>' % _e(f.poc)) if f.poc else '',
        ('<h3>Workflow (fragmento)</h3><pre>%s</pre>' % _e(f.active[0].content)) if f.active else '',
        _e(f.remediation),
    )


def render_html(results: List[Finding], stats=None, meta=None) -> str:
    data = summarize(results, stats, meta)
    counts = data['counts']
    cards = []
    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'FALSE_POSITIVE'):
        cards.append('<div class="card"><div class="n" style="color:%s">%d</div><div class="l">%s</div></div>' % (
            SEV_COLORS[sev], counts.get(sev, 0), sev.replace('_', ' ')))
    cards.append('<div class="card"><div class="n">%d</div><div class="l">Total</div></div>' % len(results))

    ordered = sorted(results, key=lambda f: (-P.SEVERITY_ORDER.get(f.verdict, 0), -f.score, f.repo, f.path))
    findings_html = '\n'.join(_finding_html(f) for f in ordered) or '<p>Sin hallazgos.</p>'
    meta_bits = []
    for k, v in (meta or {}).items():
        meta_bits.append('%s: %s' % (k, v))
    if stats is not None:
        st = stats.as_dict()
        meta_bits.append('repos=%d archivos=%d analizados=%d errores=%d' % (
            st['repos'], st['files'], st['analyzed'], st['errors']))

    buttons = ['<button class="active" onclick="filter(\'ALL\', this)">Todos</button>']
    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'FALSE_POSITIVE'):
        if counts.get(sev):
            buttons.append('<button onclick="filter(\'%s\', this)">%s (%d)</button>' % (
                sev, sev.replace('_', ' '), counts[sev]))

    return """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ghascan - reporte</title>
<style>%s</style></head>
<body>
<header>
  <h1>ghascan</h1>
  <p>GitHub Actions expression-injection scanner &middot; %s</p>
</header>
<div class="wrap">
  <div class="cards">%s</div>
  <p class="meta">%s</p>
  <div class="toolbar">%s</div>
  %s
  <footer>Reporte generado por ghascan. Los PoC son benignos: solo imprimen una marca.</footer>
</div>
<script>%s</script>
</body></html>
""" % (
        CSS, _e(data['generated_at']), ''.join(cards), _e(' | '.join(meta_bits)),
        ''.join(buttons), findings_html, JS,
    )


def write_html(results: List[Finding], path: str, stats=None, meta=None) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    html_text = render_html(results, stats, meta)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(html_text)
    return path


def _browsers() -> List[str]:
    candidates = []
    for name in ('msedge', 'chrome', 'google-chrome', 'chromium', 'chromium-browser', 'microsoft-edge'):
        p = shutil.which(name)
        if p:
            candidates.append(p)
    if sys.platform.startswith('win'):
        for p in (
            r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
            r'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
            r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
        ):
            if os.path.exists(p):
                candidates.append(p)
    elif sys.platform == 'darwin':
        for p in ('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
                  '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'):
            if os.path.exists(p):
                candidates.append(p)
    # dedupe preservando orden
    out = []
    for c in candidates:
        if c not in out:
            out.append(c)
    return out


def write_pdf(html_path: str, pdf_path: str, timeout: int = 120) -> bool:
    browsers = _browsers()
    if not browsers:
        print('[!] No encontre Chrome/Edge/Chromium para generar el PDF.', file=sys.stderr)
        print('    El HTML quedo listo; abrilo y usa Imprimir > Guardar como PDF.', file=sys.stderr)
        return False
    abs_html = os.path.abspath(html_path)
    abs_pdf = os.path.abspath(pdf_path)
    uri = 'file:///' + abs_html.replace('\\', '/').lstrip('/')
    if sys.platform.startswith('win'):
        uri = 'file:///' + abs_html.replace('\\', '/')
    last = None
    for browser in browsers:
        for flag in ('--no-pdf-header-footer', None):
            args = [browser, '--headless=new', '--disable-gpu', '--no-first-run',
                    '--disable-extensions']
            if flag:
                args.append(flag)
            args.append('--print-to-pdf=' + abs_pdf)
            args.append(uri)
            try:
                proc = subprocess.run(args, capture_output=True, timeout=timeout)
                if os.path.exists(abs_pdf) and os.path.getsize(abs_pdf) > 1000:
                    return True
                last = proc.stderr.decode('utf-8', 'replace')[:300]
            except Exception as exc:
                last = str(exc)
                break
    print('[!] No se pudo generar el PDF: %s' % (last or 'error desconocido'), file=sys.stderr)
    return False
