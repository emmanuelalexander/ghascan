#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghascan - GitHub Actions dorker + SAST.

Detecta inyeccion de expresiones en workflows (.github/workflows/*.yml):
issue/PR titles y bodies, comentarios, branch names, labels, toJSON(),
contains(), format(), GITHUB_ENV y github-script.

Uso rapido:
  ghascan demo
  ghascan selftest
  ghascan queries
  ghascan scan --local .
  ghascan scan --repo owner/repo
  ghascan scan --org mi-org --max-repos 50
  ghascan dork --queries 1,2,3 --max 50
  ghascan dork --all --org mi-org --format json,html,pdf

Los PoC son benignos: solo imprimen GHA_POC. No exfiltran datos.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from typing import Iterable, List, Optional

# Permite ejecutar `python ghascan.py` desde cualquier carpeta.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ghascan_lib import __version__          # noqa: E402
from ghascan_lib import patterns as P        # noqa: E402
from ghascan_lib import report as R          # noqa: E402
from ghascan_lib import scan as S            # noqa: E402
from ghascan_lib.analyze import analyze_text  # noqa: E402
from ghascan_lib.github import GitHubClient   # noqa: E402


# --------------------------------------------------------------------------
# Fixtures para demo/selftest (no requieren red)
# --------------------------------------------------------------------------

VULN_PRT = """\
name: pr-title
on:
  pull_request_target:
    types: [opened, edited]
permissions: write-all
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - name: echo title
        run: |
          echo "PR: ${{ github.event.pull_request.title }}"
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""

VULN_COMMENT = """\
name: comment
on:
  issue_comment:
    types: [created]
jobs:
  reply:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.comment.body }}"
"""

VULN_ENV = """\
name: env-inject
on:
  issues:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}" >> "$GITHUB_ENV"
      - run: echo "importado ${{ env.TITLE }}"
"""

VULN_SCRIPT = """\
name: script
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            console.log("${{ github.event.issue.title }}")
"""

SAFE_ENV = """\
name: safe
on:
  issues:
    types: [opened]
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: printf '%s\\n' "$TITLE"
"""

SAFE_DISABLED = """\
name: disabled
on:
  issues:
    types: [opened]
jobs:
  old:
    if: false
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
"""

SAFE_GATE = """\
name: gated
on:
  issues:
    types: [opened]
jobs:
  only-bug:
    runs-on: ubuntu-latest
    steps:
      - if: github.event.label.name == 'security'
        run: echo "${{ github.event.label.name }}"
"""

SAFE_LIMITED_TRIGGER = """\
name: push-only
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
"""

DEMO_FILES = [
    ('.github/workflows/pr-title.yml', VULN_PRT),
    ('.github/workflows/comment.yml', VULN_COMMENT),
    ('.github/workflows/env.yml', VULN_ENV),
    ('.github/workflows/script.yml', VULN_SCRIPT),
    ('.github/workflows/safe.yml', SAFE_ENV),
    ('.github/workflows/disabled.yml', SAFE_DISABLED),
    ('.github/workflows/gated.yml', SAFE_GATE),
    ('.github/workflows/push-only.yml', SAFE_LIMITED_TRIGGER),
]


# --------------------------------------------------------------------------
# Utilidades CLI
# --------------------------------------------------------------------------

def load_tokens(args) -> List[str]:
    toks: List[str] = []
    for t in args.token or []:
        toks.append(t.strip())
    if args.tokens_file:
        try:
            with open(args.tokens_file, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        toks.append(line)
        except OSError as exc:
            print('[!] No pude leer --tokens-file: %s' % exc, file=sys.stderr)
    for env in ('GITHUB_TOKENS', 'GH_TOKENS', 'GITHUB_TOKEN', 'GH_TOKEN'):
        val = os.environ.get(env)
        if not val:
            continue
        for part in val.replace(';', ',').split(','):
            if part.strip():
                toks.append(part.strip())
    out = []
    for t in toks:
        if t not in out:
            out.append(t)
    return out


def parse_ids(raw: str) -> List[int]:
    ids = []
    for part in raw.replace(' ', ',').split(','):
        if not part.strip():
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            ids.extend(range(int(a), int(b) + 1))
        else:
            ids.append(int(part))
    return ids


def console_summary(results, stats, out_paths) -> None:
    counts = {}
    for f in results:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1
    print('')
    print('=' * 62)
    print(' ghascan %s' % __version__)
    print('=' * 62)
    order = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'FALSE_POSITIVE')
    for sev in order:
        if counts.get(sev):
            print('  %-15s %d' % (sev, counts[sev]))
    print('  %-15s %d' % ('TOTAL', len(results)))
    if stats is not None:
        st = stats.as_dict()
        print('  repos=%d archivos=%d analizados=%d errores=%d omitidos=%d' % (
            st['repos'], st['files'], st['analyzed'], st['errors'], st['skipped']))
    if out_paths:
        print('-' * 62)
        for kind, path in out_paths.items():
            print('  %-6s %s' % (kind.upper(), path))
    print('=' * 62)


def emit(results, stats, args, meta=None) -> int:
    min_sev = P.SEVERITY_ORDER.get((args.min_severity or 'INFO').upper(), 0)
    shown = [f for f in results if P.SEVERITY_ORDER.get(f.verdict, 0) >= min_sev]

    out_dir = args.out or os.path.join(os.getcwd(), 'ghascan-out')
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    base = os.path.join(out_dir, 'ghascan-' + stamp)
    formats = [x.strip().lower() for x in (args.format or 'json,html,pdf').split(',') if x.strip()]

    paths = {}
    if 'json' in formats:
        paths['json'] = R.write_json(shown, base + '.json', stats, meta)
    if 'html' in formats or 'pdf' in formats:
        html_path = base + '.html'
        paths['html'] = R.write_html(shown, html_path, stats, meta)
        if 'pdf' in formats:
            pdf_path = base + '.pdf'
            if R.write_pdf(html_path, pdf_path):
                paths['pdf'] = pdf_path

    if not args.quiet:
        console_summary(shown, stats, paths)

    fail_on = [x.strip().upper() for x in (args.fail_on or '').split(',') if x.strip()]
    if fail_on:
        for f in shown:
            if f.verdict in fail_on:
                return 2
    return 0


def build_client(args, require_auth: bool = False) -> GitHubClient:
    tokens = load_tokens(args)
    if require_auth and not tokens:
        print('[!] Code search requiere token. Exporta GITHUB_TOKEN/GITHUB_TOKENS o usa --token.', file=sys.stderr)
        print('    Para pruebas sin token: ghascan demo | selftest | scan --local | scan --repo', file=sys.stderr)
        raise SystemExit(3)
    if not tokens:
        print('[i] Sin token: modo anonimo (60 req/h). Code search no esta disponible.', file=sys.stderr)
    return GitHubClient(tokens, verbose=args.verbose)


# --------------------------------------------------------------------------
# Comandos
# --------------------------------------------------------------------------

def cmd_queries(args) -> int:
    print('Dorks disponibles (%d):' % len(P.QUERIES))
    for qid in sorted(P.QUERIES):
        name, q = P.QUERIES[qid]
        print('%2d  %-42s %s' % (qid, name, q))
    return 0


def cmd_demo(args) -> int:
    results = []
    for path, content in DEMO_FILES:
        f = analyze_text(content, path=path, repo='demo/local')
        results.append(f)
        if not args.quiet:
            first = f.active[0].expression if f.active else '-'
            print('  %-16s %-34s %s' % (f.verdict, path, first))
    return emit(results, None, args, meta={'mode': 'demo'})


def cmd_selftest(args) -> int:
    checks = [
        ('pr-title', VULN_PRT, ('CRITICAL', 'HIGH')),
        ('comment', VULN_COMMENT, ('CRITICAL', 'HIGH')),
        ('env', VULN_ENV, ('CRITICAL', 'HIGH')),
        ('script', VULN_SCRIPT, ('CRITICAL', 'HIGH', 'MEDIUM')),
        ('safe-env', SAFE_ENV, ('FALSE_POSITIVE',)),
        ('disabled', SAFE_DISABLED, ('FALSE_POSITIVE',)),
        ('gated', SAFE_GATE, ('FALSE_POSITIVE', 'LOW')),
        ('push-only', SAFE_LIMITED_TRIGGER, ('FALSE_POSITIVE',)),
    ]
    ok = True
    for name, content, expected in checks:
        f = analyze_text(content, path=name + '.yml', repo='selftest')
        passed = f.verdict in expected
        ok = ok and passed
        print('  %-3s %-12s %-16s esperado=%s' % (
            'OK' if passed else 'FAIL', name, f.verdict, '/'.join(expected)))
        if not passed and f.explanation:
            print('       %s' % f.explanation[:160])
    print('')
    print('selftest: %s' % ('OK' if ok else 'FALLÓ'))
    return 0 if ok else 1


def cmd_scan(args) -> int:
    if args.local:
        results, stats = S.scan_local(args.local, all_yaml=args.all_yaml, verbose=args.verbose)
        meta = {'mode': 'local', 'target': args.local}
        return emit(results, stats, args, meta)

    client = build_client(args)
    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='replace') as fh:
            f = analyze_text(fh.read(), path=args.file, repo='local')
        return emit([f], None, args, meta={'mode': 'file', 'target': args.file})

    if args.repo:
        results, stats = S.scan_repo(client, args.repo, verbose=args.verbose)
        return emit(results, stats, args, meta={'mode': 'repo', 'target': args.repo})

    if args.org:
        repos = client.list_org_repos(args.org, limit=args.max_repos)
        if not args.quiet:
            print('[+] %d repo(s) en %s' % (len(repos), args.org))
        results, stats = S.scan_many_repos(client, repos, verbose=args.verbose)
        return emit(results, stats, args, meta={'mode': 'org', 'target': args.org})

    if args.user:
        repos = client.list_user_repos(args.user, limit=args.max_repos)
        if not args.quiet:
            print('[+] %d repo(s) de %s' % (len(repos), args.user))
        results, stats = S.scan_many_repos(client, repos, verbose=args.verbose)
        return emit(results, stats, args, meta={'mode': 'user', 'target': args.user})

    print('[!] Indica --local, --repo, --org, --user o --file.', file=sys.stderr)
    return 3


def cmd_dork(args) -> int:
    ids = list(P.QUERIES.keys()) if args.all else parse_ids(args.queries or '1,2,3,4,5')
    client = build_client(args, require_auth=True)
    results, stats = S.dork(
        client, ids, max_per_query=args.max,
        org=args.org, repo=args.repo, verbose=args.verbose,
    )
    meta = {
        'mode': 'dork',
        'queries': ids,
        'org': args.org or '',
        'repo': args.repo or '',
    }
    return emit(results, stats, args, meta)


def cmd_search(args) -> int:
    client = build_client(args, require_auth=True)
    results, stats = S.scan_search(client, args.query, max_results=args.max,
                                   verbose=args.verbose)
    return emit(results, stats, args, meta={'mode': 'search', 'query': args.query})


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

def add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument('--token', action='append', help='token de GitHub (repetible)')
    p.add_argument('--tokens-file', help='archivo con un token por linea')
    p.add_argument('--format', default='json,html,pdf',
                   help='json,html,pdf (default: los tres)')
    p.add_argument('--out', help='carpeta de salida (default: ./ghascan-out)')
    p.add_argument('--min-severity', default='INFO',
                   choices=['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    p.add_argument('--fail-on', default='',
                   help='sale con codigo 2 si hay estos veredictos (ej: CRITICAL,HIGH)')
    p.add_argument('--quiet', action='store_true')
    p.add_argument('--verbose', action='store_true')


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog='ghascan',
        description='GitHub Actions expression-injection dorker + SAST.',
    )
    ap.add_argument('--version', action='version', version='ghascan ' + __version__)
    sub = ap.add_subparsers(dest='cmd')

    q = sub.add_parser('queries', help='lista los 43 dorks')
    q.set_defaults(func=cmd_queries)

    d = sub.add_parser('demo', help='escanea workflows de ejemplo (sin red)')
    add_common(d)
    d.set_defaults(func=cmd_demo)

    t = sub.add_parser('selftest', help='pruebas internas del analizador')
    add_common(t)
    t.set_defaults(func=cmd_selftest)

    s = sub.add_parser('scan', help='escanea repo/org/usuario/carpeta')
    add_common(s)
    s.add_argument('--repo', help='owner/name')
    s.add_argument('--org', help='organizacion')
    s.add_argument('--user', help='usuario')
    s.add_argument('--local', help='carpeta local')
    s.add_argument('--file', help='un workflow suelto')
    s.add_argument('--all-yaml', action='store_true',
                   help='en --local, analiza todo .yml (no solo .github/workflows)')
    s.add_argument('--max-repos', type=int, default=100)
    s.set_defaults(func=cmd_scan)

    dk = sub.add_parser('dork', help='ejecuta dorks de code search')
    add_common(dk)
    dk.add_argument('--queries', help='ids separados por coma o rango (1-10)')
    dk.add_argument('--all', action='store_true', help='los 43 dorks')
    dk.add_argument('--max', type=int, default=100, help='resultados por dork')
    dk.add_argument('--org', help='limita a una organizacion')
    dk.add_argument('--repo', help='limita a un repo')
    dk.set_defaults(func=cmd_dork)

    se = sub.add_parser('search', help='code search libre + analisis')
    add_common(se)
    se.add_argument('--query', required=True)
    se.add_argument('--max', type=int, default=100)
    se.set_defaults(func=cmd_search)

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, 'cmd', None):
        ap.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print('\n[!] interrumpido', file=sys.stderr)
        return 130
    except SystemExit:
        raise
    except Exception as exc:
        print('[!] %s: %s' % (type(exc).__name__, exc), file=sys.stderr)
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
