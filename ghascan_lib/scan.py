"""
Modos de escaneo de ghascan.
"""

from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional

from . import patterns as P
from .analyze import Finding, analyze_text
from .github import GitHubClient


class ScanStats:
    def __init__(self) -> None:
        self.repos = 0
        self.files = 0
        self.analyzed = 0
        self.errors = 0
        self.skipped = 0

    def as_dict(self) -> dict:
        return {
            'repos': self.repos,
            'files': self.files,
            'analyzed': self.analyzed,
            'errors': self.errors,
            'skipped': self.skipped,
        }


def _dedup_key(f: Finding) -> str:
    return '%s|%s|%s' % (f.repo, f.path, f.content_hash)


def _add(results: List[Finding], seen: set, f: Finding) -> None:
    key = _dedup_key(f)
    if key in seen:
        return
    seen.add(key)
    results.append(f)


def iter_local_workflows(root: str, all_yaml: bool = False):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ('.git', 'node_modules', 'vendor', 'dist', 'build')]
        for name in filenames:
            if not name.endswith(('.yml', '.yaml')):
                continue
            full = os.path.join(dirpath, name)
            if all_yaml:
                yield full
                continue
            norm = full.replace('\\', '/')
            if '/.github/workflows/' in norm:
                yield full


def scan_local(root: str, all_yaml: bool = False, verbose: bool = False):
    stats = ScanStats()
    results: List[Finding] = []
    seen: set = set()
    base = os.path.abspath(root if os.path.isdir(root) else os.path.dirname(root) or '.')
    label = os.path.basename(base) or 'local'
    for path in iter_local_workflows(root, all_yaml=all_yaml):
        stats.files += 1
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except OSError:
            stats.errors += 1
            continue
        rel = os.path.relpath(path, base).replace('\\', '/')
        f = analyze_text(content, path=rel, repo=label)
        stats.analyzed += 1
        _add(results, seen, f)
        if verbose:
            print('  %-10s %s' % (f.verdict, path), flush=True)
    return results, stats


def scan_repo(client: GitHubClient, full_name: str, verbose: bool = False):
    stats = ScanStats()
    results: List[Finding] = []
    seen: set = set()
    stats.repos = 1
    try:
        files = client.workflow_files(full_name)
    except Exception as exc:
        print('  [!] %s: %s' % (full_name, exc), flush=True)
        stats.errors += 1
        return results, stats
    if verbose:
        print('  %s: %d workflow(s)' % (full_name, len(files)), flush=True)
    for path in files:
        stats.files += 1
        content = client.raw_file(full_name, path)
        if not content:
            stats.skipped += 1
            continue
        url = 'https://github.com/%s/blob/HEAD/%s' % (full_name, path)
        f = analyze_text(content, path=path, repo=full_name, source_url=url)
        stats.analyzed += 1
        _add(results, seen, f)
        if verbose:
            print('  %-10s %s/%s' % (f.verdict, full_name, path), flush=True)
    return results, stats


def scan_many_repos(client: GitHubClient, repos: Iterable[str], verbose: bool = False):
    all_results: List[Finding] = []
    total = ScanStats()
    seen: set = set()
    for repo in repos:
        res, st = scan_repo(client, repo, verbose=verbose)
        total.repos += 1
        total.files += st.files
        total.analyzed += st.analyzed
        total.errors += st.errors
        total.skipped += st.skipped
        for f in res:
            _add(all_results, seen, f)
    return all_results, total


def scan_search(client: GitHubClient, query: str, max_results: int = 100,
                verbose: bool = False):
    stats = ScanStats()
    results: List[Finding] = []
    seen: set = set()
    items = client.search_code(query, max_results=max_results)
    stats.files = len(items)
    for item in items:
        repo = (item.get('repository') or {}).get('full_name') or ''
        path = item.get('path') or ''
        if not repo or not path:
            stats.skipped += 1
            continue
        content = client.raw_file(repo, path)
        if not content:
            stats.skipped += 1
            continue
        f = analyze_text(
            content, path=path, repo=repo,
            source_url=item.get('html_url', ''),
            dork_query=query,
        )
        stats.analyzed += 1
        _add(results, seen, f)
        if verbose:
            print('  %-10s %s/%s' % (f.verdict, repo, path), flush=True)
    return results, stats


def dork(client: GitHubClient, query_ids: List[int], max_per_query: int = 100,
         org: Optional[str] = None, repo: Optional[str] = None,
         verbose: bool = False):
    """Ejecuta los dorks pedidos y analiza los resultados."""
    ids = query_ids or list(P.QUERIES.keys())
    results: List[Finding] = []
    seen: set = set()
    total = ScanStats()
    for qid in ids:
        if qid not in P.QUERIES:
            print('  [!] dork %s no existe (1-43)' % qid, flush=True)
            continue
        name, query = P.QUERIES[qid]
        if org:
            query += ' org:' + org
        if repo:
            query += ' repo:' + repo
        print('[dork %02d] %s' % (qid, name), flush=True)
        try:
            items = client.search_code(query, max_results=max_per_query)
        except Exception as exc:
            print('  [!] %s' % exc, flush=True)
            total.errors += 1
            continue
        print('  %d resultado(s)' % len(items), flush=True)
        total.files += len(items)
        for item in items:
            full = (item.get('repository') or {}).get('full_name') or ''
            path = item.get('path') or ''
            if not full or not path:
                total.skipped += 1
                continue
            content = client.raw_file(full, path)
            if not content:
                total.skipped += 1
                continue
            f = analyze_text(
                content, path=path, repo=full,
                source_url=item.get('html_url', ''),
                dork_query=query,
            )
            total.analyzed += 1
            _add(results, seen, f)
            if verbose:
                print('    %-10s %s/%s' % (f.verdict, full, path), flush=True)
    return results, total
