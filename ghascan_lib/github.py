"""
Cliente minimo de la API de GitHub con soporte multi-token.

- Rota tokens ante 401/403/429.
- Respeta el rate limit de code search (10 req/min por token).
- Cachea respuestas en memoria durante la corrida.
- No usa dependencias externas (solo stdlib).
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Iterable, List, Optional, Tuple

API = 'https://api.github.com'
RAW = 'https://raw.githubusercontent.com'
UA = 'ghascan/1.0'


class Token:
    def __init__(self, value: str, label: str = ''):
        self.value = value
        self.label = label or ('token-...' + value[-4:] if len(value) > 4 else 'token')
        self.invalid = False
        self.blocked_until = 0.0
        self.last_search = 0.0
        self.remaining: Optional[int] = None

    def __repr__(self) -> str:
        return '<Token %s>' % self.label


class TokenPool:
    def __init__(self, tokens: Iterable[str]):
        self.tokens = [Token(t.strip()) for t in tokens if t and t.strip()]
        self.anonymous = not self.tokens
        if self.anonymous:
            # Sin token: la API publica permite 60 req/h. Code search requiere auth.
            self.tokens = [Token('', 'anonymous')]

    def __len__(self) -> int:
        return len(self.tokens)

    def acquire(self, search: bool = False) -> Token:
        while True:
            now = time.time()
            alive = [t for t in self.tokens if not t.invalid]
            if not alive:
                raise RuntimeError(
                    'Todos los tokens fueron rechazados (401). '
                    'Sin token, la API publica tiene un limite de 60 req/h.'
                )
            ready = [t for t in alive if t.blocked_until <= now]
            if ready:
                if search:
                    ready.sort(key=lambda t: t.last_search)
                    tok = ready[0]
                    # 10 req/min por token => 6s entre busquedas
                    wait = 6.05 - (now - tok.last_search)
                    if wait > 0:
                        time.sleep(min(wait, 10))
                    tok.last_search = time.time()
                    return tok
                return ready[0]
            wait = min(t.blocked_until for t in alive) - now
            time.sleep(max(0.5, min(wait, 30)))

    def penalize(self, tok: Token, seconds: float) -> None:
        tok.blocked_until = max(tok.blocked_until, time.time() + max(1.0, seconds))

    def invalidate(self, tok: Token) -> None:
        tok.invalid = True


class GitHubClient:
    def __init__(self, tokens: Iterable[str], verbose: bool = False,
                 cache: bool = True):
        self.pool = TokenPool(tokens)
        self.verbose = verbose
        self._cache: Dict[str, dict] = {}
        self._use_cache = cache
        self.calls = 0

    # ------------------------------------------------------------------
    def _log(self, msg: str) -> None:
        if self.verbose:
            print('  [api] ' + msg, flush=True)

    def _request(self, url: str, method: str = 'GET',
                 search: bool = False, attempts: int = 6) -> dict:
        if not url.startswith('http'):
            url = API + url
        tok = None
        last_error: Optional[Exception] = None
        for attempt in range(attempts):
            tok = self.pool.acquire(search=search)
            req = urllib.request.Request(url, method=method)
            if tok.value:
                req.add_header('Authorization', 'Bearer ' + tok.value)
            req.add_header('Accept', 'application/vnd.github+json')
            req.add_header('X-GitHub-Api-Version', '2022-11-28')
            req.add_header('User-Agent', UA)
            try:
                with urllib.request.urlopen(req, timeout=45) as resp:
                    self.calls += 1
                    body = resp.read()
                    self._log('%s %s -> %s' % (method, url, resp.status))
                    if not body:
                        return {}
                    return json.loads(body.decode('utf-8', 'replace'))
            except urllib.error.HTTPError as e:
                last_error = e
                code = e.code
                headers = e.headers
                if code == 401:
                    self.pool.invalidate(tok)
                    continue
                if code in (403, 429):
                    reset = headers.get('x-ratelimit-reset')
                    retry_after = headers.get('retry-after')
                    remaining = headers.get('x-ratelimit-remaining')
                    wait = 60.0
                    if retry_after and retry_after.isdigit():
                        wait = float(retry_after)
                    elif reset and reset.isdigit():
                        wait = max(5.0, float(reset) - time.time())
                    elif remaining not in (None, '0'):
                        wait = 15.0
                    wait = min(wait, 180.0)
                    self._log('rate limit %s; esperando %.0fs' % (code, wait))
                    self.pool.penalize(tok, wait)
                    continue
                if code >= 500:
                    time.sleep(2 + attempt * 2)
                    continue
                detail = ''
                try:
                    detail = e.read().decode('utf-8', 'replace')[:300]
                except Exception:
                    pass
                raise RuntimeError('GitHub API %s en %s: %s' % (code, url, detail))
            except (urllib.error.URLError, TimeoutError) as e:
                last_error = e
                time.sleep(2 + attempt * 2)
        raise RuntimeError('No se pudo completar %s: %s' % (url, last_error))

    def get(self, path: str) -> dict:
        if path in self._cache and self._use_cache:
            return self._cache[path]
        data = self._request(path)
        if self._use_cache:
            self._cache[path] = data
        return data

    # ------------------------------------------------------------------
    # Busqueda
    # ------------------------------------------------------------------
    def search_code(self, query: str, max_results: int = 100,
                    per_page: int = 100) -> List[dict]:
        items: List[dict] = []
        page = 1
        while len(items) < max_results and page <= 10:
            q = urllib.parse.quote(query)
            url = '/search/code?q=%s&per_page=%d&page=%d' % (q, min(per_page, 100), page)
            data = self._request(url, search=True)
            batch = data.get('items', [])
            if not batch:
                break
            items.extend(batch)
            if len(batch) < per_page:
                break
            page += 1
        return items[:max_results]

    # ------------------------------------------------------------------
    # Repos
    # ------------------------------------------------------------------
    def repo(self, full_name: str) -> dict:
        return self.get('/repos/' + full_name.strip('/'))

    def default_branch(self, full_name: str) -> str:
        try:
            return self.repo(full_name).get('default_branch') or 'main'
        except Exception:
            return 'main'

    def tree(self, full_name: str, branch: Optional[str] = None,
             recursive: bool = True) -> List[dict]:
        if not branch:
            branch = self.default_branch(full_name)
        data = self.get('/repos/%s/git/trees/%s?recursive=%d' % (
            full_name, urllib.parse.quote(branch), 1 if recursive else 0))
        return data.get('tree', [])

    def list_org_repos(self, org: str, limit: int = 100, forks: bool = False) -> List[str]:
        out: List[str] = []
        page = 1
        while len(out) < limit and page <= 20:
            data = self.get('/orgs/%s/repos?per_page=100&page=%d&type=all' % (org, page))
            if not isinstance(data, list):
                break
            for r in data:
                if r.get('fork') and not forks:
                    continue
                out.append(r['full_name'])
                if len(out) >= limit:
                    break
            if len(data) < 100:
                break
            page += 1
        return out

    def list_user_repos(self, user: str, limit: int = 100, forks: bool = False) -> List[str]:
        out: List[str] = []
        page = 1
        while len(out) < limit and page <= 20:
            data = self.get('/users/%s/repos?per_page=100&page=%d&type=owner' % (user, page))
            if not isinstance(data, list):
                break
            for r in data:
                if r.get('fork') and not forks:
                    continue
                out.append(r['full_name'])
                if len(out) >= limit:
                    break
            if len(data) < 100:
                break
            page += 1
        return out

    # ------------------------------------------------------------------
    # Contenido
    # ------------------------------------------------------------------
    def raw_file(self, full_name: str, path: str, ref: str = 'HEAD') -> Optional[str]:
        """Lee un archivo sin gastar cuota de API (raw.githubusercontent.com)."""
        url = '%s/%s/%s/%s' % (RAW, full_name, urllib.parse.quote(ref, safe=''),
                               urllib.parse.quote(path))
        req = urllib.request.Request(url)
        req.add_header('User-Agent', UA)
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                return resp.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError:
            pass
        # Fallback a la Contents API
        try:
            data = self.get('/repos/%s/contents/%s?ref=%s' % (
                full_name, urllib.parse.quote(path), urllib.parse.quote(ref)))
            if isinstance(data, dict) and data.get('content'):
                return base64.b64decode(data['content']).decode('utf-8', 'replace')
        except Exception:
            return None
        return None

    def workflow_files(self, full_name: str, branch: Optional[str] = None) -> List[str]:
        """Lista .github/workflows/*.yml|yaml del repo."""
        tree = self.tree(full_name, branch)
        out = []
        for item in tree:
            if item.get('type') != 'blob':
                continue
            p = item.get('path', '')
            if not (p.startswith('.github/workflows/') or '/.github/workflows/' in p):
                continue
            if p.endswith(('.yml', '.yaml')):
                out.append(p)
        return sorted(out)
