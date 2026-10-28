"""In-memory stand-in for the Elasticsearch/Kibana calls scripts/elastic_api.py users make (plain http, no TLS)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


def dig(doc, dotted):
    cur = doc
    for k in dotted.split("."):
        if not isinstance(cur, dict) or k not in cur:
            return doc.get(dotted) if isinstance(doc, dict) else None
        cur = cur[k]
    return cur


def matches(doc, q):
    if not q or "match_all" in q:
        return True
    if "bool" in q:
        b = q["bool"]
        return all(matches(doc, c) for c in b.get("filter", []) + b.get("must", []))
    if "term" in q:
        (f, v), = q["term"].items()
        v = v.get("value") if isinstance(v, dict) else v
        return str(dig(doc, f)) == str(v)
    if "match_phrase" in q:
        (f, v), = q["match_phrase"].items()
        return str(v) in str(dig(doc, f) or "")
    if "range" in q:
        (f, c), = q["range"].items()
        got = dig(doc, f)
        return got is not None and all((got >= c[k] if k == "gte" else got <= c[k]) for k in c)
    raise AssertionError("fake_elastic: unsupported query %r" % q)


class FakeEs:
    def __init__(self, password="pw"):
        self.docs = {}        # data stream -> [doc]
        self.calls = []       # (method, path, body)
        self.disk_percent = 40
        self.down = False     # simulate an outage: every request is a 503
        self.drop_drain = False  # a drain marker that never arrives
        self.srv = HTTPServer(("127.0.0.1", 0), self._handler())
        self.url = "http://127.0.0.1:%d" % self.srv.server_port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    def add(self, stream, doc):
        self.docs.setdefault(stream, []).append(doc)

    def select(self, pattern):
        prefix = pattern.rstrip("*")
        return [d for s, ds in self.docs.items() if s.startswith(prefix) for d in ds]

    def deletes(self):
        return [c for c in self.calls if c[0] == "DELETE" or "_delete_by_query" in c[1]]

    def _route(self, method, path, body):
        path, _, _q = path.partition("?")
        if path == "/":
            return 200, {"version": {"number": "9.5.5"}}
        if path == "/_cluster/health":
            return 200, {"status": "green", "number_of_nodes": 1}
        if path == "/_cat/allocation":
            return 200, [{"node": "n1", "disk.percent": str(self.disk_percent)}]
        if path.endswith("/_doc") and method == "POST":
            stream = path.split("/")[1]
            if not (self.drop_drain and "drain" in json.dumps(body)):
                self.add(stream, body)
            return 201, {"result": "created"}
        if path.endswith("/_search"):
            hits = [d for d in self.select(path.split("/")[1]) if matches(d, body.get("query"))]
            hits.sort(key=lambda d: d.get("@timestamp", ""))
            return 200, {"hits": {"total": {"value": len(hits)}, "hits": [{"_source": d} for d in hits[: body.get("size", 10)]]}}
        if path.endswith("/_count"):
            return 200, {"count": len([d for d in self.select(path.split("/")[1]) if matches(d, (body or {}).get("query"))])}
        if path.endswith("/_delete_by_query"):
            name = path.split("/")[1]
            n = 0
            for s in list(self.docs):
                if s.startswith(name.rstrip("*")):
                    keep = [d for d in self.docs[s] if not matches(d, body.get("query"))]
                    n += len(self.docs[s]) - len(keep)
                    self.docs[s] = keep
            return 200, {"deleted": n}
        if path.startswith("/_data_stream/") and method == "DELETE":
            name = path.split("/")[-1]
            for s in [s for s in self.docs if s.startswith(name.rstrip("*"))]:
                del self.docs[s]
            return 200, {"acknowledged": True}
        return 404, {}

    def _handler(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                fake.calls.append((self.command, self.path, body))
                code, out = (503, {}) if fake.down else fake._route(self.command, self.path, body)
                data = json.dumps(out).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = _do

        return H
