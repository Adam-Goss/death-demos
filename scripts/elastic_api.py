"""Minimal Elasticsearch/Kibana client for the operator commands (issue #24).

Reached from the workstation through the SSH tunnel (scripts/elastic-tunnel.sh) for 9200; Kibana is direct on 5601.
Env: ELASTIC_ES_URL (default https://127.0.0.1:19200), ELASTIC_KB_URL (default https://<plan elastic ip>:5601),
     ELASTIC_CA (default secrets/elastic/ca/ca.crt; ignored for plain http URLs, used by tests),
     ELASTIC_PASSWORD_FILE (default secrets/elastic/elastic.password).
"""
import base64
import json
import os
import ssl
import urllib.error
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class EsError(RuntimeError):
    pass


class Client:
    def __init__(self, url, ca=None, password=None):
        self.url = url.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=ca) if url.startswith("https") else None
        self.auth = None
        if password is not None:
            self.auth = "Basic " + base64.b64encode(("elastic:%s" % password).encode()).decode()

    def call(self, path, body=None, method=None):
        method = method or ("POST" if body is not None else "GET")
        headers = {"Content-Type": "application/json", "kbn-xsrf": "labops"}
        if self.auth:
            headers["Authorization"] = self.auth
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30, context=self.ctx) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise EsError("%s %s: http %d" % (method, path, e.code))
        except Exception as e:  # noqa: BLE001
            raise EsError("%s %s: %s" % (method, path, e))


def _password():
    path = os.environ.get("ELASTIC_PASSWORD_FILE", os.path.join(ROOT, "secrets/elastic/elastic.password"))
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        raise SystemExit("no Elastic password at %s: run the elastic playbook first" % path)


def _ca():
    return os.environ.get("ELASTIC_CA", os.path.join(ROOT, "secrets/elastic/ca/ca.crt"))


def es_client():
    return Client(os.environ.get("ELASTIC_ES_URL", "https://127.0.0.1:19200"), _ca(), _password())


def kibana_client(plan):
    url = os.environ.get("ELASTIC_KB_URL", "https://%s:5601" % plan["hosts"]["elastic"]["ip"])
    return Client(url, _ca(), _password())
