"""Code analyzer: a Python repository -> SystemModel fragment.

Static analysis only (the :mod:`ast` module + import/call heuristics) - no code
is executed, so it runs fully offline on any repo on disk, including the bundled
samples. It recovers the system's structure:

* **Processes**  - web apps / services, detected from web frameworks and routes.
* **Data stores** - databases, caches, queues, object stores, detected from the
  client libraries they import.
* **External entities** - third-party services the code calls out to (HTTP
  clients), plus the implicit end user when internet-facing routes exist.
* **Entrypoints** - routes/handlers, which mark where untrusted data enters and
  make the owning process internet-facing.

Security attributes (authn, authz, input validation, TLS, rate limiting, audit
logging) are inferred from well-known markers (decorators, imports, call names).
When there is no evidence of a control, the attribute is left ``False`` -
deliberately conservative, so the tool surfaces a candidate threat for a human
to confirm or prune rather than silently assuming a control exists. This is the
"draft for review" stance; the honest cost is some false positives, reported in
the evaluation.
"""

from __future__ import annotations

import ast
import os

from ..model.schema import (
    DataFlow,
    Element,
    ElementType,
    SystemModel,
    TrustZone,
)

# library import root -> (kind, display name, data store?)
_DATASTORE_LIBS = {
    "sqlite3": "SQLite Database",
    "psycopg2": "PostgreSQL Database",
    "psycopg": "PostgreSQL Database",
    "pymysql": "MySQL Database",
    "MySQLdb": "MySQL Database",
    "sqlalchemy": "SQL Database",
    "redis": "Redis Cache",
    "pymongo": "MongoDB",
    "boto3": "AWS S3 Bucket",
    "pika": "RabbitMQ Queue",
    "kafka": "Kafka Topic",
    "elasticsearch": "Elasticsearch Index",
}
_HTTP_CLIENT_LIBS = {"requests", "httpx", "urllib", "urllib3", "aiohttp", "http"}
_WEB_FRAMEWORKS = {"flask", "fastapi", "django", "starlette", "bottle", "tornado", "aiohttp"}

# markers that indicate a control is present
_AUTHN_MARKERS = {"login_required", "requires_auth", "authenticate", "jwt", "oauth",
                  "current_user", "verify_token", "check_password", "HTTPBasicAuth"}
_AUTHZ_MARKERS = {"requires_role", "has_permission", "authorize", "is_admin",
                  "permission_required", "roles_required", "check_access"}
_VALIDATION_MARKERS = {"validate", "schema", "marshmallow", "pydantic", "BaseModel",
                       "cerberus", "jsonschema", "clean", "sanitize"}
_RATELIMIT_MARKERS = {"limiter", "rate_limit", "ratelimit", "throttle", "Limiter"}
_LOGGING_MARKERS = {"logging", "logger", "log", "audit", "structlog"}
_ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "endpoint"}


class _Visitor(ast.NodeVisitor):
    def __init__(self):
        self.imports: set[str] = set()
        self.names: set[str] = set()         # all identifier/attr names used
        self.decorators: set[str] = set()
        self.has_routes = False

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.add(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self.imports.add(node.module.split(".")[0])
        for alias in node.names:
            self.names.add(alias.name)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        self.names.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        self.names.add(node.attr)
        self.generic_visit(node)

    def _record_decorators(self, node):
        for dec in node.decorator_list:
            name = _dec_name(dec)
            if name:
                self.decorators.add(name)
                last = name.split(".")[-1]
                if last in _ROUTE_DECORATORS:
                    self.has_routes = True

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._record_decorators(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._record_decorators(node)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        self._record_decorators(node)
        self.generic_visit(node)


def _dec_name(dec) -> str:
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Call):
        return _dec_name(dec.func)
    return ""


def _has_marker(tokens: set[str], markers: set[str]) -> bool:
    low = {t.lower() for t in tokens}
    return any(m.lower() in low for m in markers)


def analyze_python_repo(repo_path: str, name: str | None = None) -> SystemModel:
    """Analyze a Python repo directory into a SystemModel fragment."""
    repo_path = os.path.abspath(repo_path)
    app_name = name or os.path.basename(repo_path.rstrip("/"))
    agg = _Visitor()
    file_count = 0

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {".venv", "venv", "__pycache__", ".git", "node_modules"}]
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    tree = ast.parse(fh.read(), filename=path)
            except (SyntaxError, UnicodeDecodeError):
                continue
            file_count += 1
            v = _Visitor()
            v.visit(tree)
            agg.imports |= v.imports
            agg.names |= v.names
            agg.decorators |= v.decorators
            agg.has_routes = agg.has_routes or v.has_routes

    model = SystemModel(name=app_name)
    model.metadata["input"] = "code"
    model.metadata["files_analyzed"] = file_count

    tokens = agg.imports | agg.names | agg.decorators
    framework = next((f for f in _WEB_FRAMEWORKS if f in agg.imports), None)
    internet_facing = bool(framework or agg.has_routes)

    # --- The application process ------------------------------------------
    app_proc = Element(
        id="app",
        name=f"{app_name} Service",
        type=ElementType.PROCESS,
        zone=TrustZone.APPLICATION,
        attributes={
            "internet_facing": internet_facing,
            "technology": framework or "python",
            "authenticated": _has_marker(tokens, _AUTHN_MARKERS),
            "authorization": _has_marker(tokens, _AUTHZ_MARKERS),
            "validates_input": _has_marker(tokens, _VALIDATION_MARKERS),
            "rate_limited": _has_marker(tokens, _RATELIMIT_MARKERS),
            "audit_logging": _has_marker(tokens, _LOGGING_MARKERS),
            "handles_sensitive": True,
        },
        source=f"code:{app_name}",
    )
    model.add_element(app_proc)

    # --- End user (if internet-facing) ------------------------------------
    if internet_facing:
        user = Element(
            id="end_user",
            name="End User",
            type=ElementType.EXTERNAL_ENTITY,
            zone=TrustZone.PUBLIC,
            attributes={"authenticated": app_proc.attributes["authenticated"]},
            source="code:routes",
        )
        model.add_element(user)
        model.add_flow(
            DataFlow(
                id="f_user_app",
                source=user.id,
                dest=app_proc.id,
                name="user request",
                data=["credentials", "pii"],
                protocol="https",
                authenticated=app_proc.attributes["authenticated"],
                encrypted=True,
            )
        )

    # --- Data stores -------------------------------------------------------
    for i, (lib, disp) in enumerate(sorted(_DATASTORE_LIBS.items())):
        if lib not in agg.imports:
            continue
        ds = Element(
            id=f"store_{i}",
            name=disp,
            type=ElementType.DATA_STORE,
            zone=TrustZone.DATA,
            attributes={
                "handles_sensitive": True,
                "encrypted": False,  # no static evidence of at-rest encryption
                "integrity_protected": _has_marker(tokens, _LOGGING_MARKERS),
                "audit_logging": _has_marker(tokens, _LOGGING_MARKERS),
                "data": ["credentials", "pii"],
                "technology": lib,
            },
            source=f"code:import {lib}",
        )
        model.add_element(ds)
        model.add_flow(
            DataFlow(
                id=f"f_app_{ds.id}",
                source=app_proc.id,
                dest=ds.id,
                name="persist",
                data=["credentials", "pii"],
                protocol="tcp",
                authenticated=True,
                encrypted=False,
            )
        )

    # --- Third-party HTTP calls -------------------------------------------
    if agg.imports & _HTTP_CLIENT_LIBS:
        tp = Element(
            id="third_party",
            name="Third-party API",
            type=ElementType.EXTERNAL_ENTITY,
            zone=TrustZone.THIRD_PARTY,
            attributes={"authenticated": True},
            source="code:http client",
        )
        model.add_element(tp)
        model.add_flow(
            DataFlow(
                id="f_app_tp",
                source=app_proc.id,
                dest=tp.id,
                name="outbound call",
                data=["request"],
                protocol="https",
                authenticated=True,
                encrypted=True,
            )
        )

    return model
