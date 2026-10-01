"""Code analyzer for JavaScript / TypeScript repositories.

Demonstrates that ThreatForge's structure recovery generalizes beyond Python
(Tier 3). JS/TS has no stdlib AST in Python, so this uses dependency + source
heuristics: it reads ``package.json`` dependencies and scans ``.js/.ts/.jsx/.tsx``
sources for well-known imports, route definitions, and control markers, emitting
the same :class:`SystemModel` vocabulary as the Python analyzer so the rest of
the pipeline is identical.
"""

from __future__ import annotations

import json
import os
import re

from ..model.schema import (
    DataFlow,
    Element,
    ElementType,
    SystemModel,
    TrustZone,
)

_WEB_FRAMEWORKS = {"express", "fastify", "koa", "next", "nestjs", "@nestjs/core",
                   "hapi", "@hapi/hapi", "restify"}
_DATASTORE_LIBS = {
    "pg": "PostgreSQL Database", "mysql": "MySQL Database", "mysql2": "MySQL Database",
    "mongoose": "MongoDB", "mongodb": "MongoDB", "redis": "Redis Cache",
    "ioredis": "Redis Cache", "sqlite3": "SQLite Database", "better-sqlite3": "SQLite Database",
    "knex": "SQL Database", "prisma": "SQL Database", "@prisma/client": "SQL Database",
    "typeorm": "SQL Database", "sequelize": "SQL Database", "aws-sdk": "AWS S3 Bucket",
    "@aws-sdk/client-s3": "AWS S3 Bucket", "amqplib": "RabbitMQ Queue", "kafkajs": "Kafka Topic",
}
_HTTP_CLIENT_LIBS = {"axios", "node-fetch", "got", "superagent", "undici"}
_AUTHN_LIBS = {"passport", "jsonwebtoken", "express-jwt", "@nestjs/jwt", "next-auth",
               "bcrypt", "bcryptjs", "argon2"}
_AUTHZ_LIBS = {"casbin", "accesscontrol", "acl", "@casl/ability"}
_VALIDATION_LIBS = {"joi", "zod", "yup", "express-validator", "class-validator", "ajv"}
_RATELIMIT_LIBS = {"express-rate-limit", "rate-limiter-flexible", "@fastify/rate-limit", "bottleneck"}
_LOGGING_LIBS = {"winston", "pino", "morgan", "bunyan", "@nestjs/common"}

_ROUTE_RE = re.compile(
    r"\.(get|post|put|delete|patch|all)\s*\(\s*['\"`]|@(Get|Post|Put|Delete|Patch)\s*\(")
_IMPORT_RE = re.compile(
    r"""(?:require\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"]|import\s+['"]([^'"]+)['"])""")


def _collect(repo_path: str):
    deps: set[str] = set()
    imports: set[str] = set()
    has_routes = False
    file_count = 0

    pkg = os.path.join(repo_path, "package.json")
    if os.path.exists(pkg):
        try:
            with open(pkg, encoding="utf-8") as fh:
                data = json.load(fh)
            for key in ("dependencies", "devDependencies", "peerDependencies"):
                deps |= set((data.get(key) or {}).keys())
        except (json.JSONDecodeError, OSError):
            pass

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "dist", "build", ".next"}]
        for fn in files:
            if not fn.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            file_count += 1
            for m in _IMPORT_RE.finditer(text):
                mod = m.group(1) or m.group(2) or m.group(3)
                if mod and not mod.startswith("."):
                    imports.add(mod.split("/")[0] if not mod.startswith("@") else "/".join(mod.split("/")[:2]))
            if _ROUTE_RE.search(text):
                has_routes = True
    return deps, imports, has_routes, file_count


def analyze_js_repo(repo_path: str, name: str | None = None) -> SystemModel:
    repo_path = os.path.abspath(repo_path)
    app_name = name or os.path.basename(repo_path.rstrip("/"))
    deps, imports, has_routes, file_count = _collect(repo_path)
    tokens = deps | imports

    model = SystemModel(name=app_name)
    model.metadata["input"] = "code"
    model.metadata["language"] = "javascript"
    model.metadata["files_analyzed"] = file_count

    framework = next((f for f in _WEB_FRAMEWORKS if f in tokens), None)
    internet_facing = bool(framework or has_routes)

    def present(libs):
        return bool(tokens & libs)

    app = Element(
        id="app",
        name=f"{app_name} Service",
        type=ElementType.PROCESS,
        zone=TrustZone.APPLICATION,
        attributes={
            "internet_facing": internet_facing,
            "technology": framework or "node",
            "authenticated": present(_AUTHN_LIBS),
            "authorization": present(_AUTHZ_LIBS),
            "validates_input": present(_VALIDATION_LIBS),
            "rate_limited": present(_RATELIMIT_LIBS),
            "audit_logging": present(_LOGGING_LIBS),
            "handles_sensitive": True,
        },
        source=f"code:{app_name} (js/ts)",
    )
    model.add_element(app)

    if internet_facing:
        user = Element("end_user", "End User", ElementType.EXTERNAL_ENTITY,
                       TrustZone.PUBLIC, {"authenticated": app.attributes["authenticated"]},
                       source="code:routes")
        model.add_element(user)
        model.add_flow(DataFlow("f_user_app", user.id, app.id, name="user request",
                                data=["credentials", "pii"], protocol="https",
                                authenticated=app.attributes["authenticated"], encrypted=True))

    idx = 0
    seen_stores: set[str] = set()
    for lib, disp in _DATASTORE_LIBS.items():
        if lib in tokens and disp not in seen_stores:
            seen_stores.add(disp)
            ds = Element(f"store_{idx}", disp, ElementType.DATA_STORE, TrustZone.DATA,
                         {"handles_sensitive": True, "encrypted": False,
                          "integrity_protected": present(_LOGGING_LIBS),
                          "audit_logging": present(_LOGGING_LIBS),
                          "data": ["credentials", "pii"], "technology": lib},
                         source=f"code:dependency {lib}")
            model.add_element(ds)
            model.add_flow(DataFlow(f"f_app_{ds.id}", app.id, ds.id, name="persist",
                                    data=["credentials", "pii"], protocol="tcp",
                                    authenticated=True, encrypted=False))
            idx += 1

    if tokens & _HTTP_CLIENT_LIBS:
        tp = Element("third_party", "Third-party API", ElementType.EXTERNAL_ENTITY,
                     TrustZone.THIRD_PARTY, {"authenticated": True}, source="code:http client")
        model.add_element(tp)
        model.add_flow(DataFlow("f_app_tp", app.id, tp.id, name="outbound call",
                                data=["request"], protocol="https", authenticated=True,
                                encrypted=True))

    return model
