"""Infrastructure-as-code analyzer: Terraform + Kubernetes -> SystemModel.

Models cloud/platform architecture, not just app code: public buckets, security
groups open to the internet, publicly-accessible databases, load-balanced
services, ingress edges, secrets, and IAM trust - the places cloud teams get
breached. Uses lightweight pattern parsing (no provider plugins) so it runs
offline on any ``.tf`` / ``.yaml`` tree, emitting the same DFD vocabulary as the
code and diagram analyzers.

Heuristic by design (a human reviews the result): exposure is inferred from
well-known signals (``0.0.0.0/0`` ingress, ``publicly_accessible = true``,
``acl = "public-read"``, Service ``type: LoadBalancer``), and absence of a signal
is treated conservatively.
"""

from __future__ import annotations

import os
import re

from ..model.schema import (
    DataFlow,
    Element,
    ElementType,
    SystemModel,
    TrustZone,
)

# Terraform resource type -> (element type, display suffix)
_TF_DATASTORE = {
    "aws_s3_bucket": "S3 Bucket", "aws_db_instance": "RDS Database",
    "aws_rds_cluster": "RDS Cluster", "aws_dynamodb_table": "DynamoDB Table",
    "aws_elasticache_cluster": "ElastiCache", "google_storage_bucket": "GCS Bucket",
    "azurerm_storage_account": "Azure Storage", "aws_sqs_queue": "SQS Queue",
}
_TF_PROCESS = {
    "aws_instance": "EC2 Instance", "aws_lambda_function": "Lambda Function",
    "aws_ecs_service": "ECS Service", "aws_api_gateway_rest_api": "API Gateway",
    "google_cloud_run_service": "Cloud Run Service", "aws_eks_cluster": "EKS Cluster",
}
_TF_EDGE = {"aws_lb": "Load Balancer", "aws_alb": "Load Balancer",
            "aws_cloudfront_distribution": "CloudFront CDN"}

_TF_RESOURCE_RE = re.compile(r'resource\s+"([a-z0-9_]+)"\s+"([a-zA-Z0-9_-]+)"\s*\{')


def _find_tf_files(root: str) -> list[str]:
    out = []
    for dp, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {".terraform", ".git"}]
        out += [os.path.join(dp, f) for f in files if f.endswith(".tf")]
    return out


def _block_body(text: str, start: int) -> str:
    """Return the text of the { ... } block beginning at the brace index `start`."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return text[start:]


def analyze_terraform(root: str, name: str | None = None) -> SystemModel:
    root = os.path.abspath(root)
    model = SystemModel(name=name or f"{os.path.basename(root)} (terraform)")
    model.metadata["input"] = "iac"
    model.metadata["iac"] = "terraform"

    internet = Element("internet", "Internet", ElementType.EXTERNAL_ENTITY,
                       TrustZone.PUBLIC, {"authenticated": False}, source="iac")
    model.add_element(internet)
    has_public = False
    idx = 0

    for path in _find_tf_files(root):
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        rel = os.path.relpath(path, root)
        for m in _TF_RESOURCE_RE.finditer(text):
            rtype, rname = m.group(1), m.group(2)
            body = _block_body(text, m.end() - 1)
            line = text[: m.start()].count("\n") + 1
            src = f"{rel}:{line}"
            public = ("0.0.0.0/0" in body or "publicly_accessible = true" in body.replace('"', "")
                      or 'acl = "public-read"' in body or '"public-read"' in body)
            encrypted = ("encrypted = true" in body or "server_side_encryption" in body
                         or "kms_key" in body)
            if rtype in _TF_DATASTORE:
                el = Element(f"tf_{idx}", f"{_TF_DATASTORE[rtype]} ({rname})",
                             ElementType.DATA_STORE,
                             TrustZone.PUBLIC if public else TrustZone.DATA,
                             {"handles_sensitive": True, "encrypted": encrypted,
                              "integrity_protected": False, "audit_logging": "logging" in body,
                              "internet_facing": public, "data": ["pii"],
                              "technology": rtype}, source=src)
                model.add_element(el)
                if public:
                    has_public = True
                    model.add_flow(DataFlow(f"f_pub_{idx}", internet.id, el.id,
                                            name="public access", data=["pii"],
                                            protocol="https" if encrypted else "http",
                                            encrypted=encrypted))
                idx += 1
            elif rtype in _TF_PROCESS:
                el = Element(f"tf_{idx}", f"{_TF_PROCESS[rtype]} ({rname})",
                             ElementType.PROCESS,
                             TrustZone.DMZ if public else TrustZone.APPLICATION,
                             {"internet_facing": public, "authenticated": "authorizer" in body
                              or "authentication" in body, "rate_limited": "throttle" in body
                              or "rate_limit" in body, "authorization": "iam" in body.lower(),
                              "validates_input": False, "audit_logging": "logging" in body
                              or "log_group" in body, "technology": rtype}, source=src)
                model.add_element(el)
                if public:
                    has_public = True
                    model.add_flow(DataFlow(f"f_in_{idx}", internet.id, el.id,
                                            name="ingress", data=["request"],
                                            protocol="https", encrypted=True))
                idx += 1
            elif rtype in _TF_EDGE:
                el = Element(f"tf_{idx}", f"{_TF_EDGE[rtype]} ({rname})",
                             ElementType.PROCESS, TrustZone.DMZ,
                             {"internet_facing": True, "authenticated": False,
                              "rate_limited": False, "technology": rtype}, source=src)
                model.add_element(el)
                has_public = True
                model.add_flow(DataFlow(f"f_edge_{idx}", internet.id, el.id, name="ingress",
                                        data=["request"], protocol="https", encrypted=True))
                idx += 1

    if not has_public:
        # Keep the Internet node only if something is actually exposed.
        model.elements = [e for e in model.elements if e.id != "internet"]
    return model


# -- Kubernetes --------------------------------------------------------------
def _k8s_docs(root: str):
    import yaml
    for dp, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != ".git"]
        for f in files:
            if not f.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(dp, f)
            try:
                with open(path, encoding="utf-8") as fh:
                    for doc in yaml.safe_load_all(fh):
                        if isinstance(doc, dict) and doc.get("kind"):
                            yield doc, os.path.relpath(path, root)
            except Exception:
                continue


def analyze_kubernetes(root: str, name: str | None = None) -> SystemModel:
    root = os.path.abspath(root)
    model = SystemModel(name=name or f"{os.path.basename(root)} (k8s)")
    model.metadata["input"] = "iac"
    model.metadata["iac"] = "kubernetes"
    internet = Element("internet", "Internet", ElementType.EXTERNAL_ENTITY,
                       TrustZone.PUBLIC, {"authenticated": False}, source="iac")
    model.add_element(internet)
    has_public = False
    idx = 0

    for doc, rel in _k8s_docs(root):
        kind = doc.get("kind", "")
        meta = doc.get("metadata", {}) or {}
        nm = meta.get("name", kind.lower())
        spec = doc.get("spec", {}) or {}
        if kind in ("Deployment", "StatefulSet", "Pod", "DaemonSet", "Job"):
            el = Element(f"k8s_{idx}", f"{nm} ({kind})", ElementType.PROCESS,
                         TrustZone.APPLICATION,
                         {"internet_facing": False, "authenticated": False,
                          "authorization": False, "validates_input": False,
                          "rate_limited": False, "audit_logging": False,
                          "handles_sensitive": True, "technology": "kubernetes"},
                         source=rel)
            model.add_element(el)
            idx += 1
        elif kind == "Service":
            svc_type = spec.get("type", "ClusterIP")
            public = svc_type in ("LoadBalancer", "NodePort")
            el = Element(f"k8s_{idx}", f"{nm} (Service/{svc_type})", ElementType.PROCESS,
                         TrustZone.DMZ if public else TrustZone.APPLICATION,
                         {"internet_facing": public, "authenticated": False,
                          "rate_limited": False, "technology": "kubernetes"}, source=rel)
            model.add_element(el)
            if public:
                has_public = True
                model.add_flow(DataFlow(f"f_svc_{idx}", internet.id, el.id, name="ingress",
                                        data=["request"], protocol="https", encrypted=True))
            idx += 1
        elif kind == "Ingress":
            el = Element(f"k8s_{idx}", f"{nm} (Ingress)", ElementType.PROCESS,
                         TrustZone.DMZ, {"internet_facing": True, "authenticated": False,
                          "rate_limited": False, "technology": "kubernetes"}, source=rel)
            model.add_element(el)
            has_public = True
            model.add_flow(DataFlow(f"f_ing_{idx}", internet.id, el.id, name="ingress",
                                    data=["request"], protocol="https", encrypted=True))
            idx += 1
        elif kind in ("PersistentVolumeClaim", "Secret", "ConfigMap"):
            el = Element(f"k8s_{idx}", f"{nm} ({kind})", ElementType.DATA_STORE,
                         TrustZone.DATA, {"handles_sensitive": kind in ("Secret", "PersistentVolumeClaim"),
                          "encrypted": False, "integrity_protected": False,
                          "audit_logging": False, "data": ["secrets" if kind == "Secret" else "data"],
                          "technology": "kubernetes"}, source=rel)
            model.add_element(el)
            idx += 1

    if not has_public:
        model.elements = [e for e in model.elements if e.id != "internet"]
    return model


def analyze_iac(root: str, name: str | None = None) -> SystemModel:
    """Auto-detect Terraform vs Kubernetes and analyze."""
    root = os.path.abspath(root)
    tf = _find_tf_files(root)
    if tf:
        return analyze_terraform(root, name=name)
    return analyze_kubernetes(root, name=name)
