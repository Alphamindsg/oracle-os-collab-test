#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

SHA40 = re.compile(r"^[0-9a-f]{40}$")
TERMINAL = {"verified_fixed", "verified_not_affected", "documented_exception"}
FORBIDDEN_KEYS = {"secret", "token", "password", "private_key", "authority", "credential"}


def load_contract(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _walk_keys(value, path="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            yield path, str(key).lower()
            yield from _walk_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            yield from _walk_keys(child, f"{path}[{idx}]")


def validate(contract, exact_head=None):
    errors = []
    if contract.get("laboratory_only") is not True:
        errors.append("canary must remain laboratory_only")

    source = contract.get("source", {})
    if not SHA40.fullmatch(str(source.get("head_sha", ""))):
        errors.append("source evidence requires an exact 40-hex head_sha")
    if not source.get("version"):
        errors.append("source capability version is required")

    edges = contract.get("dependency_edges", [])
    graph = {}
    for edge in edges:
        if not isinstance(edge, list) or len(edge) != 2:
            errors.append("dependency edge must be [from, to]")
            continue
        graph.setdefault(edge[0], []).append(edge[1])
        graph.setdefault(edge[1], [])

    visiting, visited = set(), set()

    def visit(node):
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for nxt in sorted(graph.get(node, [])):
            if visit(nxt):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    if any(visit(node) for node in sorted(graph) if node not in visited):
        errors.append("dependency graph contains a cycle")

    for blocker in contract.get("shared_blockers", []):
        affected = blocker.get("affected_repos", [])
        dispositions = blocker.get("dispositions", {})
        if blocker.get("status") == "closed":
            for repo in affected:
                if dispositions.get(repo) not in TERMINAL:
                    errors.append(f"closed blocker {blocker.get('id')} lacks terminal disposition for {repo}")
        evidence = blocker.get("evidence", {})
        if not SHA40.fullmatch(str(evidence.get("head_sha", ""))):
            errors.append(f"blocker {blocker.get('id')} evidence lacks exact head")
        if not evidence.get("run_id"):
            errors.append(f"blocker {blocker.get('id')} evidence lacks run_id")

    for defect in contract.get("defects", []):
        if defect.get("material"):
            if not defect.get("reproducer"):
                errors.append(f"material defect {defect.get('id')} lacks reproducer")
            if not defect.get("root_cause"):
                errors.append(f"material defect {defect.get('id')} lacks root_cause")
            if not defect.get("regression_guard"):
                errors.append(f"material defect {defect.get('id')} lacks regression_guard")
            if not defect.get("applicability"):
                errors.append(f"material defect {defect.get('id')} lacks applicability decision")

    for path, key in _walk_keys(contract):
        normalized = key.replace("-", "_")
        if normalized in FORBIDDEN_KEYS or normalized.endswith("_secret") or normalized.endswith("_token"):
            errors.append(f"forbidden shared authority/secret field at {path}: {key}")

    if exact_head is not None and not SHA40.fullmatch(exact_head):
        errors.append("runtime exact head must be a 40-hex SHA")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("contract")
    parser.add_argument("--exact-head")
    args = parser.parse_args()
    contract = load_contract(args.contract)
    errors = validate(contract, args.exact_head)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        raise SystemExit(1)
    print(f"PASS: {contract['canary_id']} validated")
    if args.exact_head:
        print(f"EXACT_HEAD: {args.exact_head}")


if __name__ == "__main__":
    main()
