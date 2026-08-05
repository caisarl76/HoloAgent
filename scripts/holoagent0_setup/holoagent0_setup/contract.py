"""Load and enforce the closed HoloAgent0 evidence contract.

The project intentionally has no runtime JSON Schema dependency.  This module
implements only the Draft 2020-12 keyword subset used by the tracked schemas;
it is not, and must not be presented as, a general JSON Schema validator.
Cross-field gate decisions are enforced from the tracked policy tables.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Iterable, Mapping, Sequence
from urllib.parse import urlparse


_SCHEMA_FILES = {
    "agentos-plan-v1",
    "holoagent0-offline-ledger-v1",
    "holoagent0-result-v1",
    "holoagent0-trace-tool-policy-v1",
    "openclaw-provisioning-v1",
}
_POLICY_FILES = {
    "holoagent0-gate-policy-v1",
    "holoagent0-reason-codes-v1",
    "holoagent0-trace-tool-v1",
}
_EXPECTED_SCHEMA_IDS = {
    "agentos-plan-v1": "holoagent.agentos.plan.v1",
    "holoagent0-offline-ledger-v1": "holoagent0.offline-ledger.v1",
    "holoagent0-result-v1": "holoagent0.result.v1",
    "holoagent0-trace-tool-policy-v1": "holoagent0.trace-tool-policy.v1",
    "openclaw-provisioning-v1": "holoagent0.openclaw.provisioning.v1",
}
_EXPECTED_POLICY_VERSIONS = {
    "holoagent0-gate-policy-v1": "holoagent0.gate-policy.v1",
    "holoagent0-reason-codes-v1": "holoagent0.reason-codes.v1",
    "holoagent0-trace-tool-v1": "holoagent0.trace-tool-policy.v1",
}

_TRACE_OPTIONS = (
    "--kill-on-exit",
    "-f",
    "-yy",
    "-ttt",
    "-T",
    "--no-abbrev",
    "--string-limit=1048576",
    "--quiet=none",
    "--trace=all",
)
_TRACE_RAW_SYSCALLS = (
    "read",
    "readv",
    "pread64",
    "preadv",
    "preadv2",
    "write",
    "writev",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "sendfile",
    "splice",
    "vmsplice",
    "tee",
    "copy_file_range",
)
_TRACE_DECODED_ADDRESS_SYSCALLS = (
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "sendmmsg",
    "recvmmsg",
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ValidationDecision:
    """Stable result of validating one evidence document."""

    ok: bool
    code: str
    errors: tuple[str, ...] = ()


class ContractLoadError(ValueError):
    """Raised when tracked contract data is absent, malformed, or unreviewed."""


class ContractError(ValueError):
    """Raised by :meth:`ContractSet.require_valid_result` for invalid evidence."""

    def __init__(self, decision: ValidationDecision) -> None:
        self.decision = decision
        detail = "; ".join(decision.errors) or decision.code
        super().__init__(f"{decision.code}: {detail}")


class ContractSet:
    """One immutable-on-disk set of schemas and reviewed policy tables."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)
        self.schemas = _load_closed_json(self.root / "schemas")
        self.policies = _load_closed_json(self.root / "policies")
        _require_exact_keys("schema", self.schemas, _SCHEMA_FILES)
        _require_exact_keys("policy", self.policies, _POLICY_FILES)
        self._validate_contract_files()
        self._digests = _contract_digests(self.root)
        self._schemas = copy.deepcopy(self.schemas)
        self._policies = copy.deepcopy(self.policies)

    def validate_result(self, value: Mapping[str, object]) -> ValidationDecision:
        schema_errors = tuple(
            _schema_errors(self._schemas["holoagent0-result-v1"], value)
        )
        policy_errors: tuple[str, ...] = ()
        if not schema_errors:
            policy_errors = tuple(_policy_errors(self._policies, value)) + tuple(
                _digest_binding_errors(self._digests, value)
            )
        errors = schema_errors + policy_errors
        return ValidationDecision(
            not errors,
            "OK" if not errors else "EVIDENCE_SCHEMA_INVALID",
            errors,
        )

    def require_valid_result(self, value: Mapping[str, object]) -> None:
        """Require a valid result or raise a dedicated, inspectable error."""

        decision = self.validate_result(value)
        if not decision.ok:
            raise ContractError(decision)

    def validate_document(
        self, schema_name: str, value: Mapping[str, object]
    ) -> ValidationDecision:
        """Validate against one tracked schema and its closed semantic checks."""

        if schema_name == "holoagent0-result-v1":
            return self.validate_result(value)
        schema = self._schemas.get(schema_name)
        if schema is None:
            errors = (f"unknown tracked schema: {schema_name}",)
        else:
            errors = tuple(_schema_errors(schema, value))
            if not errors and schema_name == "agentos-plan-v1":
                errors = tuple(_agentos_plan_errors(value))
            if not errors and schema_name == "holoagent0-offline-ledger-v1":
                errors = tuple(_offline_ledger_errors(self._policies, value))
        return ValidationDecision(
            not errors,
            "OK" if not errors else "EVIDENCE_SCHEMA_INVALID",
            errors,
        )

    def trace_tool_rows(self) -> tuple[dict[str, object], ...]:
        """Return defensive copies of the single reviewed trace-tool row."""

        rows = self._policies["holoagent0-trace-tool-v1"]["rows"]
        return tuple(copy.deepcopy(row) for row in rows)

    def _validate_contract_files(self) -> None:
        for name, expected_id in _EXPECTED_SCHEMA_IDS.items():
            schema = self.schemas[name]
            if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                raise ContractLoadError(f"schema {name} is not Draft 2020-12")
            if schema.get("$id") != expected_id:
                raise ContractLoadError(f"schema {name} has the wrong $id")
            _reject_unsupported_schema_keywords(schema, name)

        for name, expected_version in _EXPECTED_POLICY_VERSIONS.items():
            policy = self.policies[name]
            if policy.get("$id") != expected_version:
                raise ContractLoadError(f"policy {name} has the wrong $id")
            if policy.get("schema_version") != expected_version:
                raise ContractLoadError(f"policy {name} has the wrong version")
            if policy.get("additionalProperties") is not False:
                raise ContractLoadError(f"policy {name} is not closed")

        trace_policy = self.policies["holoagent0-trace-tool-v1"]
        trace_errors = tuple(
            _schema_errors(
                self.schemas["holoagent0-trace-tool-policy-v1"], trace_policy
            )
        )
        if trace_errors:
            raise ContractLoadError(
                "trace tool policy does not match its schema: "
                + "; ".join(trace_errors)
            )
        _require_reviewed_trace_policy(trace_policy)
        _validate_policy_integrity(self.policies)


def _load_closed_json(root: Path) -> dict[str, dict[str, object]]:
    """Load only regular, non-symlink JSON files from one resolved directory."""

    resolved_root = root.resolve(strict=True)
    if not resolved_root.is_dir():
        raise ContractLoadError(f"contract path is not a directory: {resolved_root}")

    loaded: dict[str, dict[str, object]] = {}
    entries = sorted(resolved_root.iterdir(), key=lambda path: path.name)
    for path in entries:
        if path.is_symlink() or not path.is_file() or path.suffix != ".json":
            raise ContractLoadError(f"unexpected contract directory entry: {path.name}")
        name = path.name
        key = (
            name[: -len(".schema.json")] if name.endswith(".schema.json") else name[:-5]
        )
        if key in loaded:
            raise ContractLoadError(f"duplicate contract key: {key}")
        try:
            value = json.loads(
                path.read_text(encoding="utf-8"),
                parse_constant=lambda token: (_ for _ in ()).throw(
                    ValueError(f"non-JSON numeric constant {token}")
                ),
            )
        except (OSError, UnicodeError, ValueError) as error:
            raise ContractLoadError(f"invalid JSON contract {path}: {error}") from error
        if not isinstance(value, dict):
            raise ContractLoadError(f"contract root must be an object: {path}")
        loaded[key] = value
    return loaded


def _require_exact_keys(
    kind: str, actual: Mapping[str, object], expected: set[str]
) -> None:
    actual_keys = set(actual)
    if actual_keys != expected:
        missing = sorted(expected - actual_keys)
        extra = sorted(actual_keys - expected)
        raise ContractLoadError(
            f"closed {kind} inventory mismatch; missing={missing}, extra={extra}"
        )


def _contract_digests(root: Path) -> dict[str, str]:
    paths = {
        "result_schema_sha256": root / "schemas/holoagent0-result-v1.schema.json",
        "openclaw_provisioning_schema_sha256": root
        / "schemas/openclaw-provisioning-v1.schema.json",
        "offline_ledger_schema_sha256": root
        / "schemas/holoagent0-offline-ledger-v1.schema.json",
        "trace_tool_policy_schema_sha256": root
        / "schemas/holoagent0-trace-tool-policy-v1.schema.json",
        "agentos_plan_schema_sha256": root / "schemas/agentos-plan-v1.schema.json",
        "gate_policy_sha256": root / "policies/holoagent0-gate-policy-v1.json",
        "reason_code_policy_sha256": root / "policies/holoagent0-reason-codes-v1.json",
        "trace_tool_policy_sha256": root / "policies/holoagent0-trace-tool-v1.json",
    }
    return {
        field: hashlib.sha256(path.read_bytes()).hexdigest()
        for field, path in paths.items()
    }


def _digest_binding_errors(
    expected: Mapping[str, str], value: Mapping[str, object]
) -> Iterable[str]:
    for field, digest in expected.items():
        if field in value and value[field] != digest:
            yield f"$.{field}: does not bind the loaded contract artifact"


_SUPPORTED_SCHEMA_KEYWORDS = {
    "$schema",
    "$id",
    "$defs",
    "$ref",
    "$comment",
    "type",
    "required",
    "properties",
    "additionalProperties",
    "const",
    "enum",
    "allOf",
    "anyOf",
    "oneOf",
    "if",
    "then",
    "else",
    "not",
    "items",
    "prefixItems",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minLength",
    "maxLength",
    "pattern",
    "format",
    "minimum",
    "maximum",
}


def _reject_unsupported_schema_keywords(schema: object, name: str) -> None:
    def visit(node: object, path: str) -> None:
        if isinstance(node, bool):
            return
        if not isinstance(node, dict):
            raise ContractLoadError(f"schema {name} has invalid node at {path}")
        unsupported = set(node) - _SUPPORTED_SCHEMA_KEYWORDS
        if unsupported:
            raise ContractLoadError(
                f"schema {name} uses unsupported keywords at {path}: "
                f"{sorted(unsupported)}"
            )
        _validate_schema_keyword_shapes(node, name, path)
        for container in ("properties", "$defs"):
            children = node.get(container, {})
            if isinstance(children, dict):
                for key, child in children.items():
                    visit(child, f"{path}.{container}.{key}")
        for container in ("allOf", "anyOf", "oneOf", "prefixItems"):
            children = node.get(container, [])
            if isinstance(children, list):
                for index, child in enumerate(children):
                    visit(child, f"{path}.{container}[{index}]")
        for key in ("items", "if", "then", "else", "not", "additionalProperties"):
            child = node.get(key)
            if isinstance(child, (dict, bool)):
                visit(child, f"{path}.{key}")

    visit(schema, "$")


def _validate_schema_keyword_shapes(
    node: Mapping[str, object], name: str, path: str
) -> None:
    def invalid(keyword: str) -> ContractLoadError:
        return ContractLoadError(
            f"schema {name} has invalid {keyword} keyword at {path}"
        )

    if "$schema" in node and not isinstance(node["$schema"], str):
        raise invalid("$schema")
    if "$id" in node and not isinstance(node["$id"], str):
        raise invalid("$id")
    if "$ref" in node and (
        not isinstance(node["$ref"], str) or not node["$ref"].startswith("#/")
    ):
        raise invalid("$ref")
    allowed_types = {
        "object",
        "array",
        "string",
        "integer",
        "number",
        "boolean",
        "null",
    }
    if "type" in node:
        declared = node["type"]
        types = declared if isinstance(declared, list) else [declared]
        if not types or any(
            not isinstance(item, str) or item not in allowed_types for item in types
        ):
            raise invalid("type")
    if "required" in node and (
        not isinstance(node["required"], list)
        or any(not isinstance(item, str) for item in node["required"])
        or len(node["required"]) != len(set(node["required"]))
    ):
        raise invalid("required")
    for keyword in ("properties", "$defs"):
        if keyword in node and not isinstance(node[keyword], dict):
            raise invalid(keyword)
    for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
        if keyword in node and not isinstance(node[keyword], list):
            raise invalid(keyword)
    if "enum" in node and (not isinstance(node["enum"], list) or not node["enum"]):
        raise invalid("enum")
    for keyword in ("minItems", "maxItems", "minLength", "maxLength"):
        if keyword in node and (
            not isinstance(node[keyword], int)
            or isinstance(node[keyword], bool)
            or node[keyword] < 0
        ):
            raise invalid(keyword)
    for keyword in ("minimum", "maximum"):
        if keyword in node and not _is_number(node[keyword]):
            raise invalid(keyword)
    if "uniqueItems" in node and not isinstance(node["uniqueItems"], bool):
        raise invalid("uniqueItems")
    if "pattern" in node:
        if not isinstance(node["pattern"], str):
            raise invalid("pattern")
        try:
            re.compile(node["pattern"])
        except re.error as error:
            raise invalid("pattern") from error
    if "format" in node and node["format"] not in {"date-time", "uri"}:
        raise invalid("format")
    if "additionalProperties" in node and node["additionalProperties"] is not False:
        raise invalid("additionalProperties")
    for keyword in ("items", "if", "then", "else", "not"):
        if keyword in node and not isinstance(node[keyword], (dict, bool)):
            raise invalid(keyword)


def _require_reviewed_trace_policy(policy: Mapping[str, object]) -> None:
    rows = policy.get("rows")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ContractLoadError("trace tool policy must contain exactly one row")
    row = rows[0]
    source = row.get("source")
    argv = row.get("argv")
    exact_scalars = {
        "tool": "strace",
        "version": "6.6",
        "platform": "linux-x86_64",
        "syscall_abi": "linux-x86_64",
    }
    if any(row.get(key) != expected for key, expected in exact_scalars.items()):
        raise ContractLoadError("trace tool policy row identity differs from review")
    if not isinstance(source, dict) or source != {
        "url": "https://strace.io/files/6.6/strace-6.6.tar.xz",
        "size": 2420364,
        "sha256": "421b4186c06b705163e64dc85f271ebdcf67660af8667283147d5e859fc8a96c",
    }:
        raise ContractLoadError("trace tool policy source pin differs from review")
    if not isinstance(argv, dict):
        raise ContractLoadError("trace tool policy argv is missing")
    if tuple(argv.get("options", ())) != _TRACE_OPTIONS:
        raise ContractLoadError("trace tool policy invocation differs from review")
    if tuple(argv.get("raw_syscalls", ())) != _TRACE_RAW_SYSCALLS:
        raise ContractLoadError("trace tool policy raw syscall set differs from review")
    if (
        tuple(argv.get("decoded_address_syscalls", ()))
        != _TRACE_DECODED_ADDRESS_SYSCALLS
    ):
        raise ContractLoadError(
            "trace tool policy decoded syscall set differs from review"
        )
    if argv.get("environment") != {"LC_ALL": "C", "TZ": "UTC"}:
        raise ContractLoadError("trace tool policy environment differs from review")
    reviewed_fields = {
        "build": ("recipe_sha256", "container_image_digest"),
        "runtime": ("elf_size", "elf_sha256", "version_output_sha256"),
        "parser": ("sha256",),
        "argv": ("canonical_sha256",),
        "fixtures": ("manifest_sha256",),
    }
    for section_name, fields in reviewed_fields.items():
        section = row.get(section_name)
        if not isinstance(section, dict):
            raise ContractLoadError(f"trace tool policy {section_name} is missing")
        state = section.get("review_state")
        values = [section.get(field) for field in fields]
        if state == "REVIEWED" and any(value is None for value in values):
            raise ContractLoadError(
                f"trace tool policy {section_name} claims review without literal pins"
            )
        if state != "REVIEWED" and any(value is not None for value in values):
            raise ContractLoadError(
                f"trace tool policy {section_name} has unreviewed literal pins"
            )


def _validate_policy_integrity(policies: Mapping[str, Mapping[str, object]]) -> None:
    gate_policy = policies["holoagent0-gate-policy-v1"]
    reason_policy = policies["holoagent0-reason-codes-v1"]
    expected_gate_keys = {
        "$id",
        "schema_version",
        "digest_algorithm",
        "gate_statuses",
        "top_statuses",
        "roles",
        "profiles",
        "label_tuples",
        "non_failure_outcomes",
        "failure_outcomes",
        "precedence",
        "safety_gate_patterns",
        "harness_gates",
        "same_class_tie_breaker",
        "additionalProperties",
    }
    expected_reason_keys = {
        "$id",
        "schema_version",
        "digest_algorithm",
        "reason_codes",
        "gate_status_reasons",
        "nested_contexts",
        "emergency_record_reasons",
        "additionalProperties",
    }
    if set(gate_policy) != expected_gate_keys:
        raise ContractLoadError("gate policy root fields are not closed")
    if set(reason_policy) != expected_reason_keys:
        raise ContractLoadError("reason policy root fields are not closed")
    if gate_policy.get("precedence") != [
        "safety",
        "harness",
        "interruption",
        "functional",
        "qualification",
        "pass",
    ]:
        raise ContractLoadError("gate policy precedence differs from review")
    if gate_policy.get("same_class_tie_breaker") != "profile_gate_order":
        raise ContractLoadError("gate policy tie breaker differs from review")
    expected_lists = {
        "gate_statuses": ["PASS", "FAIL", "QUALIFIED", "SKIPPED", "NOT_RUN"],
        "top_statuses": ["PASS", "QUALIFIED", "FAIL", "INTERRUPTED"],
        "roles": [
            "required",
            "diagnostic",
            "qualification",
            "required_qualification",
            "finalizer",
        ],
        "safety_gate_patterns": [
            "safety.*",
            "pc2.camera_cleanup",
            "offline.network_policy",
        ],
        "harness_gates": ["offline.trace_integrity", "offline.evidence_binding"],
    }
    for field, expected_values in expected_lists.items():
        values = gate_policy.get(field)
        if values != expected_values:
            raise ContractLoadError(f"gate policy {field} differs from review")
    profiles = gate_policy.get("profiles")
    if not isinstance(profiles, dict) or set(profiles) != {
        "workstation_offline",
        "workstation_mujoco",
        "pc2_inventory",
        "pc2_camera",
        "pc2_full_streams",
    }:
        raise ContractLoadError("gate policy profile catalog is not closed")

    catalog: set[str] = set()
    for mode, profile in profiles.items():
        if not isinstance(profile, dict):
            raise ContractLoadError(f"gate policy profile is invalid: {mode}")
        if set(profile) != {"gate_order", "roles", "finalizers"}:
            raise ContractLoadError(
                f"gate policy profile fields are not closed: {mode}"
            )
        order = profile.get("gate_order")
        roles = profile.get("roles")
        finalizers = profile.get("finalizers")
        if not isinstance(order, list) or len(order) != len(set(order)):
            raise ContractLoadError(f"gate policy order is invalid: {mode}")
        if not isinstance(roles, dict) or list(roles) != order:
            raise ContractLoadError(f"gate policy roles do not match order: {mode}")
        if not isinstance(finalizers, dict):
            raise ContractLoadError(f"gate policy finalizers are invalid: {mode}")
        if set(finalizers) != {
            gate for gate, role in roles.items() if role == "finalizer"
        }:
            raise ContractLoadError(f"mandatory finalizers are incomplete: {mode}")
        catalog.update(order)

    label_tuples = gate_policy.get("label_tuples")
    if not isinstance(label_tuples, list) or any(
        not isinstance(row, dict)
        or set(row) != {"labels", "status", "exit_class", "process_exit_code"}
        or not isinstance(row.get("labels"), list)
        or not row["labels"]
        or any(not isinstance(label, str) for label in row["labels"])
        or not isinstance(row.get("status"), str)
        or not isinstance(row.get("exit_class"), str)
        or not isinstance(row.get("process_exit_code"), int)
        or isinstance(row.get("process_exit_code"), bool)
        for row in label_tuples
    ):
        raise ContractLoadError("gate policy tuple rows are not closed")
    for key in ("non_failure_outcomes", "failure_outcomes"):
        outcomes = gate_policy.get(key)
        if not isinstance(outcomes, dict) or set(outcomes) != set(profiles):
            raise ContractLoadError(f"gate policy {key} profile keys are not closed")
        for mode, mapping in outcomes.items():
            if not isinstance(mapping, dict) or any(
                not isinstance(selector, str) or not isinstance(label, str)
                for selector, label in mapping.items()
            ):
                raise ContractLoadError(
                    f"gate policy {key} mappings are invalid for {mode}"
                )

    mappings = reason_policy.get("gate_status_reasons")
    codes = reason_policy.get("reason_codes")
    if not isinstance(mappings, dict) or set(mappings) != catalog:
        raise ContractLoadError("reason policy gate catalog differs from gate policy")
    if not isinstance(codes, list) or len(codes) != len(set(codes)):
        raise ContractLoadError("reason code enum is invalid")
    known_codes = set(codes)
    for gate_id, statuses in mappings.items():
        if not isinstance(statuses, dict) or not statuses:
            raise ContractLoadError(f"reason policy is empty for {gate_id}")
        for status, reasons in statuses.items():
            if status not in {"PASS", "FAIL", "QUALIFIED", "SKIPPED", "NOT_RUN"}:
                raise ContractLoadError(
                    f"unknown gate status in reason policy: {status}"
                )
            if (
                not isinstance(reasons, list)
                or not reasons
                or not set(reasons) <= known_codes
            ):
                raise ContractLoadError(
                    f"unknown or empty reason mapping for {gate_id}/{status}"
                )
    nested = reason_policy.get("nested_contexts")
    if not isinstance(nested, dict) or set(nested) != {"inventory_candidate"}:
        raise ContractLoadError("reason policy nested contexts are not closed")
    inventory = nested["inventory_candidate"]
    if not isinstance(inventory, dict) or set(inventory) != {
        "policy_state",
        "allowed_reason",
        "containing_gate_status",
        "containing_gate_reason",
    }:
        raise ContractLoadError("inventory reason context fields are not closed")


def _policy_errors(
    policies: Mapping[str, Mapping[str, object]], value: Mapping[str, object]
) -> Iterable[str]:
    gate_policy = policies["holoagent0-gate-policy-v1"]
    reason_policy = policies["holoagent0-reason-codes-v1"]
    profiles = gate_policy["profiles"]
    mode = value.get("mode")
    if not isinstance(mode, str) or mode not in profiles:
        yield "$.mode: no closed profile policy exists"
        return

    profile = profiles[mode]
    expected_order = profile["gate_order"]
    expected_roles = profile["roles"]
    gates = value.get("gates")
    if not isinstance(gates, list):
        yield "$.gates: must be an array before policy validation"
        return
    gate_ids = [gate.get("id") if isinstance(gate, dict) else None for gate in gates]
    if gate_ids != expected_order:
        yield f"$.gates: expected exact {mode} gate order"

    gates_by_id: dict[str, Mapping[str, object]] = {}
    for index, gate in enumerate(gates):
        if not isinstance(gate, dict):
            yield f"$.gates[{index}]: must be an object"
            continue
        gate_id = gate.get("id")
        if not isinstance(gate_id, str) or gate_id not in expected_roles:
            yield f"$.gates[{index}].id: unknown or wrong-profile gate"
            continue
        if gate_id in gates_by_id:
            yield f"$.gates[{index}].id: duplicate gate {gate_id}"
            continue
        gates_by_id[gate_id] = gate
        if gate.get("role") != expected_roles[gate_id]:
            yield f"$.gates[{index}].role: wrong role for {gate_id}"
        status = gate.get("status")
        reason = gate.get("reason")
        allowed = reason_policy["gate_status_reasons"][gate_id]
        role_statuses = {
            "required": {"PASS", "FAIL", "NOT_RUN"},
            "diagnostic": {"PASS", "FAIL", "SKIPPED", "NOT_RUN"},
            "qualification": {"PASS", "QUALIFIED", "NOT_RUN"},
            "required_qualification": {"PASS", "FAIL", "QUALIFIED", "NOT_RUN"},
            "finalizer": {"PASS", "FAIL", "SKIPPED"},
        }
        expected_role = expected_roles[gate_id]
        if not isinstance(status, str):
            yield f"$.gates[{index}].status: must be a string"
        elif status not in role_statuses[expected_role]:
            yield f"$.gates[{index}].status: {status!r} is invalid for role {expected_role}"
        elif status not in allowed:
            yield f"$.gates[{index}].status: {status!r} is invalid for {gate_id}"
        elif reason not in allowed[status]:
            yield (
                f"$.gates[{index}].reason: {reason!r} is invalid for {gate_id}/{status}"
            )

    yield from _lineage_errors(mode, value)
    yield from _result_timing_errors(value)
    yield from _mode_evidence_errors(mode, value)
    yield from _conditional_status_errors(mode, gates_by_id)
    yield from _trace_authorization_errors(policies, mode, value.get("status"))
    yield from _terminal_state_errors(
        expected_order, expected_roles, gates_by_id, value.get("status")
    )
    yield from _selector_and_outcome_errors(
        gate_policy, mode, expected_order, expected_roles, gates_by_id, value
    )


def _lineage_errors(mode: str, value: Mapping[str, object]) -> Iterable[str]:
    role = value.get("invocation_role")
    parent = value.get("parent_run_id")
    nonce = value.get("lineage_nonce")
    if role == "child":
        if mode != "workstation_offline":
            yield "$.invocation_role: only workstation_offline may be a child"
        if not isinstance(parent, str) or not parent:
            yield "$.parent_run_id: child requires a non-null parent run ID"
        if not isinstance(nonce, str) or _SHA256_PATTERN.fullmatch(nonce) is None:
            yield "$.lineage_nonce: child requires a 64-character lowercase-hex nonce"
    else:
        if parent is not None or nonce is not None:
            yield "$.parent_run_id/lineage_nonce: non-child lineage fields must be null"
    if mode == "workstation_mujoco" and role != "parent":
        yield "$.invocation_role: workstation_mujoco must be a parent"
    if mode.startswith("pc2_") and role != "standalone":
        yield "$.invocation_role: PC2 profiles must be standalone"


def _result_timing_errors(value: Mapping[str, object]) -> Iterable[str]:
    started = _parse_datetime(value.get("started_at"))
    ended = _parse_datetime(value.get("ended_at"))
    if started is not None and ended is not None and ended < started:
        yield "$.started_at/ended_at: result timestamps are reversed"


def _mode_evidence_errors(mode: str, value: Mapping[str, object]) -> Iterable[str]:
    workstation_digest_fields = {
        "agentos_plan_schema_sha256",
        "openclaw_provisioning_schema_sha256",
        "offline_ledger_schema_sha256",
        "trace_tool_policy_sha256",
        "trace_tool_policy_schema_sha256",
        "trace_parser_fixture_manifest_sha256",
        "cyclonedds_config_set_sha256",
        "graph_sha256",
        "dataset_sha256",
        "checkpoint_sha256",
    }
    if mode.startswith("pc2_"):
        forbidden = workstation_digest_fields | {
            "offline_evidence",
            "offline_evidence_bundle_sha256",
            "offline_reference_evidence_bundle_sha256",
        }
        for field in sorted(forbidden & value.keys()):
            yield f"$.{field}: workstation-only evidence is forbidden in PC2 results"
        if value.get("status") == "PASS":
            evidence = value.get("pc2_evidence")
            if isinstance(evidence, dict):
                started = _parse_datetime(evidence.get("action_window_started_at"))
                ended = _parse_datetime(evidence.get("action_window_ended_at"))
                if started is None:
                    yield "$.pc2_evidence.action_window_started_at: PASS requires a timestamp"
                if ended is None:
                    yield "$.pc2_evidence.action_window_ended_at: PASS requires a timestamp"
                if started is not None and ended is not None and ended < started:
                    yield "$.pc2_evidence: action window timestamps are reversed"
                samples = evidence.get("monitor_samples")
                if not isinstance(samples, list) or not samples:
                    yield "$.pc2_evidence.monitor_samples: PASS requires monitor evidence"
                elif started is not None and ended is not None:
                    for sample in samples:
                        if not isinstance(sample, dict):
                            continue
                        timestamp = _parse_datetime(sample.get("timestamp"))
                        if timestamp is not None and not started <= timestamp <= ended:
                            yield "$.pc2_evidence.monitor_samples: sample is outside action window"
                        if sample.get("state") == "CONTROL_VIOLATION":
                            yield "$.pc2_evidence.monitor_samples: PASS cannot contain CONTROL_VIOLATION"
                        if (
                            mode in {"pc2_camera", "pc2_full_streams"}
                            and sample.get("state") != "EXACT_MATCH"
                        ):
                            yield "$.pc2_evidence.monitor_samples: camera/streams PASS requires EXACT_MATCH"
                if mode in {"pc2_camera", "pc2_full_streams"}:
                    processes = evidence.get("owned_processes")
                    if not isinstance(processes, list) or not processes:
                        yield "$.pc2_evidence.owned_processes: camera PASS requires owned identity evidence"
        return

    if "pc2_evidence" in value:
        yield "$.pc2_evidence: PC2-only evidence is forbidden in workstation results"
    if "script_sha256" in value:
        yield "$.script_sha256: PC2-only digest is forbidden in workstation results"
    if mode == "workstation_offline":
        if "offline_reference_evidence_bundle_sha256" in value:
            yield "$.offline_reference_evidence_bundle_sha256: parent-only evidence"
        evidence = value.get("offline_evidence")
        top_digest = value.get("offline_evidence_bundle_sha256")
        if isinstance(evidence, dict) and evidence.get("bundle_sha256") != top_digest:
            yield "$.offline_evidence.bundle_sha256: must equal the top-level bundle digest"
        if isinstance(evidence, dict):
            window = evidence.get("semantic_dds_window")
            begin = evidence.get("dds_begin_record_index")
            end = evidence.get("dds_end_record_index")
            if window == "NOT_ENTERED" and (begin is not None or end is not None):
                yield "$.offline_evidence: NOT_ENTERED requires null DDS marker indices"
            if window == "CLOSED" and (
                not isinstance(begin, int)
                or isinstance(begin, bool)
                or not isinstance(end, int)
                or isinstance(end, bool)
                or begin > end
            ):
                yield "$.offline_evidence: CLOSED requires ordered DDS marker indices"
    elif mode == "workstation_mujoco":
        for field in ("offline_evidence", "offline_evidence_bundle_sha256"):
            if field in value:
                yield f"$.{field}: child-only evidence is forbidden in the MuJoCo parent"


def _conditional_status_errors(
    mode: str, gates: Mapping[str, Mapping[str, object]]
) -> Iterable[str]:
    if mode == "workstation_offline":
        trace_status = gates.get("offline.trace_integrity", {}).get("status")
        network_status = gates.get("offline.network_policy", {}).get("status")
        if network_status == "SKIPPED" and trace_status != "FAIL":
            yield "$.gates[offline.network_policy]: skip requires failed trace integrity"
    if mode.startswith("pc2_"):
        preflight = gates.get("safety.pc2_preflight", {}).get("status")
        monitor = gates.get("safety.pc2_runtime_monitor", {}).get("status")
        if monitor == "SKIPPED" and preflight != "FAIL":
            yield "$.gates[safety.pc2_runtime_monitor]: skip requires failed preflight"
    if mode in {"pc2_camera", "pc2_full_streams"}:
        cleanup = gates.get("pc2.camera_cleanup", {}).get("status")
        camera_sample = gates.get("pc2.camera_sample", {}).get("status")
        camera_rate = gates.get("pc2.camera_rate", {}).get("status")
        if cleanup == "SKIPPED" and (camera_sample == "PASS" or camera_rate == "PASS"):
            yield "$.gates[pc2.camera_cleanup]: skip contradicts successful camera action"

    for prefix, schema_gate in (("pc2.lidar", "pc2.lidar_schema"), ("pc2.imu", None)):
        advertisement = gates.get(f"{prefix}_advertisement", {})
        sample = gates.get(f"{prefix}_sample", {})
        dependent_ids = [f"{prefix}_sample", f"{prefix}_rate"]
        if schema_gate is not None:
            dependent_ids.append(schema_gate)
        for gate_id in dependent_ids:
            gate = gates.get(gate_id, {})
            if gate.get("status") != "SKIPPED":
                continue
            prerequisite_absent = advertisement.get("status") == "FAIL"
            if gate_id != f"{prefix}_sample":
                prerequisite_absent = (
                    prerequisite_absent or sample.get("status") == "FAIL"
                )
            if not prerequisite_absent:
                yield f"$.gates[{gate_id}]: skip requires an absent prerequisite"


def _trace_authorization_errors(
    policies: Mapping[str, Mapping[str, object]], mode: str, status: object
) -> Iterable[str]:
    if not mode.startswith("workstation_") or status not in {"PASS", "QUALIFIED"}:
        return
    row = policies["holoagent0-trace-tool-v1"]["rows"][0]
    for section_name in ("build", "runtime", "parser", "argv", "fixtures"):
        if row[section_name]["review_state"] != "REVIEWED":
            yield f"trace tool policy {section_name} is not reviewed for readiness"


def _terminal_state_errors(
    order: Sequence[str],
    roles: Mapping[str, str],
    gates: Mapping[str, Mapping[str, object]],
    top_status: object,
) -> Iterable[str]:
    blocking_action_seen = False
    interrupted_action_seen = False
    for gate_id in order:
        gate = gates.get(gate_id)
        if gate is None:
            continue
        role = roles[gate_id]
        status = gate.get("status")
        reason = gate.get("reason")
        if role != "finalizer":
            if (
                status == "NOT_RUN"
                and reason == "EARLIER_BLOCKING_GATE"
                and not blocking_action_seen
            ):
                yield f"$.gates[{gate_id}]: EARLIER_BLOCKING_GATE has no earlier block"
            if (
                status == "NOT_RUN"
                and reason == "INTERRUPTED_BEFORE_GATE"
                and top_status != "INTERRUPTED"
            ):
                yield f"$.gates[{gate_id}]: interrupted gate requires top-level interruption"
            if blocking_action_seen and status != "NOT_RUN":
                yield f"$.gates[{gate_id}]: later action gate must be NOT_RUN after a block"
            if interrupted_action_seen and status != "NOT_RUN":
                yield f"$.gates[{gate_id}]: later action gate must be NOT_RUN after interruption"
            if status == "FAIL" and role in {"required", "required_qualification"}:
                blocking_action_seen = True
            if status == "NOT_RUN" and reason == "INTERRUPTED_BEFORE_GATE":
                interrupted_action_seen = True


def _selector_and_outcome_errors(
    gate_policy: Mapping[str, object],
    mode: str,
    order: Sequence[str],
    roles: Mapping[str, str],
    gates: Mapping[str, Mapping[str, object]],
    value: Mapping[str, object],
) -> Iterable[str]:
    blockers = [
        gate_id
        for gate_id in order
        if gate_id in gates
        and gates[gate_id].get("status") == "FAIL"
        and roles[gate_id] in {"required", "required_qualification", "finalizer"}
    ]
    qualifications = [
        gate_id
        for gate_id in order
        if gate_id in gates and gates[gate_id].get("status") == "QUALIFIED"
    ]
    reported_blockers = value.get("blocking_gates")
    reported_qualifications = value.get("qualifications")
    if reported_blockers != blockers:
        yield "$.blocking_gates: must exactly list blocking failures in profile order"
    if reported_qualifications != qualifications:
        yield "$.qualifications: must exactly list QUALIFIED gates in profile order"

    status = value.get("status")
    label = value.get("label")
    primary = value.get("primary_blocking_gate")
    expected_primary = _primary_blocker(gate_policy, order, blockers)
    if primary != expected_primary:
        yield "$.primary_blocking_gate: does not select the precedence-winning blocker"

    if blockers:
        failure_map = gate_policy["failure_outcomes"][mode]
        expected_label = failure_map.get(expected_primary)
        if expected_label is None:
            yield "$.primary_blocking_gate: selected gate has no blocking outcome"
        elif label != expected_label:
            yield f"$.label: {expected_primary} requires {expected_label}"
        if status != "FAIL":
            yield "$.status: blocking gates require top-level FAIL"
    elif status == "INTERRUPTED":
        if label != "INTERRUPTED":
            yield "$.label: interruption requires INTERRUPTED"
        if not any(
            gate.get("reason") == "INTERRUPTED_BEFORE_GATE" for gate in gates.values()
        ):
            yield "$.status: interruption requires an INTERRUPTED_BEFORE_GATE marker"
    else:
        qualification_key = ",".join(qualifications)
        expected_label = gate_policy["non_failure_outcomes"][mode].get(
            qualification_key
        )
        if expected_label is None:
            yield "$.qualifications: qualification set has no closed mode outcome"
        elif label != expected_label:
            yield f"$.label: mode and qualification set require {expected_label}"
        expected_status = "QUALIFIED" if qualifications else "PASS"
        if status != expected_status:
            yield f"$.status: selector state requires {expected_status}"

    matching_tuples = [
        row
        for row in gate_policy["label_tuples"]
        if label in row["labels"]
        and status == row["status"]
        and value.get("exit_class") == row["exit_class"]
        and value.get("process_exit_code") == row["process_exit_code"]
    ]
    if len(matching_tuples) != 1:
        yield "$.label/status/exit_class/process_exit_code: tuple is not allowed"


def _primary_blocker(
    gate_policy: Mapping[str, object], order: Sequence[str], blockers: Sequence[str]
) -> str | None:
    if not blockers:
        return None
    classes = {
        "safety": set(gate_policy["safety_gate_patterns"][1:])
        | {gate for gate in blockers if gate.startswith("safety.")},
        "harness": set(gate_policy["harness_gates"]),
        "functional": set(blockers),
    }
    for class_name in gate_policy["precedence"]:
        candidate_class = classes.get(class_name, set())
        for gate_id in order:
            if gate_id in blockers and gate_id in candidate_class:
                return gate_id
    return None


def _schema_errors(schema: Mapping[str, object], value: object) -> Iterable[str]:
    """Validate the exact Draft 2020-12 subset used by tracked contracts."""

    root = schema
    yield from _validate_schema_node(schema, value, "$", root)


def _agentos_plan_errors(value: Mapping[str, object]) -> Iterable[str]:
    nodes = value.get("nodes")
    if not isinstance(nodes, list):
        return
    ids = [node.get("id") for node in nodes if isinstance(node, dict)]
    if len(ids) != len(set(ids)):
        yield "$.nodes: node IDs must be unique"
        return
    known_ids = set(ids)
    dependencies: dict[object, list[object]] = {}
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        node_id = node.get("id")
        depends_on = node.get("depends_on")
        if not isinstance(depends_on, list):
            continue
        dependencies[node_id] = depends_on
        for dependency in depends_on:
            if dependency not in known_ids:
                yield f"$.nodes[{index}].depends_on: unknown node ID {dependency!r}"

    visiting: set[object] = set()
    visited: set[object] = set()

    def has_cycle(node_id: object) -> bool:
        if node_id in visiting:
            return True
        if node_id in visited:
            return False
        visiting.add(node_id)
        cycle = any(
            dependency in dependencies and has_cycle(dependency)
            for dependency in dependencies.get(node_id, [])
        )
        visiting.remove(node_id)
        visited.add(node_id)
        return cycle

    if any(has_cycle(node_id) for node_id in dependencies):
        yield "$.nodes: depends_on graph must be acyclic"


def _offline_ledger_errors(
    policies: Mapping[str, Mapping[str, object]], value: Mapping[str, object]
) -> Iterable[str]:
    gates = value.get("gates")
    if not isinstance(gates, list):
        return
    profile = policies["holoagent0-gate-policy-v1"]["profiles"]["workstation_offline"]
    reasons = policies["holoagent0-reason-codes-v1"]["gate_status_reasons"]
    for index, (gate, gate_id) in enumerate(zip(gates, profile["gate_order"])):
        if not isinstance(gate, dict):
            continue
        status = gate.get("status")
        reason = gate.get("reason")
        allowed = reasons[gate_id]
        if not isinstance(status, str) or status not in allowed:
            yield f"$.gates[{index}].status: invalid ledger status for {gate_id}"
        elif reason not in allowed[status]:
            yield f"$.gates[{index}].reason: invalid ledger reason for {gate_id}/{status}"


def _validate_schema_node(
    schema: object, value: object, path: str, root: Mapping[str, object]
) -> Iterable[str]:
    if schema is True:
        return
    if schema is False:
        yield f"{path}: forbidden by schema"
        return
    if not isinstance(schema, dict):
        yield f"{path}: invalid tracked schema node"
        return

    reference = schema.get("$ref")
    if reference is not None:
        if not isinstance(reference, str) or not reference.startswith("#/"):
            yield f"{path}: unsupported non-local $ref"
            return
        target: object = root
        try:
            for part in reference[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                target = target[part]  # type: ignore[index]
        except (KeyError, TypeError):
            yield f"{path}: unresolved tracked schema $ref {reference}"
            return
        yield from _validate_schema_node(target, value, path, root)

    if "const" in schema and value != schema["const"]:
        yield f"{path}: expected constant {schema['const']!r}"
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        yield f"{path}: value is outside the closed enum"

    expected_type = schema.get("type")
    if expected_type is not None and not _matches_type(value, expected_type):
        yield f"{path}: expected JSON type {expected_type!r}"
        return

    if isinstance(value, dict):
        required = schema.get("required", ())
        if isinstance(required, list):
            for key in required:
                if key not in value:
                    yield f"{path}.{key}: required property is missing"
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, child_schema in properties.items():
                if key in value:
                    yield from _validate_schema_node(
                        child_schema, value[key], f"{path}.{key}", root
                    )
            if schema.get("additionalProperties") is False:
                for key in value.keys() - properties.keys():
                    yield f"{path}.{key}: additional property is forbidden"

    if isinstance(value, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if isinstance(minimum, int) and len(value) < minimum:
            yield f"{path}: has fewer than {minimum} items"
        if isinstance(maximum, int) and len(value) > maximum:
            yield f"{path}: has more than {maximum} items"
        if schema.get("uniqueItems") is True:
            encoded = [
                json.dumps(item, sort_keys=True, separators=(",", ":"))
                for item in value
            ]
            if len(encoded) != len(set(encoded)):
                yield f"{path}: array items must be unique"
        prefix = schema.get("prefixItems")
        if isinstance(prefix, list):
            for index, child_schema in enumerate(prefix[: len(value)]):
                yield from _validate_schema_node(
                    child_schema, value[index], f"{path}[{index}]", root
                )
        items = schema.get("items")
        if items is not None:
            start = len(prefix) if isinstance(prefix, list) else 0
            for index in range(start, len(value)):
                yield from _validate_schema_node(
                    items, value[index], f"{path}[{index}]", root
                )

    if isinstance(value, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if isinstance(minimum, int) and len(value) < minimum:
            yield f"{path}: string is shorter than {minimum}"
        if isinstance(maximum, int) and len(value) > maximum:
            yield f"{path}: string is longer than {maximum}"
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            yield f"{path}: string does not match {pattern}"
        format_name = schema.get("format")
        if format_name == "date-time" and not _is_datetime(value):
            yield f"{path}: invalid RFC 3339 date-time"
        if format_name == "uri" and not _is_uri(value):
            yield f"{path}: invalid URI"

    if _is_number(value):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if _is_number(minimum) and value < minimum:
            yield f"{path}: value is below {minimum}"
        if _is_number(maximum) and value > maximum:
            yield f"{path}: value is above {maximum}"

    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for child_schema in all_of:
            yield from _validate_schema_node(child_schema, value, path, root)
    any_of = schema.get("anyOf")
    if isinstance(any_of, list) and not any(
        not tuple(_validate_schema_node(branch, value, path, root)) for branch in any_of
    ):
        yield f"{path}: does not match any allowed schema branch"
    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        matches = sum(
            not tuple(_validate_schema_node(branch, value, path, root))
            for branch in one_of
        )
        if matches != 1:
            yield f"{path}: must match exactly one schema branch"
    if_schema = schema.get("if")
    if isinstance(if_schema, dict):
        condition_matches = not tuple(
            _validate_schema_node(if_schema, value, path, root)
        )
        branch = schema.get("then" if condition_matches else "else")
        if branch is not None:
            yield from _validate_schema_node(branch, value, path, root)
    not_schema = schema.get("not")
    if isinstance(not_schema, dict) and not tuple(
        _validate_schema_node(not_schema, value, path, root)
    ):
        yield f"{path}: matches a forbidden schema branch"


def _matches_type(value: object, expected: object) -> bool:
    if isinstance(expected, list):
        return any(_matches_type(value, item) for item in expected)
    matchers = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": _is_number,
        "boolean": lambda item: isinstance(item, bool),
        "null": lambda item: item is None,
    }
    matcher = matchers.get(expected)
    return bool(matcher and matcher(value))


def _is_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _is_datetime(value: str) -> bool:
    if not value.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


def _parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def _is_uri(value: str) -> bool:
    parsed = urlparse(value)
    return bool(parsed.scheme and (parsed.netloc or parsed.scheme == "file"))
