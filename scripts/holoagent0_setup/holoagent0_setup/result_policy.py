"""Policy-driven HoloAgent0 result classification."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Mapping, Sequence

from .contract import ContractSet


class ResultPolicyError(ValueError):
    """Observed gate state cannot be classified under the closed policy."""


@dataclass(frozen=True)
class ResultDecision:
    label: str
    status: str
    exit_class: str
    exit_code: int
    primary: str | None
    blocking_gates: tuple[str, ...]
    qualifications: tuple[str, ...]


class ResultPolicy:
    """Apply the tracked precedence and mode-to-outcome tables."""

    def __init__(self, contract: ContractSet) -> None:
        self._gate_policy = copy.deepcopy(
            contract.policies["holoagent0-gate-policy-v1"]
        )
        self._reason_policy = copy.deepcopy(
            contract.policies["holoagent0-reason-codes-v1"]
        )
        self._tuple_by_label = {
            label: row
            for row in self._gate_policy["label_tuples"]
            for label in row["labels"]
        }

    def decide(
        self,
        mode: str,
        gates: Sequence[Mapping[str, object]],
        *,
        signal: str | None = None,
        safety_decision_possible: bool = True,
    ) -> ResultDecision:
        if type(mode) is not str:
            raise ResultPolicyError("mode must be an exact string")
        if signal is not None and type(signal) is not str:
            raise ResultPolicyError(
                "interruption signal must be an exact string or null"
            )
        if type(safety_decision_possible) is not bool:
            raise ResultPolicyError("safety_decision_possible must be an exact boolean")
        if type(gates) not in {list, tuple}:
            raise ResultPolicyError("gates must be an exact list or tuple")
        if any(type(gate) is not dict for gate in gates):
            raise ResultPolicyError("every observed gate must be an exact object")
        for gate in gates:
            if type(gate.get("id")) is not str:
                raise ResultPolicyError(
                    "every observed gate ID must be an exact string"
                )
            if type(gate.get("status")) is not str:
                raise ResultPolicyError(
                    "every observed gate status must be an exact string"
                )
            if type(gate.get("reason")) is not str:
                raise ResultPolicyError(
                    "every observed gate reason must be an exact string"
                )

        profiles = self._gate_policy["profiles"]
        if mode not in profiles:
            raise ResultPolicyError(f"unknown mode: {mode}")
        if signal not in {None, "HUP", "INT", "TERM"}:
            raise ResultPolicyError(f"unknown interruption signal: {signal}")

        profile = profiles[mode]
        order = profile["gate_order"]
        roles = profile["roles"]
        supplied_ids = [gate.get("id") for gate in gates]
        if supplied_ids != order:
            raise ResultPolicyError(
                f"authoritative decision requires the exact ordered profile gate set for {mode}"
            )
        for gate in gates:
            gate_id = gate["id"]
            if roles[gate_id] == "finalizer" and gate.get("status") not in {
                "PASS",
                "FAIL",
                "SKIPPED",
            }:
                raise ResultPolicyError(
                    f"mandatory finalizer {gate_id} is not terminal"
                )
        observed: dict[str, Mapping[str, object]] = {}
        blocking_observation_order: list[str] = []
        qualifications: list[str] = []
        for gate in gates:
            gate_id = gate.get("id")
            if not isinstance(gate_id, str) or gate_id not in roles:
                raise ResultPolicyError(f"unknown or wrong-profile gate: {gate_id!r}")
            if gate_id in observed:
                raise ResultPolicyError(f"duplicate observed gate: {gate_id}")
            observed[gate_id] = gate
            status = gate.get("status")
            reason = gate.get("reason")
            allowed = self._reason_policy["gate_status_reasons"][gate_id]
            if not isinstance(status, str) or reason not in allowed.get(status, ()):
                raise ResultPolicyError(
                    f"invalid status/reason for {gate_id}: {status!r}/{reason!r}"
                )
            role = roles[gate_id]
            if status == "FAIL" and role in {
                "required",
                "required_qualification",
                "finalizer",
            }:
                blocking_observation_order.append(gate_id)
            if status == "QUALIFIED" and role in {
                "qualification",
                "required_qualification",
            }:
                qualifications.append(gate_id)

        self._require_terminal_action_sequence(profile, gates, signal)
        interrupted_actions = [
            gate
            for gate in gates
            if roles[gate["id"]] != "finalizer"
            and gate.get("status") == "NOT_RUN"
            and gate.get("reason") == "INTERRUPTED_BEFORE_GATE"
        ]
        not_run_actions = [
            gate
            for gate in gates
            if roles[gate["id"]] != "finalizer" and gate.get("status") == "NOT_RUN"
        ]
        if signal is None and interrupted_actions:
            raise ResultPolicyError(
                "action interruption markers require an interruption signal"
            )

        safety = [gate for gate in blocking_observation_order if self._is_safety(gate)]
        harness = [
            gate
            for gate in blocking_observation_order
            if gate in self._gate_policy["harness_gates"]
        ]
        if interrupted_actions and len(interrupted_actions) != len(not_run_actions):
            raise ResultPolicyError(
                "interrupted outcome requires an exact action interruption marker suffix"
            )
        if (
            not safety
            and not harness
            and signal is not None
            and not interrupted_actions
        ):
            raise ResultPolicyError(
                "interrupted outcome requires an exact action interruption marker suffix"
            )
        functional = [
            gate
            for gate in blocking_observation_order
            if gate not in safety and gate not in harness
        ]

        primary: str | None
        if safety:
            primary = min(safety, key=order.index)
        elif harness:
            primary = min(harness, key=order.index)
        elif not safety_decision_possible:
            raise ResultPolicyError(
                "safety decision impossible without a harness blocker"
            )
        elif signal is not None:
            return ResultDecision(
                label="INTERRUPTED",
                status="INTERRUPTED",
                exit_class=signal,
                exit_code={"HUP": 129, "INT": 130, "TERM": 143}[signal],
                primary=None,
                blocking_gates=tuple(blocking_observation_order),
                qualifications=tuple(qualifications),
            )
        elif functional:
            primary = min(functional, key=order.index)
        else:
            primary = None

        if primary is not None:
            try:
                label = self._gate_policy["failure_outcomes"][mode][primary]
            except KeyError as error:
                raise ResultPolicyError(
                    f"no closed failure outcome for {mode}/{primary}"
                ) from error
        else:
            qualifications.sort(key=order.index)
            selector = ",".join(qualifications)
            try:
                label = self._gate_policy["non_failure_outcomes"][mode][selector]
            except KeyError as error:
                raise ResultPolicyError(
                    f"no closed qualification outcome for {mode}/{selector!r}"
                ) from error

        row = self._tuple_by_label[label]
        return ResultDecision(
            label=label,
            status=row["status"],
            exit_class=row["exit_class"],
            exit_code=row["process_exit_code"],
            primary=primary,
            blocking_gates=tuple(blocking_observation_order),
            qualifications=tuple(qualifications),
        )

    def _is_safety(self, gate_id: str) -> bool:
        return gate_id.startswith("safety.") or gate_id in {
            "pc2.camera_cleanup",
            "offline.network_policy",
        }

    @staticmethod
    def _require_terminal_action_sequence(
        profile: Mapping[str, object],
        gates: Sequence[Mapping[str, object]],
        signal: str | None,
    ) -> None:
        roles = profile["roles"]
        finalizer_failure = any(
            roles[gate["id"]] == "finalizer" and gate.get("status") == "FAIL"
            for gate in gates
        )
        blocked = False
        interrupted_suffix = False
        for gate in gates:
            gate_id = gate["id"]
            role = roles[gate_id]
            if role == "finalizer":
                continue
            status = gate.get("status")
            if blocked and status != "NOT_RUN":
                raise ResultPolicyError(
                    f"action gate {gate_id} ran after an earlier blocking failure"
                )
            if status == "NOT_RUN":
                if not blocked and signal is None and not finalizer_failure:
                    raise ResultPolicyError(
                        f"action gate {gate_id} is NOT_RUN without a blocker or interruption"
                    )
                interrupted_suffix = True
                continue
            if interrupted_suffix:
                raise ResultPolicyError(
                    f"action gate {gate_id} ran after a terminal NOT_RUN suffix began"
                )
            if status == "FAIL" and role in {"required", "required_qualification"}:
                blocked = True
