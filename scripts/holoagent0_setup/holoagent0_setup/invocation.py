"""Value objects for deterministic offline setup invocations."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class OfflineInvocation:
    mode: Literal["workstation_offline"]
    output_root: Path
    run_id: str
    invocation_role: Literal["standalone", "child"]
    parent_run_id: str | None
    lineage_nonce: str | None

    @property
    def result_path(self) -> Path:
        return self.output_root / self.run_id / "result.json"
