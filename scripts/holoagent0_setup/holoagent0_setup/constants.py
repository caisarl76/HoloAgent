"""Closed constants shared by HoloAgent0 setup validation."""

PROFILE_MODES = (
    "workstation_offline",
    "workstation_mujoco",
    "pc2_inventory",
    "pc2_camera",
    "pc2_full_streams",
)

OFFLINE_GATE_ORDER = (
    "source.repository",
    "runtime.workstation",
    "safety.workstation_preflight",
    "openclaw.preexisting",
    "openclaw.version_pin",
    "openclaw.registry_integrity",
    "openclaw.config_pin",
    "openclaw.config_validate",
    "openclaw.doctor_lint",
    "skills.registry",
    "skills.dry_run",
    "agentos.plan_schema",
    "agentos.offline_execution",
    "agentos.network_attempts",
    "source.semantic_blobs",
    "semantic.asset_lock",
    "semantic.fixture_graph",
    "semantic.fixture_query",
    "semantic.natural_language_parser",
    "chatbot.dependencies",
    "chatbot.configuration",
    "chatbot.credentials",
    "chatbot.audio_hardware",
    "safety.workstation_postflight",
    "offline.trace_integrity",
    "offline.network_policy",
    "offline.evidence_binding",
)
