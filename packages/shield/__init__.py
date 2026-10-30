"""Sentinel X live shield: reverse proxy, detection, and intent labeling."""

from .config import ShieldConfig, load_shield_config
from .detect import Detector, Signal, SignalRule, WindowRule
from .intent import SIGNAL_TO_INTENT, IntentAssessment, IntentVerdict, build_intent, map_intent
from .proxy import ShieldProxy
from .recorder import ShieldRecorder, hash_client_key, path_template

__all__ = [
    "ShieldConfig",
    "load_shield_config",
    "Detector",
    "Signal",
    "SignalRule",
    "WindowRule",
    "IntentAssessment",
    "IntentVerdict",
    "build_intent",
    "map_intent",
    "SIGNAL_TO_INTENT",
    "ShieldProxy",
    "ShieldRecorder",
    "hash_client_key",
    "path_template",
]
