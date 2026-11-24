"""OodaTap 3-signal detection suite and host correlation engine."""

from oodatap.detectors.coupler import analyze_coupling
from oodatap.detectors.engine import OodaTapEngine
from oodatap.detectors.kinematics import analyze_kinematics
from oodatap.detectors.sawtooth import analyze_sawtooth

__all__ = [
    "OodaTapEngine",
    "analyze_coupling",
    "analyze_kinematics",
    "analyze_sawtooth",
]
