"""
MAESTRO Threat Assessment Framework

A comprehensive security risk assessment tool for agentic workflows
using the MAESTRO (Model, Agent framework, Ecosystem, Security, 
Threat landscape, Risk mitigation, Operational oversight) framework.
"""

__version__ = "1.0.0"
__author__ = "MAESTRO Security Team"

from .core.maestro_engine import MAESTROEngine
from .core.workflow_parser import WorkflowParser
from .core.risk_calculator import RiskCalculator

from .core.hybrid_analyzer import HybridAnalysisEngine
from .adapters.baseline_comparator import BaselineComparator
from .cli.main import cli

__all__ = [
    'MAESTROEngine',
    'WorkflowParser', 
    'RiskCalculator',

    'HybridAnalysisEngine',
    'BaselineComparator',
    'cli'
] 