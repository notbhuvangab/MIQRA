"""
MAESTRO Framework Constants and Configuration

Contains all the constants, weights, and configuration values
derived from CSA's 2025 threat statistics and implementation guide.
"""

from enum import Enum
from typing import Dict, List
import numpy as np

class MAESTROLayer(Enum):
    """MAESTRO Security Framework Layers"""
    L1_FOUNDATION_MODELS = 1
    L2_DATA_OPERATIONS = 2  
    L3_AGENT_FRAMEWORKS = 3
    L4_DEPLOYMENT = 4
    L5_OBSERVABILITY = 5
    L6_COMPLIANCE = 6
    L7_ECOSYSTEM = 7

# MAESTRO layer criticality weights (derived from CSA's 2025 threat statistics)
MAESTRO_LAYER_WEIGHTS = {
    MAESTROLayer.L1_FOUNDATION_MODELS: 0.15,
    MAESTROLayer.L2_DATA_OPERATIONS: 0.10,
    MAESTROLayer.L3_AGENT_FRAMEWORKS: 0.20,
    MAESTROLayer.L4_DEPLOYMENT: 0.18,
    MAESTROLayer.L5_OBSERVABILITY: 0.12,
    MAESTROLayer.L6_COMPLIANCE: 0.15,
    MAESTROLayer.L7_ECOSYSTEM: 0.10
}

# MAESTRO layer exposure indices (from CSA's 2025 implementation guide)
MAESTRO_EXPOSURE_INDEX = {
    MAESTROLayer.L1_FOUNDATION_MODELS: 0.30,
    MAESTROLayer.L2_DATA_OPERATIONS: 0.25,
    MAESTROLayer.L3_AGENT_FRAMEWORKS: 0.45,
    MAESTROLayer.L4_DEPLOYMENT: 0.40,
    MAESTROLayer.L5_OBSERVABILITY: 0.35,
    MAESTROLayer.L6_COMPLIANCE: 0.50,
    MAESTROLayer.L7_ECOSYSTEM: 0.20
}

# MAESTRO-layered cost factors matrix
MAESTRO_COST_WEIGHTS = {
    MAESTROLayer.L1_FOUNDATION_MODELS: 0.15,  # Model hardening, Bias mitigation
    MAESTROLayer.L2_DATA_OPERATIONS: 0.12,   # Anonymization, Vector DB security
    MAESTROLayer.L3_AGENT_FRAMEWORKS: 0.22,  # Protocol validation, Tool vetting
    MAESTROLayer.L4_DEPLOYMENT: 0.18,        # Sandboxing, Zero Trust networking
    MAESTROLayer.L5_OBSERVABILITY: 0.10,     # AI-specific monitoring tools
    MAESTROLayer.L6_COMPLIANCE: 0.15,        # Audit trails, Policy engines
    MAESTROLayer.L7_ECOSYSTEM: 0.08          # Third-party agent vetting
}

# Vulnerability to MAESTRO layer mapping
VULNERABILITY_LAYER_MAPPING = {
    'prompt_injection': MAESTROLayer.L1_FOUNDATION_MODELS,
    'model_poisoning': MAESTROLayer.L1_FOUNDATION_MODELS,
    'bias_amplification': MAESTROLayer.L1_FOUNDATION_MODELS,
    'data_leakage': MAESTROLayer.L2_DATA_OPERATIONS,
    'data_poisoning': MAESTROLayer.L2_DATA_OPERATIONS,
    'privacy_violation': MAESTROLayer.L2_DATA_OPERATIONS,
    'tool_poisoning': MAESTROLayer.L3_AGENT_FRAMEWORKS,
    'agent_impersonation': MAESTROLayer.L3_AGENT_FRAMEWORKS,
    'protocol_manipulation': MAESTROLayer.L3_AGENT_FRAMEWORKS,
    'sandbox_escape': MAESTROLayer.L4_DEPLOYMENT,
    'privilege_escalation': MAESTROLayer.L4_DEPLOYMENT,
    'network_exposure': MAESTROLayer.L4_DEPLOYMENT,
    'monitoring_evasion': MAESTROLayer.L5_OBSERVABILITY,
    'log_tampering': MAESTROLayer.L5_OBSERVABILITY,
    'audit_trail_manipulation': MAESTROLayer.L5_OBSERVABILITY,
    'compliance_violation': MAESTROLayer.L6_COMPLIANCE,
    'regulatory_breach': MAESTROLayer.L6_COMPLIANCE,
    'policy_bypass': MAESTROLayer.L6_COMPLIANCE,
    'supply_chain_attack': MAESTROLayer.L7_ECOSYSTEM,
    'third_party_compromise': MAESTROLayer.L7_ECOSYSTEM,
    'dependency_vulnerability': MAESTROLayer.L7_ECOSYSTEM
}

# Attack complexity scale (1-3)
ATTACK_COMPLEXITY_SCALE = {
    'low': 1,
    'medium': 2,
    'high': 3
}

# Business impact scale (1-5)
BUSINESS_IMPACT_SCALE = {
    'negligible': 1,
    'minor': 2,
    'moderate': 3,
    'major': 4,
    'critical': 5
}

# Vulnerability severity scale (1-10)
VULNERABILITY_SEVERITY_SCALE = {
    'info': 1,
    'low': 2,
    'medium': 4,
    'high': 7,
    'critical': 10
}

# Protocol coupling factor scale (1-3)
PROTOCOL_COUPLING_SCALE = {
    'loose': 1,
    'moderate': 2,
    'tight': 3
}

# MAESTRO layer descriptions
MAESTRO_LAYER_DESCRIPTIONS = {
    MAESTROLayer.L1_FOUNDATION_MODELS: "Foundation model security, prompt injection protection, bias mitigation",
    MAESTROLayer.L2_DATA_OPERATIONS: "Data pipeline security, privacy protection, vector database hardening",
    MAESTROLayer.L3_AGENT_FRAMEWORKS: "Agent protocol security, tool validation, inter-agent communication",
    MAESTROLayer.L4_DEPLOYMENT: "Runtime security, sandboxing, network isolation, infrastructure hardening",
    MAESTROLayer.L5_OBSERVABILITY: "Security monitoring, logging, anomaly detection, audit trails",
    MAESTROLayer.L6_COMPLIANCE: "Regulatory compliance, policy enforcement, governance frameworks",
    MAESTROLayer.L7_ECOSYSTEM: "Third-party integrations, supply chain security, dependency management"
}

# Cost component descriptions
MAESTRO_COST_COMPONENTS = {
    MAESTROLayer.L1_FOUNDATION_MODELS: ["Model hardening", "Bias mitigation", "Prompt filtering"],
    MAESTROLayer.L2_DATA_OPERATIONS: ["Data anonymization", "Vector DB security", "Privacy controls"],
    MAESTROLayer.L3_AGENT_FRAMEWORKS: ["Protocol validation", "Tool vetting", "Agent sandboxing"],
    MAESTROLayer.L4_DEPLOYMENT: ["Container security", "Zero Trust networking", "Runtime protection"],
    MAESTROLayer.L5_OBSERVABILITY: ["AI-specific monitoring", "Security analytics", "Threat detection"],
    MAESTROLayer.L6_COMPLIANCE: ["Audit systems", "Policy engines", "Compliance reporting"],
    MAESTROLayer.L7_ECOSYSTEM: ["Third-party vetting", "Supply chain scanning", "Dependency analysis"]
} 