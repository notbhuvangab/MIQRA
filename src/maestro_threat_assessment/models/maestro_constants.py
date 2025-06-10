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

# MAESTRO layer criticality weights (from Layer-Description-WeightWEI-ExposureIndexRPS.csv)
MAESTRO_LAYER_WEIGHTS = {
    MAESTROLayer.L1_FOUNDATION_MODELS: 0.15,
    MAESTROLayer.L2_DATA_OPERATIONS: 0.10,
    MAESTROLayer.L3_AGENT_FRAMEWORKS: 0.20,
    MAESTROLayer.L4_DEPLOYMENT: 0.18,
    MAESTROLayer.L5_OBSERVABILITY: 0.12,
    MAESTROLayer.L6_COMPLIANCE: 0.15,
    MAESTROLayer.L7_ECOSYSTEM: 0.10
}

# MAESTRO layer exposure indices (from Layer-Description-WeightWEI-ExposureIndexRPS.csv)
MAESTRO_EXPOSURE_INDEX = {
    MAESTROLayer.L1_FOUNDATION_MODELS: 0.30,
    MAESTROLayer.L2_DATA_OPERATIONS: 0.25,
    MAESTROLayer.L3_AGENT_FRAMEWORKS: 0.45,
    MAESTROLayer.L4_DEPLOYMENT: 0.40,
    MAESTROLayer.L5_OBSERVABILITY: 0.35,
    MAESTROLayer.L6_COMPLIANCE: 0.50,
    MAESTROLayer.L7_ECOSYSTEM: 0.20
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

# Core Threat Matrix from research - specific AC, Impact, VS, PC values
CORE_THREAT_MATRIX = {
    # L1: Foundation Models
    'model_extraction': {'ac': 2, 'impact': 3, 'vs': 6, 'pc': 2, 'layer': MAESTROLayer.L1_FOUNDATION_MODELS},
    'prompt_injection': {'ac': 1, 'impact': 5, 'vs': 9, 'pc': 3, 'layer': MAESTROLayer.L1_FOUNDATION_MODELS},
    'bias_amplification': {'ac': 1, 'impact': 5, 'vs': 9, 'pc': 3, 'layer': MAESTROLayer.L1_FOUNDATION_MODELS},  # Mapped to prompt injection
    'model_poisoning': {'ac': 2, 'impact': 3, 'vs': 6, 'pc': 2, 'layer': MAESTROLayer.L1_FOUNDATION_MODELS},  # Mapped to model extraction
    
    # L2: Data Operations
    'data_poisoning': {'ac': 2, 'impact': 4, 'vs': 7, 'pc': 3, 'layer': MAESTROLayer.L2_DATA_OPERATIONS},
    'data_leakage': {'ac': 1, 'impact': 5, 'vs': 8, 'pc': 2, 'layer': MAESTROLayer.L2_DATA_OPERATIONS},  # Mapped to sensitive info disclosure
    'privacy_violation': {'ac': 1, 'impact': 5, 'vs': 8, 'pc': 2, 'layer': MAESTROLayer.L2_DATA_OPERATIONS},  # Mapped to sensitive info disclosure
    
    # L3: Agent Frameworks  
    'tool_poisoning': {'ac': 1, 'impact': 5, 'vs': 9, 'pc': 3, 'layer': MAESTROLayer.L3_AGENT_FRAMEWORKS},
    'agent_impersonation': {'ac': 2, 'impact': 4, 'vs': 7, 'pc': 3, 'layer': MAESTROLayer.L3_AGENT_FRAMEWORKS},  # Mapped to unauthorized impersonation
    'protocol_manipulation': {'ac': 1, 'impact': 5, 'vs': 9, 'pc': 3, 'layer': MAESTROLayer.L3_AGENT_FRAMEWORKS},  # Mapped to message injection
    
    # L4: Deployment
    'server_compromise': {'ac': 3, 'impact': 5, 'vs': 8, 'pc': 2, 'layer': MAESTROLayer.L4_DEPLOYMENT},
    'sandbox_escape': {'ac': 3, 'impact': 5, 'vs': 8, 'pc': 2, 'layer': MAESTROLayer.L4_DEPLOYMENT},  # Mapped to server compromise
    'privilege_escalation': {'ac': 3, 'impact': 5, 'vs': 8, 'pc': 2, 'layer': MAESTROLayer.L4_DEPLOYMENT},  # Mapped to server compromise
    'network_exposure': {'ac': 1, 'impact': 3, 'vs': 5, 'pc': 2, 'layer': MAESTROLayer.L4_DEPLOYMENT},  # Mapped to resource exhaustion
    
    # L5: Observability
    'monitoring_evasion': {'ac': 3, 'impact': 4, 'vs': 6, 'pc': 1, 'layer': MAESTROLayer.L5_OBSERVABILITY},  # Mapped to log manipulation
    'log_tampering': {'ac': 3, 'impact': 4, 'vs': 6, 'pc': 1, 'layer': MAESTROLayer.L5_OBSERVABILITY},  # Mapped to log manipulation
    'audit_trail_manipulation': {'ac': 3, 'impact': 4, 'vs': 6, 'pc': 1, 'layer': MAESTROLayer.L5_OBSERVABILITY},  # Mapped to log manipulation
    
    # L6: Compliance
    'compliance_violation': {'ac': 1, 'impact': 5, 'vs': 8, 'pc': 2, 'layer': MAESTROLayer.L6_COMPLIANCE},  # Mapped to PII mishandling
    'regulatory_breach': {'ac': 1, 'impact': 5, 'vs': 8, 'pc': 2, 'layer': MAESTROLayer.L6_COMPLIANCE},  # Mapped to PII mishandling
    'policy_bypass': {'ac': 1, 'impact': 5, 'vs': 9, 'pc': 3, 'layer': MAESTROLayer.L6_COMPLIANCE},  # Mapped to credential theft
    
    # L7: Ecosystem
    'supply_chain_attack': {'ac': 2, 'impact': 5, 'vs': 8, 'pc': 3, 'layer': MAESTROLayer.L7_ECOSYSTEM},  # Mapped to malicious server spoofing
    'third_party_compromise': {'ac': 3, 'impact': 5, 'vs': 7, 'pc': 3, 'layer': MAESTROLayer.L7_ECOSYSTEM},  # Mapped to agent trust exploitation
    'dependency_vulnerability': {'ac': 2, 'impact': 5, 'vs': 8, 'pc': 3, 'layer': MAESTROLayer.L7_ECOSYSTEM},  # Mapped to malicious server spoofing
}

# Fallback values for unknown threats (conservative estimates)
DEFAULT_THREAT_VALUES = {'ac': 2, 'impact': 3, 'vs': 5, 'pc': 2}

 