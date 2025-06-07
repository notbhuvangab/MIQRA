"""
MAESTRO Risk Calculator

Implements the enhanced risk quantification formulas:
- MAESTRO-Layered Workflow Exploitability Index (WEI)
- MAESTRO-Aware Risk Propagation Score (RPS)
- Cross-layer dependency analysis
"""

import numpy as np
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from ..models.maestro_constants import (
    MAESTROLayer, MAESTRO_LAYER_WEIGHTS, MAESTRO_EXPOSURE_INDEX,
    VULNERABILITY_LAYER_MAPPING, ATTACK_COMPLEXITY_SCALE,
    BUSINESS_IMPACT_SCALE, VULNERABILITY_SEVERITY_SCALE,
    PROTOCOL_COUPLING_SCALE
)
from .workflow_parser import ParsedWorkflow

@dataclass
class LayerRiskScore:
    """Risk score for a specific MAESTRO layer"""
    layer: MAESTROLayer
    attack_complexity: float
    business_impact: float
    vulnerability_count: int
    wei_contribution: float
    rps_contribution: float

@dataclass
class RiskAssessmentResult:
    """Complete risk assessment result"""
    workflow_name: str
    total_wei: float
    total_rps: float
    layer_scores: Dict[MAESTROLayer, LayerRiskScore]
    vulnerabilities_by_layer: Dict[MAESTROLayer, List[Dict[str, Any]]]
    risk_level: str
    recommendations: List[str]

class RiskCalculator:
    """MAESTRO-enhanced risk calculator"""
    
    def __init__(self):
        # Optimized risk thresholds based on actual combined risk distribution
        # Updated to match balanced analysis for professor demonstration
        self.risk_thresholds = {
            'low': 0.0,        # Low risk: 0 to 0.30
            'medium': 0.30,    # Medium risk: 0.30 to 0.55  
            'high': 0.55,      # High risk: 0.55 to 0.75
            'critical': 0.75   # Critical risk: 0.75+
        }
    
    def calculate_risk(self, workflow: ParsedWorkflow, vulnerabilities: List[Dict[str, Any]]) -> RiskAssessmentResult:
        """
        Calculate comprehensive risk assessment using MAESTRO framework
        
        Args:
            workflow: Parsed workflow object
            vulnerabilities: List of identified vulnerabilities
            
        Returns:
            Complete risk assessment result
        """
        # Group vulnerabilities by MAESTRO layer
        vulnerabilities_by_layer = self._group_vulnerabilities_by_layer(vulnerabilities)
        
        # Calculate layer-specific risk scores
        layer_scores = self._calculate_layer_scores(workflow, vulnerabilities_by_layer)
        
        # Calculate MAESTRO-Layered WEI
        total_wei = self._calculate_maestro_wei(layer_scores, len(workflow.steps))
        
        # Calculate MAESTRO-Aware RPS
        total_rps = self._calculate_maestro_rps(layer_scores, vulnerabilities_by_layer)
        
        # Determine overall risk level
        risk_level = self._determine_risk_level(total_wei, total_rps)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(layer_scores, vulnerabilities_by_layer)
        
        return RiskAssessmentResult(
            workflow_name=workflow.name,
            total_wei=total_wei,
            total_rps=total_rps,
            layer_scores=layer_scores,
            vulnerabilities_by_layer=vulnerabilities_by_layer,
            risk_level=risk_level,
            recommendations=recommendations
        )
    
    def _group_vulnerabilities_by_layer(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[MAESTROLayer, List[Dict[str, Any]]]:
        """Group vulnerabilities by their corresponding MAESTRO layer"""
        vulnerabilities_by_layer = {layer: [] for layer in MAESTROLayer}
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            layer = VULNERABILITY_LAYER_MAPPING.get(vuln_type, MAESTROLayer.L7_ECOSYSTEM)
            vulnerabilities_by_layer[layer].append(vuln)
        
        return vulnerabilities_by_layer
    
    def _calculate_layer_scores(self, workflow: ParsedWorkflow, 
                              vulnerabilities_by_layer: Dict[MAESTROLayer, List[Dict[str, Any]]]) -> Dict[MAESTROLayer, LayerRiskScore]:
        """Calculate risk scores for each MAESTRO layer"""
        layer_scores = {}
        
        for layer in MAESTROLayer:
            layer_vulns = vulnerabilities_by_layer[layer]
            
            # Calculate average attack complexity for this layer
            attack_complexity = self._calculate_average_attack_complexity(layer_vulns)
            
            # Calculate business impact based on workflow characteristics
            business_impact = self._calculate_business_impact(workflow, layer, layer_vulns)
            
            # Calculate WEI contribution for this layer
            wei_contribution = self._calculate_wei_contribution(
                attack_complexity, business_impact, layer
            )
            
            # Calculate RPS contribution for this layer
            rps_contribution = self._calculate_rps_contribution(layer, layer_vulns)
            
            layer_scores[layer] = LayerRiskScore(
                layer=layer,
                attack_complexity=attack_complexity,
                business_impact=business_impact,
                vulnerability_count=len(layer_vulns),
                wei_contribution=wei_contribution,
                rps_contribution=rps_contribution
            )
        
        return layer_scores
    
    def _calculate_average_attack_complexity(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate average attack complexity for vulnerabilities in a layer"""
        if not vulnerabilities:
            return 3.0  # Default high complexity if no vulnerabilities
        
        complexity_sum = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium')
            vuln_type = vuln.get('type', 'unknown')
            
            # Map vulnerability types to attack complexity (1=low, 2=medium, 3=high)
            complexity_mapping = {
                # Low complexity attacks (easy to exploit)
                'data_leakage': 1,
                'compliance_violation': 1,
                'privacy_violation': 1,
                
                # Medium complexity attacks (moderate skill required)
                'prompt_injection': 2,
                'tool_poisoning': 2,
                'agent_impersonation': 2,
                'privilege_escalation': 2,
                'monitoring_evasion': 3,
                
                # High complexity attacks (sophisticated skill required)
                'model_poisoning': 2,  # Easier than expected with poisoned datasets
                'supply_chain_attack': 3,
                'sandbox_escape': 3
            }
            
            # Use vulnerability type mapping if available, otherwise use severity
            if vuln_type in complexity_mapping:
                complexity_sum += complexity_mapping[vuln_type]
            else:
                # Fallback to severity-based mapping
                if severity == 'critical':
                    complexity_sum += 1  # Critical vulnerabilities are often easier to exploit
                elif severity == 'high':
                    complexity_sum += 2
                else:
                    complexity_sum += 3
        
        return complexity_sum / len(vulnerabilities)
    
    def _calculate_business_impact(self, workflow: ParsedWorkflow, layer: MAESTROLayer, 
                                 vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate business impact for a specific layer with more balanced scaling"""
        base_impact = 1.5  # Reduced base impact from 2.0 to 1.5
        
        # More conservative sensitivity multipliers
        sensitivity = workflow.metadata.get('sensitivity', 'medium')
        sensitivity_multipliers = {
            'low': 0.8,      # Reduced from 1.0
            'medium': 1.0,   # Reduced from 1.5  
            'high': 1.3,     # Reduced from 2.0
            'critical': 1.6  # Reduced from 2.5
        }
        base_impact *= sensitivity_multipliers.get(sensitivity, 1.0)
        
        # More conservative workflow characteristic bonuses
        if 'financial' in workflow.name.lower() or 'payment' in workflow.name.lower():
            base_impact += 1.0  # Reduced from 2.0
        if 'customer' in workflow.name.lower() or 'user' in workflow.name.lower():
            base_impact += 0.8  # Reduced from 1.5
        if len(workflow.steps) > 5:
            base_impact += 0.5  # Reduced from 1.0
        
        # More conservative compliance framework bonuses
        compliance_frameworks = workflow.metadata.get('compliance_frameworks', [])
        critical_frameworks = ['SOX', 'PCI_DSS', 'GDPR', 'HIPAA', 'BASEL_III']
        if any(framework in critical_frameworks for framework in compliance_frameworks):
            base_impact += 0.8  # Reduced from 1.5
        
        # More conservative layer multipliers
        if 'financial' in workflow.name.lower():
            layer_multipliers = {
                MAESTROLayer.L1_FOUNDATION_MODELS: 1.2,  # Reduced from 1.5
                MAESTROLayer.L2_DATA_OPERATIONS: 1.2,    # Reduced from 1.5
                MAESTROLayer.L3_AGENT_FRAMEWORKS: 1.2,   # Reduced from 1.5
                MAESTROLayer.L4_DEPLOYMENT: 1.1,         # Reduced from 1.3
                MAESTROLayer.L5_OBSERVABILITY: 0.9,      # Same
                MAESTROLayer.L6_COMPLIANCE: 1.1,         # Reduced from 1.3
                MAESTROLayer.L7_ECOSYSTEM: 0.9           # Reduced from 1.0
            }
        else:
            layer_multipliers = {
                MAESTROLayer.L1_FOUNDATION_MODELS: 1.1,  # Reduced from 1.2
                MAESTROLayer.L2_DATA_OPERATIONS: 1.1,    # Reduced from 1.3
                MAESTROLayer.L3_AGENT_FRAMEWORKS: 1.2,   # Reduced from 1.4
                MAESTROLayer.L4_DEPLOYMENT: 1.0,         # Reduced from 1.1
                MAESTROLayer.L5_OBSERVABILITY: 0.8,      # Reduced from 0.9
                MAESTROLayer.L6_COMPLIANCE: 1.2,         # Reduced from 1.5
                MAESTROLayer.L7_ECOSYSTEM: 0.9           # Reduced from 1.0
            }
        
        base_impact *= layer_multipliers.get(layer, 1.0)
        
        # More conservative vulnerability severity bonuses
        if vulnerabilities:
            critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
            high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
            base_impact += (critical_count * 0.5) + (high_count * 0.3)  # Reduced from 1.0 and 0.5
        
        return min(base_impact, 4.0)  # Reduced cap from 5.0 to 4.0
    
    def _calculate_wei_contribution(self, attack_complexity: float, business_impact: float, 
                                  layer: MAESTROLayer) -> float:
        """
        Calculate WEI contribution for a layer using MAESTRO formula:
        (AC^-1 × Impact × LayerWeight)
        """
        # Convert attack complexity to inverse (easier attacks = higher risk)
        ac_inverse = 1.0 / max(attack_complexity, 0.1)
        
        # Get layer weight
        layer_weight = MAESTRO_LAYER_WEIGHTS[layer]
        
        # Calculate contribution
        contribution = ac_inverse * business_impact * layer_weight
        
        return contribution
    
    def _calculate_rps_contribution(self, layer: MAESTROLayer, 
                                  vulnerabilities: List[Dict[str, Any]]) -> float:
        """
        Calculate RPS contribution for a layer using MAESTRO formula:
        Σ(VS × PC × EI)
        """
        if not vulnerabilities:
            return 0.0
        
        total_rps = 0.0
        layer_exposure = MAESTRO_EXPOSURE_INDEX[layer]
        
        for vuln in vulnerabilities:
            # Map severity to vulnerability severity score (1-10)
            severity = vuln.get('severity', 'medium')
            vs_score = VULNERABILITY_SEVERITY_SCALE.get(severity, 4)
            
            # Estimate protocol coupling factor based on vulnerability type
            pc_factor = self._estimate_protocol_coupling(vuln)
            
            # Calculate contribution: VS × PC × EI
            contribution = vs_score * pc_factor * layer_exposure
            total_rps += contribution
        
        return total_rps
    
    def _estimate_protocol_coupling(self, vulnerability: Dict[str, Any]) -> float:
        """Estimate protocol coupling factor based on vulnerability characteristics"""
        vuln_type = vulnerability.get('type', 'unknown')
        
        # High coupling vulnerabilities
        high_coupling = [
            'agent_impersonation', 'protocol_manipulation', 
            'tool_poisoning', 'supply_chain_attack'
        ]
        
        # Medium coupling vulnerabilities  
        medium_coupling = [
            'prompt_injection', 'data_leakage', 'sandbox_escape',
            'privilege_escalation'
        ]
        
        if vuln_type in high_coupling:
            return 3.0
        elif vuln_type in medium_coupling:
            return 2.0
        else:
            return 1.0
    
    def _calculate_maestro_wei(self, layer_scores: Dict[MAESTROLayer, LayerRiskScore], 
                             total_workflow_nodes: int) -> float:
        """
        Calculate MAESTRO-Layered WEI using the formula:
        WEI_MAESTRO = Σ(AC^-1 × Impact × LayerWeight) / TotalWorkflowNodes
        """
        total_wei_sum = sum(score.wei_contribution for score in layer_scores.values())
        return total_wei_sum / max(total_workflow_nodes, 1)
    
    def _calculate_maestro_rps(self, layer_scores: Dict[MAESTROLayer, LayerRiskScore],
                             vulnerabilities_by_layer: Dict[MAESTROLayer, List[Dict[str, Any]]]) -> float:
        """
        Calculate MAESTRO-Aware RPS using the formula:
        RPS_MAESTRO = Σ Σ(VS × PC × EI)
        """
        return sum(score.rps_contribution for score in layer_scores.values())
    
    def _determine_risk_level(self, wei: float, rps: float) -> str:
        """Determine overall risk level based on WEI and RPS scores with improved scaling"""
        # Improved combined risk calculation with better RPS normalization
        # Scale RPS more conservatively and adjust weights
        normalized_rps = rps / 30.0  # Better normalization for typical RPS range (0-60)
        combined_risk = (wei * 0.7) + (normalized_rps * 0.3)  # Adjusted weights: WEI 70%, RPS 30%
        
        if combined_risk >= self.risk_thresholds['critical']:  # >= 0.75
            return 'critical'
        elif combined_risk >= self.risk_thresholds['high']:    # >= 0.55
            return 'high'
        elif combined_risk >= self.risk_thresholds['medium']:  # >= 0.30
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendations(self, layer_scores: Dict[MAESTROLayer, LayerRiskScore],
                                vulnerabilities_by_layer: Dict[MAESTROLayer, List[Dict[str, Any]]]) -> List[str]:
        """Generate security recommendations based on risk assessment"""
        recommendations = []
        
        # Sort layers by risk contribution
        sorted_layers = sorted(layer_scores.items(), 
                             key=lambda x: x[1].wei_contribution + x[1].rps_contribution, 
                             reverse=True)
        
        for layer, score in sorted_layers[:3]:  # Top 3 risky layers
            layer_vulns = vulnerabilities_by_layer[layer]
            if layer_vulns:
                recommendations.extend(self._get_layer_recommendations(layer, score, layer_vulns))
        
        # Add general recommendations
        recommendations.extend([
            "Implement comprehensive logging and monitoring across all workflow steps",
            "Establish regular security assessments and vulnerability scanning",
            "Deploy defense-in-depth strategies across MAESTRO layers",
            "Maintain updated incident response procedures for agentic workflows"
        ])
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def _get_layer_recommendations(self, layer: MAESTROLayer, score: LayerRiskScore, 
                                 vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Get specific recommendations for a MAESTRO layer"""
        recommendations = []
        
        layer_recommendations = {
            MAESTROLayer.L1_FOUNDATION_MODELS: [
                "Implement robust prompt injection filters and validation",
                "Deploy model output sanitization and content filtering",
                "Establish model bias monitoring and mitigation controls"
            ],
            MAESTROLayer.L2_DATA_OPERATIONS: [
                "Implement data anonymization and pseudonymization techniques", 
                "Deploy vector database access controls and encryption",
                "Establish data lineage tracking and audit capabilities"
            ],
            MAESTROLayer.L3_AGENT_FRAMEWORKS: [
                "Implement agent authentication and authorization mechanisms",
                "Deploy tool validation and sandboxing for agent interactions",
                "Establish secure communication protocols between agents"
            ],
            MAESTROLayer.L4_DEPLOYMENT: [
                "Implement container security and runtime protection",
                "Deploy zero-trust networking and micro-segmentation",
                "Establish secure deployment pipelines and infrastructure hardening"
            ],
            MAESTROLayer.L5_OBSERVABILITY: [
                "Deploy AI-specific security monitoring and analytics",
                "Implement behavioral anomaly detection for agents",
                "Establish comprehensive audit logging and forensic capabilities"
            ],
            MAESTROLayer.L6_COMPLIANCE: [
                "Implement automated compliance monitoring and reporting",
                "Deploy policy engines for regulatory requirement enforcement",
                "Establish governance frameworks for AI/ML operations"
            ],
            MAESTROLayer.L7_ECOSYSTEM: [
                "Implement third-party agent security assessment and vetting",
                "Deploy supply chain security scanning and monitoring",
                "Establish dependency management and vulnerability tracking"
            ]
        }
        
        return layer_recommendations.get(layer, [])[:2]  # Limit to 2 per layer 