"""
MAESTRO Risk Calculator

Implements the enhanced risk quantification formulas with Monte Carlo estimation:
- MAESTRO-Layered Workflow Exploitability Index (WEI)
- MAESTRO-Aware Risk Propagation Score (RPS)
- Monte Carlo uncertainty quantification
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
from .monte_carlo_estimator import MonteCarloEstimator, MonteCarloResult

@dataclass
class LayerRiskScore:
    """Risk score for a specific MAESTRO layer with uncertainty"""
    layer: MAESTROLayer
    attack_complexity: MonteCarloResult
    business_impact: MonteCarloResult
    vulnerability_severity: MonteCarloResult
    protocol_coupling: MonteCarloResult
    vulnerability_count: int
    wei_contribution: MonteCarloResult
    rps_contribution: MonteCarloResult

@dataclass
class RiskAssessmentResult:
    """Complete risk assessment result with Monte Carlo uncertainty"""
    workflow_name: str
    total_wei: MonteCarloResult
    total_rps: MonteCarloResult
    layer_scores: Dict[MAESTROLayer, LayerRiskScore]
    vulnerabilities_by_layer: Dict[MAESTROLayer, List[Dict[str, Any]]]
    risk_level: str
    confidence_interval: Tuple[float, float]
    recommendations: List[str]

class RiskCalculator:
    """MAESTRO-enhanced risk calculator with Monte Carlo estimation"""
    
    def __init__(self, n_simulations: int = 10000):
        self.monte_carlo = MonteCarloEstimator()
        self.n_simulations = n_simulations
        
        # Risk thresholds based on combined WEI+RPS score (calibrated)
        self.risk_thresholds = {
            'low': 0.0,        # Low risk: 0 to 0.219
            'medium': 0.219,   # Medium risk: 0.219 to 0.481  
            'high': 0.481,     # High risk: 0.481 to 0.527
            'critical': 0.527  # Critical risk: 0.527+
        }
    
    def calculate_risk(self, workflow: ParsedWorkflow, vulnerabilities: List[Dict[str, Any]]) -> RiskAssessmentResult:
        """
        Calculate comprehensive risk assessment using MAESTRO framework with Monte Carlo estimation
        
        Args:
            workflow: Parsed workflow object
            vulnerabilities: List of identified vulnerabilities
            
        Returns:
            Complete risk assessment result with uncertainty quantification
        """
        # Group vulnerabilities by MAESTRO layer
        vulnerabilities_by_layer = self._group_vulnerabilities_by_layer(vulnerabilities)
        
        # Calculate layer-specific risk scores with Monte Carlo estimation
        layer_scores = self._calculate_layer_scores_with_uncertainty(workflow, vulnerabilities_by_layer)
        
        # Calculate MAESTRO-Layered WEI with uncertainty
        total_wei = self._calculate_maestro_wei_with_uncertainty(layer_scores, len(workflow.steps))
        
        # Calculate MAESTRO-Aware RPS with uncertainty
        total_rps = self._calculate_maestro_rps_with_uncertainty(layer_scores, vulnerabilities_by_layer)
        
        # Determine overall risk level and confidence interval
        risk_level, confidence_interval = self._determine_risk_level_with_uncertainty(total_wei, total_rps)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(layer_scores, vulnerabilities_by_layer)
        
        return RiskAssessmentResult(
            workflow_name=workflow.name,
            total_wei=total_wei,
            total_rps=total_rps,
            layer_scores=layer_scores,
            vulnerabilities_by_layer=vulnerabilities_by_layer,
            risk_level=risk_level,
            confidence_interval=confidence_interval,
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
    
    def _calculate_layer_scores_with_uncertainty(self, workflow: ParsedWorkflow, 
                              vulnerabilities_by_layer: Dict[MAESTROLayer, List[Dict[str, Any]]]) -> Dict[MAESTROLayer, LayerRiskScore]:
        """Calculate risk scores for each MAESTRO layer with Monte Carlo uncertainty estimation"""
        layer_scores = {}
        
        for layer in MAESTROLayer:
            layer_vulns = vulnerabilities_by_layer[layer]
            
            # Estimate vulnerability parameters with uncertainty using Monte Carlo
            mc_results = self.monte_carlo.estimate_vulnerability_parameters(layer_vulns)
            
            # Get uncertainty estimates for each parameter
            attack_complexity = mc_results['attack_complexity']
            business_impact = mc_results['impact']
            vulnerability_severity = mc_results['vulnerability_severity']
            protocol_coupling = mc_results['protocol_coupling']
            
            # Calculate WEI contribution with uncertainty
            wei_contribution = self._calculate_wei_contribution_with_uncertainty(
                attack_complexity, business_impact, layer
            )
            
            # Calculate RPS contribution with uncertainty
            rps_contribution = self._calculate_rps_contribution_with_uncertainty(
                layer, vulnerability_severity, protocol_coupling
            )
            
            layer_scores[layer] = LayerRiskScore(
                layer=layer,
                attack_complexity=attack_complexity,
                business_impact=business_impact,
                vulnerability_severity=vulnerability_severity,
                protocol_coupling=protocol_coupling,
                vulnerability_count=len(layer_vulns),
                wei_contribution=wei_contribution,
                rps_contribution=rps_contribution
            )
        
        return layer_scores
    
    def _calculate_wei_contribution_with_uncertainty(self, attack_complexity: MonteCarloResult, 
                                                   business_impact: MonteCarloResult, 
                                                   layer: MAESTROLayer) -> MonteCarloResult:
        """
        Calculate WEI contribution for a layer using Monte Carlo simulation
        
        Formula: WEI_layer = (1/AC) * Impact * LayerWeight
        """
        layer_weight = MAESTRO_LAYER_WEIGHTS[layer]
        
        # Perform element-wise calculation across all Monte Carlo samples
        wei_samples = (1.0 / attack_complexity.samples) * business_impact.samples * layer_weight
        
        # Calculate statistics for the resulting distribution
        return self._create_monte_carlo_result_from_samples(wei_samples)
    
    def _calculate_rps_contribution_with_uncertainty(self, layer: MAESTROLayer,
                                                   vulnerability_severity: MonteCarloResult,
                                                   protocol_coupling: MonteCarloResult) -> MonteCarloResult:
        """
        Calculate RPS contribution for a layer using Monte Carlo simulation
        
        Formula: RPS_layer = VS * PC * ExposureIndex
        """
        exposure_index = MAESTRO_EXPOSURE_INDEX[layer]
        
        # Perform element-wise calculation across all Monte Carlo samples
        rps_samples = vulnerability_severity.samples * protocol_coupling.samples * exposure_index
        
        # Calculate statistics for the resulting distribution
        return self._create_monte_carlo_result_from_samples(rps_samples)
    
    def _calculate_maestro_wei_with_uncertainty(self, layer_scores: Dict[MAESTROLayer, LayerRiskScore], 
                                              total_workflow_nodes: int) -> MonteCarloResult:
        """
        Calculate total MAESTRO WEI with uncertainty
        
        Formula: WEI = Σ(WEI_layer) / workflow_node_count
        """
        # Sum all layer WEI contributions across Monte Carlo samples
        total_wei_samples = np.zeros(self.n_simulations)
        
        for layer_score in layer_scores.values():
            total_wei_samples += layer_score.wei_contribution.samples
        
        # Normalize by workflow node count
        total_wei_samples = total_wei_samples / max(total_workflow_nodes, 1)
        
        return self._create_monte_carlo_result_from_samples(total_wei_samples)
    
    def _calculate_maestro_rps_with_uncertainty(self, layer_scores: Dict[MAESTROLayer, LayerRiskScore],
                                              vulnerabilities_by_layer: Dict[MAESTROLayer, List[Dict[str, Any]]]) -> MonteCarloResult:
        """
        Calculate total MAESTRO RPS with uncertainty
        
        Formula: RPS = Σ(RPS_layer)
        """
        # Sum all layer RPS contributions across Monte Carlo samples
        total_rps_samples = np.zeros(self.n_simulations)
        
        for layer_score in layer_scores.values():
            total_rps_samples += layer_score.rps_contribution.samples
        
        return self._create_monte_carlo_result_from_samples(total_rps_samples)
    
    def _create_monte_carlo_result_from_samples(self, samples: np.ndarray) -> MonteCarloResult:
        """Create a MonteCarloResult from samples array"""
        mean = np.mean(samples)
        std_dev = np.std(samples)
        
        # Calculate confidence interval (95% by default)
        confidence_interval = (
            np.percentile(samples, 2.5),
            np.percentile(samples, 97.5)
        )
        
        # Calculate key percentiles
        percentiles = {
            5: np.percentile(samples, 5),
            25: np.percentile(samples, 25),
            50: np.percentile(samples, 50),
            75: np.percentile(samples, 75),
            95: np.percentile(samples, 95)
        }
        
        return MonteCarloResult(
            mean=mean,
            std_dev=std_dev,
            confidence_interval=confidence_interval,
            percentiles=percentiles,
            samples=samples
        )
    
    def _determine_risk_level_with_uncertainty(self, wei: MonteCarloResult, rps: MonteCarloResult) -> Tuple[str, Tuple[float, float]]:
        """
        Determine risk level based on combined WEI and RPS with uncertainty
        
        Formula: Combined Risk = (WEI × 0.7) + (RPS/30 × 0.3)
        """
        # Calculate combined risk score using the correct formula
        # RPS needs to be normalized by 30 to match WEI scale
        normalized_rps_samples = rps.samples / 30.0
        combined_risk_samples = (wei.samples * 0.7) + (normalized_rps_samples * 0.3)
        
        # Determine risk level based on mean combined score
        mean_combined_risk = np.mean(combined_risk_samples)
        
        if mean_combined_risk >= self.risk_thresholds['critical']:
            risk_level = 'critical'
        elif mean_combined_risk >= self.risk_thresholds['high']:
            risk_level = 'high'
        elif mean_combined_risk >= self.risk_thresholds['medium']:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Calculate confidence interval for combined risk
        confidence_interval = (
            np.percentile(combined_risk_samples, 2.5),
            np.percentile(combined_risk_samples, 97.5)
        )
        
        return risk_level, confidence_interval
    
    def _generate_recommendations(self, layer_scores: Dict[MAESTROLayer, LayerRiskScore],
                                vulnerabilities_by_layer: Dict[MAESTROLayer, List[Dict[str, Any]]]) -> List[str]:
        """Generate risk mitigation recommendations based on layer analysis"""
        recommendations = []
        
        # Sort layers by risk contribution (mean WEI + RPS)
        sorted_layers = sorted(
            layer_scores.items(),
            key=lambda x: x[1].wei_contribution.mean + x[1].rps_contribution.mean,
            reverse=True
        )
        
        for layer, score in sorted_layers[:3]:  # Top 3 risky layers
            layer_name = layer.name.replace('_', ' ').title()
            
            if score.vulnerability_count > 0:
                recommendations.extend(self._get_layer_recommendations(layer, score, vulnerabilities_by_layer[layer]))
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def _get_layer_recommendations(self, layer: MAESTROLayer, score: LayerRiskScore, 
                                 vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Get specific recommendations for a MAESTRO layer"""
        recommendations = []
        layer_name = layer.name.replace('_', ' ').title()
        
        # Layer-specific recommendations based on MAESTRO framework
        if layer == MAESTROLayer.L1_FOUNDATION_MODELS:
            recommendations.extend([
                "Implement prompt injection protection and input validation",
                "Deploy model hardening techniques and bias mitigation",
                "Establish model governance and version control"
            ])
        elif layer == MAESTROLayer.L2_DATA_OPERATIONS:
            recommendations.extend([
                "Implement data anonymization and privacy controls",
                "Secure vector databases and data pipelines",
                "Deploy data loss prevention (DLP) solutions"
            ])
        elif layer == MAESTROLayer.L3_AGENT_FRAMEWORKS:
            recommendations.extend([
                "Implement agent protocol validation and tool vetting",
                "Deploy agent sandboxing and isolation",
                "Establish inter-agent communication security"
            ])
        elif layer == MAESTROLayer.L4_DEPLOYMENT:
            recommendations.extend([
                "Implement container security and runtime protection",
                "Deploy Zero Trust networking architecture",
                "Establish infrastructure hardening practices"
            ])
        elif layer == MAESTROLayer.L5_OBSERVABILITY:
            recommendations.extend([
                "Deploy AI-specific security monitoring",
                "Implement anomaly detection and threat hunting",
                "Establish comprehensive audit trails"
            ])
        elif layer == MAESTROLayer.L6_COMPLIANCE:
            recommendations.extend([
                "Implement governance frameworks and policy engines",
                "Deploy regulatory compliance monitoring",
                "Establish risk management processes"
            ])
        elif layer == MAESTROLayer.L7_ECOSYSTEM:
            recommendations.extend([
                "Implement supply chain security scanning",
                "Deploy third-party component vetting",
                "Establish dependency vulnerability management"
            ])
        
        return recommendations 