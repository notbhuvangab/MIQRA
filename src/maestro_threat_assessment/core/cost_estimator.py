"""
MAESTRO Cost Estimator

Implements enterprise cost evaluation using MAESTRO-layered cost components:
- Total Cost of Ownership (TCO) calculation
- Layer-specific cost factor analysis
- Risk-based cost impact assessment
"""

import numpy as np
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from ..models.maestro_constants import (
    MAESTROLayer, MAESTRO_COST_WEIGHTS, MAESTRO_COST_COMPONENTS,
    MAESTRO_LAYER_DESCRIPTIONS
)
from .risk_calculator import RiskAssessmentResult, LayerRiskScore

@dataclass
class LayerCostBreakdown:
    """Cost breakdown for a specific MAESTRO layer"""
    layer: MAESTROLayer
    base_cost: float
    risk_multiplier: float
    total_cost: float
    cost_components: List[str]
    recommendations: List[str]

@dataclass
class CostAssessmentResult:
    """Complete cost assessment result"""
    workflow_name: str
    base_infrastructure_cost: float
    total_tco: float
    layer_costs: Dict[MAESTROLayer, LayerCostBreakdown]
    cost_increase_percentage: float
    roi_analysis: Dict[str, float]
    cost_optimization_recommendations: List[str]

class CostEstimator:
    """MAESTRO-enhanced enterprise cost estimator"""
    
    def __init__(self):
        # Base cost factors for different enterprise sizes
        self.enterprise_size_multipliers = {
            'startup': 0.3,
            'small': 0.6,
            'medium': 1.0,
            'large': 1.8,
            'enterprise': 3.0
        }
        
        # Industry-specific cost modifiers
        self.industry_modifiers = {
            'financial': 1.5,
            'healthcare': 1.4,
            'government': 1.6,
            'technology': 1.0,
            'retail': 0.8,
            'manufacturing': 0.9
        }
        
        # Default base infrastructure costs (annual, USD)
        self.default_base_costs = {
            'compute': 50000,
            'storage': 20000,
            'networking': 15000,
            'security_baseline': 30000,
            'monitoring': 25000,
            'compliance': 35000
        }
    
    def estimate_costs(self, risk_assessment: RiskAssessmentResult, 
                      base_infrastructure_cost: float = None,
                      enterprise_size: str = 'medium',
                      industry: str = 'technology') -> CostAssessmentResult:
        """
        Estimate enterprise costs using MAESTRO framework
        
        Args:
            risk_assessment: Risk assessment result from RiskCalculator
            base_infrastructure_cost: Base annual infrastructure cost
            enterprise_size: Size of enterprise (startup, small, medium, large, enterprise)
            industry: Industry type for cost modifiers
            
        Returns:
            Complete cost assessment result
        """
        # Calculate base infrastructure cost if not provided
        if base_infrastructure_cost is None:
            base_infrastructure_cost = self._calculate_default_base_cost(enterprise_size, industry)
        
        # Calculate layer-specific cost breakdowns
        layer_costs = self._calculate_layer_costs(risk_assessment, base_infrastructure_cost)
        
        # Calculate total TCO using MAESTRO formula
        total_tco = self._calculate_maestro_tco(base_infrastructure_cost, layer_costs)
        
        # Calculate cost increase percentage
        cost_increase_percentage = ((total_tco - base_infrastructure_cost) / base_infrastructure_cost) * 100
        
        # Perform ROI analysis
        roi_analysis = self._calculate_roi_analysis(risk_assessment, total_tco, base_infrastructure_cost)
        
        # Generate cost optimization recommendations
        cost_recommendations = self._generate_cost_optimization_recommendations(layer_costs, risk_assessment)
        
        return CostAssessmentResult(
            workflow_name=risk_assessment.workflow_name,
            base_infrastructure_cost=base_infrastructure_cost,
            total_tco=total_tco,
            layer_costs=layer_costs,
            cost_increase_percentage=cost_increase_percentage,
            roi_analysis=roi_analysis,
            cost_optimization_recommendations=cost_recommendations
        )
    
    def _calculate_default_base_cost(self, enterprise_size: str, industry: str) -> float:
        """Calculate default base infrastructure cost"""
        base_cost = sum(self.default_base_costs.values())
        
        # Apply enterprise size multiplier
        size_multiplier = self.enterprise_size_multipliers.get(enterprise_size, 1.0)
        
        # Apply industry modifier
        industry_modifier = self.industry_modifiers.get(industry, 1.0)
        
        return base_cost * size_multiplier * industry_modifier
    
    def _calculate_layer_costs(self, risk_assessment: RiskAssessmentResult, 
                              base_cost: float) -> Dict[MAESTROLayer, LayerCostBreakdown]:
        """Calculate cost breakdown for each MAESTRO layer"""
        layer_costs = {}
        
        for layer in MAESTROLayer:
            layer_score = risk_assessment.layer_scores[layer]
            
            # Calculate base cost allocation for this layer
            layer_base_cost = base_cost * MAESTRO_COST_WEIGHTS[layer]
            
            # Calculate risk multiplier based on layer risk score
            risk_multiplier = self._calculate_risk_multiplier(layer_score)
            
            # Calculate total cost for this layer
            layer_total_cost = layer_base_cost * risk_multiplier
            
            # Get cost components and recommendations
            cost_components = MAESTRO_COST_COMPONENTS[layer].copy()
            layer_recommendations = self._get_layer_cost_recommendations(layer, layer_score)
            
            layer_costs[layer] = LayerCostBreakdown(
                layer=layer,
                base_cost=layer_base_cost,
                risk_multiplier=risk_multiplier,
                total_cost=layer_total_cost,
                cost_components=cost_components,
                recommendations=layer_recommendations
            )
        
        return layer_costs
    
    def _calculate_risk_multiplier(self, layer_score: LayerRiskScore) -> float:
        """
        Calculate risk-based cost multiplier for a layer
        
        Higher risk = higher security investment needed
        """
        base_multiplier = 1.0
        
        # Factor in vulnerability count
        vuln_multiplier = 1.0 + (layer_score.vulnerability_count * 0.1)
        
        # Factor in business impact
        impact_multiplier = 1.0 + (layer_score.business_impact / 5.0 * 0.5)
        
        # Factor in attack complexity (lower complexity = higher cost)
        complexity_multiplier = 1.0 + ((4.0 - layer_score.attack_complexity) / 3.0 * 0.3)
        
        # Factor in WEI and RPS contributions
        wei_multiplier = 1.0 + (layer_score.wei_contribution * 0.2)
        rps_multiplier = 1.0 + (layer_score.rps_contribution / 50.0 * 0.3)
        
        total_multiplier = (base_multiplier * vuln_multiplier * impact_multiplier * 
                          complexity_multiplier * wei_multiplier * rps_multiplier)
        
        # Cap the multiplier to reasonable bounds
        return min(max(total_multiplier, 1.0), 5.0)
    
    def _calculate_maestro_tco(self, base_cost: float, 
                              layer_costs: Dict[MAESTROLayer, LayerCostBreakdown]) -> float:
        """
        Calculate Total Cost of Ownership using MAESTRO formula:
        TCO_MAESTRO = BaseCost × Σ(RiskScore × CostWeight)
        """
        total_risk_weighted_cost = sum(layer_cost.total_cost for layer_cost in layer_costs.values())
        
        # The formula is already applied in layer cost calculation, so we just sum
        return total_risk_weighted_cost
    
    def _calculate_roi_analysis(self, risk_assessment: RiskAssessmentResult, 
                               total_tco: float, base_cost: float) -> Dict[str, float]:
        """Calculate return on investment analysis for security investments"""
        
        # Estimate potential losses without security investment
        potential_annual_loss = self._estimate_potential_losses(risk_assessment, base_cost)
        
        # Calculate security investment amount
        security_investment = total_tco - base_cost
        
        # Calculate ROI metrics
        roi_percentage = ((potential_annual_loss - security_investment) / security_investment) * 100
        payback_period_months = (security_investment / potential_annual_loss) * 12
        
        # Calculate risk reduction value
        risk_reduction_value = potential_annual_loss * 0.8  # Assume 80% risk reduction
        
        return {
            'potential_annual_loss': potential_annual_loss,
            'security_investment': security_investment,
            'roi_percentage': roi_percentage,
            'payback_period_months': payback_period_months,
            'risk_reduction_value': risk_reduction_value,
            'net_benefit': risk_reduction_value - security_investment
        }
    
    def _estimate_potential_losses(self, risk_assessment: RiskAssessmentResult, 
                                  base_cost: float) -> float:
        """Estimate potential annual losses based on risk assessment"""
        
        # Base loss estimation factors
        loss_factors = {
            'critical': 2.0,
            'high': 1.0,
            'medium': 0.3,
            'low': 0.1
        }
        
        # Get base loss potential from infrastructure cost
        base_loss_potential = base_cost * 0.5  # Assume 50% of infrastructure value at risk
        
        # Apply risk level multiplier
        risk_multiplier = loss_factors.get(risk_assessment.risk_level, 0.3)
        
        # Factor in WEI and RPS scores
        wei_factor = min(risk_assessment.total_wei / 10.0, 1.0)
        rps_factor = min(risk_assessment.total_rps / 100.0, 1.0)
        
        # Calculate total potential loss
        total_potential_loss = base_loss_potential * risk_multiplier * (1 + wei_factor + rps_factor)
        
        return total_potential_loss
    
    def _get_layer_cost_recommendations(self, layer: MAESTROLayer, 
                                       layer_score: LayerRiskScore) -> List[str]:
        """Get cost optimization recommendations for a specific layer"""
        
        recommendations = []
        
        # High-risk layers get immediate investment recommendations
        if layer_score.vulnerability_count > 2 or layer_score.wei_contribution > 0.5:
            recommendations.append(f"Prioritize immediate investment in {layer.name.lower()} security controls")
        
        # Layer-specific cost optimization recommendations
        layer_cost_recommendations = {
            MAESTROLayer.L1_FOUNDATION_MODELS: [
                "Consider shared model security services across business units",
                "Implement automated bias testing to reduce manual audit costs"
            ],
            MAESTROLayer.L2_DATA_OPERATIONS: [
                "Deploy automated data classification to reduce manual oversight",
                "Implement shared data security infrastructure across teams"
            ],
            MAESTROLayer.L3_AGENT_FRAMEWORKS: [
                "Standardize agent security frameworks to reduce per-agent costs",
                "Implement centralized tool validation services"
            ],
            MAESTROLayer.L4_DEPLOYMENT: [
                "Leverage cloud-native security services to reduce infrastructure costs",
                "Implement infrastructure-as-code for consistent security deployments"
            ],
            MAESTROLayer.L5_OBSERVABILITY: [
                "Deploy unified monitoring platforms to reduce tool proliferation",
                "Implement automated security analytics to reduce manual analysis"
            ],
            MAESTROLayer.L6_COMPLIANCE: [
                "Automate compliance reporting to reduce ongoing audit costs",
                "Implement policy-as-code to reduce manual governance overhead"
            ],
            MAESTROLayer.L7_ECOSYSTEM: [
                "Establish vendor security assessment programs for economies of scale",
                "Implement automated dependency scanning to reduce manual review costs"
            ]
        }
        
        recommendations.extend(layer_cost_recommendations.get(layer, [])[:2])
        
        return recommendations
    
    def _generate_cost_optimization_recommendations(self, 
                                                   layer_costs: Dict[MAESTROLayer, LayerCostBreakdown],
                                                   risk_assessment: RiskAssessmentResult) -> List[str]:
        """Generate overall cost optimization recommendations"""
        
        recommendations = []
        
        # Sort layers by cost impact
        sorted_layers = sorted(layer_costs.items(), 
                             key=lambda x: x[1].total_cost, reverse=True)
        
        # High-cost layer recommendations
        for layer, cost_breakdown in sorted_layers[:3]:
            if cost_breakdown.risk_multiplier > 2.0:
                recommendations.append(
                    f"Focus on {layer.name.lower()} layer - highest cost impact "
                    f"(${cost_breakdown.total_cost:,.0f} annually)"
                )
        
        # General cost optimization recommendations
        recommendations.extend([
            "Implement phased security investment approach starting with highest-risk layers",
            "Consider shared security services across multiple workflows to achieve economies of scale",
            "Establish security metrics and KPIs to measure investment effectiveness",
            "Regularly reassess risk levels to optimize ongoing security spending",
            "Investigate automation opportunities to reduce operational security costs"
        ])
        
        # Risk-based recommendations
        if risk_assessment.risk_level in ['high', 'critical']:
            recommendations.append(
                "Given high risk level, prioritize immediate security investments over cost optimization"
            )
        elif risk_assessment.risk_level == 'low':
            recommendations.append(
                "Consider cost-optimized security approaches given low overall risk level"
            )
        
        return recommendations[:8]  # Limit to top 8 recommendations 