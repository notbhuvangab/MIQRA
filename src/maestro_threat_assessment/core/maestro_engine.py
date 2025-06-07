"""
MAESTRO Engine - Main Orchestration Module

Coordinates all MAESTRO threat assessment components:
- Workflow parsing and analysis
- Vulnerability identification
- Risk quantification (WEI, RPS)
- Cost estimation and TCO calculation
- Report generation
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import json
from datetime import datetime

from .workflow_parser import WorkflowParser, ParsedWorkflow
from .risk_calculator import RiskCalculator, RiskAssessmentResult
from .cost_estimator import CostEstimator, CostAssessmentResult
from ..models.maestro_constants import MAESTROLayer, MAESTRO_LAYER_DESCRIPTIONS

@dataclass
class MAESTROAssessmentReport:
    """Complete MAESTRO threat assessment report"""
    assessment_id: str
    timestamp: datetime
    workflow: ParsedWorkflow
    vulnerabilities: List[Dict[str, Any]]
    risk_assessment: RiskAssessmentResult
    cost_assessment: CostAssessmentResult
    executive_summary: Dict[str, Any]
    recommendations: List[str]
    metadata: Dict[str, Any]

class MAESTROEngine:
    """Main MAESTRO threat assessment engine"""
    
    def __init__(self):
        self.workflow_parser = WorkflowParser()
        self.risk_calculator = RiskCalculator()
        self.cost_estimator = CostEstimator()
        
    def assess_workflow_from_yaml(self, yaml_content: str, 
                                 base_infrastructure_cost: Optional[float] = None,
                                 enterprise_size: str = 'medium',
                                 industry: str = 'technology') -> MAESTROAssessmentReport:
        """
        Perform complete MAESTRO assessment from YAML workflow definition
        
        Args:
            yaml_content: YAML workflow definition
            base_infrastructure_cost: Base annual infrastructure cost
            enterprise_size: Enterprise size category
            industry: Industry type
            
        Returns:
            Complete MAESTRO assessment report
        """
        # Parse workflow
        workflow = self.workflow_parser.parse_yaml(yaml_content)
        
        # Identify vulnerabilities
        vulnerabilities = self.workflow_parser.identify_potential_vulnerabilities(workflow)
        
        # Calculate risk assessment
        risk_assessment = self.risk_calculator.calculate_risk(workflow, vulnerabilities)
        
        # Calculate cost assessment
        cost_assessment = self.cost_estimator.estimate_costs(
            risk_assessment, 
            base_infrastructure_cost, 
            enterprise_size, 
            industry
        )
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            workflow, risk_assessment, cost_assessment
        )
        
        # Combine recommendations
        recommendations = self._combine_recommendations(risk_assessment, cost_assessment)
        
        # Generate assessment ID
        assessment_id = f"MAESTRO-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        return MAESTROAssessmentReport(
            assessment_id=assessment_id,
            timestamp=datetime.now(),
            workflow=workflow,
            vulnerabilities=vulnerabilities,
            risk_assessment=risk_assessment,
            cost_assessment=cost_assessment,
            executive_summary=executive_summary,
            recommendations=recommendations,
            metadata={
                'maestro_version': '1.0.0',
                'assessment_type': 'full',
                'enterprise_size': enterprise_size,
                'industry': industry
            }
        )
    
    def assess_workflow_from_file(self, filepath: str,
                                 base_infrastructure_cost: Optional[float] = None,
                                 enterprise_size: str = 'medium',
                                 industry: str = 'technology') -> MAESTROAssessmentReport:
        """
        Perform complete MAESTRO assessment from YAML file
        
        Args:
            filepath: Path to YAML workflow file
            base_infrastructure_cost: Base annual infrastructure cost
            enterprise_size: Enterprise size category
            industry: Industry type
            
        Returns:
            Complete MAESTRO assessment report
        """
        # Parse workflow from file
        workflow = self.workflow_parser.parse_file(filepath)
        
        # Use the YAML content assessment method
        with open(filepath, 'r', encoding='utf-8') as file:
            yaml_content = file.read()
            
        return self.assess_workflow_from_yaml(
            yaml_content, base_infrastructure_cost, enterprise_size, industry
        )
    
    def quick_assessment(self, yaml_content: str) -> Dict[str, Any]:
        """
        Perform quick risk assessment without detailed cost analysis
        
        Args:
            yaml_content: YAML workflow definition
            
        Returns:
            Quick assessment summary
        """
        # Parse workflow
        workflow = self.workflow_parser.parse_yaml(yaml_content)
        
        # Identify vulnerabilities
        vulnerabilities = self.workflow_parser.identify_potential_vulnerabilities(workflow)
        
        # Calculate risk assessment
        risk_assessment = self.risk_calculator.calculate_risk(workflow, vulnerabilities)
        
        # Generate quick summary
        return {
            'workflow_name': workflow.name,
            'risk_level': risk_assessment.risk_level,
            'total_wei': round(risk_assessment.total_wei, 2),
            'total_rps': round(risk_assessment.total_rps, 2),
            'vulnerability_count': len(vulnerabilities),
            'agents_count': len(workflow.agents),
            'steps_count': len(workflow.steps),
            'top_risks': self._get_top_risks(risk_assessment),
            'immediate_actions': risk_assessment.recommendations[:3]
        }
    
    def _generate_executive_summary(self, workflow: ParsedWorkflow, 
                                   risk_assessment: RiskAssessmentResult,
                                   cost_assessment: CostAssessmentResult) -> Dict[str, Any]:
        """Generate executive summary for the assessment"""
        
        # Calculate key metrics
        total_vulnerabilities = len([v for layer_vulns in risk_assessment.vulnerabilities_by_layer.values() 
                                   for v in layer_vulns])
        
        critical_vulnerabilities = sum(1 for layer_vulns in risk_assessment.vulnerabilities_by_layer.values()
                                     for v in layer_vulns if v.get('severity') == 'critical')
        
        high_vulnerabilities = sum(1 for layer_vulns in risk_assessment.vulnerabilities_by_layer.values()
                                 for v in layer_vulns if v.get('severity') == 'high')
        
        # Identify most vulnerable layers
        vulnerable_layers = sorted(
            [(layer, len(vulns)) for layer, vulns in risk_assessment.vulnerabilities_by_layer.items()],
            key=lambda x: x[1], reverse=True
        )[:3]
        
        # Calculate security investment percentage
        security_investment_percentage = cost_assessment.cost_increase_percentage
        
        return {
            'workflow_overview': {
                'name': workflow.name,
                'description': workflow.description,
                'agents_count': len(workflow.agents),
                'steps_count': len(workflow.steps),
                'data_flows_count': len(workflow.data_flows)
            },
            'risk_summary': {
                'overall_risk_level': risk_assessment.risk_level,
                'wei_score': round(risk_assessment.total_wei, 2),
                'rps_score': round(risk_assessment.total_rps, 2),
                'total_vulnerabilities': total_vulnerabilities,
                'critical_vulnerabilities': critical_vulnerabilities,
                'high_vulnerabilities': high_vulnerabilities
            },
            'cost_summary': {
                'base_cost': cost_assessment.base_infrastructure_cost,
                'total_tco': cost_assessment.total_tco,
                'security_investment': cost_assessment.total_tco - cost_assessment.base_infrastructure_cost,
                'cost_increase_percentage': round(security_investment_percentage, 1),
                'roi_percentage': round(cost_assessment.roi_analysis.get('roi_percentage', 0), 1),
                'payback_months': round(cost_assessment.roi_analysis.get('payback_period_months', 0), 1)
            },
            'key_findings': {
                'most_vulnerable_layers': [
                    {'layer': layer.name, 'vulnerability_count': count} 
                    for layer, count in vulnerable_layers if count > 0
                ],
                'highest_cost_layers': self._get_highest_cost_layers(cost_assessment),
                'critical_risks': self._get_critical_risks(risk_assessment)
            }
        }
    
    def _get_top_risks(self, risk_assessment: RiskAssessmentResult) -> List[Dict[str, Any]]:
        """Get top 5 risks from the assessment"""
        all_vulnerabilities = []
        
        for layer, vulns in risk_assessment.vulnerabilities_by_layer.items():
            for vuln in vulns:
                vuln_copy = vuln.copy()
                vuln_copy['maestro_layer'] = layer.name
                all_vulnerabilities.append(vuln_copy)
        
        # Sort by severity and return top 5
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        sorted_vulns = sorted(
            all_vulnerabilities,
            key=lambda x: severity_order.get(x.get('severity', 'low'), 1),
            reverse=True
        )
        
        return sorted_vulns[:5]
    
    def _get_highest_cost_layers(self, cost_assessment: CostAssessmentResult) -> List[Dict[str, Any]]:
        """Get the 3 highest cost layers"""
        sorted_layers = sorted(
            cost_assessment.layer_costs.items(),
            key=lambda x: x[1].total_cost,
            reverse=True
        )
        
        return [
            {
                'layer': layer.name,
                'cost': round(cost_breakdown.total_cost, 0),
                'risk_multiplier': round(cost_breakdown.risk_multiplier, 2)
            }
            for layer, cost_breakdown in sorted_layers[:3]
        ]
    
    def _get_critical_risks(self, risk_assessment: RiskAssessmentResult) -> List[str]:
        """Get critical risk indicators"""
        critical_risks = []
        
        if risk_assessment.risk_level in ['high', 'critical']:
            critical_risks.append(f"Overall risk level is {risk_assessment.risk_level}")
        
        if risk_assessment.total_wei > 5.0:
            critical_risks.append(f"High Workflow Exploitability Index: {risk_assessment.total_wei:.2f}")
        
        if risk_assessment.total_rps > 50.0:
            critical_risks.append(f"High Risk Propagation Score: {risk_assessment.total_rps:.2f}")
        
        # Check for critical vulnerabilities by layer
        for layer, vulns in risk_assessment.vulnerabilities_by_layer.items():
            critical_vulns = [v for v in vulns if v.get('severity') == 'critical']
            if critical_vulns:
                critical_risks.append(
                    f"Critical vulnerabilities in {layer.name}: {len(critical_vulns)}"
                )
        
        return critical_risks[:5]
    
    def _combine_recommendations(self, risk_assessment: RiskAssessmentResult,
                               cost_assessment: CostAssessmentResult) -> List[str]:
        """Combine and prioritize recommendations from risk and cost assessments"""
        
        combined_recommendations = []
        
        # Add top risk recommendations
        combined_recommendations.extend(risk_assessment.recommendations[:5])
        
        # Add top cost optimization recommendations
        combined_recommendations.extend(cost_assessment.cost_optimization_recommendations[:3])
        
        # Add MAESTRO framework-specific recommendations
        maestro_recommendations = [
            "Implement MAESTRO framework compliance monitoring across all layers",
            "Establish regular MAESTRO-based security assessments (quarterly recommended)",
            "Deploy layer-specific security controls based on MAESTRO risk priorities",
            "Maintain MAESTRO threat model documentation and update procedures"
        ]
        
        combined_recommendations.extend(maestro_recommendations)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in combined_recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:12]  # Limit to top 12 recommendations
    
    def export_report_json(self, report: MAESTROAssessmentReport) -> str:
        """Export report as JSON string"""
        
        # Convert report to serializable dict
        report_dict = {
            'assessment_id': report.assessment_id,
            'timestamp': report.timestamp.isoformat(),
            'workflow': {
                'name': report.workflow.name,
                'description': report.workflow.description,
                'agents': report.workflow.agents,
                'steps_count': len(report.workflow.steps),
                'data_flows_count': len(report.workflow.data_flows)
            },
            'vulnerabilities': report.vulnerabilities,
            'risk_assessment': {
                'risk_level': report.risk_assessment.risk_level,
                'total_wei': report.risk_assessment.total_wei,
                'total_rps': report.risk_assessment.total_rps,
                'layer_vulnerabilities': {
                    layer.name: len(vulns) 
                    for layer, vulns in report.risk_assessment.vulnerabilities_by_layer.items()
                }
            },
            'cost_assessment': {
                'base_cost': report.cost_assessment.base_infrastructure_cost,
                'total_tco': report.cost_assessment.total_tco,
                'cost_increase_percentage': report.cost_assessment.cost_increase_percentage,
                'roi_analysis': report.cost_assessment.roi_analysis
            },
            'executive_summary': report.executive_summary,
            'recommendations': report.recommendations,
            'metadata': report.metadata
        }
        
        return json.dumps(report_dict, indent=2, default=str)

    def assess_workflow(self, yaml_content: str, 
                       base_infrastructure_cost: Optional[float] = None,
                       enterprise_size: str = 'medium',
                       industry: str = 'technology') -> MAESTROAssessmentReport:
        """
        Alias for assess_workflow_from_yaml for convenience
        
        Args:
            yaml_content: YAML workflow definition
            base_infrastructure_cost: Base annual infrastructure cost
            enterprise_size: Enterprise size category
            industry: Industry type
            
        Returns:
            Complete MAESTRO assessment report
        """
        return self.assess_workflow_from_yaml(
            yaml_content, base_infrastructure_cost, enterprise_size, industry
        ) 