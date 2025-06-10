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

from ..models.maestro_constants import MAESTROLayer, MAESTRO_LAYER_DESCRIPTIONS

@dataclass
class MAESTROAssessmentReport:
    """Complete MAESTRO threat assessment report"""
    assessment_id: str
    timestamp: datetime
    workflow: ParsedWorkflow
    vulnerabilities: List[Dict[str, Any]]
    risk_assessment: RiskAssessmentResult
    executive_summary: Dict[str, Any]
    recommendations: List[str]
    metadata: Dict[str, Any]

class MAESTROEngine:
    """Main MAESTRO threat assessment engine"""
    
    def __init__(self):
        self.workflow_parser = WorkflowParser()
        self.risk_calculator = RiskCalculator()
        
    def assess_workflow_from_yaml(self, yaml_content: str) -> MAESTROAssessmentReport:
        """
        Perform complete MAESTRO assessment from YAML workflow definition
        
        Args:
            yaml_content: YAML workflow definition
            
        Returns:
            Complete MAESTRO assessment report
        """
        # Parse workflow
        workflow = self.workflow_parser.parse_yaml(yaml_content)
        
        # Identify vulnerabilities
        vulnerabilities = self.workflow_parser.identify_potential_vulnerabilities(workflow)
        
        # Calculate risk assessment
        risk_assessment = self.risk_calculator.calculate_risk(workflow, vulnerabilities)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            workflow, risk_assessment
        )
        
        # Combine recommendations
        recommendations = self._combine_recommendations(risk_assessment)
        
        # Generate assessment ID
        assessment_id = f"MAESTRO-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        return MAESTROAssessmentReport(
            assessment_id=assessment_id,
            timestamp=datetime.now(),
            workflow=workflow,
            vulnerabilities=vulnerabilities,
            risk_assessment=risk_assessment,
            executive_summary=executive_summary,
            recommendations=recommendations,
            metadata={
                'maestro_version': '1.0.0',
                'assessment_type': 'full'
            }
        )
    
    def assess_workflow_from_file(self, filepath: str) -> MAESTROAssessmentReport:
        """
        Perform complete MAESTRO assessment from YAML file
        
        Args:
            filepath: Path to YAML workflow file
            
        Returns:
            Complete MAESTRO assessment report
        """
        # Parse workflow from file
        workflow = self.workflow_parser.parse_file(filepath)
        
        # Use the YAML content assessment method
        with open(filepath, 'r', encoding='utf-8') as file:
            yaml_content = file.read()
            
        return self.assess_workflow_from_yaml(yaml_content)
    
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
            'total_wei': round(risk_assessment.total_wei.mean, 2),
            'total_wei_uncertainty': {
                'mean': round(risk_assessment.total_wei.mean, 2),
                'std_dev': round(risk_assessment.total_wei.std_dev, 2),
                'confidence_interval': (
                    round(risk_assessment.total_wei.confidence_interval[0], 2),
                    round(risk_assessment.total_wei.confidence_interval[1], 2)
                )
            },
            'total_rps': round(risk_assessment.total_rps.mean, 2),
            'total_rps_uncertainty': {
                'mean': round(risk_assessment.total_rps.mean, 2),
                'std_dev': round(risk_assessment.total_rps.std_dev, 2),
                'confidence_interval': (
                    round(risk_assessment.total_rps.confidence_interval[0], 2),
                    round(risk_assessment.total_rps.confidence_interval[1], 2)
                )
            },
            'vulnerability_count': len(vulnerabilities),
            'agents_count': len(workflow.agents),
            'steps_count': len(workflow.steps),
            'top_risks': self._get_top_risks(risk_assessment),
            'immediate_actions': risk_assessment.recommendations[:3]
        }
    
    def _generate_executive_summary(self, workflow: ParsedWorkflow, 
                                   risk_assessment: RiskAssessmentResult) -> Dict[str, Any]:
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
                'wei_score': round(risk_assessment.total_wei.mean, 2),
                'wei_uncertainty': {
                    'mean': round(risk_assessment.total_wei.mean, 2),
                    'std_dev': round(risk_assessment.total_wei.std_dev, 2),
                    'confidence_interval': risk_assessment.total_wei.confidence_interval
                },
                'rps_score': round(risk_assessment.total_rps.mean, 2),
                'rps_uncertainty': {
                    'mean': round(risk_assessment.total_rps.mean, 2),
                    'std_dev': round(risk_assessment.total_rps.std_dev, 2),
                    'confidence_interval': risk_assessment.total_rps.confidence_interval
                },
                'total_vulnerabilities': total_vulnerabilities,
                'critical_vulnerabilities': critical_vulnerabilities,
                'high_vulnerabilities': high_vulnerabilities
            },

            'key_findings': {
                'most_vulnerable_layers': [
                    {'layer': layer.name, 'vulnerability_count': count} 
                    for layer, count in vulnerable_layers if count > 0
                ],

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
    

    
    def _get_critical_risks(self, risk_assessment: RiskAssessmentResult) -> List[str]:
        """Get critical risk indicators"""
        critical_risks = []
        
        if risk_assessment.risk_level in ['high', 'critical']:
            critical_risks.append(f"Overall risk level is {risk_assessment.risk_level}")
        
        # Handle Monte Carlo results for WEI and RPS
        total_wei = risk_assessment.total_wei
        if hasattr(total_wei, 'mean'):
            wei_value = total_wei.mean
        else:
            wei_value = total_wei
            
        total_rps = risk_assessment.total_rps
        if hasattr(total_rps, 'mean'):
            rps_value = total_rps.mean
        else:
            rps_value = total_rps
        
        if wei_value > 5.0:
            critical_risks.append(f"High Workflow Exploitability Index: {wei_value:.2f}")
        
        if rps_value > 50.0:
            critical_risks.append(f"High Risk Propagation Score: {rps_value:.2f}")
        
        # Check for critical vulnerabilities by layer
        for layer, vulns in risk_assessment.vulnerabilities_by_layer.items():
            critical_vulns = [v for v in vulns if v.get('severity') == 'critical']
            if critical_vulns:
                critical_risks.append(
                    f"Critical vulnerabilities in {layer.name}: {len(critical_vulns)}"
                )
        
        return critical_risks[:5]
    
    def _combine_recommendations(self, risk_assessment: RiskAssessmentResult) -> List[str]:
        """Combine and prioritize recommendations from risk assessment"""
        
        combined_recommendations = []
        
        # Add top risk recommendations
        combined_recommendations.extend(risk_assessment.recommendations[:8])
        
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
                'total_wei': {
                    'mean': report.risk_assessment.total_wei.mean,
                    'std_dev': report.risk_assessment.total_wei.std_dev,
                    'confidence_interval': report.risk_assessment.total_wei.confidence_interval
                } if hasattr(report.risk_assessment.total_wei, 'mean') else report.risk_assessment.total_wei,
                'total_rps': {
                    'mean': report.risk_assessment.total_rps.mean,
                    'std_dev': report.risk_assessment.total_rps.std_dev,
                    'confidence_interval': report.risk_assessment.total_rps.confidence_interval
                } if hasattr(report.risk_assessment.total_rps, 'mean') else report.risk_assessment.total_rps,
                'layer_vulnerabilities': {
                    layer.name: len(vulns) 
                    for layer, vulns in report.risk_assessment.vulnerabilities_by_layer.items()
                }
            },

            'executive_summary': report.executive_summary,
            'recommendations': report.recommendations,
            'metadata': report.metadata
        }
        
        return json.dumps(report_dict, indent=2, default=str)

    def assess_workflow(self, yaml_content: str) -> MAESTROAssessmentReport:
        """
        Alias for assess_workflow_from_yaml for convenience
        
        Args:
            yaml_content: YAML workflow definition
            
        Returns:
            Complete MAESTRO assessment report
        """
        return self.assess_workflow_from_yaml(yaml_content) 