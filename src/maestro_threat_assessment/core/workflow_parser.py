"""
Workflow Parser for MAESTRO Threat Assessment

Parses YAML workflow definitions and extracts:
- Workflow structure
- Agent interactions
- Data flows
- Potential security vulnerabilities
- Protocol compliance validation
"""

import yaml
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import re

from .protocol_validator import validate_workflow_protocols, ValidationResult

@dataclass
class WorkflowStep:
    """Represents a single step in an agentic workflow"""
    step_id: str
    agent: str
    action: str
    params: Dict[str, Any]
    input_from: Optional[str] = None
    dependencies: List[str] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []

@dataclass
class DataFlow:
    """Represents data flow between workflow steps"""
    source_step: str
    target_step: str
    data_type: str
    sensitivity_level: str = "unknown"

@dataclass
class ParsedWorkflow:
    """Complete parsed workflow with metadata"""
    name: str
    description: str
    steps: List[WorkflowStep]
    data_flows: List[DataFlow]
    agents: List[str]
    metadata: Dict[str, Any]
    protocol_validation: Optional[ValidationResult] = None

class WorkflowParser:
    """YAML workflow parser with security analysis capabilities"""
    
    def __init__(self):
        self.sensitive_patterns = [
            r'(password|secret|key|token|credential)',
            r'(social_security|ssn|credit_card|card_number)',
            r'(personal|private|confidential|classified)',
            r'(financial|bank|account|payment)',
            r'(medical|health|patient|diagnosis)'
        ]
        
    def parse_yaml(self, yaml_content: str) -> ParsedWorkflow:
        """
        Parse YAML workflow definition
        
        Args:
            yaml_content: YAML string containing workflow definition
            
        Returns:
            ParsedWorkflow object with extracted information
        """
        try:
            workflow_data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML format: {e}")
            
        return self._parse_workflow_data(workflow_data)
    
    def parse_file(self, filepath: str) -> ParsedWorkflow:
        """
        Parse YAML workflow from file
        
        Args:
            filepath: Path to YAML workflow file
            
        Returns:
            ParsedWorkflow object
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                return self.parse_yaml(file.read())
        except FileNotFoundError:
            raise ValueError(f"Workflow file not found: {filepath}")
        except Exception as e:
            raise ValueError(f"Error reading workflow file: {e}")
    
    def _parse_workflow_data(self, data: Dict[str, Any]) -> ParsedWorkflow:
        """Parse workflow data dictionary"""
        
        # Validate protocol compliance first
        protocol_validation = validate_workflow_protocols(data)
        
        # Extract basic workflow info
        workflow_name = data.get('workflow', {}).get('name', 'Unnamed Workflow')
        workflow_desc = data.get('workflow', {}).get('description', '')
        workflow_meta = data.get('workflow', {}).get('metadata', {})
        
        # Extract steps
        steps_data = data.get('workflow', {}).get('steps', [])
        if not steps_data:
            raise ValueError("No workflow steps found")
            
        steps = []
        agents = set()
        
        for i, step_data in enumerate(steps_data):
            step_id = step_data.get('id', f"step_{i}")
            agent = step_data.get('agent', 'unknown_agent')
            action = step_data.get('action', 'unknown_action')
            params = step_data.get('params', {})
            input_from = step_data.get('input_from')
            dependencies = step_data.get('dependencies', [])
            
            steps.append(WorkflowStep(
                step_id=step_id,
                agent=agent,
                action=action,
                params=params,
                input_from=input_from,
                dependencies=dependencies
            ))
            
            agents.add(agent)
        
        # Analyze data flows
        data_flows = self._analyze_data_flows(steps)
        
        return ParsedWorkflow(
            name=workflow_name,
            description=workflow_desc,
            steps=steps,
            data_flows=data_flows,
            agents=list(agents),
            metadata=workflow_meta,
            protocol_validation=protocol_validation
        )
    
    def _analyze_data_flows(self, steps: List[WorkflowStep]) -> List[DataFlow]:
        """Analyze data flows between workflow steps"""
        data_flows = []
        
        for step in steps:
            # Check for explicit input_from relationships
            if step.input_from:
                sensitivity = self._detect_sensitivity(step.params)
                data_flows.append(DataFlow(
                    source_step=step.input_from,
                    target_step=step.step_id,
                    data_type="processed_data",
                    sensitivity_level=sensitivity
                ))
            
            # Check for dependency relationships
            for dep in step.dependencies:
                sensitivity = self._detect_sensitivity(step.params)
                data_flows.append(DataFlow(
                    source_step=dep,
                    target_step=step.step_id,
                    data_type="dependency_data",
                    sensitivity_level=sensitivity
                ))
        
        return data_flows
    
    def _detect_sensitivity(self, params: Dict[str, Any]) -> str:
        """Detect data sensitivity level based on parameters"""
        param_str = str(params).lower()
        
        for pattern in self.sensitive_patterns:
            if re.search(pattern, param_str):
                return "high"
        
        # Check for common sensitive keywords
        sensitive_keywords = [
            'user', 'customer', 'client', 'employee',
            'report', 'analysis', 'prediction', 'recommendation'
        ]
        
        for keyword in sensitive_keywords:
            if keyword in param_str:
                return "medium"
                
        return "low"
    
    def identify_potential_vulnerabilities(self, workflow: ParsedWorkflow) -> List[Dict[str, Any]]:
        """
        Identify potential security vulnerabilities in the workflow
        
        Args:
            workflow: Parsed workflow object
            
        Returns:
            List of potential vulnerabilities with details
        """
        vulnerabilities = []
        
        for step in workflow.steps:
            # Check for common vulnerability patterns
            step_vulns = self._analyze_step_vulnerabilities(step)
            vulnerabilities.extend(step_vulns)
        
        # Check for workflow-level vulnerabilities
        workflow_vulns = self._analyze_workflow_vulnerabilities(workflow)
        vulnerabilities.extend(workflow_vulns)
        
        return vulnerabilities
    
    def _analyze_step_vulnerabilities(self, step: WorkflowStep) -> List[Dict[str, Any]]:
        """Analyze vulnerabilities in a single workflow step"""
        vulnerabilities = []
        
        # Check for prompt injection risks (Foundation Models L1)
        if ('prompt' in str(step.params).lower() or 
            step.action in ['analyze', 'generate', 'process', 'analyze_financial_risk', 'process_risk_predictions'] or
            'AnalyticsAgent' in step.agent or 'ModelAgent' in step.agent):
            vulnerabilities.append({
                'type': 'prompt_injection',
                'step': step.step_id,
                'agent': step.agent,
                'severity': 'high',
                'description': 'Step may be vulnerable to prompt injection attacks'
            })
        
        # Check for model poisoning risks (Foundation Models L1)
        if ('model' in str(step.params).lower() or 
            'ModelAgent' in step.agent or
            'ml_predictions' in step.action.lower() or
            'inference' in step.action.lower()):
            vulnerabilities.append({
                'type': 'model_poisoning',
                'step': step.step_id,
                'agent': step.agent,
                'severity': 'critical',
                'description': 'Model processing may be vulnerable to poisoning attacks'
            })
        
        # Check for data leakage risks (Data Operations L2) - be more specific
        high_risk_data = ['financial_records', 'payment_data', 'sensitive_customer_data', 'classified']
        medium_risk_data = ['customer_data', 'user_profiles', 'analytics_data']
        
        if any(pattern in step.action.lower() for pattern in high_risk_data):
            vulnerabilities.append({
                'type': 'data_leakage',
                'step': step.step_id,
                'agent': step.agent,
                'severity': 'high',
                'description': 'High-sensitivity data processing poses leakage risks'
            })
        elif any(pattern in step.action.lower() for pattern in medium_risk_data):
            vulnerabilities.append({
                'type': 'data_leakage',
                'step': step.step_id,
                'agent': step.agent,
                'severity': 'medium',
                'description': 'Customer data processing requires proper controls'
            })
        
        # Check for privacy violations (Data Operations L2)
        if ('pii' in str(step.params).lower() or 
            'customer_records' in str(step.params).lower() or
            'payment_data' in str(step.params).lower() or
            'sensitive' in str(step.params).lower()):
            vulnerabilities.append({
                'type': 'privacy_violation',
                'step': step.step_id,
                'agent': step.agent,
                'severity': 'high',
                'description': 'Processing of PII and sensitive data poses privacy risks'
            })
        
        # Check for tool poisoning risks (Agent Frameworks L3)
        if ('tool' in str(step.params).lower() or 
            step.action in ['execute', 'run', 'invoke', 'process_analysis_tool'] or
            'external_apis' in str(step.params).lower() or
            'AnalyticsAgent' in step.agent):
            vulnerabilities.append({
                'type': 'tool_poisoning',
                'step': step.step_id,
                'agent': step.agent,
                'severity': 'high',
                'description': 'Tool execution may be vulnerable to poisoning attacks'
            })
        
        # Check for agent impersonation risks (Agent Frameworks L3)
        if (len(step.dependencies) > 0 or step.input_from or
            'a2a_' in str(step.params).lower() or
            'oauth2' in str(step.params).lower()):
            vulnerabilities.append({
                'type': 'agent_impersonation',
                'step': step.step_id,
                'agent': step.agent,
                'severity': 'medium',
                'description': 'Agent communication may allow impersonation attacks'
            })
        
        # Check for privilege escalation (Deployment L4)
        if ('critical_operations' in step.action.lower() or
            'execute_critical' in step.action.lower() or
            'WorkflowAgent' in step.agent or
            'administrator' in str(step.params).lower() or
            'privileged' in str(step.params).lower()):
            vulnerabilities.append({
                'type': 'privilege_escalation',
                'step': step.step_id,
                'agent': step.agent,
                'severity': 'high',
                'description': 'Critical operations may lead to privilege escalation'
            })
        
        return vulnerabilities
    
    def _analyze_workflow_vulnerabilities(self, workflow: ParsedWorkflow) -> List[Dict[str, Any]]:
        """Analyze workflow-level vulnerabilities"""
        vulnerabilities = []
        
        # Check for monitoring evasion (Observability L5) - only for complex workflows
        if (len(workflow.steps) > 7 and 
            not any('monitor' in step.action.lower() for step in workflow.steps)):
            vulnerabilities.append({
                'type': 'monitoring_evasion',
                'step': 'workflow',
                'agent': 'system',
                'severity': 'low',
                'description': 'Complex workflow could benefit from monitoring capabilities'
            })
        
        # Check for compliance violations (Compliance L6) - be more realistic
        high_compliance_keywords = ['payment_processing', 'credit_card', 'bank_transfer', 'financial_transaction']
        medium_compliance_keywords = ['customer_data', 'user_profiles', 'analytics']
        compliance_frameworks = workflow.metadata.get('compliance_frameworks', [])
        
        if any(keyword in workflow.name.lower() for keyword in high_compliance_keywords):
            vulnerabilities.append({
                'type': 'compliance_violation',
                'step': 'workflow',
                'agent': 'system',
                'severity': 'high',
                'description': 'Payment/financial processing requires strict compliance controls'
            })
        elif (any(keyword in workflow.name.lower() for keyword in medium_compliance_keywords) and
              any(framework in ['SOX', 'PCI_DSS', 'GDPR'] for framework in compliance_frameworks)):
            vulnerabilities.append({
                'type': 'compliance_violation',
                'step': 'workflow',
                'agent': 'system',
                'severity': 'medium',
                'description': 'Data processing workflow should follow compliance guidelines'
            })
        
        # Check for supply chain attacks (Ecosystem L7)
        agents = set(step.agent for step in workflow.steps)
        external_dependencies = any('external' in str(step.params).lower() or 
                                  'api' in str(step.params).lower() or
                                  'third_party' in str(step.params).lower()
                                  for step in workflow.steps)
        if len(agents) > 3 or external_dependencies:
            vulnerabilities.append({
                'type': 'supply_chain_attack',
                'step': 'workflow',
                'agent': 'system',
                'severity': 'medium',
                'description': 'Multiple agents and external dependencies increase supply chain attack surface'
            })
        
        return vulnerabilities 