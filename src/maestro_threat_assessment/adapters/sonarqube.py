"""
SonarQube Adapter for Baseline Comparison
Integrates with SonarQube for code quality and security analysis
"""

import requests
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class SonarQubeIssue:
    """SonarQube issue representation"""
    key: str
    rule: str
    severity: str
    component: str
    line: Optional[int]
    message: str
    type: str
    
    
@dataclass
class SonarQubeMetrics:
    """SonarQube quality metrics"""
    reliability_rating: str
    security_rating: str
    maintainability_rating: str
    coverage: float
    duplicated_lines_density: float
    bugs: int
    vulnerabilities: int
    security_hotspots: int
    code_smells: int


class SonarQubeAdapter:
    """Adapter to integrate with SonarQube for baseline comparison"""
    
    def __init__(self, server_url: str = "http://localhost:9000", token: str = None):
        self.server_url = server_url.rstrip('/')
        self.token = token
        self.session = self._create_session()
        
    def _create_session(self) -> requests.Session:
        """Create authenticated session"""
        session = requests.Session()
        if self.token:
            session.auth = (self.token, '')
        return session
    
    def analyze_workflow(self, workflow_yaml: str, project_key: str = "maestro-analysis") -> Dict[str, Any]:
        """
        Analyze workflow using SonarQube
        
        Note: This is a simulation since SonarQube doesn't natively support YAML workflow analysis.
        In a real implementation, you would:
        1. Convert YAML to analyzable code format
        2. Create temporary project
        3. Run SonarQube analysis
        4. Retrieve results
        """
        try:
            # Simulate SonarQube analysis results
            return self._simulate_sonarqube_analysis(workflow_yaml, project_key)
        except Exception as e:
            logging.error(f"SonarQube analysis failed: {e}")
            return self._get_default_results()
    
    def _simulate_sonarqube_analysis(self, workflow_yaml: str, project_key: str) -> Dict[str, Any]:
        """Simulate SonarQube analysis for demonstration"""
        
        # Simulate finding common issues
        issues = []
        metrics = {
            'reliability_rating': 'A',
            'security_rating': 'A', 
            'maintainability_rating': 'A',
            'coverage': 0.0,  # No code coverage for YAML
            'duplicated_lines_density': 0.0,
            'bugs': 0,
            'vulnerabilities': 0,
            'security_hotspots': 0,
            'code_smells': 0
        }
        
        # Check for hardcoded credentials
        if 'password' in workflow_yaml.lower() or 'secret' in workflow_yaml.lower():
            issues.append(SonarQubeIssue(
                key="hardcoded-credentials",
                rule="secrets:S6290",
                severity="CRITICAL",
                component=project_key,
                line=None,
                message="Hardcoded credentials detected",
                type="VULNERABILITY"
            ))
            metrics['vulnerabilities'] += 1
            metrics['security_rating'] = 'E'
        
        # Check for insecure HTTP
        if 'http://' in workflow_yaml:
            issues.append(SonarQubeIssue(
                key="insecure-http",
                rule="web:InsecureHttpRule",
                severity="MAJOR",
                component=project_key,
                line=None,
                message="Insecure HTTP connection detected",
                type="VULNERABILITY"
            ))
            metrics['vulnerabilities'] += 1
            if metrics['security_rating'] == 'A':
                metrics['security_rating'] = 'C'
        
        # Check for complex configurations
        if len(workflow_yaml.split('\n')) > 50:
            issues.append(SonarQubeIssue(
                key="complex-config",
                rule="yaml:ComplexityRule",
                severity="MINOR",
                component=project_key,
                line=None,
                message="Configuration is complex and may be hard to maintain",
                type="CODE_SMELL"
            ))
            metrics['code_smells'] += 1
            
        return {
            'project_key': project_key,
            'issues': [self._issue_to_dict(issue) for issue in issues],
            'metrics': metrics,
            'analysis_date': "2024-01-01T00:00:00Z",
            'source': 'sonarqube'
        }
    
    def _issue_to_dict(self, issue: SonarQubeIssue) -> Dict[str, Any]:
        """Convert SonarQubeIssue to dictionary"""
        return {
            'key': issue.key,
            'rule': issue.rule,
            'severity': issue.severity,
            'component': issue.component,
            'line': issue.line,
            'message': issue.message,
            'type': issue.type
        }
    
    def get_project_metrics(self, project_key: str) -> Optional[SonarQubeMetrics]:
        """Get quality metrics for a project"""
        try:
            url = f"{self.server_url}/api/measures/component"
            params = {
                'component': project_key,
                'metricKeys': 'reliability_rating,security_rating,maintainability_rating,coverage,duplicated_lines_density,bugs,vulnerabilities,security_hotspots,code_smells'
            }
            
            response = self.session.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            measures = data.get('component', {}).get('measures', [])
            
            # Parse metrics
            metrics_dict = {measure['metric']: measure.get('value', '0') for measure in measures}
            
            return SonarQubeMetrics(
                reliability_rating=metrics_dict.get('reliability_rating', 'A'),
                security_rating=metrics_dict.get('security_rating', 'A'),
                maintainability_rating=metrics_dict.get('maintainability_rating', 'A'),
                coverage=float(metrics_dict.get('coverage', 0.0)),
                duplicated_lines_density=float(metrics_dict.get('duplicated_lines_density', 0.0)),
                bugs=int(metrics_dict.get('bugs', 0)),
                vulnerabilities=int(metrics_dict.get('vulnerabilities', 0)),
                security_hotspots=int(metrics_dict.get('security_hotspots', 0)),
                code_smells=int(metrics_dict.get('code_smells', 0))
            )
            
        except Exception as e:
            logging.error(f"Failed to get SonarQube metrics: {e}")
            return None
    
    def get_project_issues(self, project_key: str, severity: str = None) -> List[SonarQubeIssue]:
        """Get issues for a project"""
        try:
            url = f"{self.server_url}/api/issues/search"
            params = {
                'componentKeys': project_key,
                'ps': 500  # Page size
            }
            
            if severity:
                params['severities'] = severity
                
            response = self.session.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            issues = []
            
            for issue_data in data.get('issues', []):
                issues.append(SonarQubeIssue(
                    key=issue_data['key'],
                    rule=issue_data['rule'],
                    severity=issue_data['severity'],
                    component=issue_data['component'],
                    line=issue_data.get('line'),
                    message=issue_data['message'],
                    type=issue_data['type']
                ))
            
            return issues
            
        except Exception as e:
            logging.error(f"Failed to get SonarQube issues: {e}")
            return []
    
    def _get_default_results(self) -> Dict[str, Any]:
        """Get default results when SonarQube is unavailable"""
        return {
            'project_key': 'unavailable',
            'issues': [],
            'metrics': {
                'reliability_rating': 'A',
                'security_rating': 'A',
                'maintainability_rating': 'A',
                'coverage': 0.0,
                'duplicated_lines_density': 0.0,
                'bugs': 0,
                'vulnerabilities': 0,
                'security_hotspots': 0,
                'code_smells': 0
            },
            'analysis_date': "2024-01-01T00:00:00Z",
            'source': 'sonarqube',
            'status': 'unavailable'
        }
    
    def is_available(self) -> bool:
        """Check if SonarQube server is available"""
        try:
            response = self.session.get(f"{self.server_url}/api/system/status")
            return response.status_code == 200
        except:
            return False 