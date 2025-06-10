"""
Snyk Adapter for Baseline Comparison
Integrates with Snyk for vulnerability scanning and security analysis
"""

import requests
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class SnykVulnerability:
    """Snyk vulnerability representation"""
    id: str
    title: str
    severity: str
    cvss_score: float
    cve: Optional[str]
    description: str
    remediation: str
    introduced_date: str
    
    
@dataclass
class SnykProject:
    """Snyk project representation"""
    id: str
    name: str
    type: str
    status: str
    vulnerability_count: int
    high_severity_count: int
    medium_severity_count: int
    low_severity_count: int


class SnykAdapter:
    """Adapter to integrate with Snyk for baseline comparison"""
    
    def __init__(self, api_token: str = None, org_id: str = None):
        self.api_token = api_token
        self.org_id = org_id
        self.base_url = "https://api.snyk.io/v1"
        self.session = self._create_session()
        
    def _create_session(self) -> requests.Session:
        """Create authenticated session"""
        session = requests.Session()
        if self.api_token:
            session.headers.update({
                'Authorization': f'token {self.api_token}',
                'Content-Type': 'application/json'
            })
        return session
    
    def analyze_workflow(self, workflow_yaml: str, project_name: str = "maestro-workflow") -> Dict[str, Any]:
        """
        Analyze workflow using Snyk
        
        Note: This simulates Snyk analysis since Snyk doesn't natively support YAML workflow analysis.
        In practice, you would:
        1. Extract dependency information from YAML
        2. Create a package manifest (package.json, requirements.txt, etc.)
        3. Submit for Snyk analysis
        4. Retrieve vulnerability results
        """
        try:
            return self._simulate_snyk_analysis(workflow_yaml, project_name)
        except Exception as e:
            logging.error(f"Snyk analysis failed: {e}")
            return self._get_default_results()
    
    def _simulate_snyk_analysis(self, workflow_yaml: str, project_name: str) -> Dict[str, Any]:
        """Simulate Snyk analysis for demonstration"""
        
        vulnerabilities = []
        
        # Check for vulnerable patterns in the YAML
        if 'requests' in workflow_yaml:
            vulnerabilities.append(SnykVulnerability(
                id="SNYK-PYTHON-REQUESTS-5885734",
                title="Requests SSL Certificate Verification Bypass",
                severity="medium",
                cvss_score=5.9,
                cve="CVE-2023-32681",
                description="The requests library allows SSL certificate verification to be disabled",
                remediation="Upgrade requests to version 2.31.0 or higher",
                introduced_date="2024-01-01"
            ))
        
        if 'pillow' in workflow_yaml.lower():
            vulnerabilities.append(SnykVulnerability(
                id="SNYK-PYTHON-PILLOW-6513858",
                title="Pillow Buffer Overflow",
                severity="high",
                cvss_score=7.5,
                cve="CVE-2023-50447",
                description="Buffer overflow in Pillow when processing crafted image files",
                remediation="Upgrade Pillow to version 10.2.0 or higher",
                introduced_date="2024-01-01"
            ))
        
        if 'version: 0.0.1' in workflow_yaml or 'version: 0.1.0' in workflow_yaml:
            vulnerabilities.append(SnykVulnerability(
                id="SNYK-GENERIC-DEVVERSION-001",
                title="Development Version in Production",
                severity="medium",
                cvss_score=4.0,
                cve=None,
                description="Using development or pre-release versions in production",
                remediation="Use stable released versions",
                introduced_date="2024-01-01"
            ))
        
        # Calculate severity counts
        severity_counts = {
            'critical': len([v for v in vulnerabilities if v.severity == 'critical']),
            'high': len([v for v in vulnerabilities if v.severity == 'high']),
            'medium': len([v for v in vulnerabilities if v.severity == 'medium']),
            'low': len([v for v in vulnerabilities if v.severity == 'low'])
        }
        
        return {
            'project_name': project_name,
            'vulnerabilities': [self._vulnerability_to_dict(v) for v in vulnerabilities],
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'critical_severity': severity_counts['critical'],
                'high_severity': severity_counts['high'],
                'medium_severity': severity_counts['medium'],
                'low_severity': severity_counts['low']
            },
            'scan_date': "2024-01-01T00:00:00Z",
            'source': 'snyk'
        }
    
    def _vulnerability_to_dict(self, vuln: SnykVulnerability) -> Dict[str, Any]:
        """Convert SnykVulnerability to dictionary"""
        return {
            'id': vuln.id,
            'title': vuln.title,
            'severity': vuln.severity,
            'cvss_score': vuln.cvss_score,
            'cve': vuln.cve,
            'description': vuln.description,
            'remediation': vuln.remediation,
            'introduced_date': vuln.introduced_date
        }
    
    def get_organization_projects(self) -> List[SnykProject]:
        """Get projects for the organization"""
        if not self.org_id:
            return []
            
        try:
            url = f"{self.base_url}/org/{self.org_id}/projects"
            response = self.session.get(url)
            response.raise_for_status()
            
            data = response.json()
            projects = []
            
            for project_data in data.get('projects', []):
                projects.append(SnykProject(
                    id=project_data['id'],
                    name=project_data['name'],
                    type=project_data.get('type', 'unknown'),
                    status=project_data.get('status', 'active'),
                    vulnerability_count=project_data.get('issueCountsBySeverity', {}).get('total', 0),
                    high_severity_count=project_data.get('issueCountsBySeverity', {}).get('high', 0),
                    medium_severity_count=project_data.get('issueCountsBySeverity', {}).get('medium', 0),
                    low_severity_count=project_data.get('issueCountsBySeverity', {}).get('low', 0)
                ))
            
            return projects
            
        except Exception as e:
            logging.error(f"Failed to get Snyk projects: {e}")
            return []
    
    def get_project_vulnerabilities(self, project_id: str) -> List[SnykVulnerability]:
        """Get vulnerabilities for a specific project"""
        try:
            url = f"{self.base_url}/project/{project_id}/issues"
            response = self.session.get(url)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = []
            
            for issue in data.get('issues', []):
                vulnerabilities.append(SnykVulnerability(
                    id=issue['id'],
                    title=issue.get('title', 'Unknown vulnerability'),
                    severity=issue.get('severity', 'medium'),
                    cvss_score=float(issue.get('cvssScore', 0.0)),
                    cve=issue.get('identifiers', {}).get('CVE', [None])[0],
                    description=issue.get('description', ''),
                    remediation=issue.get('remediation', ''),
                    introduced_date=issue.get('introducedDate', '')
                ))
            
            return vulnerabilities
            
        except Exception as e:
            logging.error(f"Failed to get Snyk vulnerabilities: {e}")
            return []
    
    def test_dependencies(self, manifest_file: str, manifest_content: str) -> Dict[str, Any]:
        """Test dependencies for vulnerabilities"""
        try:
            url = f"{self.base_url}/test"
            
            data = {
                'encoding': 'plain',
                'files': {
                    manifest_file: manifest_content
                }
            }
            
            response = self.session.post(url, json=data)
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            logging.error(f"Failed to test dependencies: {e}")
            return {}
    
    def _get_default_results(self) -> Dict[str, Any]:
        """Get default results when Snyk is unavailable"""
        return {
            'project_name': 'unavailable',
            'vulnerabilities': [],
            'summary': {
                'total_vulnerabilities': 0,
                'critical_severity': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0
            },
            'scan_date': "2024-01-01T00:00:00Z",
            'source': 'snyk',
            'status': 'unavailable'
        }
    
    def is_available(self) -> bool:
        """Check if Snyk API is available"""
        if not self.api_token:
            return False
            
        try:
            url = f"{self.base_url}/user/me"
            response = self.session.get(url)
            return response.status_code == 200
        except:
            return False
    
    def extract_dependencies_from_yaml(self, workflow_yaml: str) -> Dict[str, List[str]]:
        """Extract dependency information from workflow YAML"""
        dependencies = {
            'python': [],
            'javascript': [],
            'generic': []
        }
        
        # Simple pattern matching for common dependencies
        import re
        
        # Look for tool versions that might indicate dependencies
        tool_patterns = re.findall(r'name:\s*(\w+)\s*version:\s*([\d\.]+)', workflow_yaml, re.IGNORECASE)
        for tool, version in tool_patterns:
            dependencies['generic'].append(f"{tool}=={version}")
        
        # Look for Python-like imports or requirements
        python_patterns = re.findall(r'(requests|pandas|numpy|pillow|flask|django)\s*[>=<]+\s*([\d\.]+)', workflow_yaml, re.IGNORECASE)
        for lib, version in python_patterns:
            dependencies['python'].append(f"{lib}=={version}")
        
        # Look for JavaScript/Node.js packages
        js_patterns = re.findall(r'(express|react|lodash|axios)\s*[>=<]+\s*([\d\.]+)', workflow_yaml, re.IGNORECASE)
        for lib, version in js_patterns:
            dependencies['javascript'].append(f"{lib}@{version}")
        
        return dependencies 