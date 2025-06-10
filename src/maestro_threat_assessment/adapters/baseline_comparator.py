"""
Baseline Comparator - Orchestrates all security tool integrations
Implements the baseline comparison protocol from the prompt
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from .sonarqube import SonarQubeAdapter
from .snyk import SnykAdapter
from .castle import CASTLEAdapter, CASTLEComparison


@dataclass
class BaselineResults:
    """Combined baseline comparison results"""
    sonarqube_results: Dict[str, Any]
    snyk_results: Dict[str, Any]
    castle_comparison: CASTLEComparison
    comparison_metrics: Dict[str, float]
    overall_assessment: str
    
    
@dataclass
class ComparisonMetrics:
    """Metrics for comparing different tools"""
    vulnerability_detection_rate: float
    false_positive_ratio: float
    risk_score_correlation: float
    critical_path_coverage: float


class BaselineComparator:
    """Main baseline comparison orchestrator as specified in the prompt"""
    
    def __init__(self, 
                 sonarqube_url: str = None,
                 sonarqube_token: str = None,
                 snyk_token: str = None,
                 snyk_org_id: str = None):
        
        # Initialize all adapters
        self.sonarqube = SonarQubeAdapter(sonarqube_url or "http://localhost:9000", sonarqube_token)
        self.snyk = SnykAdapter(snyk_token, snyk_org_id)
        self.castle = CASTLEAdapter()
        
        # Check availability
        self.tool_availability = {
            'sonarqube': self.sonarqube.is_available(),
            'snyk': self.snyk.is_available(),
            'castle': True  # Always available (local benchmarks)
        }
        
        logging.info(f"Tool availability: {self.tool_availability}")
    
    def run_baseline_comparison(self, 
                              workflow_yaml: str,
                              measured_wei: float,
                              measured_rps: float,
                              vulnerability_counts: Dict[str, int],
                              workflow_type: str = "hybrid") -> BaselineResults:
        """
        Run comprehensive baseline comparison as specified in prompt:
        
        baselines = {
            "SonarQube": run_sonarqube(workflow_yaml),
            "Snyk": run_snyk(workflow_yaml),
            "CASTLE": get_castle_benchmark(workflow_type)
        }
        """
        
        # Run SonarQube analysis
        sonarqube_results = self._run_sonarqube_analysis(workflow_yaml)
        
        # Run Snyk analysis
        snyk_results = self._run_snyk_analysis(workflow_yaml)
        
        # Get CASTLE baseline comparison
        castle_comparison = self._run_castle_comparison(
            workflow_type, measured_wei, measured_rps, vulnerability_counts
        )
        
        # Calculate comparison metrics
        comparison_metrics = self._calculate_comparison_metrics(
            sonarqube_results, snyk_results, castle_comparison, vulnerability_counts
        )
        
        # Generate overall assessment
        overall_assessment = self._generate_overall_assessment(
            sonarqube_results, snyk_results, castle_comparison, comparison_metrics
        )
        
        return BaselineResults(
            sonarqube_results=sonarqube_results,
            snyk_results=snyk_results,
            castle_comparison=castle_comparison,
            comparison_metrics=comparison_metrics,
            overall_assessment=overall_assessment
        )
    
    def _run_sonarqube_analysis(self, workflow_yaml: str) -> Dict[str, Any]:
        """Run SonarQube baseline analysis"""
        try:
            if self.tool_availability['sonarqube']:
                return self.sonarqube.analyze_workflow(workflow_yaml)
            else:
                logging.warning("SonarQube not available, using simulation")
                return self.sonarqube.analyze_workflow(workflow_yaml)  # Falls back to simulation
        except Exception as e:
            logging.error(f"SonarQube analysis failed: {e}")
            return self.sonarqube._get_default_results()
    
    def _run_snyk_analysis(self, workflow_yaml: str) -> Dict[str, Any]:
        """Run Snyk baseline analysis"""
        try:
            if self.tool_availability['snyk']:
                return self.snyk.analyze_workflow(workflow_yaml)
            else:
                logging.warning("Snyk not available, using simulation")
                return self.snyk.analyze_workflow(workflow_yaml)  # Falls back to simulation
        except Exception as e:
            logging.error(f"Snyk analysis failed: {e}")
            return self.snyk._get_default_results()
    
    def _run_castle_comparison(self, 
                             workflow_type: str,
                             measured_wei: float,
                             measured_rps: float,
                             vulnerability_counts: Dict[str, int]) -> CASTLEComparison:
        """Run CASTLE baseline comparison"""
        try:
            return self.castle.compare_with_baseline(
                workflow_type, measured_wei, measured_rps, vulnerability_counts
            )
        except Exception as e:
            logging.error(f"CASTLE comparison failed: {e}")
            # Return default comparison
            default_benchmark = self.castle.benchmarks[self.castle.WorkflowType.HYBRID]
            return CASTLEComparison(
                workflow_type=default_benchmark.workflow_type,
                measured_wei=measured_wei,
                benchmark_wei=default_benchmark.expected_wei,
                wei_deviation=0.0,
                measured_rps=measured_rps,
                benchmark_rps=default_benchmark.expected_rps,
                rps_deviation=0.0,
                vulnerability_comparison={'measured': vulnerability_counts, 'benchmark': {}},
                compliance_comparison={'measured': 0.0, 'benchmark': 0.8, 'deviation': 0.0},
                overall_score=0.0
            )
    
    def _calculate_comparison_metrics(self,
                                    sonarqube_results: Dict[str, Any],
                                    snyk_results: Dict[str, Any],
                                    castle_comparison: CASTLEComparison,
                                    measured_vulns: Dict[str, int]) -> Dict[str, float]:
        """
        Calculate comparison metrics as specified in prompt:
        - Vulnerability Detection Rate
        - False Positive Ratio
        - Risk Score Correlation (R²)
        - Critical Path Coverage
        """
        
        # Extract vulnerability counts from each tool
        sonar_vulns = len(sonarqube_results.get('issues', []))
        snyk_vulns = len(snyk_results.get('vulnerabilities', []))
        measured_total = sum(measured_vulns.values())
        
        # Vulnerability Detection Rate
        # Average detection rate across tools vs MAESTRO
        if measured_total > 0:
            sonar_detection_rate = min(sonar_vulns / measured_total, 1.0)
            snyk_detection_rate = min(snyk_vulns / measured_total, 1.0)
            avg_detection_rate = (sonar_detection_rate + snyk_detection_rate) / 2
        else:
            avg_detection_rate = 1.0
        
        # False Positive Ratio
        # Estimate based on tool differences
        tool_variance = abs(sonar_vulns - snyk_vulns)
        max_vulns = max(sonar_vulns, snyk_vulns, measured_total)
        false_positive_ratio = tool_variance / max_vulns if max_vulns > 0 else 0.0
        
        # Risk Score Correlation (R²)
        # Simplified correlation based on severity alignment
        correlation = self._calculate_risk_correlation(
            sonarqube_results, snyk_results, measured_vulns
        )
        
        # Critical Path Coverage
        # Based on critical and high severity findings
        critical_high_measured = measured_vulns.get('critical', 0) + measured_vulns.get('high', 0)
        sonar_critical = len([issue for issue in sonarqube_results.get('issues', []) 
                             if issue.get('severity') in ['CRITICAL', 'BLOCKER']])
        snyk_critical = len([vuln for vuln in snyk_results.get('vulnerabilities', []) 
                            if vuln.get('severity') in ['critical', 'high']])
        
        if critical_high_measured > 0:
            coverage = min((sonar_critical + snyk_critical) / (2 * critical_high_measured), 1.0)
        else:
            coverage = 1.0
        
        return {
            'vulnerability_detection_rate': avg_detection_rate,
            'false_positive_ratio': false_positive_ratio,
            'risk_score_correlation': correlation,
            'critical_path_coverage': coverage
        }
    
    def _calculate_risk_correlation(self,
                                  sonarqube_results: Dict[str, Any],
                                  snyk_results: Dict[str, Any],
                                  measured_vulns: Dict[str, int]) -> float:
        """Calculate risk score correlation between tools"""
        
        # Map severities to numeric scores for correlation
        severity_scores = {
            'critical': 5, 'blocker': 5, 'high': 4, 'major': 3, 
            'medium': 2, 'minor': 1, 'low': 1
        }
        
        # Calculate weighted scores for each tool
        sonar_score = 0
        for issue in sonarqube_results.get('issues', []):
            severity = issue.get('severity', '').lower()
            sonar_score += severity_scores.get(severity, 2)
        
        snyk_score = 0
        for vuln in snyk_results.get('vulnerabilities', []):
            severity = vuln.get('severity', '').lower()
            snyk_score += severity_scores.get(severity, 2)
        
        measured_score = (
            measured_vulns.get('critical', 0) * 5 +
            measured_vulns.get('high', 0) * 4 +
            measured_vulns.get('medium', 0) * 2 +
            measured_vulns.get('low', 0) * 1
        )
        
        # Simple correlation calculation
        if measured_score == 0:
            return 1.0
        
        avg_tool_score = (sonar_score + snyk_score) / 2
        correlation = 1.0 - abs(avg_tool_score - measured_score) / max(avg_tool_score, measured_score)
        return max(0.0, correlation)
    
    def _generate_overall_assessment(self,
                                   sonarqube_results: Dict[str, Any],
                                   snyk_results: Dict[str, Any],
                                   castle_comparison: CASTLEComparison,
                                   metrics: Dict[str, float]) -> str:
        """Generate overall assessment of the baseline comparison"""
        
        # Score factors
        detection_score = metrics['vulnerability_detection_rate']
        fp_score = 1.0 - metrics['false_positive_ratio']  # Lower FP is better
        correlation_score = metrics['risk_score_correlation']
        coverage_score = metrics['critical_path_coverage']
        
        # CASTLE deviation score (lower deviation is better)
        castle_score = max(0.0, 1.0 - (castle_comparison.overall_score / 50.0))
        
        # Overall weighted score
        overall_score = (
            detection_score * 0.25 +
            fp_score * 0.20 +
            correlation_score * 0.25 +
            coverage_score * 0.20 +
            castle_score * 0.10
        )
        
        # Generate assessment
        if overall_score >= 0.8:
            assessment = "EXCELLENT"
            summary = "MAESTRO assessment aligns well with industry baselines. High confidence in results."
        elif overall_score >= 0.6:
            assessment = "GOOD"
            summary = "MAESTRO assessment generally consistent with industry tools. Minor discrepancies noted."
        elif overall_score >= 0.4:
            assessment = "FAIR"
            summary = "Some inconsistencies with baseline tools. Consider reviewing analysis parameters."
        else:
            assessment = "POOR"
            summary = "Significant discrepancies with baseline tools. Analysis may need recalibration."
        
        return f"{assessment}: {summary} (Score: {overall_score:.2f})"
    
    def generate_comprehensive_report(self, baseline_results: BaselineResults) -> Dict[str, Any]:
        """Generate comprehensive baseline comparison report"""
        
        return {
            'executive_summary': {
                'overall_assessment': baseline_results.overall_assessment,
                'tool_availability': self.tool_availability,
                'comparison_date': "2024-01-01T00:00:00Z"
            },
            'tool_results': {
                'sonarqube': baseline_results.sonarqube_results,
                'snyk': baseline_results.snyk_results,
                'castle': {
                    'workflow_type': baseline_results.castle_comparison.workflow_type.value,
                    'wei_comparison': {
                        'measured': baseline_results.castle_comparison.measured_wei,
                        'baseline': baseline_results.castle_comparison.benchmark_wei,
                        'deviation': baseline_results.castle_comparison.wei_deviation
                    },
                    'rps_comparison': {
                        'measured': baseline_results.castle_comparison.measured_rps,
                        'baseline': baseline_results.castle_comparison.benchmark_rps,
                        'deviation': baseline_results.castle_comparison.rps_deviation
                    },
                    'overall_score': baseline_results.castle_comparison.overall_score
                }
            },
            'comparison_metrics': baseline_results.comparison_metrics,
            'industry_benchmarks': self.castle.get_industry_statistics(),
            'recommendations': self._generate_recommendations(baseline_results),
            'tool_correlation_analysis': self._analyze_tool_correlations(baseline_results)
        }
    
    def _generate_recommendations(self, baseline_results: BaselineResults) -> List[str]:
        """Generate recommendations based on baseline comparison"""
        recommendations = []
        
        metrics = baseline_results.comparison_metrics
        castle = baseline_results.castle_comparison
        
        # Detection rate recommendations
        if metrics['vulnerability_detection_rate'] < 0.7:
            recommendations.append("Consider enhancing MAESTRO detection rules - some vulnerabilities may be missed")
        
        # False positive recommendations
        if metrics['false_positive_ratio'] > 0.3:
            recommendations.append("High false positive ratio detected - review rule specificity")
        
        # Correlation recommendations
        if metrics['risk_score_correlation'] < 0.6:
            recommendations.append("Risk scoring may need calibration - consider adjusting severity weights")
        
        # CASTLE recommendations
        if castle.wei_deviation > 25:
            recommendations.append("WEI score significantly exceeds industry baseline - review risk factors")
        
        if castle.rps_deviation > 30:
            recommendations.append("RPS score exceeds baseline - workflow may be more complex than typical")
        
        # Tool-specific recommendations
        sonar_issues = len(baseline_results.sonarqube_results.get('issues', []))
        snyk_vulns = len(baseline_results.snyk_results.get('vulnerabilities', []))
        
        if abs(sonar_issues - snyk_vulns) > 5:
            recommendations.append("Significant discrepancy between SonarQube and Snyk - investigate root causes")
        
        if not recommendations:
            recommendations.append("Baseline comparison results are within acceptable parameters")
        
        return recommendations
    
    def _analyze_tool_correlations(self, baseline_results: BaselineResults) -> Dict[str, Any]:
        """Analyze correlations between different tools"""
        
        # Extract vulnerability counts
        sonar_count = len(baseline_results.sonarqube_results.get('issues', []))
        snyk_count = len(baseline_results.snyk_results.get('vulnerabilities', []))
        
        # Tool agreement analysis
        tool_agreement = 1.0 - abs(sonar_count - snyk_count) / max(sonar_count, snyk_count, 1)
        
        return {
            'tool_agreement_score': tool_agreement,
            'sonarqube_findings': sonar_count,
            'snyk_findings': snyk_count,
            'average_baseline_findings': (sonar_count + snyk_count) / 2,
            'correlation_strength': baseline_results.comparison_metrics['risk_score_correlation'],
            'consistency_rating': 'HIGH' if tool_agreement > 0.8 else 'MEDIUM' if tool_agreement > 0.6 else 'LOW'
        } 