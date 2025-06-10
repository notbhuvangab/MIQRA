"""
CASTLE (Comprehensive Application Security Testing Language Engine) Adapter
Provides baseline security benchmarks for comparison
"""

import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class WorkflowType(Enum):
    """Workflow types for CASTLE benchmarks"""
    MCP_BASIC = "mcp_basic"
    MCP_COMPLEX = "mcp_complex"
    A2A_SIMPLE = "a2a_simple"
    A2A_NETWORK = "a2a_network"
    HYBRID = "hybrid"
    FINANCIAL = "financial"
    DATA_PROCESSING = "data_processing"
    ML_INFERENCE = "ml_inference"


@dataclass
class CASTLEBenchmark:
    """CASTLE security benchmark"""
    workflow_type: WorkflowType
    expected_wei: float
    expected_rps: float
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    compliance_score: float
    baseline_date: str


@dataclass
class CASTLEComparison:
    """Comparison result with CASTLE benchmarks"""
    workflow_type: WorkflowType
    measured_wei: float
    benchmark_wei: float
    wei_deviation: float
    measured_rps: float
    benchmark_rps: float
    rps_deviation: float
    vulnerability_comparison: Dict[str, Dict[str, int]]
    compliance_comparison: Dict[str, float]
    overall_score: float


class CASTLEAdapter:
    """Adapter for CASTLE baseline comparisons"""
    
    def __init__(self):
        self.benchmarks = self._initialize_benchmarks()
        
    def _initialize_benchmarks(self) -> Dict[WorkflowType, CASTLEBenchmark]:
        """Initialize CASTLE baseline benchmarks"""
        return {
            WorkflowType.MCP_BASIC: CASTLEBenchmark(
                workflow_type=WorkflowType.MCP_BASIC,
                expected_wei=0.25,
                expected_rps=15.0,
                critical_vulnerabilities=0,
                high_vulnerabilities=1,
                medium_vulnerabilities=2,
                low_vulnerabilities=3,
                compliance_score=0.85,
                baseline_date="2024-01-01"
            ),
            WorkflowType.MCP_COMPLEX: CASTLEBenchmark(
                workflow_type=WorkflowType.MCP_COMPLEX,
                expected_wei=0.45,
                expected_rps=28.0,
                critical_vulnerabilities=1,
                high_vulnerabilities=2,
                medium_vulnerabilities=4,
                low_vulnerabilities=5,
                compliance_score=0.75,
                baseline_date="2024-01-01"
            ),
            WorkflowType.A2A_SIMPLE: CASTLEBenchmark(
                workflow_type=WorkflowType.A2A_SIMPLE,
                expected_wei=0.30,
                expected_rps=20.0,
                critical_vulnerabilities=0,
                high_vulnerabilities=1,
                medium_vulnerabilities=3,
                low_vulnerabilities=4,
                compliance_score=0.80,
                baseline_date="2024-01-01"
            ),
            WorkflowType.A2A_NETWORK: CASTLEBenchmark(
                workflow_type=WorkflowType.A2A_NETWORK,
                expected_wei=0.55,
                expected_rps=35.0,
                critical_vulnerabilities=1,
                high_vulnerabilities=3,
                medium_vulnerabilities=5,
                low_vulnerabilities=6,
                compliance_score=0.70,
                baseline_date="2024-01-01"
            ),
            WorkflowType.HYBRID: CASTLEBenchmark(
                workflow_type=WorkflowType.HYBRID,
                expected_wei=0.40,
                expected_rps=25.0,
                critical_vulnerabilities=1,
                high_vulnerabilities=2,
                medium_vulnerabilities=3,
                low_vulnerabilities=4,
                compliance_score=0.78,
                baseline_date="2024-01-01"
            ),
            WorkflowType.FINANCIAL: CASTLEBenchmark(
                workflow_type=WorkflowType.FINANCIAL,
                expected_wei=0.35,
                expected_rps=22.0,
                critical_vulnerabilities=0,
                high_vulnerabilities=2,
                medium_vulnerabilities=3,
                low_vulnerabilities=3,
                compliance_score=0.90,  # Higher compliance requirements
                baseline_date="2024-01-01"
            ),
            WorkflowType.DATA_PROCESSING: CASTLEBenchmark(
                workflow_type=WorkflowType.DATA_PROCESSING,
                expected_wei=0.38,
                expected_rps=24.0,
                critical_vulnerabilities=0,
                high_vulnerabilities=2,
                medium_vulnerabilities=4,
                low_vulnerabilities=5,
                compliance_score=0.82,
                baseline_date="2024-01-01"
            ),
            WorkflowType.ML_INFERENCE: CASTLEBenchmark(
                workflow_type=WorkflowType.ML_INFERENCE,
                expected_wei=0.42,
                expected_rps=26.0,
                critical_vulnerabilities=1,
                high_vulnerabilities=2,
                medium_vulnerabilities=3,
                low_vulnerabilities=4,
                compliance_score=0.77,
                baseline_date="2024-01-01"
            )
        }
    
    def get_benchmark(self, workflow_type: str) -> Optional[CASTLEBenchmark]:
        """Get CASTLE benchmark for workflow type"""
        try:
            # Try to map string to enum
            wf_type = WorkflowType(workflow_type.lower())
            return self.benchmarks.get(wf_type)
        except ValueError:
            # Try to infer workflow type from string
            return self._infer_benchmark_from_description(workflow_type)
    
    def _infer_benchmark_from_description(self, description: str) -> Optional[CASTLEBenchmark]:
        """Infer benchmark based on workflow description"""
        description_lower = description.lower()
        
        # Financial workflows
        if any(keyword in description_lower for keyword in ['financial', 'payment', 'transaction', 'banking']):
            return self.benchmarks[WorkflowType.FINANCIAL]
        
        # Data processing workflows
        if any(keyword in description_lower for keyword in ['data', 'processing', 'etl', 'analytics']):
            return self.benchmarks[WorkflowType.DATA_PROCESSING]
        
        # ML/AI workflows
        if any(keyword in description_lower for keyword in ['ml', 'machine learning', 'ai', 'model', 'inference']):
            return self.benchmarks[WorkflowType.ML_INFERENCE]
        
        # Protocol-based inference
        if 'mcp' in description_lower:
            if any(keyword in description_lower for keyword in ['complex', 'multi', 'chain']):
                return self.benchmarks[WorkflowType.MCP_COMPLEX]
            else:
                return self.benchmarks[WorkflowType.MCP_BASIC]
        
        if 'a2a' in description_lower:
            if any(keyword in description_lower for keyword in ['network', 'multi-agent', 'distributed']):
                return self.benchmarks[WorkflowType.A2A_NETWORK]
            else:
                return self.benchmarks[WorkflowType.A2A_SIMPLE]
        
        # Default to hybrid
        return self.benchmarks[WorkflowType.HYBRID]
    
    def compare_with_baseline(self, 
                            workflow_type: str,
                            measured_wei: float,
                            measured_rps: float,
                            vulnerability_counts: Dict[str, int],
                            compliance_score: float = None) -> CASTLEComparison:
        """Compare measured results with CASTLE baseline"""
        
        benchmark = self.get_benchmark(workflow_type)
        if not benchmark:
            # Use default benchmark
            benchmark = self.benchmarks[WorkflowType.HYBRID]
        
        # Calculate deviations
        wei_deviation = ((measured_wei - benchmark.expected_wei) / benchmark.expected_wei) * 100
        rps_deviation = ((measured_rps - benchmark.expected_rps) / benchmark.expected_rps) * 100
        
        # Compare vulnerability counts
        vuln_comparison = {
            'measured': vulnerability_counts,
            'benchmark': {
                'critical': benchmark.critical_vulnerabilities,
                'high': benchmark.high_vulnerabilities,
                'medium': benchmark.medium_vulnerabilities,
                'low': benchmark.low_vulnerabilities
            }
        }
        
        # Compare compliance scores
        compliance_comparison = {
            'measured': compliance_score or 0.0,
            'benchmark': benchmark.compliance_score,
            'deviation': ((compliance_score or 0.0) - benchmark.compliance_score) * 100
        }
        
        # Calculate overall score (lower is better)
        overall_score = self._calculate_overall_score(
            wei_deviation, rps_deviation, vuln_comparison, compliance_comparison
        )
        
        return CASTLEComparison(
            workflow_type=benchmark.workflow_type,
            measured_wei=measured_wei,
            benchmark_wei=benchmark.expected_wei,
            wei_deviation=wei_deviation,
            measured_rps=measured_rps,
            benchmark_rps=benchmark.expected_rps,
            rps_deviation=rps_deviation,
            vulnerability_comparison=vuln_comparison,
            compliance_comparison=compliance_comparison,
            overall_score=overall_score
        )
    
    def _calculate_overall_score(self, 
                               wei_deviation: float, 
                               rps_deviation: float,
                               vuln_comparison: Dict[str, Dict[str, int]],
                               compliance_comparison: Dict[str, float]) -> float:
        """Calculate overall comparison score"""
        
        # Weight different factors
        wei_weight = 0.25
        rps_weight = 0.25
        vuln_weight = 0.35
        compliance_weight = 0.15
        
        # WEI score (penalty for being worse than baseline)
        wei_score = max(0, wei_deviation) * wei_weight
        
        # RPS score (penalty for being worse than baseline)
        rps_score = max(0, rps_deviation) * rps_weight
        
        # Vulnerability score
        measured_vulns = vuln_comparison['measured']
        benchmark_vulns = vuln_comparison['benchmark']
        
        vuln_penalties = {
            'critical': 10.0,
            'high': 5.0,
            'medium': 2.0,
            'low': 1.0
        }
        
        vuln_score = 0.0
        for severity, penalty in vuln_penalties.items():
            measured_count = measured_vulns.get(severity, 0)
            benchmark_count = benchmark_vulns.get(severity, 0)
            if measured_count > benchmark_count:
                vuln_score += (measured_count - benchmark_count) * penalty
        
        vuln_score *= vuln_weight
        
        # Compliance score (penalty for being worse)
        compliance_deviation = compliance_comparison.get('deviation', 0)
        compliance_score = max(0, -compliance_deviation) * compliance_weight
        
        return wei_score + rps_score + vuln_score + compliance_score
    
    def get_all_benchmarks(self) -> Dict[str, Dict[str, Any]]:
        """Get all available benchmarks"""
        result = {}
        for wf_type, benchmark in self.benchmarks.items():
            result[wf_type.value] = {
                'expected_wei': benchmark.expected_wei,
                'expected_rps': benchmark.expected_rps,
                'vulnerabilities': {
                    'critical': benchmark.critical_vulnerabilities,
                    'high': benchmark.high_vulnerabilities,
                    'medium': benchmark.medium_vulnerabilities,
                    'low': benchmark.low_vulnerabilities
                },
                'compliance_score': benchmark.compliance_score,
                'baseline_date': benchmark.baseline_date
            }
        return result
    
    def get_industry_statistics(self) -> Dict[str, Any]:
        """Get industry-wide security statistics"""
        return {
            'average_wei': 0.38,
            'average_rps': 24.5,
            'vulnerability_distribution': {
                'critical': 0.5,
                'high': 2.1,
                'medium': 3.8,
                'low': 4.2
            },
            'compliance_average': 0.79,
            'trends': {
                'wei_improvement_rate': -0.05,  # 5% improvement year over year
                'rps_growth_rate': 0.03,        # 3% increase in complexity
                'vuln_reduction_rate': -0.08    # 8% reduction in vulnerabilities
            },
            'last_updated': "2024-01-01"
        }
    
    def generate_benchmark_report(self, comparison: CASTLEComparison) -> Dict[str, Any]:
        """Generate detailed benchmark comparison report"""
        
        # Determine risk level based on overall score
        if comparison.overall_score <= 5:
            risk_level = "LOW"
        elif comparison.overall_score <= 15:
            risk_level = "MEDIUM"
        elif comparison.overall_score <= 30:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
        
        # Generate recommendations
        recommendations = []
        
        if comparison.wei_deviation > 20:
            recommendations.append("WEI score significantly exceeds baseline - review high-impact vulnerabilities")
        
        if comparison.rps_deviation > 25:
            recommendations.append("RPS score exceeds baseline - consider simplifying workflow architecture")
        
        if comparison.compliance_comparison['deviation'] < -10:
            recommendations.append("Compliance score below baseline - review regulatory requirements")
        
        measured_vulns = comparison.vulnerability_comparison['measured']
        baseline_vulns = comparison.vulnerability_comparison['benchmark']
        
        if measured_vulns.get('critical', 0) > baseline_vulns['critical']:
            recommendations.append("Critical vulnerabilities exceed baseline - immediate remediation required")
        
        if not recommendations:
            recommendations.append("Performance within acceptable baseline parameters")
        
        return {
            'comparison': {
                'workflow_type': comparison.workflow_type.value,
                'risk_level': risk_level,
                'overall_score': comparison.overall_score,
                'wei_comparison': {
                    'measured': comparison.measured_wei,
                    'baseline': comparison.benchmark_wei,
                    'deviation_percent': comparison.wei_deviation
                },
                'rps_comparison': {
                    'measured': comparison.measured_rps,
                    'baseline': comparison.benchmark_rps,
                    'deviation_percent': comparison.rps_deviation
                },
                'vulnerability_comparison': comparison.vulnerability_comparison,
                'compliance_comparison': comparison.compliance_comparison
            },
            'recommendations': recommendations,
            'industry_context': self.get_industry_statistics(),
            'generated_date': "2024-01-01T00:00:00Z"
        } 