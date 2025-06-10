#!/usr/bin/env python3
"""
MAESTRO Threat Assessment CLI Application
Implements the final deliverable: analyze-workflow --input workflow.yaml --report pdf
"""

import click
import yaml
import json
import logging
import os
from typing import Dict, Any
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from maestro_threat_assessment.core.maestro_engine import MAESTROEngine
from maestro_threat_assessment.core.hybrid_analyzer import HybridAnalysisEngine
from maestro_threat_assessment.adapters.baseline_comparator import BaselineComparator

# Optional import for visualization
try:
    from maestro_threat_assessment.visualization.report_generator import ReportGenerator
    HAS_VISUALIZATION = True
except ImportError:
    HAS_VISUALIZATION = False


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def cli(verbose):
    """MAESTRO Threat Assessment Framework CLI"""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)


@cli.command()
@click.option('--input', '-i', 'input_file', required=True, 
              help='Input workflow YAML file', type=click.Path(exists=True))
@click.option('--report', '-r', 'report_format', 
              type=click.Choice(['json', 'pdf', 'html', 'csv']), 
              default='json', help='Output report format')
@click.option('--output', '-o', 'output_file', 
              help='Output file path (default: auto-generated)')
@click.option('--baseline', '-b', is_flag=True, 
              help='Include baseline comparison with industry tools')
@click.option('--hybrid', '-h', is_flag=True,
              help='Use hybrid analysis engine (static + semantic)')
@click.option('--monte-carlo', '-m', is_flag=True, default=True,
              help='Enable Monte Carlo estimation (default: enabled)')
@click.option('--config', '-c', 'config_file',
              help='Configuration file path', type=click.Path(exists=True))
def analyze_workflow(input_file, report_format, output_file, baseline, hybrid, monte_carlo, config_file):
    """
    Analyze workflow security using MAESTRO framework
    
    Examples:
    maestro analyze-workflow --input workflow.yaml --report pdf
    maestro analyze-workflow -i workflow.yaml -r json --baseline --hybrid
    """
    
    try:
        # Load configuration
        config = load_config(config_file) if config_file else {}
        
        # Read input workflow
        with open(input_file, 'r') as f:
            workflow_yaml = f.read()
        
        click.echo(f"📋 Analyzing workflow: {input_file}")
        click.echo(f"🔍 Report format: {report_format}")
        
        # Initialize MAESTRO engine
        engine = MAESTROEngine()
        
        # Parse and analyze workflow
        report = engine.assess_workflow_from_yaml(workflow_yaml)
        parsed_workflow = report.workflow
        click.echo(f"✅ Parsed workflow with {len(parsed_workflow.steps)} steps")
        
        # Calculate risk scores (Monte Carlo is already integrated)
        if monte_carlo:
            click.echo("🎲 Running Monte Carlo estimation...")
            
        wei_result = report.risk_assessment.total_wei
        rps_result = report.risk_assessment.total_rps
        
        # Convert Monte Carlo results to simple values for display
        if hasattr(wei_result, 'mean'):
            wei_score = wei_result.mean
            wei_std = wei_result.std_dev
        else:
            wei_score = wei_result
            wei_std = 0.0
            
        if hasattr(rps_result, 'mean'):
            rps_score = rps_result.mean
            rps_std = rps_result.std_dev
        else:
            rps_score = rps_result
            rps_std = 0.0
        
        click.echo(f"📊 WEI Score: {wei_score:.3f} ± {wei_std:.3f}")
        click.echo(f"📊 RPS Score: {rps_score:.3f} ± {rps_std:.3f}")
        
                # Prepare base results from MAESTRO report
        results = {
            'workflow_name': parsed_workflow.name,
            'workflow_info': {
                'name': parsed_workflow.name,
                'description': parsed_workflow.description,
                'protocol': parsed_workflow.metadata.get('protocol', 'Unknown'),
                'steps': len(parsed_workflow.steps),
                'agents': len(parsed_workflow.agents)
            },
            'wei_score': wei_score,
            'rps_score': rps_score,
            'risk_level': report.risk_assessment.risk_level,
            'risk_scores': {
                'wei': {
                    'score': wei_score,
                    'standard_deviation': wei_std,
                    'confidence_interval': getattr(wei_result, 'confidence_interval', [wei_score, wei_score]) if hasattr(wei_result, 'confidence_interval') else [wei_score, wei_score]
                },
                'rps': {
                    'score': rps_score,
                    'standard_deviation': rps_std,
                    'confidence_interval': getattr(rps_result, 'confidence_interval', [rps_score, rps_score]) if hasattr(rps_result, 'confidence_interval') else [rps_score, rps_score]
                }
            },
            'vulnerabilities': report.vulnerabilities,
            'vulnerabilities_by_layer': {str(k): v for k, v in report.risk_assessment.vulnerabilities_by_layer.items()},
            'recommendations': report.recommendations,
            'executive_summary': report.executive_summary,
            'monte_carlo_enabled': monte_carlo
        }
        
        # Run hybrid analysis if requested
        if hybrid:
            click.echo("🔬 Running hybrid analysis (static + semantic)...")
            hybrid_engine = HybridAnalysisEngine()
            hybrid_findings = hybrid_engine.get_combined_findings(workflow_yaml)
            results['hybrid_analysis'] = {
                'findings': hybrid_findings,
                'risk_score': hybrid_engine.calculate_hybrid_risk_score(hybrid_findings)
            }
            click.echo(f"🔍 Found {len(hybrid_findings)} additional threats")
        
                # Run baseline comparison if requested
        if baseline:
            click.echo("📈 Running baseline comparison...")
            comparator = BaselineComparator(
                sonarqube_url=config.get('sonarqube_url'),
                sonarqube_token=config.get('sonarqube_token'),
                snyk_token=config.get('snyk_token'),
                snyk_org_id=config.get('snyk_org_id')
            )
            
            # Get vulnerability counts for comparison
            vulnerability_counts = get_vulnerability_counts(report.vulnerabilities)
            
            baseline_results = comparator.run_baseline_comparison(
                workflow_yaml, wei_score, rps_score, vulnerability_counts,
                workflow_type=infer_workflow_type(parsed_workflow)
            )
            
            results['baseline_comparison'] = {
                'overall_assessment': baseline_results.overall_assessment,
                'comparison_metrics': baseline_results.comparison_metrics,
                'sonarqube_available': comparator.tool_availability['sonarqube'],
                'snyk_available': comparator.tool_availability['snyk'],
                'castle_deviation': baseline_results.castle_comparison.overall_score
            }
            
            click.echo(f"📊 Baseline assessment: {baseline_results.overall_assessment}")
        
        # Generate output file name if not provided
        if not output_file:
            input_path = Path(input_file)
            output_file = f"{input_path.stem}_maestro_report.{report_format}"
        
        # Generate report
        click.echo(f"📝 Generating {report_format.upper()} report...")
        
        if report_format == 'json':
            generate_json_report(results, output_file)
        elif report_format == 'pdf':
            generate_pdf_report(results, output_file, parsed_workflow)
        elif report_format == 'html':
            generate_html_report(results, output_file, parsed_workflow)
        elif report_format == 'csv':
            generate_csv_report(results, output_file)
        
        click.echo(f"✅ Report saved to: {output_file}")
        
        # Display summary
        display_summary(results)
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option('--output', '-o', 'output_file', default='example_workflows', 
              help='Output directory for example workflows')
def generate_examples(output_file):
    """Generate example workflow files for testing"""
    
    from maestro_threat_assessment.examples.workflow_generator import WorkflowGenerator
    
    click.echo("📝 Generating example workflows...")
    
    generator = WorkflowGenerator()
    examples = generator.generate_all_examples()
    
    output_path = Path(output_file)
    output_path.mkdir(exist_ok=True)
    
    for name, workflow in examples.items():
        file_path = output_path / f"{name}.yaml"
        with open(file_path, 'w') as f:
            f.write(workflow)
        click.echo(f"✅ Generated: {file_path}")
    
    click.echo(f"📁 All examples saved to: {output_path}")


def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from file"""
    try:
        with open(config_file, 'r') as f:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                return yaml.safe_load(f)
            else:
                return json.load(f)
    except Exception as e:
        click.echo(f"⚠️  Warning: Could not load config file: {e}")
        return {}


def get_vulnerability_counts(vulnerabilities: list) -> Dict[str, int]:
    """Extract vulnerability counts by severity"""
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'medium').lower()
        if severity in counts:
            counts[severity] += 1
    
    return counts


def infer_workflow_type(parsed_workflow) -> str:
    """Infer workflow type for baseline comparison"""
    metadata = parsed_workflow.metadata
    
    # Check protocol
    protocol = metadata.get('protocol', '').lower()
    if protocol == 'mcp':
        if len(parsed_workflow.steps) > 5:
            return 'mcp_complex'
        else:
            return 'mcp_basic'
    elif protocol == 'a2a':
        if len(parsed_workflow.steps) > 5:
            return 'a2a_network'
        else:
            return 'a2a_simple'
    
    # Check workflow name/description for domain
    name = metadata.get('name', '').lower()
    if any(keyword in name for keyword in ['financial', 'payment', 'banking']):
        return 'financial'
    elif any(keyword in name for keyword in ['data', 'analytics', 'processing']):
        return 'data_processing'
    elif any(keyword in name for keyword in ['ml', 'ai', 'model']):
        return 'ml_inference'
    
    return 'hybrid'


def generate_json_report(results: Dict[str, Any], output_file: str):
    """Generate JSON report"""
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)


def generate_pdf_report(results: Dict[str, Any], output_file: str, parsed_workflow):
    """Generate PDF report"""
    if HAS_VISUALIZATION:
        try:
            generator = ReportGenerator()
            generator.generate_pdf_report(results, parsed_workflow, output_file)
        except Exception as e:
            click.echo(f"⚠️  PDF generation failed: {e}. Saving as JSON instead.")
            generate_json_report(results, output_file.replace('.pdf', '.json'))
    else:
        click.echo("⚠️  PDF generation requires additional dependencies. Saving as JSON instead.")
        generate_json_report(results, output_file.replace('.pdf', '.json'))


def generate_html_report(results: Dict[str, Any], output_file: str, parsed_workflow):
    """Generate HTML report"""
    if HAS_VISUALIZATION:
        try:
            generator = ReportGenerator()
            generator.generate_html_report(results, parsed_workflow, output_file)
        except Exception as e:
            click.echo(f"⚠️  HTML generation failed: {e}. Saving as JSON instead.")
            generate_json_report(results, output_file.replace('.html', '.json'))
    else:
        click.echo("⚠️  HTML generation requires additional dependencies. Saving as JSON instead.")
        generate_json_report(results, output_file.replace('.html', '.json'))


def generate_csv_report(results: Dict[str, Any], output_file: str):
    """Generate CSV report for vulnerability data"""
    import csv
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write headers
        writer.writerow(['Type', 'Severity', 'Step', 'Agent', 'Description'])
        
        # Write vulnerability data
        for vuln in results.get('vulnerabilities', []):
            writer.writerow([
                vuln.get('type', ''),
                vuln.get('severity', ''),
                vuln.get('step', ''),
                vuln.get('agent', ''),
                vuln.get('description', '')
            ])


def display_summary(results: Dict[str, Any]):
    """Display analysis summary"""
    click.echo("\n" + "="*50)
    click.echo("📊 MAESTRO ANALYSIS SUMMARY")
    click.echo("="*50)
    
    # Workflow info
    info = results['workflow_info']
    click.echo(f"📋 Workflow: {info['name']} ({info['protocol']})")
    click.echo(f"🔗 Steps: {info['steps']}, Agents: {info['agents']}")
    
    # Risk scores
    risk = results['risk_scores']
    wei = risk['wei']
    rps = risk['rps']
    click.echo(f"⚡ WEI Score: {wei['score']:.3f} ± {wei['standard_deviation']:.3f}")
    click.echo(f"🌊 RPS Score: {rps['score']:.3f} ± {rps['standard_deviation']:.3f}")
    
    # Vulnerabilities
    vuln_count = len(results.get('vulnerabilities', []))
    click.echo(f"🚨 Vulnerabilities: {vuln_count}")
    
    # Risk level assessment (consistent with core calculator)
    # Use the same formula as core: Combined Risk = (WEI × 0.7) + (RPS/30 × 0.3)
    normalized_rps = rps['score'] / 30.0
    combined_risk = (wei['score'] * 0.7) + (normalized_rps * 0.3)
    
    if combined_risk >= 0.527:
        risk_level = "🔴 CRITICAL RISK"
    elif combined_risk >= 0.481:
        risk_level = "🟠 HIGH RISK"
    elif combined_risk >= 0.219:
        risk_level = "🟡 MEDIUM RISK"
    else:
        risk_level = "🟢 LOW RISK"
    
    click.echo(f"📈 Risk Level: {risk_level}")
    
    # Baseline comparison if available
    if 'baseline_comparison' in results:
        baseline = results['baseline_comparison']
        click.echo(f"📊 Baseline: {baseline['overall_assessment']}")
    
    click.echo("="*50)


if __name__ == '__main__':
    cli() 