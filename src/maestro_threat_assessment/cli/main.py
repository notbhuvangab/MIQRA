"""
MAESTRO CLI Interface

Command-line interface for MAESTRO threat assessment tool.
Provides comprehensive security analysis for agentic workflows.
"""

import click
import json
import sys
from pathlib import Path
from tabulate import tabulate
from colorama import init, Fore, Style
from typing import Dict, Any

from ..core.maestro_engine import MAESTROEngine
from ..models.maestro_constants import MAESTROLayer

# Initialize colorama for colored output
init()

@click.group()
@click.version_option(version="1.0.0", prog_name="MAESTRO Threat Assessment")
def cli():
    """
    MAESTRO Threat Assessment Framework
    
    Comprehensive security risk assessment for agentic workflows using the MAESTRO
    (Model, Agent framework, Ecosystem, Security, Threat landscape, Risk mitigation, 
    Operational oversight) framework.
    """
    pass

@cli.command()
@click.argument('workflow_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for the report')
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'summary']), 
              default='summary', help='Output format')
@click.option('--enterprise-size', type=click.Choice(['startup', 'small', 'medium', 'large', 'enterprise']),
              default='medium', help='Enterprise size for cost estimation')
@click.option('--industry', type=click.Choice(['financial', 'healthcare', 'government', 'technology', 'retail', 'manufacturing']),
              default='technology', help='Industry type for cost modifiers')
@click.option('--base-cost', type=float, help='Base annual infrastructure cost in USD')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def assess(workflow_file, output, format, enterprise_size, industry, base_cost, verbose):
    """Perform complete MAESTRO threat assessment on a workflow file."""
    
    try:
        if verbose:
            click.echo(f"{Fore.BLUE}Loading MAESTRO engine...{Style.RESET_ALL}")
        
        engine = MAESTROEngine()
        
        if verbose:
            click.echo(f"{Fore.BLUE}Analyzing workflow: {workflow_file}{Style.RESET_ALL}")
        
        # Perform assessment
        report = engine.assess_workflow_from_file(
            workflow_file, base_cost, enterprise_size, industry
        )
        
        if verbose:
            click.echo(f"{Fore.GREEN}Assessment completed: {report.assessment_id}{Style.RESET_ALL}")
        
        # Format and output results
        if format == 'json':
            output_content = engine.export_report_json(report)
        elif format == 'table':
            output_content = _format_table_report(report)
        else:  # summary
            output_content = _format_summary_report(report)
        
        # Write to file or stdout
        if output:
            with open(output, 'w') as f:
                f.write(output_content)
            click.echo(f"{Fore.GREEN}Report saved to: {output}{Style.RESET_ALL}")
        else:
            click.echo(output_content)
            
    except Exception as e:
        click.echo(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('workflow_file', type=click.Path(exists=True))
@click.option('--format', '-f', type=click.Choice(['json', 'table']), 
              default='table', help='Output format')
def quick(workflow_file, format):
    """Perform quick risk assessment without detailed cost analysis."""
    
    try:
        engine = MAESTROEngine()
        
        # Read workflow file
        with open(workflow_file, 'r') as f:
            yaml_content = f.read()
        
        # Perform quick assessment
        result = engine.quick_assessment(yaml_content)
        
        if format == 'json':
            click.echo(json.dumps(result, indent=2))
        else:
            _display_quick_results(result)
            
    except Exception as e:
        click.echo(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('workflow_content', type=str)
@click.option('--enterprise-size', type=click.Choice(['startup', 'small', 'medium', 'large', 'enterprise']),
              default='medium', help='Enterprise size')
@click.option('--industry', type=click.Choice(['financial', 'healthcare', 'government', 'technology', 'retail', 'manufacturing']),
              default='technology', help='Industry type')
def analyze_yaml(workflow_content, enterprise_size, industry):
    """Analyze YAML workflow content directly (for testing/demo)."""
    
    try:
        engine = MAESTROEngine()
        result = engine.quick_assessment(workflow_content)
        _display_quick_results(result)
        
    except Exception as e:
        click.echo(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}", err=True)
        sys.exit(1)

@cli.command()
def layers():
    """Display MAESTRO framework layer information."""
    
    layer_data = []
    for layer in MAESTROLayer:
        layer_data.append([
            layer.name.replace('_', ' ').title(),
            f"{layer.value}",
            "Active"  # Could be expanded with status information
        ])
    
    headers = ["Layer", "Level", "Status"]
    click.echo(f"\n{Fore.CYAN}MAESTRO Security Framework Layers{Style.RESET_ALL}")
    click.echo("=" * 50)
    click.echo(tabulate(layer_data, headers=headers, tablefmt="grid"))

@cli.command()
@click.option('--enterprise-size', type=click.Choice(['startup', 'small', 'medium', 'large', 'enterprise']),
              default='medium', help='Enterprise size')
@click.option('--industry', type=click.Choice(['financial', 'healthcare', 'government', 'technology', 'retail', 'manufacturing']),
              default='technology', help='Industry type')
def cost_estimate(enterprise_size, industry):
    """Display base cost estimation for different enterprise configurations."""
    
    from ..core.cost_estimator import CostEstimator
    
    estimator = CostEstimator()
    base_cost = estimator._calculate_default_base_cost(enterprise_size, industry)
    
    click.echo(f"\n{Fore.CYAN}Base Infrastructure Cost Estimation{Style.RESET_ALL}")
    click.echo("=" * 40)
    click.echo(f"Enterprise Size: {enterprise_size.title()}")
    click.echo(f"Industry: {industry.title()}")
    click.echo(f"Estimated Annual Base Cost: ${base_cost:,.2f}")
    
    # Show breakdown
    cost_breakdown = [
        ["Compute Resources", "$50,000"],
        ["Storage", "$20,000"],
        ["Networking", "$15,000"],
        ["Security Baseline", "$30,000"],
        ["Monitoring", "$25,000"],
        ["Compliance", "$35,000"]
    ]
    
    click.echo(f"\n{Fore.YELLOW}Base Cost Components:{Style.RESET_ALL}")
    click.echo(tabulate(cost_breakdown, headers=["Component", "Base Cost"], tablefmt="simple"))

def _format_summary_report(report) -> str:
    """Format assessment report as human-readable summary."""
    
    summary = report.executive_summary
    output = []
    
    # Header
    output.append(f"{Fore.CYAN}{'='*60}")
    output.append(f"MAESTRO THREAT ASSESSMENT REPORT")
    output.append(f"{'='*60}{Style.RESET_ALL}")
    output.append(f"Assessment ID: {report.assessment_id}")
    output.append(f"Timestamp: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    output.append("")
    
    # Workflow Overview
    output.append(f"{Fore.YELLOW}WORKFLOW OVERVIEW{Style.RESET_ALL}")
    output.append("-" * 20)
    overview = summary['workflow_overview']
    output.append(f"Name: {overview['name']}")
    output.append(f"Agents: {overview['agents_count']}")
    output.append(f"Steps: {overview['steps_count']}")
    output.append(f"Data Flows: {overview['data_flows_count']}")
    output.append("")
    
    # Risk Summary
    risk_summary = summary['risk_summary']
    risk_level = risk_summary['overall_risk_level']
    
    # Color code risk level
    risk_color = Fore.GREEN
    if risk_level == 'medium':
        risk_color = Fore.YELLOW
    elif risk_level == 'high':
        risk_color = Fore.RED
    elif risk_level == 'critical':
        risk_color = Fore.MAGENTA
    
    output.append(f"{Fore.YELLOW}RISK ASSESSMENT{Style.RESET_ALL}")
    output.append("-" * 20)
    output.append(f"Risk Level: {risk_color}{risk_level.upper()}{Style.RESET_ALL}")
    output.append(f"WEI Score: {risk_summary['wei_score']}")
    output.append(f"RPS Score: {risk_summary['rps_score']}")
    output.append(f"Total Vulnerabilities: {risk_summary['total_vulnerabilities']}")
    output.append(f"Critical Vulnerabilities: {risk_summary['critical_vulnerabilities']}")
    output.append("")
    
    # Cost Summary
    cost_summary = summary['cost_summary']
    output.append(f"{Fore.YELLOW}COST IMPACT{Style.RESET_ALL}")
    output.append("-" * 20)
    output.append(f"Base Infrastructure Cost: ${cost_summary['base_cost']:,.0f}")
    output.append(f"Total TCO: ${cost_summary['total_tco']:,.0f}")
    output.append(f"Security Investment: ${cost_summary['security_investment']:,.0f}")
    output.append(f"Cost Increase: {cost_summary['cost_increase_percentage']:.1f}%")
    output.append(f"ROI: {cost_summary['roi_percentage']:.1f}%")
    output.append("")
    
    # Key Findings
    output.append(f"{Fore.YELLOW}KEY FINDINGS{Style.RESET_ALL}")
    output.append("-" * 20)
    
    # Most vulnerable layers
    vulnerable_layers = summary['key_findings']['most_vulnerable_layers']
    if vulnerable_layers:
        output.append("Most Vulnerable Layers:")
        for layer_info in vulnerable_layers[:3]:
            output.append(f"  • {layer_info['layer']}: {layer_info['vulnerability_count']} vulnerabilities")
    
    # Critical risks
    critical_risks = summary['key_findings']['critical_risks']
    if critical_risks:
        output.append("\nCritical Risk Indicators:")
        for risk in critical_risks:
            output.append(f"  • {risk}")
    
    output.append("")
    
    # Top Recommendations
    output.append(f"{Fore.YELLOW}TOP RECOMMENDATIONS{Style.RESET_ALL}")
    output.append("-" * 20)
    for i, rec in enumerate(report.recommendations[:5], 1):
        output.append(f"{i}. {rec}")
    
    output.append("")
    output.append(f"{Fore.CYAN}End of Report{Style.RESET_ALL}")
    
    return "\n".join(output)

def _format_table_report(report) -> str:
    """Format assessment report as structured tables."""
    
    output = []
    
    # Risk by Layer Table
    layer_risk_data = []
    for layer, vulns in report.risk_assessment.vulnerabilities_by_layer.items():
        layer_risk_data.append([
            layer.name.replace('_', ' ').title(),
            len(vulns),
            len([v for v in vulns if v.get('severity') == 'critical']),
            len([v for v in vulns if v.get('severity') == 'high'])
        ])
    
    output.append("MAESTRO Layer Risk Summary")
    output.append("=" * 30)
    output.append(tabulate(
        layer_risk_data,
        headers=["Layer", "Total Vulns", "Critical", "High"],
        tablefmt="grid"
    ))
    
    # Cost Breakdown Table
    cost_data = []
    for layer, cost_breakdown in report.cost_assessment.layer_costs.items():
        cost_data.append([
            layer.name.replace('_', ' ').title(),
            f"${cost_breakdown.base_cost:,.0f}",
            f"{cost_breakdown.risk_multiplier:.2f}x",
            f"${cost_breakdown.total_cost:,.0f}"
        ])
    
    output.append("\n\nCost Impact by Layer")
    output.append("=" * 25)
    output.append(tabulate(
        cost_data,
        headers=["Layer", "Base Cost", "Risk Multiplier", "Total Cost"],
        tablefmt="grid"
    ))
    
    return "\n".join(output)

def _display_quick_results(result: Dict[str, Any]):
    """Display quick assessment results in formatted output."""
    
    click.echo(f"\n{Fore.CYAN}Quick MAESTRO Assessment{Style.RESET_ALL}")
    click.echo("=" * 30)
    
    # Basic info
    click.echo(f"Workflow: {result['workflow_name']}")
    click.echo(f"Agents: {result['agents_count']}")
    click.echo(f"Steps: {result['steps_count']}")
    
    # Risk level with color coding
    risk_level = result['risk_level']
    risk_color = Fore.GREEN
    if risk_level == 'medium':
        risk_color = Fore.YELLOW
    elif risk_level == 'high':
        risk_color = Fore.RED
    elif risk_level == 'critical':
        risk_color = Fore.MAGENTA
    
    click.echo(f"Risk Level: {risk_color}{risk_level.upper()}{Style.RESET_ALL}")
    click.echo(f"WEI Score: {result['total_wei']}")
    click.echo(f"RPS Score: {result['total_rps']}")
    click.echo(f"Vulnerabilities: {result['vulnerability_count']}")
    
    # Top risks
    if result['top_risks']:
        click.echo(f"\n{Fore.YELLOW}Top Risks:{Style.RESET_ALL}")
        for i, risk in enumerate(result['top_risks'][:3], 1):
            severity = risk.get('severity', 'unknown')
            severity_color = Fore.GREEN
            if severity == 'high':
                severity_color = Fore.RED
            elif severity == 'critical':
                severity_color = Fore.MAGENTA
            
            click.echo(f"{i}. [{severity_color}{severity.upper()}{Style.RESET_ALL}] {risk.get('description', 'Unknown risk')}")
    
    # Immediate actions
    if result['immediate_actions']:
        click.echo(f"\n{Fore.YELLOW}Immediate Actions:{Style.RESET_ALL}")
        for i, action in enumerate(result['immediate_actions'], 1):
            click.echo(f"{i}. {action}")

if __name__ == '__main__':
    cli() 