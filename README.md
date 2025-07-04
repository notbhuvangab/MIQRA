# MAESTRO Threat Assessment Framework

A comprehensive security risk assessment tool for agentic workflows using the MAESTRO (Model, Agent framework, Ecosystem, Security, Threat landscape, Risk mitigation, Operational oversight) framework.

## Overview

The MAESTRO Threat Assessment Framework provides enterprise-grade security analysis for AI agentic workflows. It implements the latest MAESTRO security framework with enhanced risk quantification formulas and Monte Carlo uncertainty estimation, including:

- **Workflow Exploitability Index (WEI)** - MAESTRO-layered vulnerability assessment with statistical confidence intervals
- **Risk Propagation Score (RPS)** - Cross-layer risk analysis with uncertainty quantification
- **Monte Carlo Risk Assessment** - Probabilistic analysis with 10,000 simulation runs for robust uncertainty estimation
- **Total Cost of Ownership (TCO)** - Enterprise cost impact evaluation
- **Comprehensive Reporting** - Executive summaries and detailed technical reports with confidence intervals
- **Interactive Web GUI** - Modern web interface with flowchart visualization and uncertainty displays

## Features

### Core Capabilities

- **YAML Workflow Parsing**: Parse and analyze workflow definitions with agent interactions and data flows
- **Vulnerability Identification**: Automatic detection of security risks across all MAESTRO layers
- **Monte Carlo Risk Quantification**: Calculate WEI and RPS scores with statistical uncertainty using 10,000 simulation runs
- **Uncertainty Analysis**: 95% confidence intervals for all risk metrics with robust statistical foundation
- **Cost Assessment**: Enterprise cost estimation with ROI analysis
- **Multiple Output Formats**: CLI, JSON, tables, and executive summaries with uncertainty bounds
- **Interactive Web GUI**: Modern Streamlit-based interface with uncertainty visualization

### 🎲 Monte Carlo Risk Assessment

The framework implements probabilistic risk assessment using Monte Carlo simulation to quantify uncertainty in:

- **Attack Complexity**: Distribution-based estimates of exploitation difficulty
- **Business Impact**: Probabilistic assessment of potential damage
- **Vulnerability Severity**: CVSS-like scoring with confidence intervals  
- **Protocol Coupling**: Inter-component dependency risk estimation
- **Layer Exposure**: MAESTRO layer-specific risk exposure with uncertainty

Each assessment runs 10,000 Monte Carlo simulations to provide:
- Mean risk scores with standard deviations
- 95% confidence intervals for all metrics
- Percentile distributions (5th, 25th, 50th, 75th, 95th)
- Robust statistical foundation for enterprise decision-making

### 🌐 Web GUI Features

The MAESTRO framework now includes a comprehensive web interface with:

- **📤 YAML Workflow Upload**: Drag-and-drop or paste workflow definitions
- **🔄 Interactive Flowchart**: Visualize workflow steps with threat mapping and severity colors
- **⚙️ Configurable Risk Parameters**: Customize LayerWeight_l, ExposureIndex_l, VulnerabilityComplexity_l, and EnterpriseCost_l
- **🏗️ MAESTRO Layer Visualization**: Interactive charts showing WEI/RPS contributions by layer
- **💰 Cost Analysis Dashboard**: Visual cost breakdown and ROI analysis
- **📊 Comprehensive Reporting**: Executive summaries with downloadable reports
- **🎯 Threat Mapping**: Color-coded visualization of vulnerabilities by severity

### MAESTRO Framework Layers

1. **L1: Foundation Models** - Model security, prompt injection protection, bias mitigation
2. **L2: Data Operations** - Data pipeline security, privacy protection, vector database hardening
3. **L3: Agent Frameworks** - Agent protocol security, tool validation, inter-agent communication
4. **L4: Deployment** - Runtime security, sandboxing, network isolation, infrastructure hardening
5. **L5: Observability** - Security monitoring, logging, anomaly detection, audit trails
6. **L6: Compliance** - Regulatory compliance, policy enforcement, governance frameworks
7. **L7: Ecosystem** - Third-party integrations, supply chain security, dependency management

## Installation

### Prerequisites

- Python 3.8+
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Install MAESTRO Package

```bash
pip install -e .
```

## Quick Start

### 🌐 Web GUI (Recommended)

Launch the interactive web interface:

```bash
python run_gui.py
```

This will start the Streamlit application at `http://localhost:8501` with features including:
- Interactive workflow upload and analysis
- Real-time threat visualization with flowchart
- Configurable risk model parameters (custom button option)
- Comprehensive dashboard with MAESTRO layer analysis
- Export capabilities for reports and summaries

### 📋 Command Line Interface

#### 1. Analyze a Workflow (Quick Assessment)

```bash
python -m maestro_threat_assessment.cli.main quick examples/financial_analysis_workflow.yaml
```

#### 2. Full MAESTRO Assessment

```bash
python -m maestro_threat_assessment.cli.main assess examples/financial_analysis_workflow.yaml \
  --enterprise-size medium \
  --industry financial \
  --format summary
```

#### 3. Generate JSON Report

```bash
python -m maestro_threat_assessment.cli.main assess examples/financial_analysis_workflow.yaml \
  --format json \
  --output report.json
```

## Usage Examples

### Command Line Interface

The MAESTRO CLI provides several commands for different use cases:

#### Full Assessment
```bash
maestro assess workflow.yaml --enterprise-size large --industry healthcare --verbose
```

#### Quick Risk Check
```bash
maestro quick workflow.yaml
```

#### View Framework Layers
```bash
maestro layers
```

#### Cost Estimation
```bash
maestro cost-estimate --enterprise-size enterprise --industry financial
```

### Python API

```python
from maestro_threat_assessment import MAESTROEngine

# Initialize engine
engine = MAESTROEngine()

# Perform assessment
report = engine.assess_workflow_from_file(
    'workflow.yaml',
    base_infrastructure_cost=200000,
    enterprise_size='large',
    industry='financial'
)

# Access results with uncertainty
print(f"Risk Level: {report.risk_assessment.risk_level}")
print(f"WEI Score: {report.risk_assessment.total_wei.mean:.3f} ± {report.risk_assessment.total_wei.std_dev:.3f}")
print(f"WEI 95% CI: [{report.risk_assessment.total_wei.confidence_interval[0]:.3f}, {report.risk_assessment.total_wei.confidence_interval[1]:.3f}]")
print(f"RPS Score: {report.risk_assessment.total_rps.mean:.3f} ± {report.risk_assessment.total_rps.std_dev:.3f}")
print(f"TCO: ${report.cost_assessment.total_tco:,.0f}")
```

## Workflow Format

MAESTRO accepts YAML workflow definitions with the following structure:

```yaml
workflow:
  name: "Your Workflow Name"
  description: "Description of the workflow"
  metadata:
    version: "1.0"
    category: "financial"  # financial, healthcare, etc.
    sensitivity: "high"    # low, medium, high
  
  steps:
    - id: "step_1"
      agent: "AgentName"
      action: "action_name"
      params:
        key: "value"
      dependencies: []
    
    - id: "step_2"
      agent: "AnotherAgent"
      action: "process_data"
      input_from: "AgentName"
      dependencies: ["step_1"]
```

## Risk Assessment Output

### Executive Summary
- Workflow overview and metrics
- Overall risk level (Low/Medium/High/Critical)
- WEI and RPS scores
- Cost impact analysis
- Key findings and vulnerabilities

### Detailed Analysis
- Layer-by-layer vulnerability breakdown
- Risk propagation analysis
- Cost breakdown by MAESTRO layer
- Specific security recommendations

### Example Output
```
MAESTRO THREAT ASSESSMENT REPORT
================================
Risk Level: HIGH
WEI Score: 6.42
RPS Score: 23.7
Total Vulnerabilities: 8
Security Investment Required: $127,500
ROI: 240%

Top Risks:
1. [HIGH] Data extraction step may expose sensitive information
2. [MEDIUM] Financial workflow may violate regulatory compliance
3. [HIGH] Tool execution may be vulnerable to poisoning attacks
```

## Configuration

### Enterprise Sizes
- `startup`: Small teams, limited budget
- `small`: <500 employees
- `medium`: 500-5000 employees  
- `large`: 5000-50000 employees
- `enterprise`: >50000 employees

### Industries
- `financial`: Banking, investment, fintech
- `healthcare`: Medical, pharma, health tech
- `government`: Public sector, defense
- `technology`: Software, SaaS, tech services
- `retail`: E-commerce, consumer goods
- `manufacturing`: Industrial, automotive

## Architecture

```
maestro_threat_assessment/
├── core/
│   ├── maestro_engine.py       # Main orchestration
│   ├── workflow_parser.py      # YAML parsing and analysis
│   ├── risk_calculator.py      # WEI/RPS calculation
│   └── cost_estimator.py       # TCO calculation
├── models/
│   └── maestro_constants.py    # Framework constants
├── cli/
│   └── main.py                 # Command-line interface
└── examples/
    └── *.yaml                  # Example workflows
```

## Advanced Features

### Custom Cost Models
Override default cost estimates with your infrastructure costs:

```bash
maestro assess workflow.yaml --base-cost 500000
```

### Vulnerability Extensions
The framework is designed to be extensible. Add custom vulnerability detection rules by extending the `WorkflowParser` class.

### Integration Ready
- JSON API for integration with existing security tools
- Programmatic access via Python API
- CI/CD pipeline integration capabilities

## Security Considerations

- All assessments are performed locally - no data leaves your environment
- Workflow files should be treated as sensitive configuration
- Cost estimates are based on industry averages and should be validated
- Regular updates recommended as threat landscape evolves

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

Copyright 2024 MAESTRO Security Team. All rights reserved.

## Support

For questions, issues, or feature requests:
- Create an issue in the repository
- Review the examples directory for common use cases
- Check the CLI help: `maestro --help`

---

**Note**: This tool provides risk assessment guidance. Always consult with security professionals for production deployments.

## GUI Usage Guide

### 🏠 Home Page
- Framework overview and MAESTRO layer descriptions
- Sample YAML format and getting started guide

### 📤 Upload Workflow
- Upload YAML files or paste content directly
- Configure assessment parameters (base cost, enterprise size, industry)
- Run comprehensive MAESTRO assessment

### ⚙️ Configure Parameters
The quantitative risk model supports both default and custom parameters:
- **Default Mode**: Uses fixed values based on industry standards
- **Custom Mode**: Allows configuration of:
  - `LayerWeight_l`: Importance weights for each MAESTRO layer
  - `ExposureIndex_l`: Exposure levels by layer
  - `VulnerabilityComplexity_l`: Attack complexity factors
  - `EnterpriseCost_l`: Cost weights for security investments

### 📊 Assessment Results
- **Interactive Flowchart**: Nodes colored by vulnerability severity (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)
- **MAESTRO Layer Analysis**: Multi-chart visualization of WEI/RPS contributions
- **Cost Analysis**: Visual breakdown of security investments and ROI
- **Vulnerability Table**: Detailed listing of all identified threats
- **Strategic Recommendations**: Actionable security guidance

### 📄 Export Reports
- **JSON Reports**: Complete assessment data for integration
- **Executive Summaries**: High-level markdown reports for stakeholders
- **Real-time Metrics**: Current assessment overview with key indicators
