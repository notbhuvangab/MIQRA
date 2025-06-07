# MAESTRO Example Workflows

This directory contains example workflows for the MAESTRO threat assessment framework, demonstrating various security scenarios and implementations.

## 🎓 Professor Demonstration Workflows

**For comprehensive risk assessment demonstration across all risk levels:**

### Risk Level Examples

1. **01_low_risk_document_processing.yaml** - **LOW Risk**
   - Simple document parsing and formatting
   - Minimal complexity, no sensitive data
   - Basic workflow with 2 steps, 2 agents

2. **02_medium_risk_customer_processing.yaml** - **MEDIUM Risk**  
   - Customer support with data processing
   - GDPR compliance requirements
   - Moderate complexity with 3 steps, 3 agents

3. **03_high_risk_healthcare_ai.yaml** - **HIGH Risk**
   - AI-powered medical diagnosis system
   - HIPAA, GDPR, FDA compliance
   - High complexity with 6 steps, 6 agents

4. **04_critical_risk_infrastructure_control.yaml** - **CRITICAL Risk**
   - Smart grid AI management system
   - Multiple critical compliance frameworks (NERC_CIP, NIST_CSF, etc.)
   - Maximum complexity with 10 steps, 10 agents

### Quick Demonstration

Run the complete demonstration:

```bash
cd examples
python run_risk_demonstration.py
```

This will analyze all four workflows and show:
- ✅ Risk level classification (LOW → CRITICAL)
- ✅ WEI and RPS calculations
- ✅ MAESTRO layer-by-layer analysis
- ✅ Vulnerability detection results
- ✅ Mathematical formula explanations

Perfect for showing professors the framework's capabilities!

---

## Workflow Categories

### Original MAESTRO Workflows

1. **mcp_a2a_workflow.yaml** - Enterprise security analysis pipeline with comprehensive MCP/A2A interactions
2. **financial_analysis_workflow.yaml** - Basic financial analysis workflow

### WebArena-Derived Workflows

The following workflows are derived from the WebArena dataset and converted to MAESTRO format with enhanced security features, A2A coordination, and MCP protocol compliance:

#### E-Commerce Security (`webarena_shopping_101.yaml`)
- **Focus**: Payment processing security and fraud detection
- **MCP Protocols**: Payment gateway, inventory management
- **A2A Patterns**: Merchant-bank communication, supply chain coordination
- **Security Features**: PCI DSS compliance, real-time transaction monitoring, ML-enhanced fraud detection

#### Social Media Content Moderation (`webarena_reddit_102.yaml`)
- **Focus**: Content moderation and community safety
- **MCP Protocols**: Content filtering, user verification
- **A2A Patterns**: Moderator coordination, cross-platform sharing
- **Security Features**: Multi-modal content scanning, proactive community safety, adaptive learning

#### DevOps Pipeline Security (`webarena_gitlab_103.yaml`)
- **Focus**: Code security and secure deployment
- **MCP Protocols**: CI/CD pipeline, code scanning
- **A2A Patterns**: Development-QA coordination, security scan orchestration
- **Security Features**: SAST/DAST analysis, dependency scanning, container security, secret management

#### Information Integrity (`webarena_wikipedia_104.yaml`)
- **Focus**: Information verification and fact-checking
- **MCP Protocols**: Fact checking, source verification
- **A2A Patterns**: Editor collaboration, automated verification
- **Security Features**: Source credibility assessment, bias detection, blockchain attestation

#### Location Privacy (`webarena_map_105.yaml`)
- **Focus**: Privacy-aware location services
- **MCP Protocols**: Location services, privacy controls
- **A2A Patterns**: GIS data sharing, navigation coordination
- **Security Features**: Differential privacy, data minimization, zero-knowledge proofs

## Common Security Features

All WebArena-derived workflows include:

- **Multi-Factor Authentication**: Secure login with credential vault integration
- **Environment Isolation**: Container-based workspace isolation
- **Data Validation**: Comprehensive integrity verification and malware scanning
- **Security Assessment**: Automated vulnerability scanning and threat modeling
- **Agent Coordination**: Byzantine fault-tolerant A2A communication
- **MCP Compliance**: Protocol verification and continuous monitoring
- **Comprehensive Reporting**: Risk visualization and remediation recommendations

## Usage

These workflows can be used with the MAESTRO threat assessment framework to:

1. Test security assessment capabilities across different domains
2. Demonstrate A2A coordination patterns
3. Validate MCP protocol compliance
4. Benchmark risk scoring algorithms
5. Train security analysts on various threat scenarios

## Workflow Structure

Each workflow follows the MAESTRO standard format:

```yaml
workflow:
  name: "<descriptive_name>"
  description: "<detailed_description>"
  metadata:
    version: "1.0"
    category: "<domain_category>"
    sensitivity: "<high|medium|low>"
    compliance_frameworks: ["SOC2", "GDPR", "NIST"]
    mcp_version: "1.2"
    a2a_protocol: "secure_mesh"
  steps:
    - id: "<step_identifier>"
      agent: "<agent_type>"
      action: "<action_name>"
      params: { ... }
      dependencies: [...]
```

## Security Considerations

- All workflows implement defense-in-depth strategies
- Sensitive operations use encrypted A2A communication
- MCP protocols ensure controlled model execution
- Audit trails provide complete operation visibility
- Risk scoring follows CVSS v4 standards

## Contributing

To add new workflows:

1. Follow the MAESTRO YAML format
2. Include appropriate security controls
3. Implement MCP protocol compliance where applicable
4. Add A2A coordination for multi-agent scenarios
5. Update this README with workflow descriptions 