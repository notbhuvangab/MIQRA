# MAESTRO YAML Protocol Guide

## Understanding Real MCP and A2A Protocols

This guide explains how to create MAESTRO workflow YAML files that use **real** Model Context Protocol (MCP) and Agent-to-Agent (A2A) protocol values based on the actual specifications from Anthropic and Google.

## Why Protocol Compliance Matters

Using arbitrary protocol values in workflow YAML files can:
- ❌ Oversimplify security architecture
- ❌ Make workflows unrealistic and untestable  
- ❌ Lead to false security assessments
- ❌ Prevent understanding of real protocol limitations

**MAESTRO now validates all protocol values against real specifications.**

## Model Context Protocol (MCP) - Anthropic

MCP provides standardized communication between AI applications and data sources/tools.

### Valid MCP Transport Mechanisms

```yaml
mcp_transport: "stdio"    # Local process communication
mcp_transport: "sse"      # Server-Sent Events for remote servers  
mcp_transport: "http"     # HTTP-based communication
```

### Valid MCP Capabilities

```yaml
mcp_capabilities:
  - "resources"     # Data and context sharing
  - "tools"         # Executable functions 
  - "prompts"       # Templated interactions
  - "logging"       # Request/response logging
  - "progress"      # Progress tracking
  - "cancellation"  # Request cancellation
```

### MCP Protocol Versions

```yaml
mcp_version: "2025-03-26"  # Latest version (recommended)
mcp_version: "2024-11-05"  # Previous version
```

### Example MCP Configuration

```yaml
- id: "fetch_data"
  agent: "DatabaseAgent"
  action: "fetch_records"
  params:
    mcp_transport: "sse"
    mcp_capabilities: ["resources", "tools"]
    mcp_endpoint: "https://api.company.com/mcp"
```

## Agent-to-Agent Protocol (A2A) - Google

A2A enables standardized communication between autonomous AI agents.

### Valid A2A Transport Mechanisms

```yaml
a2a_transport: "https"      # HTTPS (required for production)
a2a_transport: "json-rpc"   # JSON-RPC 2.0 messaging
a2a_transport: "sse"        # Server-Sent Events for streaming
```

### Valid A2A Capabilities

```yaml
a2a_capabilities:
  - "streaming"                 # Real-time data streaming
  - "pushNotifications"         # Asynchronous notifications
  - "stateTransitionHistory"    # Task state tracking
  - "longRunningTasks"          # Extended task support
```

### Valid A2A Input/Output Modes

```yaml
a2a_input_modes:
  - "text"    # Textual content
  - "data"    # Structured data (JSON)
  - "audio"   # Audio streams
  - "video"   # Video streams  
  - "file"    # File transfers

a2a_output_modes:
  - "text"    # Textual responses
  - "data"    # Structured data
  - "audio"   # Audio generation
  - "video"   # Video generation
  - "file"    # File outputs
```

### Valid A2A Authentication Schemes

```yaml
a2a_auth_scheme: "bearer"      # Bearer token authentication
a2a_auth_scheme: "oauth2"      # OAuth 2.0 flow
a2a_auth_scheme: "apiKey"      # API key authentication
a2a_auth_scheme: "http"        # HTTP authentication
a2a_auth_scheme: "mutualTLS"   # Mutual TLS certificates
```

### Example A2A Configuration

```yaml
- id: "agent_communication"
  agent: "APIAgent"
  action: "coordinate_task"
  params:
    a2a_transport: "https"
    a2a_capabilities: ["streaming", "pushNotifications"]
    a2a_input_modes: ["text", "data"]
    a2a_output_modes: ["data"]
    a2a_auth_scheme: "oauth2"
```

## Complete Workflow Structure

### Required Metadata Fields

```yaml
workflow:
  name: "Your Workflow Name"
  description: "Detailed description of workflow purpose"
  metadata:
    version: "1.0"
    category: "financial"  # or "healthcare", "security", etc.
    sensitivity: "high"    # "low", "medium", "high", "critical"
    compliance_frameworks: ["SOX", "PCI_DSS", "GDPR"]
    mcp_version: "2025-03-26"
```

### Valid Sensitivity Levels

```yaml
sensitivity: "low"       # Minimal security concerns
sensitivity: "medium"    # Standard business data
sensitivity: "high"      # Sensitive business data
sensitivity: "critical"  # Highly regulated data
```

### Valid Compliance Frameworks

```yaml
compliance_frameworks:
  - "SOC2"       # Service Organization Control 2
  - "ISO27001"   # Information Security Management
  - "NIST_CSF"   # NIST Cybersecurity Framework
  - "GDPR"       # General Data Protection Regulation
  - "HIPAA"      # Health Insurance Portability
  - "PCI_DSS"    # Payment Card Industry Data Security
  - "SOX"        # Sarbanes-Oxley Act
  - "BASEL_III"  # Banking regulations
  - "FedRAMP"    # Federal Risk Authorization
```

## Common Agent Types

```yaml
agent: "AuthenticationAgent"  # User/system authentication
agent: "DatabaseAgent"        # Database operations
agent: "APIAgent"            # API interactions
agent: "FileAgent"           # File system operations
agent: "SecurityAgent"       # Security validations
agent: "ComplianceAgent"     # Regulatory compliance
agent: "AnalyticsAgent"      # Data analysis
agent: "NotificationAgent"   # Alerts and notifications
agent: "WorkflowAgent"       # Workflow orchestration
```

## Common Action Categories

```yaml
action: "authenticate_user"     # User authentication
action: "fetch_records"         # Data retrieval
action: "create_report"         # Report generation
action: "validate_data"         # Data validation
action: "analyze_patterns"      # Pattern analysis
action: "process_request"       # Request processing
action: "notify_stakeholders"   # Stakeholder notifications
```

## Real-World Example

```yaml
workflow:
  name: "Financial Compliance Workflow"
  description: "Demonstrates real MCP and A2A protocol usage"
  metadata:
    version: "1.0"
    category: "financial"
    sensitivity: "critical"
    compliance_frameworks: ["SOX", "PCI_DSS"]
    mcp_version: "2025-03-26"
    
  steps:
    - id: "authenticate_user"
      agent: "AuthenticationAgent"
      action: "authenticate_user"
      params:
        mcp_transport: "sse"
        mcp_capabilities: ["tools", "resources"]
        mcp_endpoint: "https://auth.company.com/mcp"
        auth_method: "oauth2"
      dependencies: []
      
    - id: "coordinate_agents"
      agent: "APIAgent"
      action: "setup_agent_communication"
      params:
        a2a_transport: "https"
        a2a_capabilities: ["streaming", "pushNotifications"]
        a2a_input_modes: ["text", "data"]
        a2a_output_modes: ["data"]
        a2a_auth_scheme: "oauth2"
        agent_card_url: "https://api.company.com/.well-known/agent.json"
      dependencies: ["authenticate_user"]
      
    - id: "fetch_financial_data"
      agent: "DatabaseAgent"
      action: "fetch_customer_records"
      params:
        mcp_transport: "stdio"
        mcp_capabilities: ["resources", "tools"]
        database_encryption: "required"
        access_controls: "enabled"
      dependencies: ["coordinate_agents"]
```

## Protocol Validation

MAESTRO automatically validates your workflow against real protocol specifications:

```python
from maestro_threat_assessment.core.protocol_validator import validate_workflow_protocols

# Validates against real MCP and A2A specifications
result = validate_workflow_protocols(workflow_data)
print(f"Valid: {result.is_valid}")
print(f"Errors: {len(result.errors)}")
```

## Key Differences from Previous Versions

### ❌ Old (Invalid) Values
```yaml
# These values are NOT real protocol values:
a2a_protocol: "secure_mesh"      # Made up
a2a_protocol: "insecure_mesh"    # Made up
mcp_transport: "https"           # Wrong - MCP uses "sse" for remote
```

### ✅ New (Valid) Values
```yaml
# These are from actual protocol specifications:
a2a_transport: "https"           # Real A2A transport
a2a_auth_scheme: "oauth2"        # Real A2A authentication
mcp_transport: "sse"             # Real MCP remote transport
mcp_capabilities: ["tools"]      # Real MCP capabilities
```

## Best Practices

1. **Always validate workflows** using the built-in protocol validator
2. **Use latest protocol versions** unless specific compatibility required
3. **Choose appropriate sensitivity levels** based on actual data classification
4. **Specify realistic agent interactions** based on protocol capabilities
5. **Include proper authentication schemes** matching your infrastructure
6. **Test workflows** with realistic protocol configurations

## Resources

- [MCP Specification](https://modelcontextprotocol.io/specification/2025-03-26)
- [A2A Protocol Documentation](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [MAESTRO Protocol Constants](../src/maestro_threat_assessment/models/protocol_constants.py)

This guide ensures your MAESTRO workflows use **real, implementable protocol values** that accurately represent how MCP and A2A protocols actually work in production systems. 