"""
Protocol Constants for MAESTRO Threat Assessment

Defines the actual MCP and A2A protocol values based on real specifications.
These are the only valid values that should be used in workflow YAML files.
"""

from enum import Enum
from typing import Dict, List, Set


class MCPTransport(Enum):
    """Valid MCP transport mechanisms"""
    STDIO = "stdio"
    SSE = "sse"  # Server-Sent Events for remote servers
    HTTP = "http"


class MCPCapability(Enum):
    """Valid MCP server capabilities"""
    RESOURCES = "resources"
    TOOLS = "tools"
    PROMPTS = "prompts"
    LOGGING = "logging"
    PROGRESS = "progress"
    CANCELLATION = "cancellation"


class A2ATransport(Enum):
    """Valid A2A transport mechanisms"""
    HTTP_HTTPS = "https"
    JSON_RPC = "json-rpc"
    SSE = "sse"  # Server-Sent Events for streaming


class A2ACapability(Enum):
    """Valid A2A agent capabilities"""
    STREAMING = "streaming"
    PUSH_NOTIFICATIONS = "pushNotifications"
    STATE_TRANSITION_HISTORY = "stateTransitionHistory"
    LONG_RUNNING_TASKS = "longRunningTasks"


class A2AInputMode(Enum):
    """Valid A2A input modalities"""
    TEXT = "text"
    DATA = "data"
    AUDIO = "audio"
    VIDEO = "video"
    FILE = "file"


class A2AOutputMode(Enum):
    """Valid A2A output modalities"""
    TEXT = "text"
    DATA = "data"
    AUDIO = "audio"
    VIDEO = "video"
    FILE = "file"


class A2AAuthScheme(Enum):
    """Valid A2A authentication schemes (aligned with OpenAPI)"""
    BEARER = "bearer"
    OAUTH2 = "oauth2"
    API_KEY = "apiKey"
    HTTP = "http"
    MUTUAL_TLS = "mutualTLS"


class A2ATaskState(Enum):
    """Valid A2A task states"""
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input-required"
    COMPLETED = "completed"
    CANCELED = "canceled"
    FAILED = "failed"
    UNKNOWN = "unknown"


# MCP Protocol Constants
MCP_PROTOCOL_VERSIONS = ["2025-03-26", "2024-11-05"]
MCP_DEFAULT_VERSION = "2025-03-26"

# Valid MCP resource schemes
MCP_RESOURCE_SCHEMES = ["file", "http", "https", "memory", "database"]

# Valid MCP tool parameter types
MCP_TOOL_PARAMETER_TYPES = ["string", "number", "integer", "boolean", "array", "object"]

# A2A Protocol Constants
A2A_PROTOCOL_VERSION = "1.0"
A2A_JSON_RPC_VERSION = "2.0"

# Valid A2A methods
A2A_METHODS = [
    "tasks/send",
    "tasks/get", 
    "tasks/cancel",
    "tasks/sendSubscribe",
    "tasks/pushNotification/set",
    "tasks/pushNotification/get",
    "tasks/resubscribe"
]

# Security Constants
VALID_TLS_VERSIONS = ["1.2", "1.3"]
VALID_CIPHER_SUITES = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256"
]

# Validation Sets (for easy checking)
VALID_MCP_TRANSPORTS = {transport.value for transport in MCPTransport}
VALID_MCP_CAPABILITIES = {cap.value for cap in MCPCapability}
VALID_A2A_TRANSPORTS = {transport.value for transport in A2ATransport}
VALID_A2A_CAPABILITIES = {cap.value for cap in A2ACapability}
VALID_A2A_INPUT_MODES = {mode.value for mode in A2AInputMode}
VALID_A2A_OUTPUT_MODES = {mode.value for mode in A2AOutputMode}
VALID_A2A_AUTH_SCHEMES = {scheme.value for scheme in A2AAuthScheme}
VALID_A2A_TASK_STATES = {state.value for state in A2ATaskState}

# Workflow Security Classifications
WORKFLOW_SENSITIVITY_LEVELS = ["low", "medium", "high", "critical"]
COMPLIANCE_FRAMEWORKS = [
    "SOC2", "ISO27001", "NIST_CSF", "GDPR", "HIPAA", 
    "PCI_DSS", "SOX", "BASEL_III", "FedRAMP"
]

# Common Agent Types (based on real implementations)
COMMON_AGENT_TYPES = [
    "DataAgent", "AuthenticationAgent", "APIAgent", "FileAgent",
    "DatabaseAgent", "WebAgent", "EmailAgent", "SchedulerAgent",
    "MonitoringAgent", "SecurityAgent", "ComplianceAgent",
    "AnalyticsAgent", "WorkflowAgent", "NotificationAgent"
]

# Common Action Categories
COMMON_ACTION_CATEGORIES = [
    "authenticate", "authorize", "fetch", "create", "update", "delete",
    "process", "analyze", "monitor", "validate", "transform", "notify",
    "schedule", "backup", "restore", "encrypt", "decrypt", "sign", "verify"
] 