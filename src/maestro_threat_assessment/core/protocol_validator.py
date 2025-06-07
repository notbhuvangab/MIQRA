"""
Protocol Validator for MAESTRO Threat Assessment

Validates that workflow YAML files use only legitimate MCP and A2A protocol values
based on the actual specifications.
"""

from typing import Dict, List, Any, Optional, Tuple
import re
from dataclasses import dataclass

from ..models.protocol_constants import (
    VALID_MCP_TRANSPORTS, VALID_MCP_CAPABILITIES, MCP_PROTOCOL_VERSIONS,
    MCP_RESOURCE_SCHEMES, MCP_TOOL_PARAMETER_TYPES,
    VALID_A2A_TRANSPORTS, VALID_A2A_CAPABILITIES, VALID_A2A_INPUT_MODES,
    VALID_A2A_OUTPUT_MODES, VALID_A2A_AUTH_SCHEMES, VALID_A2A_TASK_STATES,
    A2A_METHODS, WORKFLOW_SENSITIVITY_LEVELS, COMPLIANCE_FRAMEWORKS,
    COMMON_AGENT_TYPES, COMMON_ACTION_CATEGORIES
)


@dataclass
class ValidationError:
    """Represents a protocol validation error"""
    field: str
    value: Any
    message: str
    suggestion: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of protocol validation"""
    is_valid: bool
    errors: List[ValidationError]
    warnings: List[ValidationError]


class ProtocolValidator:
    """Validates workflow protocol configurations against real specifications"""
    
    def __init__(self):
        self.errors = []
        self.warnings = []
    
    def validate_workflow(self, workflow_data: Dict[str, Any]) -> ValidationResult:
        """
        Validate an entire workflow for protocol compliance
        
        Args:
            workflow_data: Parsed workflow YAML data
            
        Returns:
            ValidationResult with any errors or warnings found
        """
        self.errors = []
        self.warnings = []
        
        workflow = workflow_data.get('workflow', {})
        metadata = workflow.get('metadata', {})
        steps = workflow.get('steps', [])
        
        # Validate metadata
        self._validate_metadata(metadata)
        
        # Validate steps
        for i, step in enumerate(steps):
            self._validate_step(step, i)
        
        return ValidationResult(
            is_valid=len(self.errors) == 0,
            errors=self.errors,
            warnings=self.warnings
        )
    
    def _validate_metadata(self, metadata: Dict[str, Any]) -> None:
        """Validate workflow metadata fields"""
        
        # Validate MCP version
        mcp_version = metadata.get('mcp_version')
        if mcp_version and mcp_version not in MCP_PROTOCOL_VERSIONS:
            self.errors.append(ValidationError(
                field="metadata.mcp_version",
                value=mcp_version,
                message=f"Invalid MCP version. Must be one of: {MCP_PROTOCOL_VERSIONS}",
                suggestion=f"Use '{MCP_PROTOCOL_VERSIONS[0]}' for latest version"
            ))
        
        # Validate sensitivity level
        sensitivity = metadata.get('sensitivity')
        if sensitivity and sensitivity not in WORKFLOW_SENSITIVITY_LEVELS:
            self.errors.append(ValidationError(
                field="metadata.sensitivity",
                value=sensitivity,
                message=f"Invalid sensitivity level. Must be one of: {WORKFLOW_SENSITIVITY_LEVELS}"
            ))
        
        # Validate compliance frameworks
        frameworks = metadata.get('compliance_frameworks', [])
        if isinstance(frameworks, list):
            for framework in frameworks:
                if framework not in COMPLIANCE_FRAMEWORKS:
                    self.warnings.append(ValidationError(
                        field="metadata.compliance_frameworks",
                        value=framework,
                        message=f"Unknown compliance framework: {framework}",
                        suggestion=f"Consider using standard frameworks: {COMPLIANCE_FRAMEWORKS[:5]}..."
                    ))
        
        # Check for deprecated fields
        if 'a2a_protocol' in metadata:
            value = metadata['a2a_protocol']
            if isinstance(value, str) and value not in VALID_A2A_TRANSPORTS:
                self.errors.append(ValidationError(
                    field="metadata.a2a_protocol",
                    value=value,
                    message=f"Invalid A2A transport. Must be one of: {list(VALID_A2A_TRANSPORTS)}",
                    suggestion="Use 'https' for remote agents or remove field if not using A2A"
                ))
    
    def _validate_step(self, step: Dict[str, Any], step_index: int) -> None:
        """Validate individual workflow step"""
        step_id = step.get('id', f'step_{step_index}')
        
        # Validate agent type
        agent = step.get('agent')
        if agent and not self._is_valid_agent_name(agent):
            self.warnings.append(ValidationError(
                field=f"steps[{step_index}].agent",
                value=agent,
                message=f"Agent name '{agent}' doesn't follow common naming patterns",
                suggestion=f"Consider using standard agent types: {COMMON_AGENT_TYPES[:5]}..."
            ))
        
        # Validate action
        action = step.get('action')
        if action and not self._is_valid_action_name(action):
            self.warnings.append(ValidationError(
                field=f"steps[{step_index}].action",
                value=action,
                message=f"Action '{action}' doesn't follow common patterns",
                suggestion=f"Consider using standard action categories: {COMMON_ACTION_CATEGORIES[:5]}..."
            ))
        
        # Validate MCP-specific parameters
        params = step.get('params', {})
        self._validate_mcp_params(params, step_id, step_index)
        
        # Validate A2A-specific parameters
        self._validate_a2a_params(params, step_id, step_index)
    
    def _validate_mcp_params(self, params: Dict[str, Any], step_id: str, step_index: int) -> None:
        """Validate MCP-specific parameters"""
        
        # Check for MCP transport
        mcp_transport = params.get('mcp_transport')
        if mcp_transport and mcp_transport not in VALID_MCP_TRANSPORTS:
            self.errors.append(ValidationError(
                field=f"steps[{step_index}].params.mcp_transport",
                value=mcp_transport,
                message=f"Invalid MCP transport. Must be one of: {list(VALID_MCP_TRANSPORTS)}"
            ))
        
        # Check for MCP capabilities
        mcp_capabilities = params.get('mcp_capabilities', [])
        if isinstance(mcp_capabilities, list):
            for cap in mcp_capabilities:
                if cap not in VALID_MCP_CAPABILITIES:
                    self.errors.append(ValidationError(
                        field=f"steps[{step_index}].params.mcp_capabilities",
                        value=cap,
                        message=f"Invalid MCP capability. Must be one of: {list(VALID_MCP_CAPABILITIES)}"
                    ))
        
        # Check for MCP endpoint URL format
        mcp_endpoint = params.get('mcp_endpoint')
        if mcp_endpoint and not self._is_valid_url(mcp_endpoint):
            self.errors.append(ValidationError(
                field=f"steps[{step_index}].params.mcp_endpoint",
                value=mcp_endpoint,
                message="Invalid MCP endpoint URL format",
                suggestion="Use format: https://domain.com/mcp or file:///path/to/resource"
            ))
    
    def _validate_a2a_params(self, params: Dict[str, Any], step_id: str, step_index: int) -> None:
        """Validate A2A-specific parameters"""
        
        # Check for A2A transport
        a2a_transport = params.get('a2a_transport')
        if a2a_transport and a2a_transport not in VALID_A2A_TRANSPORTS:
            self.errors.append(ValidationError(
                field=f"steps[{step_index}].params.a2a_transport",
                value=a2a_transport,
                message=f"Invalid A2A transport. Must be one of: {list(VALID_A2A_TRANSPORTS)}"
            ))
        
        # Check for A2A capabilities
        a2a_capabilities = params.get('a2a_capabilities', [])
        if isinstance(a2a_capabilities, list):
            for cap in a2a_capabilities:
                if cap not in VALID_A2A_CAPABILITIES:
                    self.errors.append(ValidationError(
                        field=f"steps[{step_index}].params.a2a_capabilities",
                        value=cap,
                        message=f"Invalid A2A capability. Must be one of: {list(VALID_A2A_CAPABILITIES)}"
                    ))
        
        # Check for A2A input/output modes
        a2a_input_modes = params.get('a2a_input_modes', [])
        if isinstance(a2a_input_modes, list):
            for mode in a2a_input_modes:
                if mode not in VALID_A2A_INPUT_MODES:
                    self.errors.append(ValidationError(
                        field=f"steps[{step_index}].params.a2a_input_modes",
                        value=mode,
                        message=f"Invalid A2A input mode. Must be one of: {list(VALID_A2A_INPUT_MODES)}"
                    ))
        
        a2a_output_modes = params.get('a2a_output_modes', [])
        if isinstance(a2a_output_modes, list):
            for mode in a2a_output_modes:
                if mode not in VALID_A2A_OUTPUT_MODES:
                    self.errors.append(ValidationError(
                        field=f"steps[{step_index}].params.a2a_output_modes",
                        value=mode,
                        message=f"Invalid A2A output mode. Must be one of: {list(VALID_A2A_OUTPUT_MODES)}"
                    ))
        
        # Check for A2A authentication
        a2a_auth = params.get('a2a_auth_scheme')
        if a2a_auth and a2a_auth not in VALID_A2A_AUTH_SCHEMES:
            self.errors.append(ValidationError(
                field=f"steps[{step_index}].params.a2a_auth_scheme",
                value=a2a_auth,
                message=f"Invalid A2A auth scheme. Must be one of: {list(VALID_A2A_AUTH_SCHEMES)}"
            ))
        
        # Check for A2A task states (if specified)
        a2a_task_state = params.get('a2a_task_state')
        if a2a_task_state and a2a_task_state not in VALID_A2A_TASK_STATES:
            self.errors.append(ValidationError(
                field=f"steps[{step_index}].params.a2a_task_state",
                value=a2a_task_state,
                message=f"Invalid A2A task state. Must be one of: {list(VALID_A2A_TASK_STATES)}"
            ))
    
    def _is_valid_agent_name(self, name: str) -> bool:
        """Check if agent name follows common patterns"""
        # Check if it's a known agent type
        if name in COMMON_AGENT_TYPES:
            return True
        
        # Check if it follows naming conventions (ends with Agent)
        if name.endswith('Agent') and len(name) > 5:
            return True
        
        # Check if it's a reasonable name (alphanumeric + underscores)
        if re.match(r'^[A-Za-z][A-Za-z0-9_]*$', name):
            return True
        
        return False
    
    def _is_valid_action_name(self, action: str) -> bool:
        """Check if action name follows common patterns"""
        # Check if it starts with a known action category
        for category in COMMON_ACTION_CATEGORIES:
            if action.startswith(category):
                return True
        
        # Check if it's a reasonable action name (alphanumeric + underscores)
        if re.match(r'^[a-z][a-z0-9_]*$', action):
            return True
        
        return False
    
    def _is_valid_url(self, url: str) -> bool:
        """Basic URL format validation"""
        url_pattern = re.compile(
            r'^(https?|file|memory|database)://'
            r'(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+'
            r'(?::\d+)?'
            r'(?:/[A-Za-z0-9._~:/?#[\]@!$&\'()*+,;=-]*)?$'
        )
        return bool(url_pattern.match(url))


def validate_workflow_protocols(workflow_data: Dict[str, Any]) -> ValidationResult:
    """
    Convenience function to validate workflow protocol compliance
    
    Args:
        workflow_data: Parsed workflow YAML data
        
    Returns:
        ValidationResult with any protocol violations found
    """
    validator = ProtocolValidator()
    return validator.validate_workflow(workflow_data) 