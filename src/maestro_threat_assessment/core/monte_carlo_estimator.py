"""
Monte Carlo Risk Estimation Module

Implements probabilistic risk assessment using Monte Carlo simulation
to estimate uncertainty in vulnerability parameters before calculating
final WEI and RPS scores.
"""

import numpy as np
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from ..models.maestro_constants import MAESTROLayer, CORE_THREAT_MATRIX, DEFAULT_THREAT_VALUES

@dataclass
class MonteCarloParams:
    """Parameters for Monte Carlo simulation"""
    n_simulations: int = 10000
    confidence_interval: float = 0.95
    random_seed: int = 42

@dataclass
class UncertaintyDistribution:
    """Represents uncertainty in a parameter using probability distributions"""
    mean: float
    std_dev: float
    distribution_type: str = "normal"  # normal, uniform, beta
    lower_bound: float = None
    upper_bound: float = None

@dataclass
class MonteCarloResult:
    """Result of Monte Carlo simulation"""
    mean: float
    std_dev: float
    confidence_interval: Tuple[float, float]
    percentiles: Dict[int, float]
    samples: np.ndarray

class MonteCarloEstimator:
    """Monte Carlo estimator for risk parameters with uncertainty quantification"""
    
    def __init__(self, params: MonteCarloParams = None):
        self.params = params or MonteCarloParams()
        np.random.seed(self.params.random_seed)
    
    def estimate_vulnerability_parameters(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, MonteCarloResult]:
        """
        Estimate vulnerability parameters with uncertainty using Monte Carlo simulation
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Dictionary of Monte Carlo results for each parameter
        """
        results = {}
        
        # Estimate Attack Complexity with uncertainty
        ac_distribution = self._get_attack_complexity_distribution(vulnerabilities)
        results['attack_complexity'] = self._run_simulation(ac_distribution)
        
        # Estimate Impact with uncertainty  
        impact_distribution = self._get_impact_distribution(vulnerabilities)
        results['impact'] = self._run_simulation(impact_distribution)
        
        # Estimate Vulnerability Severity with uncertainty
        vs_distribution = self._get_vulnerability_severity_distribution(vulnerabilities)
        results['vulnerability_severity'] = self._run_simulation(vs_distribution)
        
        # Estimate Protocol Coupling with uncertainty
        pc_distribution = self._get_protocol_coupling_distribution(vulnerabilities)
        results['protocol_coupling'] = self._run_simulation(pc_distribution)
        
        return results
    
    def estimate_layer_exposure(self, layer: MAESTROLayer, vulnerabilities: List[Dict[str, Any]]) -> MonteCarloResult:
        """
        Estimate layer-specific exposure with uncertainty
        
        Args:
            layer: MAESTRO layer
            vulnerabilities: Vulnerabilities in this layer
            
        Returns:
            Monte Carlo result for layer exposure
        """
        # Base exposure with uncertainty based on vulnerability count and types
        base_exposure = self._get_base_layer_exposure(layer)
        
        # Add uncertainty based on vulnerability characteristics
        if vulnerabilities:
            vulnerability_factor = len(vulnerabilities) * 0.1
            exposure_std = base_exposure * 0.2 + vulnerability_factor * 0.05
        else:
            exposure_std = base_exposure * 0.1
        
        distribution = UncertaintyDistribution(
            mean=base_exposure,
            std_dev=exposure_std,
            distribution_type="normal",
            lower_bound=0.0,
            upper_bound=1.0
        )
        
        return self._run_simulation(distribution)
    
    def _get_attack_complexity_distribution(self, vulnerabilities: List[Dict[str, Any]]) -> UncertaintyDistribution:
        """Get uncertainty distribution for attack complexity using Core Threat Matrix"""
        if not vulnerabilities:
            # No vulnerabilities = high attack complexity (harder to exploit)
            return UncertaintyDistribution(mean=3.0, std_dev=0.3, lower_bound=2.5, upper_bound=3.0)
        
        # Get attack complexity values from Core Threat Matrix
        complexity_values = []
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            
            # Look up specific AC value from Core Threat Matrix
            threat_data = CORE_THREAT_MATRIX.get(vuln_type, DEFAULT_THREAT_VALUES)
            complexity_values.append(float(threat_data['ac']))
        
        mean_complexity = np.mean(complexity_values)
        std_complexity = max(0.3, np.std(complexity_values)) if len(complexity_values) > 1 else 0.3
        
        return UncertaintyDistribution(
            mean=mean_complexity,
            std_dev=std_complexity,
            lower_bound=1.0,
            upper_bound=3.0
        )
    
    def _get_impact_distribution(self, vulnerabilities: List[Dict[str, Any]]) -> UncertaintyDistribution:
        """Get uncertainty distribution for business impact using Core Threat Matrix"""
        if not vulnerabilities:
            # No vulnerabilities = low potential impact
            return UncertaintyDistribution(mean=1.5, std_dev=0.5, lower_bound=1.0, upper_bound=2.5)
        
        # Get impact values from Core Threat Matrix
        impact_values = []
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            
            # Look up specific Impact value from Core Threat Matrix
            threat_data = CORE_THREAT_MATRIX.get(vuln_type, DEFAULT_THREAT_VALUES)
            impact_values.append(float(threat_data['impact']))
        
        mean_impact = np.mean(impact_values)
        std_impact = max(0.5, np.std(impact_values)) if len(impact_values) > 1 else 0.5
        
        return UncertaintyDistribution(
            mean=mean_impact,
            std_dev=std_impact,
            lower_bound=1.0,
            upper_bound=5.0
        )
    
    def _get_vulnerability_severity_distribution(self, vulnerabilities: List[Dict[str, Any]]) -> UncertaintyDistribution:
        """Get uncertainty distribution for vulnerability severity using Core Threat Matrix"""
        if not vulnerabilities:
            # No vulnerabilities = low severity baseline
            return UncertaintyDistribution(mean=2.0, std_dev=1.0, lower_bound=1.0, upper_bound=4.0)
        
        # Get vulnerability severity values from Core Threat Matrix
        severity_values = []
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            
            # Look up specific VS value from Core Threat Matrix
            threat_data = CORE_THREAT_MATRIX.get(vuln_type, DEFAULT_THREAT_VALUES)
            severity_values.append(float(threat_data['vs']))
        
        mean_severity = np.mean(severity_values)
        std_severity = max(1.0, np.std(severity_values)) if len(severity_values) > 1 else 1.0
        
        return UncertaintyDistribution(
            mean=mean_severity,
            std_dev=std_severity,
            lower_bound=1.0,
            upper_bound=10.0
        )
    
    def _get_protocol_coupling_distribution(self, vulnerabilities: List[Dict[str, Any]]) -> UncertaintyDistribution:
        """Get uncertainty distribution for protocol coupling using Core Threat Matrix"""
        if not vulnerabilities:
            # No vulnerabilities = low coupling (isolated workflow)
            return UncertaintyDistribution(mean=1.2, std_dev=0.3, lower_bound=1.0, upper_bound=2.0)
        
        # Get protocol coupling values from Core Threat Matrix
        coupling_values = []
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            
            # Look up specific PC value from Core Threat Matrix
            threat_data = CORE_THREAT_MATRIX.get(vuln_type, DEFAULT_THREAT_VALUES)
            coupling_values.append(float(threat_data['pc']))
        
        mean_coupling = np.mean(coupling_values)
        std_coupling = max(0.3, np.std(coupling_values)) if len(coupling_values) > 1 else 0.3
        
        return UncertaintyDistribution(
            mean=mean_coupling,
            std_dev=std_coupling,
            lower_bound=1.0,
            upper_bound=3.0
        )
    
    def _get_base_layer_exposure(self, layer: MAESTROLayer) -> float:
        """Get base exposure for a MAESTRO layer"""
        from ..models.maestro_constants import MAESTRO_EXPOSURE_INDEX
        return MAESTRO_EXPOSURE_INDEX[layer]
    
    def _run_simulation(self, distribution: UncertaintyDistribution) -> MonteCarloResult:
        """
        Run Monte Carlo simulation for a given uncertainty distribution
        
        Args:
            distribution: Uncertainty distribution to sample from
            
        Returns:
            Monte Carlo simulation result
        """
        samples = self._generate_samples(distribution)
        
        # Calculate statistics
        mean = np.mean(samples)
        std_dev = np.std(samples)
        
        # Calculate confidence interval
        alpha = 1 - self.params.confidence_interval
        lower_percentile = (alpha / 2) * 100
        upper_percentile = (1 - alpha / 2) * 100
        
        confidence_interval = (
            np.percentile(samples, lower_percentile),
            np.percentile(samples, upper_percentile)
        )
        
        # Calculate key percentiles
        percentiles = {
            5: np.percentile(samples, 5),
            25: np.percentile(samples, 25),
            50: np.percentile(samples, 50),
            75: np.percentile(samples, 75),
            95: np.percentile(samples, 95)
        }
        
        return MonteCarloResult(
            mean=mean,
            std_dev=std_dev,
            confidence_interval=confidence_interval,
            percentiles=percentiles,
            samples=samples
        )
    
    def _generate_samples(self, distribution: UncertaintyDistribution) -> np.ndarray:
        """Generate samples from uncertainty distribution"""
        if distribution.distribution_type == "normal":
            samples = np.random.normal(
                distribution.mean, 
                distribution.std_dev, 
                self.params.n_simulations
            )
        elif distribution.distribution_type == "uniform":
            lower = distribution.lower_bound or (distribution.mean - distribution.std_dev)
            upper = distribution.upper_bound or (distribution.mean + distribution.std_dev)
            samples = np.random.uniform(lower, upper, self.params.n_simulations)
        elif distribution.distribution_type == "beta":
            # Convert mean/std to beta parameters
            mean = distribution.mean
            var = distribution.std_dev ** 2
            alpha = mean * (mean * (1 - mean) / var - 1)
            beta = (1 - mean) * (mean * (1 - mean) / var - 1)
            samples = np.random.beta(alpha, beta, self.params.n_simulations)
        else:
            raise ValueError(f"Unsupported distribution type: {distribution.distribution_type}")
        
        # Apply bounds if specified
        if distribution.lower_bound is not None:
            samples = np.maximum(samples, distribution.lower_bound)
        if distribution.upper_bound is not None:
            samples = np.minimum(samples, distribution.upper_bound)
        
        return samples 