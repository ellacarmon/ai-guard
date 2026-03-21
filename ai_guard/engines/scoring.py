import os
import yaml
from typing import List, Dict, Tuple
from ..models.schema import Finding, Category, Severity
from .normalization import NormalizationLayer

class ScoringEngine:
    def __init__(self, config_path: str = None):
        if config_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_path = os.path.join(base_dir, 'rules', 'scoring.yml')
            
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            
        weights = config.get('severity_weights', {})
        self.severity_weights = {
            Severity.LOW: float(weights.get('low', 1.0)),
            Severity.MEDIUM: float(weights.get('medium', 2.5)),
            Severity.HIGH: float(weights.get('high', 5.0)),
            Severity.CRITICAL: float(weights.get('critical', 10.0))
        }
        self.k_factor = float(config.get('k_factor', 0.25))
        
        thresholds = config.get('risk_thresholds', {})
        self.thresh_critical = float(thresholds.get('critical', 9.0))
        self.thresh_high = float(thresholds.get('high', 7.0))
        self.thresh_medium = float(thresholds.get('medium', 4.0))
        
        # Initialize Normalization Layer
        self.normalization_layer = NormalizationLayer(
            k_factor=self.k_factor,
            severity_weights=self.severity_weights
        )
        
    def calculate(self, findings: List[Finding]) -> Tuple[float, str, str, float, Dict[str, float], Dict[str, float], List[Finding]]:
        
        # Step 1 & 2: Normalization Layer - Diminishing returns & Weighted Aggregation
        categories_breakdown = self.normalization_layer.apply_diminishing_returns(findings)
        risk_score = self.normalization_layer.aggregate_weighted_scores(categories_breakdown)
        
        # Step 3: Compute Risk Levels and Recommendations
        if risk_score >= self.thresh_critical:
            risk_level = "CRITICAL"
            recommendation = "BLOCK"
        elif risk_score >= self.thresh_high:
            risk_level = "HIGH"
            recommendation = "BLOCK"
        elif risk_score >= self.thresh_medium:
            risk_level = "MEDIUM"
            recommendation = "WARN"
        else:
            risk_level = "LOW"
            recommendation = "ALLOW"
        
        # Calculate Confidence
        confidence = 1.0
        if findings:
            avg_conf = sum(getattr(f, 'confidence', 1.0) for f in findings) / len(findings)
            confidence = round(avg_conf, 2)
            
        # Calculate Normalized Contributions
        normalized_contributions: Dict[str, float] = {}
        total_category_score = sum(categories_breakdown.values())
        if total_category_score > 0:
            for cat, score in categories_breakdown.items():
                if score > 0:
                    normalized_contributions[cat] = round(score / total_category_score, 2)
                    
        # Sort all findings by effective impact for top findings
        top_findings = sorted(
            findings, 
            key=lambda f: self.severity_weights.get(f.severity, 0.0) * getattr(f, 'confidence', 1.0), 
            reverse=True
        )[:5]
        
        return risk_score, risk_level, recommendation, confidence, categories_breakdown, normalized_contributions, top_findings
