import math
import os
import yaml
from typing import List, Dict, Tuple
from ..models.schema import Finding, Category, Severity

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
        
    def calculate(self, findings: List[Finding]) -> Tuple[float, str, str, float, Dict[str, float], Dict[str, float], List[Finding]]:
        categories_breakdown: Dict[str, float] = {
            Category.CODE_EXECUTION.value: 0.0,
            Category.PROMPT_INJECTION.value: 0.0,
            Category.NETWORK_ACCESS.value: 0.0,
            Category.SUPPLY_CHAIN.value: 0.0,
            Category.FILESYSTEM_ACCESS.value: 0.0
        }
        
        # Group findings by category
        grouped_findings: Dict[Category, List[Finding]] = {cat: [] for cat in Category}
        for finding in findings:
            grouped_findings[finding.category].append(finding)
            
        # Step 1: Diminishing Returns per Category using exact exponential model
        for cat, cats_findings in grouped_findings.items():
            impact_sum = 0.0
            for f in cats_findings:
                weight = self.severity_weights.get(f.severity, 0.0)
                # Confidence scales the impact directly
                impact_sum += weight * getattr(f, 'confidence', 1.0)
                
            # Score limit asymptotes to 10 based on formula 10 * (1 - e^(-k * sum(I)))
            score_c = 10.0 * (1.0 - math.exp(-self.k_factor * impact_sum))
            categories_breakdown[cat.value] = round(min(10.0, score_c), 2)
            
        # Step 2: Probabilistic OR Aggregation
        p_safe = 1.0
        for score_c in categories_breakdown.values():
            p_safe *= (1.0 - (score_c / 10.0))
            
        risk_score = 10.0 * (1.0 - p_safe)
        risk_score = round(risk_score, 2)
        
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
