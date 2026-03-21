import math
from typing import List, Dict
from ..models.schema import Finding, Category

class NormalizationLayer:
    """
    Applies mathematical normalizations to raw security findings to prevent score saturation:
    - Caps per Category (max 10.0)
    - Diminishing Returns (Exponential Decay function)
    - Weighted Aggregation across disparate categories
    """
    def __init__(self, k_factor: float, severity_weights: Dict[str, float]):
        self.k_factor = k_factor
        self.severity_weights = severity_weights

    def apply_diminishing_returns(self, findings: List[Finding]) -> Dict[str, float]:
        """Calculates category scores using exponential decay and explicit caps."""
        categories_breakdown: Dict[str, float] = {cat.value: 0.0 for cat in Category}
        
        grouped_findings: Dict[Category, List[Finding]] = {cat: [] for cat in Category}
        for finding in findings:
            grouped_findings[finding.category].append(finding)
            
        for cat, cats_findings in grouped_findings.items():
            impact_sum = 0.0
            for f in cats_findings:
                weight = self.severity_weights.get(f.severity, 0.0)
                impact_sum += weight * getattr(f, 'confidence', 1.0)
                
            # Score limit asymptotes to 10 based on formula 10 * (1 - e^(-k * sum(I)))
            score_c = 10.0 * (1.0 - math.exp(-self.k_factor * impact_sum))
            
            # Explicit Caps per category
            categories_breakdown[cat.value] = round(min(10.0, score_c), 2)
            
        return categories_breakdown

    def aggregate_weighted_scores(self, categories_breakdown: Dict[str, float]) -> float:
        """Weighted aggregation using Probabilistic OR mapped across the category space."""
        p_safe = 1.0
        for score_c in categories_breakdown.values():
            p_safe *= (1.0 - (score_c / 10.0))
            
        risk_score = 10.0 * (1.0 - p_safe)
        return round(risk_score, 2)
