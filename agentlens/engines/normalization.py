from typing import Dict, Union

from ..models.schema import Category

class NormalizationLayer:
    """
    Feature-driven normalization:
    - Category score = max of triggered feature scores (quantity-independent)
    - Supports bool, count, and string (key=value) feature matching
    - Caps per category (max 10.0)
    - Probabilistic OR aggregation across categories
    """
    def __init__(self, feature_scores: Dict[str, Dict[str, float]]):
        self.feature_scores = feature_scores

    def compute_category_scores(self, features: Dict[str, Union[bool, int, str]]) -> Dict[str, float]:
        """
        Derive category scores from extracted features.
        
        Supports three feature types in the YAML mapping:
        - Boolean:  "has_exec" → True/False
        - Count:    "prompt_override_patterns" → int > 0
        - String:   "execution_complexity=critical" → matched against feature value
        """
        categories_breakdown: Dict[str, float] = {cat.value: 0.0 for cat in Category}
        
        for category, feature_map in self.feature_scores.items():
            triggered_scores = []
            
            for feature_key, score_value in feature_map.items():
                # String feature: "key=value" syntax
                if "=" in feature_key:
                    feat_name, expected_val = feature_key.split("=", 1)
                    actual_val = features.get(feat_name, "none")
                    if str(actual_val) == expected_val:
                        triggered_scores.append(float(score_value))
                else:
                    # Bool or Count feature
                    feat_val = features.get(feature_key, False)
                    if feat_val and feat_val is not False:
                        triggered_scores.append(float(score_value))
            
            if triggered_scores:
                categories_breakdown[category] = round(min(10.0, max(triggered_scores)), 2)
                
        return categories_breakdown

    def aggregate_weighted_scores(self, categories_breakdown: Dict[str, float]) -> float:
        """Weighted aggregation using Probabilistic OR across the category space."""
        p_safe = 1.0
        for score_c in categories_breakdown.values():
            p_safe *= (1.0 - (score_c / 10.0))
            
        risk_score = 10.0 * (1.0 - p_safe)
        return round(risk_score, 2)
