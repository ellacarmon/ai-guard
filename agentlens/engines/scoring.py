import os
import yaml
from typing import List, Dict
from ..models.schema import Finding, Category, Severity
from .normalization import NormalizationLayer
from .features import FeatureExtractor
from .decision import DecisionEngine
from .exploitability import ExploitabilityEngine


class ScoringEngine:
    def __init__(self, config_path: str = None, policy_path: str = None):
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

        # Feature-driven Normalization Layer
        feature_scores = config.get('feature_scores', {})
        self.normalization_layer = NormalizationLayer(feature_scores=feature_scores)
        self.decision_engine = DecisionEngine(policy_path=policy_path)
        self.exploitability_engine = ExploitabilityEngine()

    def calculate(self, findings: List[Finding], context: Dict = None) -> Dict:
        if context is None:
            context = {}

        # Step 0: Feature Abstraction Layer — findings → features
        feature_extractor = FeatureExtractor()
        features = feature_extractor.extract(findings, context=context)

        # Step 1: Feature-driven category scoring (quantity-independent)
        categories_breakdown = self.normalization_layer.compute_category_scores(features)

        # Step 2: Probabilistic OR aggregation across categories
        base_risk_score = self.normalization_layer.aggregate_weighted_scores(categories_breakdown)

        # Step 3: Exploitability Engine
        exploitability = self.exploitability_engine.evaluate(features, findings)
        
        # Apply Exploitability Multiplier
        multiplier = max(0.1, exploitability.exploitability_score / 10.0)
        risk_score = round(base_risk_score * multiplier, 2)

        # Step 4: Decision Engine — multi-signal decision with policy
        decision_result = self.decision_engine.evaluate(
            risk_score=risk_score,
            categories=categories_breakdown,
            features=features,
            exploitability=exploitability,
            findings=findings,
        )

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

        return {
            "risk_score": risk_score,
            "risk_level": decision_result.risk_level.value.upper(),
            "decision": decision_result.decision.value,
            "confidence": decision_result.confidence,
            "top_risks": decision_result.top_risks,
            "explanation": decision_result.explanation,
            "recommendation": decision_result.recommendation,
            "categories": categories_breakdown,
            "normalized_contributions": normalized_contributions,
            "top_findings": top_findings,
            "features": features,
            "exploitability": exploitability,
        }
