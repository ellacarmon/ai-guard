import yaml
import os
from pydantic import BaseModel
from typing import List, Union, Optional
from ..models.schema import Category, Severity

class RuleDefinition(BaseModel):
    id: str
    category: Category
    severity: Severity
    type: str
    target: Union[List[str], str]
    module: Optional[str] = None
    description: str
    confidence_base: float = 1.0

class RuleEngine:
    def __init__(self, rules_path: Optional[str] = None):
        if rules_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            rules_path = os.path.join(base_dir, 'rules', 'default_rules.yml')
            
        self.rules: List[RuleDefinition] = self._load_rules(rules_path)
        
    def _load_rules(self, path: str) -> List[RuleDefinition]:
        if not os.path.exists(path):
            return []
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            
        rules = []
        for r_dict in data.get('rules', []):
            try:
                rule = RuleDefinition(**r_dict)
                rules.append(rule)
            except Exception as e:
                import click
                click.echo(f"Warning: Failed to parse rule {r_dict.get('id', 'unknown')}: {e}", err=True)
        return rules

    def get_rules_by_type(self, rule_type: str) -> List[RuleDefinition]:
        return [r for r in self.rules if r.type == rule_type]
