# Logic Audit Benchmark Datasets

This directory contains benchmark datasets for evaluating the logic audit engine's ability to detect incoherences between documentation and implementation.

## Dataset Structure

```
datasets/
├── data_thief/          # Data Thief archetype (E2+SC2: credential harvest + remote exec)
│   ├── undeclared_env_vars/
│   ├── credential_exfil/
│   └── remote_script_exec/
├── agent_hijacker/      # Agent Hijacker archetype (P1/P2/P4: instruction override + autonomy suppression)
│   ├── instruction_override/
│   ├── hidden_instructions/
│   └── behavior_manipulation/
├── incoherence/         # General documentation-code mismatches
│   ├── undocumented_network/
│   ├── undocumented_subprocess/
│   ├── undocumented_filesystem/
│   └── contradictory_claims/
├── benign/              # Clean skills with proper documentation
│   ├── simple_calculator/
│   ├── text_formatter/
│   └── data_parser/
└── benign_discrepancy/  # Minor doc-code discrepancies that shouldn't block
    ├── extra_error_handling/
    └── implementation_details/
```

## Evaluation Criteria

### True Positives (TP)
Skills with malicious incoherences that should be blocked:
- Undeclared environment variable access (E2)
- Network access contradicting "offline only" claims
- Cross-skill path access (privilege escalation)
- Credential exfiltration patterns
- Instruction override + autonomy suppression

### False Positives (FP)
Benign skills incorrectly flagged:
- Implementation details not in docs (error handling, logging)
- Framework-specific patterns (Flask route decorators)
- Development/testing code paths

### True Negatives (TN)
Benign skills correctly allowed:
- Well-documented, coherent implementations
- Standard library usage with proper disclosure

### False Negatives (FN)
Malicious skills that evade detection:
- Novel obfuscation techniques
- Context-dependent attacks
- Time-bomb patterns

## Expected Performance Targets

Based on Liu et al. (2026) empirical validation:

| Metric | Target | Notes |
|--------|--------|-------|
| Precision | ≥ 95% | Minimize false blocks on benign skills |
| Recall | ≥ 90% | Detect Data Thief (OR=556), Agent Hijacker patterns |
| F1 Score | ≥ 92% | Balanced performance |
| Accuracy | ≥ 93% | Overall correctness |
| Avg Time | < 2s | Fast pre-installation scanning |

## Dataset Sources

1. **Synthetic**: Hand-crafted examples covering archetypes
2. **Real-world**: Anonymized malicious skills from wild (pending ethical review)
3. **Benign baseline**: Popular open-source libraries and frameworks
4. **Edge cases**: Adversarial examples designed to test robustness
