# Benign Plugin Test Case

**Expected Label**: `ALLOW`

**Pattern**: Legitimate text formatting utility

## Characteristics

This test case demonstrates benign code that should NOT trigger behavioral analysis warnings:

1. **Static Imports Only**: Uses standard library imports (`json`, `re`, `typing`)
2. **No Dynamic Execution**: No `exec()`, `eval()`, `compile()`, or dynamic imports
3. **No Obfuscation**: Clean, readable code with proper documentation
4. **No Suspicious Patterns**: No exfiltration domains, suspicious file writes, or encoded payloads
5. **Type Hints**: Proper Python type annotations throughout

## Expected Behavioral Findings

- Dynamic imports detected: 0
- Runtime execution patterns: 0
- Obfuscation detected: 0
- Suspicious patterns: 0

## Risk Assessment

- **Risk Score**: 0.0-1.0 (LOW)
- **Decision**: ALLOW
- **Primary Characteristics**: Clean utility code with no security concerns
