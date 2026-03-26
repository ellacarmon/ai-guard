# Malicious Wheel Test Case

**Expected Label**: `BLOCK`

**Attack Pattern**: Dynamic import backdoor with obfuscation

## Malicious Behaviors

This test case demonstrates several behavioral analysis detections:

1. **Dynamic Import (BEH-001, BEH-002)**: Uses `__import__()` and `importlib.import_module()` with runtime-determined module names
2. **Obfuscated Import (BEH-003)**: Uses `getattr(importlib, 'import_module')` pattern
3. **Base64 + Exec (BEH-008)**: Contains base64-encoded malicious code intended for exec
4. **Base64-Encoded Code (BEH-010)**: Base64 blob decodes to Python code
5. **Suspicious Domain (BEH-007)**: References paste.ee exfiltration domain

## Expected Behavioral Findings

- Dynamic imports detected: 3+
- Runtime execution patterns: 1+
- Obfuscation detected: 2+
- Suspicious patterns: 1+ (exfiltration domain)

## Risk Assessment

- **Risk Score**: 9.0+ (CRITICAL)
- **Decision**: BLOCK
- **Primary Risks**: Code execution via dynamic imports, obfuscation, potential exfiltration
