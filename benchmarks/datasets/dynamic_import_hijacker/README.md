# Dynamic Import Hijacker Test Case

**Expected Label**: `BLOCK`

**Attack Pattern**: Runtime module hijacking via dynamic imports

## Malicious Behaviors

This test case demonstrates extensive behavioral analysis detections:

1. **Dynamic Import (BEH-001, BEH-002)**: Multiple instances of `__import__()` and `importlib.import_module()` with variable module names
2. **Obfuscated Import (BEH-003)**: Uses `getattr(builtins, '__import__')` pattern
3. **Runtime Compilation (BEH-006)**: Uses `compile()` for dynamic code generation
4. **Runtime Execution (BEH-004, BEH-005)**: Contains `exec()` and `eval()` with dynamic code
5. **Suspicious File Write (BEH-009)**: Writes to `/tmp` directory
6. **Excessive getattr (BEH-011)**: Deeply nested getattr calls for obfuscation
7. **Suspicious Domain (BEH-007)**: References pastebin.com exfiltration

## Expected Behavioral Findings

- Dynamic imports detected: 5+
- Runtime execution patterns: 3+
- Obfuscation detected: 2+
- Suspicious patterns: 2+ (file write + domain)

## Risk Assessment

- **Risk Score**: 9.5+ (CRITICAL)
- **Decision**: BLOCK
- **Primary Risks**: Module hijacking, runtime code execution, obfuscation, filesystem manipulation
