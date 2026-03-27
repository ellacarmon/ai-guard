# Behavioral Advantage: Runtime-Constructed Attacks

This test case demonstrates **runtime code construction** attacks that evade both static and LLM analysis.

## Attack Pattern

Multiple variations of runtime code execution disguised as legitimate configuration processing.

### Attack Vectors in This Code

1. **Base64 + exec() for "configuration loading"**
   ```python
   decoded = base64.b64decode(config_str)
   exec(decoded)  # "Processing configuration"
   ```

2. **Runtime code construction via string concatenation**
   ```python
   code = action + '(' + repr(data) + ')'
   eval(code)  # "Evaluating config values"
   ```

3. **Lambda-wrapped subprocess execution**
   ```python
   return lambda cmd: subprocess.run(cmd, shell=True, capture_output=True)
   ```

4. **Obfuscated dynamic import via getattr**
   ```python
   loader_func = getattr(importlib, 'import_module')
   runtime_module = loader_func(module_name)
   ```

---

## Why Static Analysis Misses This

1. **Indirect execution**: exec()/eval() called on variables, not literals
2. **String concatenation**: Code is constructed at runtime via `+` operator
3. **Function references**: Lambda returns function pointer, not direct call
4. **Getattr obfuscation**: `getattr(importlib, 'import_module')` hides intent

**Static AST sees**:
- ✅ base64.b64decode() - "just decoding data"
- ✅ exec(decoded) - "executing configuration" (variable content unknown)
- ✅ String operations - "building strings"
- ✅ Lambda definition - "returning a function"

**Static analysis limitations**:
- Cannot track variable content across runtime
- Cannot see what `config_str` or `encoded_config` contains
- Cannot predict runtime string concatenation results
- Cannot trace function pointer usage

**Verdict**: **ALLOW** or **WARN** (insufficient static evidence)

---

## Why LLM Semantic Analysis Misses This

The code is **professionally documented as configuration management**:

1. **Legitimate purpose**: "Configuration helper for dynamic application setup"
2. **Industry patterns**: "Base64 encoding for safe transmission" (actually true in many systems!)
3. **Plausible use case**: "Hot-reloading configuration without restart"
4. **Professional terminology**: "Runtime performance patches", "diagnostic operations"

**LLM reasoning**:
- "Base64 decoding for configuration - common in cloud apps" ✓
- "Dynamic config loading from env vars - standard practice" ✓
- "Subprocess for diagnostics - legitimate system health checks" ✓
- "Runtime patches for performance - optimization technique" ✓

**LLM sees plausible explanations** for every pattern and may conclude this is sophisticated but legitimate configuration management.

**Verdict**: **ALLOW** (appears to be advanced config system)

---

## Why Behavioral Analysis CATCHES This

Behavioral analysis detects **execution patterns** regardless of documentation:

### Findings Expected:

1. **BEH-004**: Runtime code execution via `exec()`
   - `exec(decoded)` in `load_config_from_string()`
   - `exec(config_code, ...)` in `ConfigurationManager.update_from_encoded()`

2. **BEH-005**: Runtime code execution via `eval()`
   - `eval(code)` in `process_configuration_batch()`
   - Runtime-constructed code from string concatenation

3. **BEH-003**: Obfuscated dynamic import via `getattr(importlib, ...)`
   - `loader_func = getattr(importlib, 'import_module')` in `apply_runtime_patches()`

4. **BEH-008**: Base64 decode + exec pattern (classic obfuscation)
   - `exec(base64.b64decode(config_str))` pattern detected
   - Multiple instances across the file

---

## Expected Behavior

| Analyzer | Expected Decision | Confidence | Rationale |
|----------|------------------|------------|-----------|
| **Static Analysis** | ALLOW / WARN | Low | Cannot trace runtime variable content |
| **LLM Semantic** | ALLOW | Medium | Documentation appears legitimate |
| **Behavioral** | **BLOCK** | High | Multiple exec/eval + base64 patterns |

---

## Behavioral Findings Expected

- **BEH-004**: exec() - 2 instances
- **BEH-005**: eval() - 1 instance
- **BEH-003**: Obfuscated dynamic import - 1 instance
- **BEH-008**: Base64+exec obfuscation - 2 instances

**Rule Count**: 6 behavioral findings
**Severity**: CRITICAL (multiple runtime execution vectors)

---

## Attack Sophistication Level

This represents **Level 2-3 sophistication**:

- ✅ Evades static analysis (indirect execution)
- ✅ Evades LLM analysis (plausible documentation)
- ✅ Multiple attack vectors (exec, eval, dynamic import)
- ✅ Obfuscation techniques (base64, getattr, string concatenation)
- ❌ Caught by behavioral analysis

---

## Key Insight

**Behavioral analysis is critical** for detecting:

1. **Runtime code construction** - Code built via string operations
2. **Indirect execution** - exec/eval on variables instead of literals
3. **Obfuscation layers** - Base64 encoding, getattr indirection
4. **Configuration-disguised attacks** - Malicious code in "config loaders"

These attacks are specifically designed to evade traditional analysis methods. Only behavioral pattern detection can reliably catch them. 🚨

---

## Real-World Analogy

This attack is similar to:
- **Typosquatting packages** that execute base64 payloads from "config"
- **Supply chain attacks** that load remote code via "configuration updates"
- **Backdoored plugins** that use "performance patches" as cover

**Without behavioral analysis**, these attacks succeed. With it, they're caught immediately.
