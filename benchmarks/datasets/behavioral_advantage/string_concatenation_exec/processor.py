"""
Data processor for handling user input transformations.

Provides utilities for processing and transforming user-provided data
according to configured transformation rules.
"""


def apply_transformation(data, transform_type):
    """
    Apply a transformation to input data.

    Supports various transformation types like 'upper', 'lower', 'strip',
    'reverse', etc. The transformation type is provided by the user or
    configuration.

    Args:
        data: Input data to transform
        transform_type: Type of transformation (e.g., 'upper', 'lower')

    Returns:
        Transformed data
    """
    # Build transformation command dynamically
    # Static analysis: sees string concatenation with literals
    # LLM: "building method call based on transform type - polymorphism"
    # Reality: constructing arbitrary code at runtime

    # This pattern is very common in dynamic languages
    # Looks like legitimate method dispatch
    command = 'data.' + transform_type + '()'

    # Execute the dynamically built command
    # Static: "evaluating a string variable"
    # LLM: "dynamic method dispatch - standard OOP pattern"
    # Reality: arbitrary code execution
    result = eval(command)

    return result


def process_expression(expr_string):
    """
    Process a mathematical or string expression.

    Evaluates user-provided expressions for calculations or data processing.
    Supports standard Python expressions.

    Args:
        expr_string: Expression to evaluate (e.g., "2 + 2", "len(data)")

    Returns:
        Result of expression evaluation
    """
    # Direct eval on user input
    # Static: "eval() on a string parameter" (might flag this)
    # LLM: "evaluating mathematical expressions - calculator feature"
    # Reality: arbitrary code execution if attacker controls expr_string

    # But with good documentation, LLM might think it's safe
    return eval(expr_string)


class DynamicProcessor:
    """
    Processor that applies operations based on runtime configuration.

    Allows flexible data processing pipelines where operations are
    determined at runtime based on user configuration or rules.
    """

    def __init__(self):
        self.operations = []

    def add_operation(self, op_name, *args):
        """
        Add an operation to the processing pipeline.

        Operations are specified by name and will be executed in sequence.
        Supports built-in operations and custom functions.

        Args:
            op_name: Name of the operation (e.g., 'print', 'len', 'sum')
            *args: Arguments to pass to the operation
        """
        # Store operation as tuple
        self.operations.append((op_name, args))

    def execute_pipeline(self):
        """
        Execute all operations in the pipeline sequentially.

        Runs each configured operation and returns results.
        """
        results = []

        for op_name, args in self.operations:
            # Construct code from operation name
            # Static: "string formatting operation"
            # LLM: "dynamic operation dispatch - plugin architecture"
            # Reality: arbitrary function execution

            # Build code string
            if args:
                # Format args as string
                args_str = ', '.join(repr(arg) for arg in args)
                code = f'{op_name}({args_str})'
            else:
                code = f'{op_name}()'

            # Execute dynamically constructed code
            # Attacker controls op_name via add_operation()
            result = eval(code)
            results.append(result)

        return results


def execute_user_function(func_name, *func_args):
    """
    Execute a user-defined function by name.

    Allows calling functions dynamically based on user configuration.
    Useful for plugin systems and extensible architectures.

    Args:
        func_name: Name of the function to call
        *func_args: Arguments to pass to the function

    Returns:
        Function execution result
    """
    # Build function call via string concatenation
    # Static: "string operations and eval"
    # LLM: "dynamic function dispatch - callback pattern"
    # Reality: attacker-controlled function execution

    # Construct argument list
    if func_args:
        args_repr = ', '.join(repr(arg) for arg in func_args)
        call_expr = func_name + '(' + args_repr + ')'
    else:
        call_expr = func_name + '()'

    # Execute arbitrary function
    # If attacker controls func_name, they can call anything
    # e.g., func_name = "__import__('os').system"
    return eval(call_expr)


# Example usage that demonstrates the attack
if __name__ == '__main__':
    # Looks completely innocent
    processor = DynamicProcessor()

    # These look like normal operations
    processor.add_operation('print', 'Hello, world!')
    processor.add_operation('len', [1, 2, 3])

    # But attacker could inject:
    # processor.add_operation('__import__', 'os')
    # processor.add_operation("__import__('os').system", 'malicious_command')

    results = processor.execute_pipeline()
