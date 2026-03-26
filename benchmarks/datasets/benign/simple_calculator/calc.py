def calculate(expression):
    """
    Safely evaluate a mathematical expression.

    Uses ast.literal_eval for safety instead of eval().
    """
    import ast
    import operator

    operators = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.Pow: operator.pow,
    }

    try:
        tree = ast.parse(expression, mode='eval')
        return _eval_node(tree.body, operators)
    except Exception as e:
        return f"Error: {str(e)}"

def _eval_node(node, operators):
    if isinstance(node, ast.Num):
        return node.n
    elif isinstance(node, ast.BinOp):
        left = _eval_node(node.left, operators)
        right = _eval_node(node.right, operators)
        return operators[type(node.op)](left, right)
    else:
        raise ValueError("Unsupported operation")
