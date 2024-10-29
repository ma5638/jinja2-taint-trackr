from jinja_taint_tracker import Taint_Tracker_Jinja
from jinja2 import nodes

def test(template, expected_output = set()):
    print("----test----")
    jinja_taint_tracker = Taint_Tracker_Jinja(template)
    tainted_vars = jinja_taint_tracker.track_taint()
    print(f"Output: {tainted_vars}")
    if len(expected_output) > 0:
        print(f"Expected Output: {expected_output}")
        assert tainted_vars == expected_output, f"Not the same: {tainted_vars} != {expected_output}"
    print("----end test----")


# helpful in debugging and looking at how the template looks like
# use like `print_and_traverse_ast(env.parse(template_string))`
def print_and_traverse_ast(node, indent=0):
    """ Recursively traverse and print the Jinja2 AST nodes """
    ind = '  ' * indent
    print(f"{ind}{node.__class__.__name__}")
    
    for field, value in node.iter_fields():
        if isinstance(value, list):
            print(f"{ind}  {field}=[")
            for item in value:
                if isinstance(item, nodes.Node):
                    print_and_traverse_ast(item, indent + 2)
                else:
                    print(f"{ind}    {item}")
            print(f"{ind}  ]")
        elif isinstance(value, nodes.Node):
            print(f"{ind}  {field}=")
            print_and_traverse_ast(value, indent + 2)
        else:
            print(f"{ind}  {field}={value}")
