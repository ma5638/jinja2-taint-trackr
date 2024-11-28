from jinja2 import Environment, nodes
import copy

TARGET_FILTER = "dangerous_filter"

# setting dummy environment. Should replace with jsql.jenv environment
def dummy_filter(value):
    return value


env = Environment()
env.filters[TARGET_FILTER] = dummy_filter



class Taint_Tracker_Jinja:
    root: nodes.Node
    external_vars : set # all variables that have to be provided from the code/external (not defined inside the jinja2 snippet)
    tainted_vars : set   # this is the set of vars that the scanner should know are tainted from the jinja2 expression

    def __init__(self, template):
        self.root = env.parse(template)
        self.tainted_vars = set()


    def track_taint(self):
        # self.flowing_vars = {}
        self.tainted_vars = set()
        return self._track_taint(self.root, {})


    def _track_taint(self, node, flowing_vars_ref):
        flowing_vars = copy.deepcopy(flowing_vars_ref) # store mapping between variable -> taint source variable
        for field, value in node.iter_fields():
            if isinstance(value, list): # list of values -> need to loop through
                for item in value:
                    if isinstance(item, nodes.For):

                        # Take `{% for a, b in x.items() %}`: `a,b` are looping_vars and `x` is the looped_var 
                        looping_vars = self.extract_names(item.target) # there can be multiple variables to loop through like {% for a,b,c in x %}
                        looped_var = self.extract_names(item.iter)
                        if len(looped_var) > 1:
                            print("THIS SHOULD NOT BE PRINTED")
                            # this code block should not be triggered because we expect only 1 variable to be iterated through
                        looped_var = looped_var.pop()

                        for lv in looping_vars:
                            # self.flowing_vars store mapping between variable -> taint source variable
                            flowing_vars[lv] = flowing_vars.get(looped_var, looped_var)

                        self._track_taint(item, flowing_vars)
                        # Now that we are out of the for-loop context, the looping_vars are no longer defined
                        for lv in looping_vars:
                            del flowing_vars[lv]
                    elif isinstance(item, nodes.Filter) and item.name == TARGET_FILTER:
                        variable_names = self.extract_names(item.node)
                        for var in variable_names:
                            source_var = var
                            if var in flowing_vars:
                                source_var = flowing_vars[var]
                            # elif var in self.external_vars:
                            #     pass
                            else:
                                pass
                                # print("SHOULD NOT BE PRINTED - DID NOT FIND FLOW FOR", var)
                                # we expect that `var` comes from some taint source
                                # this code block indicates that a taint source was not found, so this var's definition was not loaded well into this script
                            self.tainted_vars.add(source_var)
                    elif isinstance(item, nodes.Node):
                        self._track_taint(item, flowing_vars)
            elif isinstance(value, nodes.Call):
                print(value)
                self._track_taint(value, flowing_vars)
            elif isinstance(value, nodes.Node):
                self._track_taint(value, flowing_vars)
        return self.tainted_vars


    # extract list of all variables from node (does not matter if they are loaded or stored variables)
    def extract_names(self, node):
        tracking_list = set()
        return self._extract_names(node, tracking_list)

    
    def _extract_names(self, node, tracking_list):
        if isinstance(node, nodes.Call):
            for n in node.args:
                self._extract_names(n, tracking_list)
            return tracking_list
        if isinstance(node, nodes.Name):
            tracking_list.add(node.name)

        for field, value in node.iter_fields():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, nodes.Call):
                        self._extract_names(item.args, tracking_list)
                    elif isinstance(item, nodes.Node):
                        self._extract_names(item, tracking_list)
            elif isinstance(value, nodes.Call):
                self._extract_names(value.args, tracking_list)
            elif isinstance(value, nodes.Node):
                self._extract_names(value, tracking_list)
        return tracking_list
