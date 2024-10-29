from test_util import test

test("""
select * from x where
{% for x in b %}
{% for j in x %}
a = {{ j | dangerous_filter }} {{ comma if not loop.last }}
{{ j | dangerous_filter | dangerous_filter }}
{% endfor %}
{% endfor %}
{{ e }}
""", set(["b"]))
# set(["b"]) is the expected output of the taint tracker

test("""
select * from x where
{% for x in b %}
{% set a = x %}
{% for j in x %}
a = {{ j | aaa }} {{ comma if not loop.last }}
{{ j | aaa | aaa }}
{% endfor %}
{% endfor %}
{{ e }}
""", set(["b"]))



test("""
        SELECT {{col_name}} FROM {{table_name | dangerous_filter}}
        WHERE {{col_name}} = :value
""", set(["table_name"]))


test("""
        SELECT {{col_name | dangerous_filter}} FROM {{table_name | dangerous_filter}}
        WHERE {{col_name | dangerous_filter}} = :value
""", set(["table_name", "col_name"]))