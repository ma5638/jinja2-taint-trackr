# Introduction

This is a project that has the sole purpose of tracking taint throughout a jinja2 template to a given sink.

Take the following jinja2 template:

What is the source? 
-> Assumed to be `Any undefined variable`

What is the sink?
-> Variables used inside a `dangerous_filter` e.g. `{{ x | dangerous_filter}}`


Example: 
```py
# Case 1:
"{{a | dangerous_filter}}"
# Above case, the source is `a`, which is in the sink, so the function `track_taint` will return `a`
# Function will return [`a`]

# Case 2:
"""
{% for b in x %}
{{b | dangerous_filter}}
{% endfor %}
"""
# Above case, the source is `x`, because the variable `b` (in the sink) is defined by `x`
# Function will return [`x`]
```