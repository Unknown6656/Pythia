import sys
import os
import re


pattern = re.compile(r'\$\{\s*(?P<var>\w+)(\s*:-?(?P<def>[^\}]+))?\s*\}')
input : str = ''

if len(sys.argv) < 2:
    input = sys.stdin.read()
else:
    with open(sys.argv[1], 'r') as file:
        input = file.read()

def replace_variable(match) -> str:
    var_name : str = match.group('var')
    default_value : str | None = match.group('def')

    if var_name in os.environ:
        return os.environ[var_name]
    elif default_value is not None:
        return default_value
    else:
        return ''

output: str = pattern.sub(replace_variable, input)

print(output, end='')
