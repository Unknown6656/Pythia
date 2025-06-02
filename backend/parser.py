from typing import Any
import pyparsing as pp

from common import toint, unix_to_ISO


# 
# identifier          := /[a-z_]\w*/
# 
# number              := /-?[0-9]+/
#                      | /-?0b[01]+/
#                      | /-?0x[0-9a-f]+/
# 
# type_name_userdef   := identifier
# 
# type_name_builtin   := 'bool'
#                      | 'int8'
#                      | 'uint8'
#                      | 'int16'
#                      | 'uint16'
#                      | 'int32'
#                      | 'uint32'
#                      | 'int128'
#                      | 'uint128'
#                      | 'float16'
#                      | 'float32'
#                      | 'float64'
#                      | 'float128'
#                      | 'uuid'
#                      | 'time32'
#                      | 'char8'
#                      | 'char16'
#                      | 'char32'
#                      | 'str'
#                      | 'cstr'
#                     ...
# 
# type_name           := type_name_userdef
#                      | type_name_builtin
# 
# type_definition     := 'struct' type_name_userdef type_body
#                      | 'union' type_name_userdef type_body
# 
# type_body           := '{' type_fields '}' ';'
# 
# type_fields         := [type_fields] type_field
# 
# type_field          := identifier ':' type_identifier ';'
# 
# type_identifier     := type_name
#                      | type_identifier '[' array_size ']'
#                      | type_identifier '*'
# 
# array_dimension     := <empty>
#                      | number
#                      | type_name_userdef
# 
# array_size          := array_dimension
#                      | array_size ',' array_dimension
# 


class LayoutParser():
    def __init__(self : 'LayoutParser') -> None:
        number = pp.Regex(r'-?(\d+|0b[01]+|0x[0-9a-fA-F]+)')

        symbol_dot = pp.Suppress('.')
        symbol_comma = pp.Suppress(',')
        symbol_pointer = pp.Word('*', exact = 1)
        symbol_colon = pp.Suppress(':')
        symbol_semicolon = pp.Suppress(';')
        symbol_leftparen = pp.Suppress('(')
        symbol_rightparen = pp.Suppress(')')
        symbol_leftbrace = pp.Suppress('{')
        symbol_rightbrace = pp.Suppress('}')
        symbol_leftbracket = pp.Suppress('[')
        symbol_rightbracket = pp.Suppress(']')

        keyword_struct = pp.Keyword('struct')
        keyword_union = pp.Keyword('union')
        keyword_builtin = pp.Regex(r'(bool|(u?int|float)(16|32|64|128)|u?int8|uuid|time32|[cuw]?str|char(8|16|32)?)')

        token_identifier = pp.Word(pp.alphas + '_', pp.alphanums + '_')

        token_typename_userdef: pp.ParserElement = token_identifier('name')
        token_typename = pp.Group(keyword_builtin('builtin') | token_typename_userdef('userdef'))

        token_qualified_typename = pp.DelimitedList(token_typename_userdef, symbol_dot)

        token_type_identifier = pp.Forward()

        token_type_member = pp.Group(
            token_identifier('name') +
            symbol_colon +
            token_type_identifier('type') +
            symbol_semicolon
        )

        token_type_members = pp.ZeroOrMore(token_type_member)

        token_type_body = pp.Group(symbol_leftbrace + token_type_members('members') + symbol_rightbrace)

        token_type_definition = pp.Group(
            (keyword_struct | keyword_union)('type') +
            token_typename_userdef('name') +
            token_type_body('body') +
            symbol_semicolon
        )

        token_inline_type_definition = pp.Group(
            symbol_leftparen +
            (keyword_struct | keyword_union)('type') +
            token_type_body('body') +
            symbol_rightparen
        )

        token_array_dimension = pp.Group(number('fixed') | token_qualified_typename('dynamic'))

        token_array_size = pp.Group(
            symbol_leftbracket +
            pp.Optional(pp.DelimitedList(token_array_dimension, symbol_comma)('size')) +
            symbol_rightbracket
        )

        token_type_suffix = pp.ZeroOrMore(pp.Group(symbol_pointer('pointer') | token_array_size('array')))

        token_type_identifier <<= pp.Group(
            token_inline_type_definition('inline') |
            (token_typename('base') + token_type_suffix('suffix'))
        )

        self.parser: pp.ParserElement = token_type_definition.ignore_whitespace()
        # self.parser.set_debug(True, True)


    def __call__(self: 'LayoutParser', string : str) -> list[dict[str, Any]]:
        raw: pp.ParseResults = self.parser.parseString(string)
        parsed : list[dict[str, Any]] = []


        def struct_converter(type : str, name : str | None, members : pp.ParseResults) -> dict[str, Any]:
            return {
                '$type': type,
                'name': name,
                'body': {
                    '$type': 'body',
                    'members': [
                        {
                            '$type': 'member',
                            'name': member.name,
                            'type': type_converter(member.type),
                        } for member in members
                    ]
                }
            }

        def type_converter(item : pp.ParseResults) -> dict[str, Any]:
            if 'builtin' in item:
                return {
                    '$type': 'type',
                    'builtin': True,
                    'name': item.builtin,
                }
            elif 'userdef' in item:
                return {
                    '$type': 'type',
                    'builtin': False,
                    'name': item.userdef,
                }
            elif 'inline' in item:
                inline: pp.ParseResults = item.inline

                if 'type' in inline and 'body' in inline:
                    return struct_converter(inline.type, None, inline.body.members)
                else:
                    return {
                        '$type': 'unknown',
                        '$raw': inline.dump()
                    }
            elif 'suffix' in item and 'base' in item:
                result: dict[str, Any] = type_converter(item.base)

                for suffix in item.suffix:
                    if 'array' in suffix:
                        if 'size' in suffix.array:
                            for raw_size in suffix.array.size:
                                size: tuple[Any, str] = None, 'dynamic'

                                if 'fixed' in raw_size:
                                    size = int(raw_size.fixed), 'fixed'
                                elif 'dynamic' in raw_size:
                                    size = {
                                        '$type': 'reference',
                                        'name': [token for token in raw_size.dynamic]
                                    }, 'reference'

                                result = {
                                    '$type': 'array',
                                    '$size': size[1],
                                    'base': result,
                                    'size': size[0],
                                }
                        else:
                            result = {
                                '$type': 'array',
                                '$size': 'dynamic',
                                'base': result,
                                'size': None
                            }
                    elif 'pointer' in suffix:
                        result = {
                            '$type': 'pointer',
                            'base': result
                        }
                    else:
                        result = {
                            '$type': 'unknown',
                            '$raw': suffix.dump(),
                            'base': result,
                        }

                return result
            elif 'type' in item and 'body' in item:
                return struct_converter(item.type, item.name if 'name' in item else None, item.body.members)
            else:
                return {
                    '$type': 'unknown',
                    '$raw': item.dump()
                }

        for item in raw:
            parsed.append(type_converter(item))

        return parsed

