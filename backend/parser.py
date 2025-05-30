import pyparsing as pp
import re


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
        symbol_asterisk = pp.Suppress('*')
        symbol_colon = pp.Suppress(':')
        symbol_semicolon = pp.Suppress(';')
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

        token_qualified_typename = pp.Group(
            keyword_builtin('builtin') |
            pp.DelimitedList(token_typename_userdef, symbol_dot, min = 1)('userdef')
        )

        token_type_identifier = pp.Forward()

        token_type_field = pp.Group(
            token_identifier('name') + symbol_colon + token_type_identifier('type') + symbol_semicolon
            # token_type_identifier('type') + token_identifier('name') + symbol_semicolon
        )

        token_type_fields = pp.ZeroOrMore(token_type_field)

        token_type_body = pp.Group(symbol_leftbrace + token_type_fields('fields') + symbol_rightbrace)

        token_type_definition = pp.Group(
            (keyword_struct | keyword_union)('base') +
            token_typename_userdef('name') +
            token_type_body('body') +
            symbol_semicolon
        )

        token_inline_type_definition = pp.Group((keyword_struct | keyword_union)('base') + token_type_body('body'))

        token_array_dimension = pp.Group(number('fixed') | token_qualified_typename('dynamic'))

        token_array_size = pp.DelimitedList(token_array_dimension, symbol_comma)
        # token_array_size.set_parse_action(lambda t: t.as_list())

        token_composite_type = pp.Group(
            token_typename('base') +
            pp.Optional(
                symbol_asterisk('pointer') |
                (symbol_leftbracket + pp.Optional(token_array_size)('size') + symbol_rightbracket)('array')
            )
        )

        token_type_identifier <<= token_inline_type_definition('inline') | token_composite_type('composite')

        self.parser: pp.ParserElement = token_type_definition.ignore_whitespace()
        self.parser.set_debug(True, True)


    def __call__(self: 'LayoutParser', string : str) -> pp.ParseResults:
        return self.parser.parseString(string)
