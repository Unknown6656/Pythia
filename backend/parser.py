from dataclasses import dataclass
from enum import Enum
from typing import Any
import base64
import uuid
import ipaddress
import datetime

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
        keyword_builtin = pp.Regex(r'(bool|(u?int|float)(16|32|64|128)|u?int8|uuid|time32|[cuw]?str|char(8|16|32)?|[uw]?char)')

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
            # symbol_leftparen +
            (keyword_struct | keyword_union)('type') +
            token_type_body('body')
            # + symbol_rightparen
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


    def __call__(self: 'LayoutParser', string : str) -> dict[str, Any]:
        raw: pp.ParseResults = self.parser.parseString(string, parse_all = True)

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

        return type_converter(raw[0])


class Endianness(Enum):
    LITTLE = 'little'
    BIG = 'big'

    def __str__(self : 'Endianness') -> str:
        return self.value


@dataclass
class InterpretedLayout:
    def __init__(
            self : 'InterpretedLayout',
            raw: bytes,
            name: str | None, 
            data: str | None = None,
            members: list['InterpretedLayout'] = []
    ) -> None:
        self.raw: bytes = raw
        self.name: str | None = name
        self.size: int = len(raw)
        self.data: str | None = data
        self.members: list['InterpretedLayout'] = members

    def to_dict(self : 'InterpretedLayout') -> dict[str, Any]:
        return {
            'raw': base64.b64encode(self.raw).decode('utf-8'),
            'name': self.name,
            'size': self.size,
            'data': self.data,
            'members': [member.to_dict() for member in self.members]
        }


@dataclass
class InterpretationContext:
    def __init__(
            self : 'InterpretationContext',
            global_data : bytes,
            data : bytes,
            offset : int,
            name : str | None,
            qualified_name: str | None
    ) -> None:
        self.global_data = global_data
        self.qualified_name = qualified_name
        self.data = data[offset:]
        self.name = name

    def __str__(self : 'InterpretationContext') -> str:
        return f'"{self.qualified_name or self.name}" @ {self.data.hex()[:16]}... ({self.data})'

    @staticmethod
    def global_context(data : bytes, name : str | None) -> 'InterpretationContext':
        return InterpretationContext(data, data, 0, name, name)

    def local(self : 'InterpretationContext', offset : int, name : str | None = None) -> 'InterpretationContext':
        return InterpretationContext(
            self.global_data,
            self.data,
            offset,
            name,
            f'{self.qualified_name}.{name}' if len(self.qualified_name or '') and len(name or '') else (name or self.qualified_name)
        )

    def result(self : 'InterpretationContext', size : int, repr : str | None, members : list[InterpretedLayout]) -> InterpretedLayout:
        return InterpretedLayout(
            raw = self.data[:size],
            name = self.name,
            data = repr,
            members = members
        )


class LayoutInterpreter():
    def __init__(self : 'LayoutInterpreter',
                 layout : dict[str, Any],
                 endianness : Endianness,
                 pointer_size : int = 8
    ) -> None:
        self.layout: dict[str, Any] = layout
        self.default_endianness: Endianness = endianness
        self.pointer_size: int = pointer_size

    @staticmethod
    def interpret(data : bytes, typename : str) -> tuple[str, int]:
        typename = typename.lower()
        repr: str = f'(TODO: {typename})'

        if typename == 'int8':
            data = data[:1]
            repr = toint(data, 8, True)
        elif typename == 'uint8':
            data = data[:1]
            repr = toint(data, 8, False)
        elif typename == 'int16':
            data = data[:2]
            repr = toint(data, 16, True)
        elif typename == 'uint16':
            data = data[:2]
            repr = toint(data, 16, False)
        elif typename == 'int32':
            data = data[:4]
            repr = toint(data, 32, True)
        elif typename == 'uint32':
            data = data[:4]
            repr = toint(data, 32, False)
        elif typename == 'int64':
            data = data[:8]
            repr = toint(data, 64, True)
        elif typename == 'uint64':
            data = data[:8]
            repr = toint(data, 64, False)
        elif typename == 'int128':
            data = data[:16]
            repr = toint(data, 128, True)
        elif typename == 'uint128':
            data = data[:16]
            repr = toint(data, 128, False)
        elif typename == 'float16':
            data = data[:2]
            repr = '(TODO: float16)'
        elif typename == 'float32':
            data = data[:4]
            repr = str(float.fromhex(data.hex()))
        elif typename == 'float64':
            data = data[:8]
            repr = str(float.fromhex(data.hex()))
        elif typename == 'float128':
            data = data[:16]
            repr = '(TODO: float128)'
        elif typename == 'time32':
            data = data[:4]
            repr = unix_to_ISO(int.from_bytes(data, 'little'))
        elif typename == 'uuid':
            data = data[:16]
            repr = str(uuid.UUID(bytes = data))
        elif typename == 'ipv4':
            data = data[:4]
            repr = f'{data[0]}.{data[1]}.{data[2]}.{data[3]}'
        elif typename == 'ipv6':
            data = data[:16]
            repr = f'[{ipaddress.ip_address(data).compressed}]'
        elif typename == 'char8' or typename == 'char':
            data = data[:1]
            repr = data.decode('ascii', 'ignore')
        elif typename == 'char16' or typename == 'wchar':
            data = data[:2]
            repr = data.decode('utf-16', 'ignore')
        elif typename == 'char32': pass # utf-32
        elif typename == 'uchar':
            if data[0] >> 7 == 0b0:
                data = data[:1]
            elif data[0] >> 5 == 0b110:
                data = data[:2]
            elif data[0] >> 4 == 0b1110:
                data = data[:3]
            else:
                data = data[:4]

            repr = data.decode('utf-8', 'ignore')
        elif typename == 'str' or typename == 'cstr': pass # zero-terminated string
        elif typename == 'wstr': pass # zero-terminated utf-16 string
        elif typename == 'ustr': pass # zero-terminated utf-8 string

        return repr, len(data)

    def _interpret_builtin_type(self : 'LayoutInterpreter', context : InterpretationContext, typename : str) -> InterpretedLayout:
        repr, size = LayoutInterpreter.interpret(context.data, typename)

        return InterpretedLayout(context.data[:size], context.name, repr)

    def _interpret_pointer(self : 'LayoutInterpreter', context : InterpretationContext, type : dict[str, Any]) -> InterpretedLayout:
        print('-------- POINTER',context)

        data: bytes = context.data[:self.pointer_size]
        address: int = 0

        for i in range(self.pointer_size):
            address <<= 8
            address |= data[i] & 0xFF

        subcontext = InterpretationContext(
            context.global_data,
            context.global_data,
            address,
            context.name,
            context.qualified_name
        )
        value: InterpretedLayout = self._interpret_member(subcontext, type)

        return context.result(self.pointer_size, f'0x{address:0{self.pointer_size * 2}x}', [value])

    def _interpret_member(self : 'LayoutInterpreter', context : InterpretationContext, type : dict[str, Any]) -> InterpretedLayout:
        _type: str = type['$type']

        print('-------- MEMBER',context)

        if _type == 'type':
            if type['builtin']:
                return self._interpret_builtin_type(context, type['name'])
            else:
                # Handle user-defined type
                pass
        elif _type == 'pointer':
            return self._interpret_pointer(context, type['base'])
        elif _type == 'array':
            pass
        elif _type == 'struct':
            pass
        elif _type == 'unknown':
            pass

        return context.result(0, None, [])

    def _interpret_union(self : 'LayoutInterpreter', context : InterpretationContext, members : list[dict[str, Any]]) -> InterpretedLayout:
        print('-------- UNION',context,'\n',members)

        interpreted_members: list[InterpretedLayout] = []
        size: int = 0

        for member in members:
            interpreted_member: InterpretedLayout = self._interpret_member(context.local(0, member['name']), member['type'])
            interpreted_members.append(interpreted_member)
            size = max(size, interpreted_member.size)

        return context.result(size, None, interpreted_members)

    def _interpret_struct(self : 'LayoutInterpreter', context : InterpretationContext, members : list[dict[str, Any]]) -> InterpretedLayout:
        print('-------- STRUCT',context,'\n',members)

        interpreted_members: list[InterpretedLayout] = []
        offset = 0

        for member in members:
            interpreted_member: InterpretedLayout = self._interpret_member(context.local(offset, member['name']), member['type'])
            interpreted_members.append(interpreted_member)
            offset += interpreted_member.size

        return context.result(offset, None, interpreted_members)

    def __call__(self: 'LayoutInterpreter', data : bytes) -> InterpretedLayout:
        _type: str = self.layout['$type']
        context: InterpretationContext = InterpretationContext.global_context(data, self.layout.get('name'))

        print('-------- INTERPRET',data,'\n',self.layout)

        if _type == 'struct':
            return self._interpret_struct(context, self.layout['body']['members'])
        elif _type == 'union':
            return self._interpret_union(context, self.layout['body']['members'])

        raise ValueError(f'Unknown layout type: {_type}')
