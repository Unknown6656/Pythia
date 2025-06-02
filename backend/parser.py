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
        keyword_builtin = pp.Regex(r'((u?int|float|bool)(16|32|64|128)|bool(8|ean)?|u?int8|byte|uuid|time32|(c[uw]?|[uw]c?)?str|char(8|16|32)?|[uw]?char)')

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
            offset : int,
            raw: bytes,
            name: str | None,
            repr: str | None = None,
            data: Any | None = None,
            members: list['InterpretedLayout'] = []
    ) -> None:
        self.raw: bytes = raw
        self.offset: int = offset
        self.name: str | None = name
        self.size: int = len(raw)
        self.repr: str | None = repr
        self.data: Any | None = data
        self.members: list['InterpretedLayout'] = members

    def __str__(self : 'InterpretedLayout') -> str:
        return f'{self.name}@[{self.offset}:{self.offset + self.size}, {self.size}]: "{self.repr}" ({self.data})'

    def to_dict(self : 'InterpretedLayout') -> dict[str, Any]:
        return {
            'raw': base64.b64encode(self.raw).decode('utf-8'),
            'offset': self.offset,
            'name': self.name,
            'size': self.size,
            'repr': self.repr,
            'data': str(self.data) if self.data is not None else None,
            'members': [member.to_dict() for member in self.members],
        }


@dataclass
class InterpretationContext:
    def __init__(
            self : 'InterpretationContext',
            parent : 'InterpretationContext | None',
            offset : int,
            data : bytes,
            name : str | None
    ) -> None:
        self.parent: InterpretationContext | None = parent
        self.data: bytes = data[offset:]
        self.name: str | None = name
        self.global_name: str | None = f'{parent.global_name}.{name}' if parent and name else (parent.global_name or name if parent else name)
        self.global_data: bytes = parent.global_data if parent else data
        self.global_offset: int = parent.global_offset + offset if parent else offset
        self.scope : dict[str | None, Any] = { **parent.scope } if parent else { }

    def __str__(self : 'InterpretationContext') -> str:
        return f'{self.global_name} @ {self.global_offset:08x}: {self.data}'

    @staticmethod
    def global_context(data : bytes, name : str | None) -> 'InterpretationContext':
        return InterpretationContext(None, 0, data, name)

    def local(self : 'InterpretationContext', offset : int, name : str | None = None) -> 'InterpretationContext':
        return InterpretationContext(self, offset, self.data, name)

    def result(self : 'InterpretationContext', size : int, repr : str | None, data : Any | None, members : list[InterpretedLayout]) -> InterpretedLayout:
        return InterpretedLayout(
            offset = self.global_offset,
            raw = self.data[:size],
            name = self.name,
            repr = repr,
            data = data,
            members = members
        )

    def resolve(self : 'InterpretationContext', member : str | list[str]) -> InterpretedLayout | None:
        member : str = member if isinstance(member, str) else '.'.join(member)

        if member in self.scope:
            return self.scope[member]
        elif f'{self.global_name}.{member}' in self.scope:
            return self.scope[f'{self.global_name}.{member}']
        elif self.parent is not None:
            return self.parent.resolve(member)
        else:
            return None


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
    def interpret_data(raw : bytes, typename : str) -> tuple[str, Any | None, int]:
        typename = typename.lower()
        repr: str | None = None
        data: Any | None = None

        if typename in ['bool', 'boolean', 'bool8']:
            raw = raw[:1]
            repr, data = ('true', True) if raw[0] != 0 else ('false', False)
        elif typename == 'bool16':
            raw = raw[:2]
            repr, data = ('true', True) if toint(raw, 16, False) != 0 else ('false', False)
        elif typename == 'bool32':
            raw = raw[:4]
            repr, data = ('true', True) if toint(raw, 32, False) != 0 else ('false', False)
        elif typename == 'bool64':
            raw = raw[:8]
            repr, data = ('true', True) if toint(raw, 64, False) != 0 else ('false', False)
        elif typename == 'bool128':
            raw = raw[:16]
            repr, data = ('true', True) if toint(raw, 128, False) != 0 else ('false', False)
        elif typename == 'int8':
            raw = raw[:1]
            repr, data = toint(raw, 8, True)
        elif typename == 'byte':
            raw = raw[:1]
            data = raw[0]
            repr = f'0x{raw[0]:02x}'
        elif typename == 'uint8':
            raw = raw[:1]
            repr, data = toint(raw, 8, False)
        elif typename == 'int16':
            raw = raw[:2]
            repr, data = toint(raw, 16, True)
        elif typename == 'uint16':
            raw = raw[:2]
            repr, data = toint(raw, 16, False)
        elif typename == 'int32':
            raw = raw[:4]
            repr, data = toint(raw, 32, True)
        elif typename == 'uint32':
            raw = raw[:4]
            repr, data = toint(raw, 32, False)
        elif typename == 'int64':
            raw = raw[:8]
            repr, data = toint(raw, 64, True)
        elif typename == 'uint64':
            raw = raw[:8]
            repr, data = toint(raw, 64, False)
        elif typename == 'int128':
            raw = raw[:16]
            repr, data = toint(raw, 128, True)
        elif typename == 'uint128':
            raw = raw[:16]
            repr, data = toint(raw, 128, False)
        elif typename == 'float16':
            raw = raw[:2] # TODO
        elif typename == 'float32':
            raw = raw[:4]
            data = float.fromhex(raw.hex())
        elif typename == 'float64':
            raw = raw[:8]
            data = float.fromhex(raw.hex())
        elif typename == 'float128':
            raw = raw[:16] # TODO
        elif typename == 'time32':
            raw = raw[:4]
            repr, data = unix_to_ISO(int.from_bytes(raw, 'little'))
        elif typename == 'uuid':
            raw = raw[:16]
            data = uuid.UUID(bytes = raw)
        elif typename == 'ipv4':
            raw = raw[:4]
            data = ipaddress.ip_address(raw)
            repr = f'{raw[0]}.{raw[1]}.{raw[2]}.{raw[3]}'
        elif typename == 'ipv6':
            raw = raw[:16]
            data = ipaddress.ip_address(raw)
            repr = f'[{data.compressed}]'
        elif typename in ['char8', 'char']:
            raw = raw[:1]
            repr = data = raw.decode('ascii', 'ignore')
        elif typename in ['char16', 'wchar']:
            raw = raw[:2]
            repr = data = raw.decode('utf-16', 'ignore')
        elif typename == 'char32':
            pass # TODO: utf-32 char
        elif typename == 'uchar':
            if raw[0] >> 7 == 0b0:
                raw = raw[:1]
            elif raw[0] >> 5 == 0b110:
                raw = raw[:2]
            elif raw[0] >> 4 == 0b1110:
                raw = raw[:3]
            else:
                raw = raw[:4]

            data = repr = raw.decode('utf-8', 'ignore')
        elif typename in ['str', 'cstr']:
            pass # TODO: zero-terminated ascii string
        elif typename in ['wstr', 'cwstr', 'wcstr']:
            pass # TODO: zero-terminated utf-16 string
        elif typename in ['ustr', 'custr', 'ucstr']:
            pass # TODO: zero-terminated utf-8 string
        # TODO: length-prefixed strings (ascii, utf-16, utf-8)

        if repr is None:
            repr = f'(TODO: {typename})' if data is None else str(data)

        return repr, data, len(raw)

    def _interpret_builtin_type(self : 'LayoutInterpreter', context : InterpretationContext, typename : str) -> InterpretedLayout:
        repr, data, size = LayoutInterpreter.interpret_data(context.data, typename)

        return InterpretedLayout(
            context.global_offset,
            context.data[:size],
            context.name,
            repr,
            data,
            []
        )

    def _interpret_pointer(self : 'LayoutInterpreter', context : InterpretationContext, base : dict[str, Any]) -> InterpretedLayout:
        data: bytes = context.data[:self.pointer_size]
        address: int = 0

        for i in range(self.pointer_size):
            address <<= 8
            address |= data[i] & 0xFF

        subcontext = InterpretationContext(None, address, context.global_data, None)
        value: InterpretedLayout = self._interpret_member(subcontext, base)

        return context.result(self.pointer_size, f'[0x{address:0{self.pointer_size * 2}x}]', value.data, [value])

    def _interpret_array(self : 'LayoutInterpreter', context : InterpretationContext, base : dict[str, Any], size : dict[str, Any] | int | None, sizetype : str) -> InterpretedLayout:
        elements : list[InterpretedLayout] = []
        intsize : int = 0
        offset : int = 0

        if sizetype == 'fixed':
            intsize = max(0, size if isinstance(size, int) else 0)
        elif sizetype == 'reference':
            reference : list[str] = size['name']

            if (member := context.resolve(reference)) is not None:
                intsize = int(member.data or 0)
        elif sizetype == 'dynamic':
            raise NotImplementedError(f'Dynamic arrays are not supported yet: {context}')

        for i in range(intsize):
            subcontext: InterpretationContext = context.local(offset, None)
            value: InterpretedLayout = self._interpret_member(subcontext, base)
            offset += value.size
            elements.append(value)

        return context.result(offset, f'{len(elements)} Items', [e.data for e in elements], elements)

    def _interpret_member(self : 'LayoutInterpreter', context : InterpretationContext, type : dict[str, Any]) -> InterpretedLayout:
        _type: str = type['$type']

        if _type == 'type':
            if type['builtin']:
                return self._interpret_builtin_type(context, type['name'])
            else:
                # Handle user-defined type
                pass
        elif _type == 'pointer':
            return self._interpret_pointer(context, type['base'])
        elif _type == 'array':
            return self._interpret_array(context, type['base'], type['size'], type['$size'])
        elif _type == 'struct':
            return self._interpret_struct(context, type['body']['members'])
        elif _type == 'union':
            return self._interpret_union(context, type['body']['members'])

        return context.result(0, f'(unknown: {type})', None, [])

    def _interpret_union(self : 'LayoutInterpreter', context : InterpretationContext, members : list[dict[str, Any]]) -> InterpretedLayout:
        interpreted_members: list[InterpretedLayout] = []
        size: int = 0

        for member in members:
            interpreted_member: InterpretedLayout = self._interpret_member(context.local(0, member['name']), member['type'])
            interpreted_members.append(interpreted_member)
            size = max(size, interpreted_member.size)
            context.scope[f'{context.global_name}.{interpreted_member.name}'] = interpreted_member

        return context.result(size, 'union { ... }', {m.name:m.data for m in interpreted_members}, interpreted_members)

    def _interpret_struct(self : 'LayoutInterpreter', context : InterpretationContext, members : list[dict[str, Any]]) -> InterpretedLayout:
        interpreted_members: list[InterpretedLayout] = []
        offset = 0

        for member in members:
            interpreted_member: InterpretedLayout = self._interpret_member(context.local(offset, member['name']), member['type'])
            interpreted_members.append(interpreted_member)
            offset += interpreted_member.size
            context.scope[f'{context.global_name}.{interpreted_member.name}'] = interpreted_member

        return context.result(offset, 'struct { ... }', {m.name:m.data for m in interpreted_members}, interpreted_members)

    def __call__(self: 'LayoutInterpreter', data : bytes) -> InterpretedLayout:
        _type: str = self.layout['$type']
        context: InterpretationContext = InterpretationContext.global_context(data, self.layout.get('name'))

        if _type == 'struct':
            return self._interpret_struct(context, self.layout['body']['members'])
        elif _type == 'union':
            return self._interpret_union(context, self.layout['body']['members'])
        else:
            raise ValueError(f'Unknown layout type: {_type}')


