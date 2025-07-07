from dataclasses import dataclass
from enum import Enum
from typing import Any

import base64
import uuid
import json
import re

import ipaddress
import pyparsing as pp

from common import toint, unix_to_ISO, timeout



def _dump(obj: pp.ParseResults | list | dict | Any | None, indent: int = 1) -> str:
    spacing: str = '¦   ' * (indent)
    objlist: list = []
    objdict: dict = {}
    result: str = f'({type(obj).__name__}) '

    if obj is None:
        return 'None'
    elif isinstance(obj, pp.ParseResults):
        objlist = obj._toklist
        objdict = obj._tokdict
    elif isinstance(obj, pp.results._ParseResultsWithOffset):
        return _dump(obj.tup[0], indent)
    elif isinstance(obj, list):
        objlist = obj
    elif isinstance(obj, dict):
        objdict = obj

    if len(objdict) > 0:
        result += ''.join(
            f'\n{spacing}- {key}: {_dump(value, indent + 1)}'
            for key, value in objdict.items()
        )
    elif len(objlist) > 0:
        result += ''.join(
            f'\n{spacing}[{index}] {_dump(item, indent + 1)}'
            for index, item in enumerate(objlist)
        )
    else:
        result += str(obj)

    return result



# Grammar: see README.md
class LayoutParser():
    BULTIIN_TYPES: str = r'((u?int|float|bool)(8|16|32|64|128)|bool|byte|uuid|ipv?[46]|mac|time32|([cl][wu]|[wu][cl]|[clwu])?str|char(8|16|32)?|[uw]?char)'
    SIZE_MODIFIERS: str = r'(8|16|32|64)bit|x(16|32|64|86)'
    BYTE_ORDER_MODIFIERS: str = r'[lm]sb|[lb]e'

    def __init__(self: 'LayoutParser') -> None:
        number = pp.Regex(r'((?P<dec>[0-9_]+)|(?P<bin>0b[01_]+)|(?P<hex>0x[0-9a-f_]+|[0-9a-f_]+h))', re.I)

        comment: pp.ParserElement = pp.cpp_style_comment | pp.python_style_comment

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
        keyword_skip = pp.Keyword('skip')
        keyword_modifier_byteorder = pp.Regex(LayoutParser.BYTE_ORDER_MODIFIERS, re.I)
        keyword_modifier_size = pp.Regex(LayoutParser.SIZE_MODIFIERS, re.I)
        keyword_builtin = pp.Regex(LayoutParser.BULTIIN_TYPES)

        token_identifier = pp.Word(pp.alphas + '_', pp.alphanums + '_')

        token_typename_userdef: pp.ParserElement = token_identifier('name')
        token_typename = pp.Group(keyword_builtin('builtin') | token_typename_userdef('userdef'))

        token_qualified_typename = pp.DelimitedList(token_typename_userdef, symbol_dot)

        token_type_identifier = pp.Forward()

        token_type_member = pp.Group(
            pp.Optional(keyword_skip)('skip') +
            token_identifier('name') +
            symbol_colon +
            token_type_identifier('type') +
            symbol_semicolon
        )

        token_type_members = pp.ZeroOrMore(token_type_member)

        token_type_body = pp.Group(symbol_leftbrace + token_type_members('members') + symbol_rightbrace)

        token_type_definition: pp.ParserElement = pp.Group(
            pp.Optional(keyword_skip)('skip') +
            (keyword_struct | keyword_union)('type') +
            token_typename_userdef('name') +
            token_type_body('body') +
            symbol_semicolon
        ).ignore_whitespace()

        token_inline_type_definition = pp.Group(
            (keyword_struct | keyword_union)('type') +
            token_type_body('body')
        )

        token_array_dimension = pp.Group(number('fixed') | token_qualified_typename('dynamic'))

        token_array_size = pp.Group(
            symbol_leftbracket +
            pp.Optional(pp.DelimitedList(token_array_dimension, symbol_comma)('size')) +
            symbol_rightbracket
        )

        token_type_suffix = pp.ZeroOrMore(pp.Group(symbol_pointer('pointer') | token_array_size('array')))

        token_type_identifier <<= pp.Group(
            (token_inline_type_definition('inline') | token_typename('base')) +
            token_type_suffix('suffix')
        )

        code_file = pp.ZeroOrMore(token_type_definition)

        self.parser: pp.ParserElement = code_file('definitions').ignore_whitespace()
        self.parser.ignore(comment)
        # self.parser.set_debug(True, True)

    def __call__(self: 'LayoutParser', string: str) -> list[dict[str, Any]]:
        raw: pp.ParseResults = self.parser.parseString(string, parse_all = True)

        def struct_converter(type: str, name: str | None, members: pp.ParseResults, skip: bool) -> dict[str, Any]:
            print(_dump(members))
            return {
                '$type': type,
                '$skip': skip,
                'name': name,
                'body': {
                    '$type': 'body',
                    'members': [
                        {
                            '$type': 'member',
                            '$skip': skip | ('skip' in member),
                            'name': member.name,
                            'type': type_converter(member.type, skip),
                        } for member in members
                    ]
                }
            }

        def type_converter(item: pp.ParseResults, skip: bool) -> dict[str, Any]:
            if 'builtin' in item:
                return {
                    '$type': 'type',
                    '$skip': skip,
                    'builtin': True,
                    'name': item.builtin,
                }
            elif 'userdef' in item:
                return {
                    '$type': 'type',
                    '$skip': skip,
                    'builtin': False,
                    'name': item.userdef,
                }
            elif 'inline' in item:
                inline: pp.ParseResults = item.inline # type: ignore

                if 'type' in inline and 'body' in inline:
                    return struct_converter(inline.type, None, inline.body.members, skip) # type: ignore
                else:
                    return {
                        '$type': 'unknown',
                        '$skip': skip,
                        '$raw': _dump(inline),
                    }
            elif 'suffix' in item and 'base' in item:
                result: dict[str, Any] = type_converter(item.base, skip) # type: ignore

                for suffix in item.suffix:
                    if 'array' in suffix:
                        if 'size' in suffix.array: # type: ignore
                            for raw_size in suffix.array.size: # type: ignore
                                size: tuple[Any, str] = None, 'dynamic'

                                if 'fixed' in raw_size:
                                    size = int(raw_size.fixed), 'fixed'
                                elif 'dynamic' in raw_size:
                                    size = {
                                        '$type': 'reference',
                                        '$skip': skip,
                                        'name': [token for token in raw_size.dynamic]
                                    }, 'reference'

                                result = {
                                    '$type': 'array',
                                    '$skip': skip,
                                    '$size': size[1],
                                    'base': result,
                                    'size': size[0],
                                }
                        else:
                            result = {
                                '$type': 'array',
                                '$skip': skip,
                                '$size': 'dynamic',
                                'base': result,
                                'size': None
                            }
                    elif 'pointer' in suffix:
                        result = {
                            '$type': 'pointer',
                            '$skip': skip,
                            'base': result
                        }
                    else:
                        result = {
                            '$type': 'unknown',
                            '$skip': skip,
                            '$raw': _dump(suffix),
                            'base': result,
                        }

                return result
            elif 'type' in item and 'body' in item:
                return struct_converter(
                    item.type, # type: ignore
                    item.name if 'name' in item else None, # type: ignore
                    item.body.members, # type: ignore
                    'skip' in item
                )
            else:
                return {
                    '$type': 'unknown',
                    '$skip': skip,
                    '$raw': _dump(item),
                }

        return [
            type_converter(p, False)
            for p in raw.get('definitions', []) # type: ignore
        ]


class Endianness(Enum):
    LITTLE = 'little'
    BIG = 'big'

    def __str__(self: 'Endianness') -> str:
        return self.value


@dataclass
class InterpreterError:
    def __init__(self: 'InterpreterError', message: str, scope: str) -> None:
        self.message: str = message
        self.scope: str = scope
        # TODO: line, char, etc.

    def to_dict(self: 'InterpreterError') -> dict[str, Any]:
        return {
            'message': self.message,
            'scope': self.scope,
            # TODO: line, char, etc.
        }


@dataclass
class InterpretedLayout:
    def __init__(
            self: 'InterpretedLayout',
            skip: bool,
            offset: int,
            raw: bytes,
            scope: str | None,
            name: str,
            repr: str | None = None,
            data: Any | None = None,
            members: list['InterpretedLayout'] = [],
            errors: list[InterpreterError] = []
    ) -> None:
        self.raw: bytes = raw
        self.skip: bool = skip
        self.offset: int = offset
        self.name: str = name
        self.size: int = len(raw)
        self.repr: str | None = repr
        self.data: Any | None = data
        self.path: str = f'{scope}.{self.name}' if scope else self.name or '/'
        self.members: list['InterpretedLayout'] = members
        self.errors: list[InterpreterError] = errors

    @staticmethod
    def skipped(scope: str | None, name: str) -> 'InterpretedLayout':
        return InterpretedLayout(True, 0, b'', scope, name, '(skipped)', None, [], [])

    def add_error(self: 'InterpretedLayout', message: str) -> None:
        self.errors.append(InterpreterError(message, self.path))

    def __str__(self: 'InterpretedLayout') -> str:
        return f'{'⚠️ ' if len(self.errors) > 0 else ''}{self.name}@[{self.offset}:{self.offset + self.size}, {self.size}]: "{self.repr}" ({self.data})'

    def to_dict(self: 'InterpretedLayout') -> dict[str, Any]:
        return {
            'raw': base64.b64encode(self.raw).decode('utf-8'),
            'skip': self.skip,
            'offset': self.offset,
            'path': self.path,
            'name': self.name,
            'size': self.size,
            'repr': self.repr,
            'data': str(self.data) if self.data else None,
            'members': [member.to_dict() for member in self.members],
            'errors': [error.to_dict() for error in self.errors]
        }


@dataclass
class InterpreterContext:
    def __init__(
            self: 'InterpreterContext',
            parent: 'InterpreterContext | None',
            offset: int,
            data: bytes,
            name: str,
            endianness: Endianness | None,
            pointer_size: int | None,
            skip: bool | None,
    ) -> None:
        self.parent: InterpreterContext | None = parent
        self.data: bytes = data[offset:]
        self.name: str = name
        self.errors: list[InterpreterError] = []
        self.global_name: str = f'{parent.global_name}.{name}' if parent and name else (parent.global_name or name if parent else name)
        self.global_data: bytes = parent.global_data if parent else data
        self.global_offset: int = parent.global_offset + offset if parent else offset
        self.scope: dict[str | None, Any] = { **parent.scope } if parent else { }
        self.endianness: Endianness | None = endianness if endianness else (parent.endianness if parent else None)
        self.pointer_size: int | None = pointer_size if pointer_size else (parent.pointer_size if parent else None)
        self.skip: bool | None = skip if skip is not None else (parent.skip if parent else None)

    def __str__(self: 'InterpreterContext') -> str:
        prefix: str = ''

        if len(self.errors):
            prefix += f'⚠️{len(self.errors)} '

        if self.skip:
            prefix += '(skipped) '

        return f'{prefix}{self.global_name} @ {self.global_offset:08x}: {self.data}'

    @staticmethod
    def global_context(interpreter: 'LayoutInterpreter', data: bytes, name: str, skip: bool | None) -> 'InterpreterContext':
        return InterpreterContext(
            None,
            0,
            data,
            name,
            interpreter.default_endianness,
            interpreter.pointer_size,
            skip
        )

    def add_error(self: 'InterpreterContext', message: str) -> None:
        self.errors.append(InterpreterError(message, self.global_name))

    def local(
            self: 'InterpreterContext',
            offset: int,
            name: str,
            endianness: Endianness | None = None,
            pointer_size: int | None = None,
            skip: bool | None = None
    ) -> 'InterpreterContext':
        return InterpreterContext(self, offset, self.data, name, endianness, pointer_size, skip)

    def result(
            self: 'InterpreterContext',
            size: int,
            repr: str | None,
            data: Any | None,
            members: list[InterpretedLayout]
    ) -> InterpretedLayout:
        member_names: dict[str, int] = {}

        for member in members:
            if member.name:
                member_names[member.name] = 1 + member_names.get(member.name, 0)

        for name in member_names:
            if member_names[name] > 1:
                self.add_error(f'Duplicate member definition "{name}" in "{self.global_name}".')

        if self.skip:
            return InterpretedLayout.skipped(self.global_name, self.name)
        else:
            return InterpretedLayout(
                False,
                self.global_offset,
                self.data[:size],
                self.global_name,
                self.name,
                repr,
                data,
                members,
                self.errors
            )

    def resolve(self: 'InterpreterContext', member: str | list[str]) -> InterpretedLayout | None:
        member_name: str = member if isinstance(member, str) else '.'.join(member)

        if member_name in self.scope:
            return self.scope[member_name]
        elif f'{self.global_name}.{member_name}' in self.scope:
            return self.scope[f'{self.global_name}.{member_name}']
        elif self.parent:
            return self.parent.resolve(member_name)
        else:
            return None


class GlobalInterpreterResult:
    def __init__(self: 'GlobalInterpreterResult', result: list[InterpretedLayout]) -> None:
        self.errors: list[InterpreterError] = []
        self.data: list[InterpretedLayout] = result

        def collect_errors(layout: InterpretedLayout) -> None:
            self.errors.extend(layout.errors)

            for member in layout.members:
                collect_errors(member)

        for layout in result:
            collect_errors(layout)

        self.success: bool = len(self.errors) == 0

    def to_dict(self: 'GlobalInterpreterResult') -> dict[str, Any]:
        return {
            'success': self.success,
            'data': [data.to_dict() for data in self.data],
            'errors': [error.to_dict() for error in self.errors]
        }


class LayoutInterpreter():
    def __init__(self: 'LayoutInterpreter',
                 layout: list[dict[str, Any]],
                 endianness: Endianness,
                 pointer_size: int
    ) -> None:
        self.layout: list[dict[str, Any]] = layout
        self.default_endianness: Endianness = endianness
        self.pointer_size: int = pointer_size

    def interpret_data(
            self: 'LayoutInterpreter',
            raw: bytes,
            typename: str,
            endianness: Endianness | None = None,
            pointer_size: int | None = None
    ) -> tuple[str, Any | None, int]:
        endianness = endianness if endianness else self.default_endianness
        pointer_size = pointer_size if pointer_size else self.pointer_size
        typename = typename.lower()
        repr: str | None = None
        data: Any | None = None

        def grab_bytes(size: int) -> bytes:
            padded: bytes = raw.ljust(size, b'\x00') if len(raw) < size else raw
            padded = padded[:size]

            return padded[::-1] if endianness == Endianness.BIG else padded

        if typename in ['bool', 'boolean', 'bool8']:
            raw = grab_bytes(1)
            repr, data = ('true', True) if raw[0] != 0 else ('false', False)
        elif typename == 'bool16':
            raw = grab_bytes(2)
            repr, data = ('true', True) if toint(raw, 16, False) != 0 else ('false', False)
        elif typename == 'bool32':
            raw = grab_bytes(4)
            repr, data = ('true', True) if toint(raw, 32, False) != 0 else ('false', False)
        elif typename == 'bool64':
            raw = grab_bytes(8)
            repr, data = ('true', True) if toint(raw, 64, False) != 0 else ('false', False)
        elif typename == 'bool128':
            raw = grab_bytes(16)
            repr, data = ('true', True) if toint(raw, 128, False) != 0 else ('false', False)
        elif typename == 'int8':
            raw = grab_bytes(1)
            repr, data = toint(raw, 8, True)
        elif typename == 'byte':
            raw = grab_bytes(1)
            data = raw[0]
            repr = f'0x{raw[0]:02x}'
        elif typename == 'uint8':
            raw = grab_bytes(1)
            repr, data = toint(raw, 8, False)
        elif typename == 'int16':
            raw = grab_bytes(2)
            repr, data = toint(raw, 16, True)
        elif typename == 'uint16':
            raw = grab_bytes(2)
            repr, data = toint(raw, 16, False)
        elif typename == 'int32':
            raw = grab_bytes(4)
            repr, data = toint(raw, 32, True)
        elif typename == 'uint32':
            raw = grab_bytes(4)
            repr, data = toint(raw, 32, False)
        elif typename == 'int64':
            raw = grab_bytes(8)
            repr, data = toint(raw, 64, True)
        elif typename == 'uint64':
            raw = grab_bytes(8)
            repr, data = toint(raw, 64, False)
        elif typename == 'int128':
            raw = grab_bytes(16)
            repr, data = toint(raw, 128, True)
        elif typename == 'uint128':
            raw = grab_bytes(16)
            repr, data = toint(raw, 128, False)
        elif typename == 'float16':
            raw = grab_bytes(2)
            # TODO
        elif typename == 'float32':
            raw = grab_bytes(4)
            data = float.fromhex(raw.hex())
        elif typename == 'float64':
            raw = grab_bytes(8)
            data = float.fromhex(raw.hex())
        elif typename == 'float128':
            raw = grab_bytes(16)
            # TODO
        elif typename == 'time32':
            raw = grab_bytes(4)
            repr, data = unix_to_ISO(int.from_bytes(raw, 'little'))
        elif typename == 'uuid':
            raw = grab_bytes(16)
            data = uuid.UUID(bytes = raw)
        elif typename == 'mac':
            raw = grab_bytes(6)
            repr = data = ':'.join(f'{b:02x}' for b in raw)
        elif typename == 'ipv4' or typename == 'ip4':
            raw = grab_bytes(4)
            data = ipaddress.ip_address(raw)
            repr = f'{raw[0]}.{raw[1]}.{raw[2]}.{raw[3]}'
        elif typename == 'ipv6' or typename == 'ip6':
            raw = grab_bytes(16)
            data = ipaddress.ip_address(raw)
            repr = f'[{data.compressed}]'
        elif typename in ['char8', 'char']:
            raw = grab_bytes(1)
            repr = data = raw.decode('ascii', 'ignore')
        elif typename in ['char16', 'wchar']:
            raw = grab_bytes(2)
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
            raw = raw.split(b'\x00', 1)[0]
            repr = data = raw.decode('ascii', 'ignore')
        elif typename in ['wstr', 'cwstr', 'wcstr', 'cstr16', 'str16']:
            raw = raw.split(b'\x00\x00', 1)[0]
            repr = data = raw.decode('utf-16', 'ignore')
        elif typename in ['ustr', 'custr', 'ucstr']:
            pass # TODO: zero-terminated utf-8 string
        # TODO: length-prefixed strings (ascii, utf-16, utf-8)

        if repr is None:
            repr = f'(TODO: {typename})' if data is None else str(data)

        return repr, data, len(raw)

    def _interpret_builtin_type(self: 'LayoutInterpreter', context: InterpreterContext, typename: str) -> InterpretedLayout:
        repr, data, size = self.interpret_data(context.data, typename)

        return context.result(size, repr, data, [])

    def _interpret_pointer(self: 'LayoutInterpreter', context: InterpreterContext, base: dict[str, Any]) -> InterpretedLayout:
        pointer_size: int = context.pointer_size if context.pointer_size else self.pointer_size
        data: bytes = context.data[:pointer_size]
        address = int(self.interpret_data(data, f'uint{pointer_size * 8}', context.endianness, pointer_size)[1] or 0)
        subcontext = InterpreterContext(
            None,
            address,
            context.global_data,
            f'*{context.name}' if context.name else '*',
            context.endianness,
            pointer_size,
            context.skip
        )
        value: InterpretedLayout = self._interpret_member(subcontext, base)

        return context.result(
            pointer_size,
            f'[0x{address:0{pointer_size * 2}x}]',
            value.data,
            [value]
        )

    def _interpret_array(self: 'LayoutInterpreter', context: InterpreterContext, base: dict[str, Any], size: dict[str, Any] | int | None, sizetype: str) -> InterpretedLayout:
        elements: list[InterpretedLayout] = []
        intsize: int = 0
        offset: int = 0

        if sizetype == 'fixed':
            intsize = max(0, size if isinstance(size, int) else 0)
        elif sizetype == 'reference':
            reference: list[str] = size['name']

            if member := context.resolve(reference):
                intsize = int(member.data or 0)
            else:
                context.add_error(f'Cannot resolve member "{'.'.join(reference)}". Did you accidentally define "{'.'.join(reference)}" after "{context.global_name}" instead of before it?')
        elif sizetype == 'dynamic':
            pointer_size: int = context.pointer_size if context.pointer_size else self.pointer_size
            _, raw_array_size, _ = self.interpret_data(context.data[:pointer_size], f'uint{pointer_size * 8}', context.endianness, pointer_size)
            intsize = int(raw_array_size or 0)
            offset += pointer_size
        else:
            context.add_error(f'Unknown/unsupported array type "{sizetype}".')

        for i in range(intsize):
            subcontext: InterpreterContext = context.local(offset, f'[{i}]')
            value: InterpretedLayout = self._interpret_member(subcontext, base)
            offset += value.size
            elements.append(value)

        return context.result(offset, f'{len(elements)} Items', [e.data for e in elements], elements)

    def _interpret_member(self: 'LayoutInterpreter', context: InterpreterContext, type: dict[str, Any]) -> InterpretedLayout:
        _type: str = type['$type']

        # TODO: error on out of range pointer ?

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

    def _interpret_union(self: 'LayoutInterpreter', context: InterpreterContext, members: list[dict[str, Any]]) -> InterpretedLayout:
        interpreted_members: list[InterpretedLayout] = []
        size: int = 0

        for member in members:
            name: str = member['name']

            if member.get('$skip') or context.skip:
                interpreted_member = InterpretedLayout.skipped(context.global_name, name)
            else:
                local_context: InterpreterContext = context.local(0, name)
                interpreted_member: InterpretedLayout = self._interpret_member(local_context, member['type'])

            size = max(size, interpreted_member.size)
            interpreted_members.append(interpreted_member)
            context.scope[f'{context.global_name}.{interpreted_member.name}'] = interpreted_member

        return context.result(size, 'union { ... }', {m.name:m.data for m in interpreted_members}, interpreted_members)

    def _interpret_struct(self: 'LayoutInterpreter', context: InterpreterContext, members: list[dict[str, Any]]) -> InterpretedLayout:
        interpreted_members: list[InterpretedLayout] = []
        offset = 0

        for member in members:
            name: str = member['name']

            if member.get('$skip') or context.skip:
                interpreted_member = InterpretedLayout.skipped(context.global_name, name)
            else:
                local_context: InterpreterContext = context.local(offset, name)
                interpreted_member: InterpretedLayout = self._interpret_member(local_context, member['type'])

            interpreted_members.append(interpreted_member)
            offset += interpreted_member.size
            context.scope[f'{context.global_name}.{interpreted_member.name}'] = interpreted_member

        return context.result(offset, 'struct { ... }', {m.name:m.data for m in interpreted_members}, interpreted_members)

    def __call__(self: 'LayoutInterpreter', data: bytes) -> GlobalInterpreterResult:
        results: list[InterpretedLayout] = []

        for layout in self.layout:
            _type: str = layout['$type']
            context: InterpreterContext = InterpreterContext.global_context(
                self,
                data,
                layout.get('name', ''),
                layout.get('$skip')
            )
            result: InterpretedLayout = context.result(0, 'unknown { ... }', None, [])

            try:
                @timeout(seconds = 1)
                def inner_interpret() -> None:
                    nonlocal result

                    if _type == 'struct':
                        result = self._interpret_struct(context, layout['body']['members'])
                    elif _type == 'union':
                        result = self._interpret_union(context, layout['body']['members'])
                    else:
                        result.add_error(f'Unknown layout type: {_type}')

                inner_interpret()
            except TimeoutError:
                result.add_error(f'Interpetation timed out. This may be a hint of corrupted array sizes or invalid/overflowing pointers.')
            except Exception as e:
                result.add_error(f'Error interpreting layout: {str(e)}')

            results.append(result)

        return GlobalInterpreterResult(results)


# TODO: array of structs/unions
# TODO: return which token/node/memeber and offset was interpreted when an error occurs
