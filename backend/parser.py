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


MEMBER_DELIMITER: str = '.'

# Grammar: see README.md
class LayoutParser():
    BULTIIN_TYPES: str = r'((u?int|float|bool)(8|16|32|64|128)|bool|void|addr|ptr|byte|uuid|ipv?[46]|mac|time32|([cl][wu]|[wu][cl]|[clwu])?str|char(8|16|32)?|[uw]?char)'
    SIZE_MODIFIERS: str = r'__x(86?|16|32|64)'
    BYTE_ORDER_MODIFIERS: str = r'__([lm]sb|[lb]e)'

    def __init__(self: 'LayoutParser') -> None:
        def parse_number(s, loc, toks) -> int:
            if dec_ := toks.get('dec'):
                return int(dec_.replace('_', ''), 10)
            elif bin_ := toks.get('bin'):
                return int(bin_.replace('_', ''), 2)
            elif hex_ := toks.get('hex'):
                return int(hex_.replace('_', ''), 16)
            elif oct_ := toks.get('oct'):
                return int(oct_.replace('_', ''), 8)
            else:
                raise pp.ParseException(s, loc, f'Invalid number: {toks}')

        number = pp.Regex(r'\b((?P<dec>[0-9_]+)|(?P<bin>0b[01_]+)|(?P<hex>0x[0-9a-f_]+)|(?P<oct>0o[0-7_]+))\b', re.I)
        number.setParseAction(parse_number)

        comment: pp.ParserElement = pp.cpp_style_comment | pp.python_style_comment

        symbol_dot = pp.Suppress(MEMBER_DELIMITER)
        symbol_comma = pp.Suppress(',')
        symbol_pointer = pp.Word('*', exact = 1)
        symbol_colon = pp.Suppress(':')
        symbol_semicolon = pp.Suppress(';')
        symbol_leftparen = pp.Suppress('(')
        symbol_rightparen = pp.Suppress(')')
        symbol_leftangle = pp.Suppress('<')
        symbol_rightangle = pp.Suppress('>')
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

        token_fixed_size_constraint = pp.Group(symbol_leftangle + number('value') + symbol_rightangle)
        token_fixed_size_constraint.setParseAction(lambda s, loc, toks: int(toks[0].value)) # type: ignore

        token_type_member = pp.Group(
            pp.Optional(keyword_skip)('skip') +
            token_identifier('name') +
            symbol_colon +
            pp.Optional(keyword_modifier_byteorder)('byteorder') +
            pp.Optional(keyword_modifier_size)('ptrsize') +
            token_type_identifier('type') +
            pp.Optional(token_fixed_size_constraint)('fixedsize') +
            symbol_semicolon
        )

        token_type_members = pp.ZeroOrMore(token_type_member)

        token_type_body = pp.Group(symbol_leftbrace + token_type_members('members') + symbol_rightbrace)

        token_type_definition: pp.ParserElement = pp.Group(
            pp.Optional(keyword_skip)('skip') +
            pp.Optional(keyword_modifier_byteorder)('byteorder') +
            pp.Optional(keyword_modifier_size)('ptrsize') +
            (keyword_struct | keyword_union)('type') +
            token_typename_userdef('name') +
            pp.Optional(token_fixed_size_constraint)('fixedsize') +
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

        def struct_converter(
                type: str,
                name: str | None,
                members: pp.ParseResults,
                skip: bool,
                ptrsize: str | None = None,
                byteorder: str | None = None,
                fixedsize: str | None = None
        ) -> dict[str, Any]:
            processed_members: list[dict[str, Any]] = []

            for member in members:
                member_ptrsize = member.ptrsize if 'ptrsize' in member else ptrsize
                member_fixedsize = member.fixedsize[0] if 'fixedsize' in member else None
                member_byteorder = member.byteorder if 'byteorder' in member else byteorder
                processed_members.append({
                    '$type': 'member',
                    '$skip': 'skip' in member,
                    'ptrsize': member_ptrsize,
                    'fixedsize': member_fixedsize,
                    'byteorder': member_byteorder,
                    'name': member.name,
                    'type': type_converter(member.type, False, member_ptrsize, member_byteorder),
                })

            return {
                '$type': type,
                '$skip': skip,
                'name': name,
                'ptrsize': ptrsize,
                'byteorder': byteorder,
                'fixedsize': fixedsize,
                'body': {
                    '$type': 'body',
                    'members': processed_members
                }
            }

        def type_converter(item: pp.ParseResults, skip: bool, ptrsize: str | None = None, byteorder: str | None = None) -> dict[str, Any]:
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
                    return struct_converter(inline.type, None, inline.body.members, skip, ptrsize, byteorder) # type: ignore
                else:
                    return {
                        '$type': 'unknown',
                        '$skip': skip,
                        '$raw': _dump(inline),
                    }
            elif 'suffix' in item and 'base' in item:
                result: dict[str, Any] = type_converter(item.base, skip, ptrsize, byteorder) # type: ignore

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
                    'skip' in item,
                    item.ptrsize if 'ptrsize' in item else ptrsize, # type: ignore
                    item.byteorder if 'byteorder' in item else byteorder, # type: ignore
                    item.fixedsize[0] if 'fixedsize' in item else None # type: ignore
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

    @staticmethod
    def parse(value: str | None) -> 'Endianness | None':
        if value is None:
            return None

        value = value.lower().strip('_')

        if value in ['little', 'lsb', 'le']:
            return Endianness.LITTLE
        elif value in ['big', 'msb', 'be']:
            return Endianness.BIG
        else:
            raise ValueError(f'Invalid endianness: {value}')


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
            endianess: Endianness,
            pointer_size: int,
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
        self.endianess: Endianness = endianess
        self.pointer_size: int = pointer_size
        self.offset: int = offset
        self.name: str = name
        self.size: int = len(raw)
        self.repr: str | None = repr
        self.data: Any | None = data
        self.path: str = scope or self.name or '/'
        self.members: list['InterpretedLayout'] = members
        self.errors: list[InterpreterError] = errors

    @staticmethod
    def skipped(scope: str | None, name: str) -> 'InterpretedLayout':
        return InterpretedLayout(True, Endianness.LITTLE, 0, 0, b'', scope, name, '(skipped)', None, [], [])

    def add_error(self: 'InterpretedLayout', message: str) -> None:
        self.errors.append(InterpreterError(message, self.path))

    def __str__(self: 'InterpretedLayout') -> str:
        return f'{'⚠️ ' if len(self.errors) > 0 else ''}{self.name}@[{self.offset}:{self.offset + self.size}, {self.size}]: "{self.repr}" ({self.data})'

    def to_dict(self: 'InterpretedLayout') -> dict[str, Any]:
        return {
            'raw': base64.b64encode(self.raw).decode('utf-8'),
            'skip': self.skip,
            'endianess': self.endianess.value,
            'pointer_size': self.pointer_size,
            'offset': self.offset,
            'path': self.path,
            'name': self.name,
            'size': self.size,
            'repr': self.repr,
            'data': str(self.data) if self.data else None,
            'members': [member.to_dict() for member in self.members],
            'errors': [error.to_dict() for error in self.errors]
        }


class RootInterpreterContext:
    resolved: dict[str, InterpretedLayout] = {}

@dataclass
class InterpreterContext:
    def __init__(
            self: 'InterpreterContext',
            parent: 'InterpreterContext | None',
            offset: int,
            data: bytes,
            name: str,
            skip: bool,
            endianness: Endianness,
            pointer_size: int
    ) -> None:
        self.parent: InterpreterContext | None = parent
        self.root: RootInterpreterContext = parent.root if parent else RootInterpreterContext()
        self.data: bytes = data[offset:]
        self.name: str = name
        self.errors: list[InterpreterError] = []
        self.global_name: str = f'{parent.global_name}{MEMBER_DELIMITER}{name}' if parent and name else (parent.global_name or name if parent else name)
        self.global_data: bytes = parent.global_data if parent else data
        self.global_offset: int = parent.global_offset + offset if parent else offset
        self.endianness: Endianness = endianness
        self.pointer_size: int = pointer_size
        self.skip: bool = skip
        self.depth: int = (parent.depth + 1) if parent else 0

    def __str__(self: 'InterpreterContext') -> str:
        prefix: str = ''

        if len(self.errors):
            prefix += f'⚠️{len(self.errors)} '

        if self.skip:
            prefix += '(skipped) '

        return f'{prefix}{self.global_name} @ {self.global_offset:08x}: {self.data}'

    def add_error(self: 'InterpreterContext', message: str) -> None:
        self.errors.append(InterpreterError(message, self.global_name))

    @staticmethod
    def global_context(
            data: bytes,
            name: str,
            skip: bool,
            endianness: Endianness,
            pointer_size: int
    ) -> 'InterpreterContext':
        return InterpreterContext(None, 0, data, name, skip, endianness, pointer_size)

    def local(
            self: 'InterpreterContext',
            offset: int,
            name: str,
            skip: bool | None = None,
            endianness: Endianness | None = None,
            pointer_size: int | None = None
    ) -> 'InterpreterContext':
        return InterpreterContext(
            self,
            offset,
            self.data,
            name,
            skip or self.skip,
            endianness or self.endianness,
            pointer_size or self.pointer_size
        )

    def result(
            self: 'InterpreterContext',
            size: int,
            repr: str | None,
            data: Any | None,
            members: list[InterpretedLayout]
    ) -> InterpretedLayout:
        member_names: dict[str, int] = {}
        layout: InterpretedLayout

        for member in members:
            if member.name:
                member_names[member.name] = 1 + member_names.get(member.name, 0)

        for name in member_names:
            if member_names[name] > 1:
                self.add_error(f'Duplicate member definition "{name}" in "{self.global_name}".')

        if self.skip:
            layout = InterpretedLayout.skipped(self.global_name, self.name)
        else:
            layout = InterpretedLayout(
                False,
                self.endianness,
                self.pointer_size,
                self.global_offset,
                self.data[:size],
                self.global_name,
                self.name,
                repr,
                data,
                members,
                self.errors
            )

        if '[' not in layout.path:
            self.root.resolved[layout.path] = layout

        return layout

    def resolve(self: 'InterpreterContext', member: str | list[str]) -> InterpretedLayout | None:
        member_list: list[str] = member if isinstance(member, list) else member.split(MEMBER_DELIMITER)
        search_scopes: list[list[str]] = [self.global_name.split(MEMBER_DELIMITER)[:i] for i in range(self.depth, -1, -1)]

        for scope in search_scopes:
            key: str = MEMBER_DELIMITER.join([*scope, *member_list])

            if result := self.root.resolved.get(key):
                return result

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
            endianness: Endianness,
            pointer_size: int,
            fixed_size: int | None
    ) -> tuple[str, Any | None, int]:
        if fixed_size is not None:
            raw = raw.ljust(fixed_size, b'\x00') if len(raw) < fixed_size else raw[:fixed_size]

        typename = typename.lower()
        repr: str | None = None
        data: Any | None = None

        def grab_bytes(size: int) -> bytes:
            padded: bytes = raw.ljust(size, b'\x00') if len(raw) < size else raw
            padded = padded[:size]

            return padded[::-1] if endianness == Endianness.LITTLE else padded

        if typename in ['void', 'skip']:
            raw = b''
            repr = '(void)'
            data = None
        elif typename in ['bool', 'boolean', 'bool8']:
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
        elif typename in ['addr', 'ptr']:
            raw = grab_bytes(pointer_size)
            data = toint(raw, pointer_size * 8, False)[1]
            repr = f'[0x{data:0{pointer_size * 2}x}]'
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

        return repr, data, fixed_size or len(raw)

    @staticmethod
    def _parse_ptr_size(size: str | None) -> int | None:
        return {
            '__x8': 1,
            '__x16': 2,
            '__x32': 4,
            '__x86': 4,
            '__x64': 8,
        }.get((size or '').strip().lower())

    def _interpret_builtin_type(self: 'LayoutInterpreter', context: InterpreterContext, typename: str, fixed_size: int | None) -> InterpretedLayout:
        repr, data, size = self.interpret_data(context.data, typename, context.endianness, context.pointer_size, fixed_size)

        return context.result(size, repr, data, [])

    def _interpret_pointer(self: 'LayoutInterpreter', context: InterpreterContext, base: dict[str, Any], fixed_size: int | None) -> InterpretedLayout:
        data: bytes = context.data[:context.pointer_size]
        address = int(self.interpret_data(
            data,
            f'uint{context.pointer_size * 8}',
            context.endianness,
            context.pointer_size,
            fixed_size
        )[1] or 0)
        subcontext = InterpreterContext(
            None,
            address,
            context.global_data,
            context.global_name + '*',
            context.skip,
            context.endianness,
            context.pointer_size
        )
        value: InterpretedLayout = self._interpret_member(subcontext, base, None)

        return context.result(
            context.pointer_size,
            f'[0x{address:0{context.pointer_size * 2}x}]',
            address,
            [value]
        )

    def _interpret_array(
            self: 'LayoutInterpreter',
            context: InterpreterContext,
            base: dict[str, Any],
            size: dict[str, Any] | int | None,
            sizetype: str,
            fixed_size: int | None
    ) -> InterpretedLayout:
        elements: list[InterpretedLayout] = []
        intsize: int = 0
        offset: int = 0

        if sizetype == 'fixed':
            intsize = max(0, size if isinstance(size, int) else 0)
        elif sizetype == 'reference':
            reference: list[str] = size['name'] # type: ignore

            if member := context.resolve(reference):
                intsize = int(member.data or 0)
            else:
                context.add_error(f'Cannot resolve member "{MEMBER_DELIMITER.join(reference)}". Did you accidentally define "{MEMBER_DELIMITER.join(reference)}" after "{context.global_name}" instead of before it?')
        elif sizetype == 'dynamic':
            ptr_size = min(fixed_size, context.pointer_size) if fixed_size is not None else context.pointer_size
            _, raw_array_size, _ = self.interpret_data(
                context.data[:ptr_size],
                f'uint{ptr_size * 8}',
                context.endianness,
                ptr_size,
                None
            )

            if fixed_size is not None:
                fixed_size -= ptr_size

            intsize = int(raw_array_size or 0)
            offset += context.pointer_size
        else:
            context.add_error(f'Unknown/unsupported array type "{sizetype}".')

        for i in range(intsize):
            subcontext: InterpreterContext = context.local(offset, f'[{i}]')
            value: InterpretedLayout = self._interpret_member(subcontext, base, fixed_size)
            elements.append(value)
            offset += value.size

            if fixed_size is not None:
                fixed_size -= value.size
                if fixed_size <= 0:
                    break

        if base['$type'] == 'type' and base['builtin'] and 'char' in base['name']:
            # Special case for char arrays, where we want to interpret the data as a string
            data = ''.join(str(e.data) for e in elements)
            repr = f'"{data}"'
        else:
            data: list | str = [e.data for e in elements]
            repr: str = f'({len(elements)} elements)' if len(elements) > 0 else '(empty)'

        return context.result(offset, repr, data, elements)

    def _interpret_member(self: 'LayoutInterpreter', context: InterpreterContext, type: dict[str, Any], fixed_size: int | None) -> InterpretedLayout:
        _type: str = type['$type']

        # TODO: error on out of range pointer ?

        if _type == 'type':
            if type['builtin']:
                return self._interpret_builtin_type(context, type['name'], fixed_size)
            else:
                typename: str = type['name']
                layouts = [l for l in self.layout if l.get('name') == typename]

                if len(layouts) == 0:
                    context.add_error(f'Unknown user-defined type "{typename}" in "{context.global_name}". Did you forget to define it before using it?')
                elif len(layouts) > 1:
                    context.add_error(f'Multiple user-defined types with name "{typename}" in "{context.global_name}". Did you accidentally define it multiple times?')
                else:
                    return self._interpret_member(context, layouts[0], fixed_size)
        elif _type == 'pointer':
            return self._interpret_pointer(context, type['base'], fixed_size)
        elif _type == 'array':
            return self._interpret_array(context, type['base'], type['size'], type['$size'], fixed_size)
        elif _type == 'struct':
            return self._interpret_struct(context, type['body']['members'], False, fixed_size)
        elif _type == 'union':
            return self._interpret_struct(context, type['body']['members'], True, fixed_size)
        else:
            context.add_error(f'Unknown type "{type}" in "{context.global_name}".')

        result: InterpretedLayout = context.result(0, 'unknown { ... }', None, [])
        result.skip = True

        return result

    def _interpret_struct(
            self: 'LayoutInterpreter',
            context: InterpreterContext,
            members: list[dict[str, Any]],
            is_union: bool,
            fixed_size: int | None
    ) -> InterpretedLayout:
        interpreted_members: list[InterpretedLayout] = []
        offset: int = 0
        size: int = 0

        for member in members:
            name: str = member['name']
            endianess: Endianness = Endianness.parse(member.get('byteorder')) or self.default_endianness
            pointer_size: int = LayoutInterpreter._parse_ptr_size(member.get('ptrsize')) or self.pointer_size
            member_fixed_size: int | None = member.get('fixedsize', fixed_size)

            if member_fixed_size is not None and fixed_size is not None:
                member_fixed_size = min(member_fixed_size, fixed_size)

                if fixed_size <= 0:
                    break
                elif not is_union and member_fixed_size <= fixed_size:
                    fixed_size -= member_fixed_size

            if member.get('$skip') or context.skip:
                interpreted_member = InterpretedLayout.skipped(context.global_name, name)
            else:
                local_context: InterpreterContext = context.local(offset, name, False, endianess, pointer_size)
                interpreted_member: InterpretedLayout = self._interpret_member(local_context, member['type'], member_fixed_size)

            interpreted_members.append(interpreted_member)

            if is_union:
                size = max(size, interpreted_member.size)
            else:
                offset += interpreted_member.size
                size = offset

        return context.result(size, f'{'union' if is_union else 'struct'} {{ ... }}', {m.name:m.data for m in interpreted_members}, interpreted_members)

    def __call__(self: 'LayoutInterpreter', data: bytes) -> GlobalInterpreterResult:
        user_defined_types: dict[str, InterpretedLayout] = {}
        results: list[InterpretedLayout] = []

        for layout in self.layout:
            _type: str = layout['$type']
            endianess: Endianness = Endianness.parse(layout.get('byteorder')) or self.default_endianness
            pointer_size: int = LayoutInterpreter._parse_ptr_size(layout.get('ptrsize')) or self.pointer_size
            fixed_size: int | None = layout.get('fixedsize')
            context: InterpreterContext = InterpreterContext.global_context(
                data,
                layout.get('name', ''),
                layout.get('$skip', False),
                endianess,
                pointer_size
            )
            result: InterpretedLayout = context.result(0, 'unknown { ... }', None, [])

            try:
                @timeout(seconds = 1)
                def inner_interpret() -> None:
                    nonlocal result

                    if _type == 'struct':
                        result = self._interpret_struct(context, layout['body']['members'], False, fixed_size)
                    elif _type == 'union':
                        result = self._interpret_struct(context, layout['body']['members'], True, fixed_size)
                    else:
                        result.add_error(f'Unknown layout type: {_type}')

                inner_interpret()
            except TimeoutError:
                result.add_error(f'Interpetation timed out. This may be a hint of corrupted array sizes or invalid/overflowing pointers.')
            except Exception as e:
                result.add_error(f'Error interpreting layout: {str(e)}')

            results.append(result)
            user_defined_types[result.name] = result

        return GlobalInterpreterResult(results)

