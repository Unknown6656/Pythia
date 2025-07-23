from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal

import base64
import uuid
import json
import re

import ipaddress
import pyparsing as pp

from common import toint, unix_to_ISO, timeout, _dump, _dumps
from parser import (
    MEMBER_DELIMITER,
    Endianness,
    ParsedFile,
)



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
                 parsed: list[ParsedFile],
                 endianness: Endianness,
                 address_size: int
    ) -> None:
        _dump(parsed)

        self.parsed: list[ParsedFile] = parsed
        self.default_endianness: Endianness = endianness
        self.default_address_size: int = address_size

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
            addr_size = min(fixed_size, context.pointer_size) if fixed_size is not None else context.pointer_size
            _, raw_array_size, _ = self.interpret_data(
                context.data[:addr_size],
                f'uint{addr_size * 8}',
                context.endianness,
                addr_size,
                None
            )

            if fixed_size is not None:
                fixed_size -= addr_size

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
                layouts = [l for l in self.parsed if l.get('name') == typename]

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
            endianess: Endianness = Endianness.parse(member.get('endianess')) or self.default_endianness
            pointer_size: int = member.get('addrsize') or self.default_address_size
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

        for layout in self.parsed:
            _type: str = layout['$type']
            endianess: Endianness = Endianness.parse(layout.get('endianess',{}).get('endianess')) or self.default_endianness
            pointer_size: int = layout.get('addrsize') or self.default_address_size
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

