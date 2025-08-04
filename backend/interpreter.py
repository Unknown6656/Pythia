from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal, overload

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
    ParserConstructor,
    StructType,
    ParsedObject,
    ParsedNumber,
    ParsedEndianess,
    ParsedAddressSize,
    ParsedFixedSize,
    ParsedUserDefinedTypename,
    ParsedTypename,
    ParsedQualifiedMemberName,
    ParsedPointerSuffix,
    ParsedDynamicArraySizeSuffix,
    ParsedType,
    ParsedScalarType,
    ParsedPointerType,
    ParsedArrayType,
    ParsedStructMember,
    ParsedStructBody,
    ParsedStructDefinition,
    ParsedFile,
)



@dataclass
class InterpreterError:
    def __init__(self: 'InterpreterError', message: str, scope: str, lineno: int, column: int, text: str | None) -> None:
        self.message: str = message
        self.scope: str = scope
        self.lineno: int = lineno
        self.column: int = column
        self.text: str = str(text or '')

    def to_dict(self: 'InterpreterError') -> dict[str, Any]:
        return {
            'message': self.message,
            'scope': self.scope,
            'line': self.lineno,
            'column': self.column,
            'text': self.text,
            'length': len(self.text)
        }


@dataclass
class InterpretedLayout:
    def __init__(
            self: 'InterpretedLayout',
            endianess: Endianness,
            address_size: int,
            offset: int,
            raw: bytes,
            scope: str | None,
            name: str,
            repr: str | None = None,
            data: Any | None = None,
            members: list['InterpretedLayout'] = [],
            errors: list[InterpreterError] = [],
            parsed: ParsedObject = ParsedObject.empty()
    ) -> None:
        self.raw: bytes = raw
        self.endianess: Endianness = endianess
        self.address_size: int = address_size
        self.offset: int = offset
        self.name: str = name
        self.size: int = len(raw)
        self.repr: str | None = repr
        self.data: Any | None = data
        self.path: str = scope or self.name or '/'
        self.members: list['InterpretedLayout'] = members
        self.errors: list[InterpreterError] = errors
        self.parsed: ParsedObject = parsed

    @staticmethod
    def skipped(scope: str | None, name: str) -> 'InterpretedLayout':
        return InterpretedLayout(
            Endianness.LITTLE,
            0,
            0,
            b'',
            scope,
            name,
            '(skipped)',
            None,
            [],
            [],
            ParsedObject.empty()
        )

    @overload
    def add_error(self: 'InterpretedLayout', message: str, lineno: int, column: int, text: str | None = None) -> None: pass

    @overload
    def add_error(self: 'InterpretedLayout', message: str, parsed: ParsedObject | None = None) -> None: pass

    def add_error(self: 'InterpretedLayout', message: str, *args) -> None: # type: ignore
        lineno: int = -1
        column: int = -1
        text: str | None = None

        if len(args) == 1:
            parsed: ParsedObject = args[0]
            lineno = parsed._source_lineno
            column = parsed._source_column
            text = parsed._source_code[parsed._source_location:parsed._source_location + parsed._source_length]
        elif len(args) == 2:
            lineno, column = args
        elif len(args) == 3:
            lineno, column, text = args

        self.errors.append(InterpreterError(message, self.path, lineno, column, text))

    def __str__(self: 'InterpretedLayout') -> str:
        return f'{'⚠️ ' if len(self.errors) > 0 else ''}{self.name}@[{self.offset}:{self.offset + self.size}, {self.size}]: "{self.repr}" ({self.data})'

    def to_dict(self: 'InterpretedLayout') -> dict[str, Any]:
        return {
            'raw': base64.b64encode(self.raw).decode('utf-8'),
            'endianess': self.endianess.value,
            'address_size': self.address_size,
            'offset': self.offset,
            'path': self.path,
            'name': self.name,
            'size': self.size,
            'repr': self.repr,
            'data': str(self.data) if self.data else None,
            'members': [member.to_dict() for member in self.members],
            'errors': [error.to_dict() for error in self.errors],
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
            address_size: int
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
        self.address_size: int = address_size
        self.skip: bool = skip
        self.depth: int = (parent.depth + 1) if parent else 0

    def __str__(self: 'InterpreterContext') -> str:
        prefix: str = ''

        if len(self.errors):
            prefix += f'⚠️{len(self.errors)} '

        if self.skip:
            prefix += '(skipped) '

        return f'{prefix}{self.global_name} @ {self.global_offset:08x}: {self.data}'

    @overload
    def add_error(self: 'InterpreterContext', message: str, lineno: int, column: int, text: str | None = None) -> None: pass

    @overload
    def add_error(self: 'InterpreterContext', message: str, parsed: ParsedObject) -> None: pass

    def add_error(self: 'InterpreterContext', message: str, *args) -> None: # type: ignore
        lineno: int = -1
        column: int = -1
        text: str | None = None

        if len(args) == 1:
            parsed: ParsedObject = args[0]
            lineno = parsed._source_lineno
            column = parsed._source_column
            text = parsed._source_code[parsed._source_location:parsed._source_location + parsed._source_length]
        elif len(args) == 2:
            lineno, column = args
        elif len(args) == 3:
            lineno, column, text = args

        self.errors.append(InterpreterError(message, self.global_name, lineno, column, text))

    @staticmethod
    def global_context(
            data: bytes,
            name: str,
            skip: bool,
            endianness: Endianness,
            address_size: int
    ) -> 'InterpreterContext':
        return InterpreterContext(None, 0, data, name, skip, endianness, address_size)

    def local(
            self: 'InterpreterContext',
            offset: int,
            name: str,
            skip: bool | None = None,
            endianness: Endianness | None = None,
            address_size: int | None = None
    ) -> 'InterpreterContext':
        return InterpreterContext(
            self,
            offset,
            self.data,
            name,
            skip or self.skip,
            endianness or self.endianness,
            address_size or self.address_size
        )

    def result(
            self: 'InterpreterContext',
            size: int,
            repr: str | None,
            data: Any | None,
            members: list[InterpretedLayout],
            parsed: ParsedObject
    ) -> InterpretedLayout:
        member_names: dict[str, list[InterpretedLayout]] = {}
        layout: InterpretedLayout

        for member in members:
            if member.name:
                member_names[member.name] = [*member_names.get(member.name, []), member]

        for name in member_names:
            if len(member_names[name]) > 1:
                first: ParsedObject = member_names[name][0].parsed

                for duplicate in member_names[name][1:]:
                    self.add_error(f'Duplicate member definition "{name}" in "{self.global_name}" (already defined in line {first._source_lineno}:{first._source_column}).', duplicate.parsed)

        if self.skip:
            layout = InterpretedLayout.skipped(self.global_name, self.name)
        else:
            layout = InterpretedLayout(
                self.endianness,
                self.address_size,
                self.global_offset,
                self.data[:size],
                self.global_name,
                self.name,
                repr,
                data,
                members,
                self.errors,
                parsed
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
    def __init__(self: 'GlobalInterpreterResult', result: InterpretedLayout) -> None:
        self.errors: list[InterpreterError] = []
        self.data: InterpretedLayout = result

        def collect_errors(layout: InterpretedLayout) -> None:
            self.errors.extend(layout.errors)

            for member in layout.members:
                collect_errors(member)

        collect_errors(result)

        self.success: bool = len(self.errors) == 0

    def to_dict(self: 'GlobalInterpreterResult') -> dict[str, Any]:
        return {
            'success': self.success,
            'data': [self.data.to_dict()],
            'errors': [error.to_dict() for error in self.errors]
        }


class LayoutInterpreter():
    def __init__(self: 'LayoutInterpreter',
                 parsed: ParsedFile,
                 default_endianness: Endianness,
                 default_address_size: int
    ) -> None:
        self.parsed: ParsedFile = parsed
        self.default_endianness: Endianness = default_endianness
        self.default_address_size: int = default_address_size

    def interpret_data(
            self: 'LayoutInterpreter',
            raw: bytes,
            typename: str,
            endianness: Endianness,
            address_size: int,
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
            raw = grab_bytes(address_size)
            data = toint(raw, address_size * 8, False)[1]
            repr = f'[0x{data:0{address_size * 2}x}]'
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


    def _interpret_builtin_type(self: 'LayoutInterpreter', context: InterpreterContext, typename: ParsedTypename, fixed_size: int | None) -> InterpretedLayout:
        repr, data, size = self.interpret_data(context.data, typename.name, context.endianness, context.address_size, fixed_size)

        return context.result(size, repr, data, [], typename)

    def _interpret_pointer(self: 'LayoutInterpreter', context: InterpreterContext, pointer: ParsedPointerType, fixed_size: int | None) -> InterpretedLayout:
        data: bytes = context.data[:context.address_size]
        address = int(self.interpret_data(
            data,
            f'uint{context.address_size * 8}',
            context.endianness,
            context.address_size,
            fixed_size
        )[1] or 0)
        subcontext = InterpreterContext(
            None,
            address,
            context.global_data,
            context.global_name + '*',
            context.skip,
            context.endianness,
            context.address_size
        )
        value: InterpretedLayout = self._interpret_member(subcontext, pointer.base, None)

        return context.result(
            context.address_size,
            f'[0x{address:0{context.address_size * 2}x}]',
            address,
            [value],
            pointer
        )

    def _interpret_array(
            self: 'LayoutInterpreter',
            context: InterpreterContext,
            array: ParsedArrayType,
            fixed_size: int | None
    ) -> InterpretedLayout:
        base: ParsedType = array.base
        size: ParsedDynamicArraySizeSuffix | ParsedNumber | ParsedQualifiedMemberName = array.size
        elements: list[InterpretedLayout] = []
        intsize: int = 0
        offset: int = 0

        if isinstance(size, ParsedNumber):
            if size.value < 0:
                context.add_error(f'Invalid array size "{size.value}". Array size must be non-negative.', size)
            else:
                intsize = size.value
        elif isinstance(size, ParsedQualifiedMemberName):
            reference: list[ParsedUserDefinedTypename] = size.name
            fullname: str = MEMBER_DELIMITER.join(r.name for r in reference)

            if member := context.resolve([r.name for r in reference]):
                intsize = int(member.data or 0)
            else:
                context.add_error(f'Cannot resolve member "{fullname}". Did you accidentally define "{fullname}" after "{context.global_name}" instead of before it?', size)
        elif isinstance(size, ParsedDynamicArraySizeSuffix):
            addr_size: int = min(fixed_size, context.address_size) if fixed_size is not None else context.address_size
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
            offset += context.address_size
        else:
            context.add_error(f'Unknown/unsupported array type "{type(size)}".', size if isinstance(size, ParsedObject) else base)

        for i in range(intsize):
            subcontext: InterpreterContext = context.local(offset, f'[{i}]')
            value: InterpretedLayout = self._interpret_member(subcontext, base, fixed_size)
            elements.append(value)
            offset += value.size

            if fixed_size is not None:
                fixed_size -= value.size
                if fixed_size <= 0:
                    break

        if isinstance(base, ParsedScalarType) and base.type.builtin and 'char' in base.type.name:
            # Special case for char arrays, where we want to interpret the data as a string
            data = ''.join(str(e.data) for e in elements)
            repr = f'"{data}"'
        else:
            data: list | str = [e.data for e in elements]
            repr: str = f'({len(elements)} elements)' if len(elements) > 0 else '(empty)'

        return context.result(offset, repr, data, elements, array)

    def _interpret_member(self: 'LayoutInterpreter', context: InterpreterContext, type: ParsedType, fixed_size: int | None) -> InterpretedLayout:
        # TODO: error on out of range pointer ?

        if isinstance(type, ParsedScalarType):
            type_name: ParsedTypename = type.type

            if type_name.builtin:
                return self._interpret_builtin_type(context, type_name, fixed_size)
            else:
                definitions: list[ParsedStructDefinition] = [df for df in self.parsed.definitions if df.name == type_name.name]

                if len(definitions) == 0:
                    context.add_error(f'The user-defined type "{type_name.name}" cannot be found. Did you missspell it?', type_name)
                elif len(definitions) > 1:
                    context.add_error(f'Multiple user-defined types with name "{type_name}" found. Did you accidentally define it multiple times?', type_name)
                else:
                    return self._interpret_member(context, definitions[0], fixed_size)
        elif isinstance(type, ParsedPointerType):
            return self._interpret_pointer(context, type, fixed_size)
        elif isinstance(type, ParsedArrayType):
            return self._interpret_array(context, type, fixed_size)
        elif isinstance(type, ParsedStructDefinition):
            return self._interpret_struct(context, type, fixed_size)
        else:
            context.add_error(f'Unknown type "{type}" in "{context.global_name}".', type)

        return context.result(0, 'unknown { ... }', None, [], type)

    def _interpret_struct(
            self: 'LayoutInterpreter',
            context: InterpreterContext,
            struct: ParsedStructDefinition,
            fixed_size: int | None
    ) -> InterpretedLayout:
        members: list[ParsedStructMember] = struct.body.members
        struct_type: StructType = struct.type
        interpreted_members: list[InterpretedLayout] = []
        offset: int = 0
        size: int = 0

        for member in members:
            endianess: Endianness = member.endianess.endianess if member.endianess else self.default_endianness
            address_size: int = member.addrsize.addrsize if member.addrsize else self.default_address_size
            member_fixed_size: int | None = member.fixedsize.size if member.fixedsize else fixed_size

            if member_fixed_size is not None and fixed_size is not None:
                member_fixed_size = min(member_fixed_size, fixed_size)

                if fixed_size <= 0:
                    break
                elif struct_type == StructType.STRUCT and member_fixed_size <= fixed_size:
                    fixed_size -= member_fixed_size

            local_context: InterpreterContext = context.local(offset, member.name.name, False, endianess, address_size)
            interpreted_member: InterpretedLayout = self._interpret_member(local_context, member.type, member_fixed_size)
            interpreted_members.append(interpreted_member)

            if member.name.name in ParserConstructor.BUILTIN_TYPES:
                context.add_error(f'Built-in type "{member.name.name}" cannot be used as a type name for user-defined types.', member.name)

            if struct_type == StructType.UNION:
                size = max(size, interpreted_member.size)
            else:
                offset += interpreted_member.size
                size = offset

        return context.result(
            size,
            f'{'union' if struct_type == StructType.UNION else 'struct'} {{ ... }}',
            {m.name:m.data for m in interpreted_members},
            interpreted_members,
            struct
        )

    def __call__(self: 'LayoutInterpreter', data: bytes) -> GlobalInterpreterResult:
        result: InterpretedLayout = InterpretedLayout.skipped(None, '(no type definition)')
        definitions: list[ParsedStructDefinition] = [df for df in self.parsed.definitions if df.parse]

        if len(definitions) == 0 and len(self.parsed.definitions) > 0:
            result.add_error('No type definition found to parse. Did you forget to add "parse" to your user-defined "struct"/"union"?')
        else:
            type_definition: ParsedStructDefinition = definitions[0]
            endianess: Endianness = type_definition.endianess.endianess if type_definition.endianess else self.default_endianness
            address_size: int = type_definition.addrsize.addrsize if type_definition.addrsize else self.default_address_size
            fixed_size: int | None = type_definition.fixedsize.size if type_definition.fixedsize else None

            context: InterpreterContext = InterpreterContext.global_context(
                data,
                type_definition.name,
                False,
                endianess,
                address_size
            )
            result = context.result(0, 'unknown { ... }', None, [], type_definition)

            try:
                @timeout(seconds = 1)
                def inner_interpret() -> None:
                    nonlocal result

                    # _dump(type_definition)
                    result = self._interpret_struct(context, type_definition, fixed_size)

                inner_interpret()
            except TimeoutError:
                result.add_error(f'Interpetation timed out. This may be a hint of corrupted array sizes or invalid/overflowing pointers.', type_definition)
            except Exception as e:
                _dump(e)
                result.add_error(f'Error interpreting the type definition: {str(e)}', type_definition)

            if len(definitions) > 1:
                for type_definition in definitions[1:]:
                    result.add_error(f'Ignoring additional type definition "{type_definition.name}". Only one type definition with the "parse" keyword is allowed per file.', type_definition)

        return GlobalInterpreterResult(result)

