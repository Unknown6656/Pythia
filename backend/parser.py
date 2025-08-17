from enum import Enum

import uuid
import re

import pyparsing as pp


from common import _dumps


MEMBER_DELIMITER: str = '.'


class Endianness(str, Enum):
    LITTLE = 'little'
    BIG = 'big'

    def __str__(self: 'Endianness') -> str:
        return self.value

    @staticmethod
    def parse(value: str | None) -> 'Endianness | None':
        if value is None:
            return None
        elif isinstance(value, Endianness):
            return value

        value = value.lower().strip('_')

        if value in ['little', 'lsb', 'le']:
            return Endianness.LITTLE
        elif value in ['big', 'msb', 'be']:
            return Endianness.BIG
        else:
            raise ValueError(f'Invalid endianness: {value}')

class StructType(str, Enum):
    STRUCT = 'struct'
    UNION = 'union'

    def __str__(self: 'StructType') -> str:
        return self.value

class ParsedObject:
    def __init__(self: 'ParsedObject', source_code: str, source_location: int, source_token: pp.ParseResults) -> None:
        self._source_lineno: int = pp.lineno(source_location, source_code)
        self._source_column: int = pp.col(source_location, source_code)
        self._source_length: int = len(str(source_token[0])) if len(source_token) else 0
        self._source_code: str = source_code
        self._source_location: int = source_location
        self._source_token: pp.ParseResults = source_token

    @staticmethod
    def empty() -> 'ParsedObject': return ParsedObject('', 0, pp.ParseResults(['']))

class ParsedNumber(ParsedObject):
    def __init__(self: 'ParsedNumber', source_code: str, source_location: int, source_token: pp.ParseResults, value: int) -> None:
        super().__init__(source_code, source_location, source_token)
        self.value: int = value

class ParsedEndianess(ParsedObject):
    def __init__(self: 'ParsedEndianess', source_code: str, source_location: int, source_token: pp.ParseResults, endianess: Endianness) -> None:
        super().__init__(source_code, source_location, source_token)
        self.endianess: Endianness = endianess

class ParsedAddressSize(ParsedObject):
    def __init__(self: 'ParsedAddressSize', source_code: str, source_location: int, source_token: pp.ParseResults, addrsize: int) -> None:
        super().__init__(source_code, source_location, source_token)
        self.addrsize: int = addrsize

class ParsedFixedSize(ParsedObject):
    def __init__(self: 'ParsedFixedSize', source_code: str, source_location: int, source_token: pp.ParseResults, size: int) -> None:
        super().__init__(source_code, source_location, source_token)
        self.size: int = size

class ParsedUserDefinedTypename(ParsedObject):
    def __init__(self: 'ParsedUserDefinedTypename', source_code: str, source_location: int, source_token: pp.ParseResults, name: str) -> None:
        super().__init__(source_code, source_location, source_token)
        self.name: str = name

class ParsedTypename(ParsedObject):
    def __init__(self: 'ParsedTypename', source_code: str, source_location: int, source_token: pp.ParseResults, name: str, builtin: bool) -> None:
        super().__init__(source_code, source_location, source_token)
        self.name: str = name
        self.builtin: bool = builtin

class ParsedQualifiedMemberName(ParsedObject):
    def __init__(self: 'ParsedQualifiedMemberName', source_code: str, source_location: int, source_token: pp.ParseResults, name: list[ParsedUserDefinedTypename]) -> None:
        super().__init__(source_code, source_location, source_token)
        self.name: list[ParsedUserDefinedTypename] = name

class ParsedPointerSuffix(ParsedObject):
    def __init__(self: 'ParsedPointerSuffix', source_code: str, source_location: int, source_token: pp.ParseResults) -> None:
        super().__init__(source_code, source_location, source_token)

class ParsedDynamicArraySizeSuffix(ParsedObject):
    def __init__(self: 'ParsedDynamicArraySizeSuffix', source_code: str, source_location: int, source_token: pp.ParseResults) -> None:
        super().__init__(source_code, source_location, source_token)

class ParsedType(ParsedObject): pass

class ParsedScalarType(ParsedType):
    def __init__(self: 'ParsedScalarType', source_code: str, source_location: int, source_token: pp.ParseResults, type: ParsedTypename) -> None:
        super().__init__(source_code, source_location, source_token)
        self.type: ParsedTypename = type

class ParsedPointerType(ParsedType):
    def __init__(self: 'ParsedPointerType', source_code: str, source_location: int, source_token: pp.ParseResults, base: ParsedType) -> None:
        super().__init__(source_code, source_location, source_token)
        self.base: ParsedType = base

class ParsedArrayType(ParsedType):
    def __init__(self: 'ParsedArrayType', source_code: str, source_location: int, source_token: pp.ParseResults, base: ParsedType, size: ParsedNumber | ParsedQualifiedMemberName | ParsedDynamicArraySizeSuffix) -> None:
        super().__init__(source_code, source_location, source_token)
        self.base: ParsedType = base
        self.size: ParsedNumber | ParsedQualifiedMemberName | ParsedDynamicArraySizeSuffix = size

class ParsedStructMember(ParsedObject):
    def __init__(
            self,
            source_code: str,
            source_location: int,
            source_token: pp.ParseResults,
            name: ParsedUserDefinedTypename,
            type: ParsedType,
            endianess: ParsedEndianess | None,
            addrsize: ParsedAddressSize | None,
            fixedsize: ParsedFixedSize | None,
    ) -> None:
        super().__init__(source_code, source_location, source_token)
        self.name: ParsedUserDefinedTypename = name
        self.type: ParsedType = type
        self.endianess: ParsedEndianess | None = endianess
        self.addrsize: ParsedAddressSize | None = addrsize
        self.fixedsize: ParsedFixedSize | None = fixedsize

class ParsedStructBody(ParsedObject):
    def __init__(self: 'ParsedStructBody', source_code: str, source_location: int, source_token: pp.ParseResults, members: list[ParsedStructMember]) -> None:
        super().__init__(source_code, source_location, source_token)
        self.members: list[ParsedStructMember] = members

class ParsedStructDefinition(ParsedType):
    def __init__(
            self,
            source_code: str,
            source_location: int,
            source_token: pp.ParseResults,
            parse: bool,
            type: StructType,
            name: str,
            inline: bool,
            body: ParsedStructBody,
            addrsize: ParsedAddressSize | None,
            endianess: ParsedEndianess | None,
            fixedsize: ParsedFixedSize | None
    ) -> None:
        super().__init__(source_code, source_location, source_token)
        self.parse: bool = parse
        self.type: StructType = type
        self.name: str = name
        self.inline: bool = inline
        self.body: ParsedStructBody = body
        self.addrsize: ParsedAddressSize | None = addrsize
        self.endianess: ParsedEndianess | None = endianess
        self.fixedsize: ParsedFixedSize | None = fixedsize

class ParsedEnumMember(ParsedObject):
    def __init__(self, source_code: str, source_location: int, source_token: pp.ParseResults, name: str, value: ParsedNumber | None) -> None:
        super().__init__(source_code, source_location, source_token)
        self.name: str = name
        self.value: ParsedNumber | None = value

class ParsedEnumBody(ParsedObject):
    def __init__(self: 'ParsedEnumBody', source_code: str, source_location: int, source_token: pp.ParseResults, members: list[ParsedEnumMember]) -> None:
        super().__init__(source_code, source_location, source_token)
        self.members: list[ParsedEnumMember] = members

class ParsedEnumDefinition(ParsedType):
    def __init__(
            self,
            source_code: str,
            source_location: int,
            source_token: pp.ParseResults,
            flags: bool,
            name: str,
            base_type: ParsedTypename | None,
            body: ParsedEnumBody,
            addrsize: ParsedAddressSize | None,
            endianess: ParsedEndianess | None
    ) -> None:
        super().__init__(source_code, source_location, source_token)
        self.name: str = name
        self.flags: bool = flags
        self.body: ParsedEnumBody = body
        self.base_type: ParsedTypename | None = base_type
        self.addrsize: ParsedAddressSize | None = addrsize
        self.endianess: ParsedEndianess | None = endianess

class ParsedFile(ParsedObject):
    def __init__(self: 'ParsedFile', source_code: str, source_location: int, source_token: pp.ParseResults, definitions: list[ParsedStructDefinition | ParsedEnumDefinition]) -> None:
        super().__init__(source_code, source_location, source_token)
        self.definitions: list[ParsedStructDefinition | ParsedEnumDefinition] = definitions


class ParserConstructor:
    BUILTIN_TYPES: list[str] = [
        'uint',
        'uint8',
        'uint16',
        'uint32',
        'uint64',
        'uint128',
        'int',
        'int8',
        'int16',
        'int32',
        'int64',
        'int128',
        'float16',
        'float32',
        'float64',
        'float128',
        'bool8',
        'bool16',
        'bool32',
        'bool64',
        'bool128',
        'bool',
        'void',
        'addr',
        'bool64',
        'bool128',
        'ptr',
        'byte',
        'uuid',
        'ipv4',
        'bool64',
        'bool128',
        'ipv6',
        'mac',
        'time32',
        'str',
        'cstr',
        'lstr',
        'wstr',
        'ustr',
        'custr',
        'lustr',
        'cwstr',
        'lwstr',
        'wcstr',
        'wlstr',
        'ucstr',
        'ulstr',
        'char',
        'uchar',
        'wchar',
        'char8',
        'char16',
        'char32',
    ]
    KEYWORDS: list[str] = [
        'struct',
        'union',
        'enum',
        'flags',
        'parse',
        '__x8',
        '__x16',
        '__x32',
        '__x64',
        '__x86',
        '__le',
        '__be',
        '__lsb',
        '__msb',
        *BUILTIN_TYPES,
    ]
    BUILTIN_TYPES_PATTERN: str = f'({"|".join(BUILTIN_TYPES)})'
    NUMBERS_PATTERN: str = r'\b((?P<dec>[0-9_]+)|(?P<bin>0b[01_]+)|(?P<hex>0x[0-9a-f_]+)|(?P<oct>0o[0-7_]+))\b'
    SIZE_MODIFIERS_PATTERN: str = r'__x(86?|16|32|64)'
    BYTE_ORDER_MODIFIERS_PATTERN: str = r'__([lm]sb|[lb]e)'


    @staticmethod
    def _token_number() -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedNumber:
            if dec_ := toks.get('dec'):
                value = int(dec_.replace('_', ''), 10)
            elif bin_ := toks.get('bin'):
                value = int(bin_.replace('_', ''), 2)
            elif hex_ := toks.get('hex'):
                value = int(hex_.replace('_', ''), 16)
            elif oct_ := toks.get('oct'):
                value = int(oct_.replace('_', ''), 8)
            else:
                raise pp.ParseException(s, loc, f'Invalid or unparsable number: {toks}')

            return ParsedNumber(s, loc, toks, value)

        number = pp.Regex(ParserConstructor.NUMBERS_PATTERN, re.I)
        number.set_parse_action(action)

        return number

    @staticmethod
    def _token_modifier_endianess() -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedEndianess:
            if (res := Endianness.parse(toks[0])) is not None:
                return ParsedEndianess(s, loc, toks, res)
            else:
                raise pp.ParseException(s, loc, f'Unknown or invalid endianess/byte order: {toks[0]}')

        endianess = pp.Regex(ParserConstructor.BYTE_ORDER_MODIFIERS_PATTERN, re.I)
        endianess.set_parse_action(action)

        return endianess

    @staticmethod
    def _token_modifier_addrsize() -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedAddressSize:
            size_str: str = toks[0].strip().lower()
            size: int | None = {
                '__x8': 1,
                '__x16': 2,
                '__x32': 4,
                '__x86': 4,
                '__x64': 8,
            }.get(size_str, None)

            if size is not None:
                return ParsedAddressSize(s, loc, toks, size)
            else:
                raise pp.ParseException(s, loc, f'Unknown or invalid address size: {toks[0]}')

        token_modifier_addrsize = pp.Regex(ParserConstructor.SIZE_MODIFIERS_PATTERN, re.I)
        token_modifier_addrsize.set_parse_action(action)

        return token_modifier_addrsize

    @staticmethod
    def _token_typename_userdef(token_identifier: pp.ParserElement) -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedUserDefinedTypename:
            return ParsedUserDefinedTypename(s, loc, toks, toks.name or toks.userdef) # TODO: fix this shite

        token_typename_userdef: pp.ParserElement = token_identifier('name')
        token_typename_userdef.set_parse_action(action)

        return token_typename_userdef

    @staticmethod
    def _token_typename(token_typename_userdef: pp.ParserElement) -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedTypename:
            if 'builtin' in toks[0]:
                return ParsedTypename(s, loc, toks, toks[0].builtin, True)
            elif 'userdef' in toks[0]:
                name: ParsedUserDefinedTypename = toks[0].userdef
                return ParsedTypename(s, loc, toks, name.name, False)
            else:
                raise pp.ParseException(s, loc, f'Invalid type name: {toks}')

        token_typename_builtin = pp.Regex(ParserConstructor.BUILTIN_TYPES_PATTERN, re.I)
        token_typename = pp.Group(token_typename_builtin('builtin') | token_typename_userdef('userdef'))
        token_typename.set_parse_action(action)

        return token_typename

    @staticmethod
    def _token_qualified_membername(token_typename_userdef: pp.ParserElement, symbol_dot: pp.ParserElement) -> pp.ParserElement:
        def action(s, loc, toks: pp.ParseResults) -> ParsedQualifiedMemberName:
            names: list[ParsedUserDefinedTypename] = toks.as_list()
            return ParsedQualifiedMemberName(s, loc, toks, names)

        token_qualified_membername = pp.DelimitedList(token_typename_userdef, symbol_dot)
        token_qualified_membername.set_parse_action(action)

        return token_qualified_membername

    @staticmethod
    def _token_constraint_fixedsize(symbol_leftangle: pp.ParserElement, token_number: pp.ParserElement, symbol_rightangle: pp.ParserElement) -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedFixedSize:
            number: ParsedNumber = toks[0].value

            return ParsedFixedSize(s, loc, toks, number.value)

        token_fixed_size_constraint = pp.Group(symbol_leftangle + token_number('value') + symbol_rightangle)
        token_fixed_size_constraint.set_parse_action(action)

        return token_fixed_size_constraint

    @staticmethod
    def _token_array_dimension(token_number: pp.ParserElement, token_qualified_typename: pp.ParserElement) -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedNumber | ParsedQualifiedMemberName:
            if fixed_size := toks[0].get('fixed'):
                fixed_size: ParsedNumber
                return fixed_size
            elif dynamic := toks[0].get('dynamic'):
                dynamic: ParsedQualifiedMemberName
                return dynamic
            else:
                raise pp.ParseException(s, loc, f'Invalid array size/dimension: {toks}')

        token_array_dimension = pp.Group(token_number('fixed') | token_qualified_typename('dynamic'))
        token_array_dimension.set_parse_action(action)

        return token_array_dimension

    @staticmethod
    def _token_array_size(symbol_leftbracket: pp.ParserElement, token_array_dimension: pp.ParserElement, symbol_comma: pp.ParserElement, symbol_rightbracket: pp.ParserElement) -> pp.ParserElement:
        def action(s, loc, toks: pp.ParseResults) -> list[ParsedNumber | ParsedQualifiedMemberName | ParsedDynamicArraySizeSuffix]:
            sizes: list[ParsedNumber | ParsedQualifiedMemberName] | None = toks[0].get('size', None) # type: ignore

            return [ParsedDynamicArraySizeSuffix(s, loc, toks)] if len(sizes or []) == 0 else sizes # type: ignore

        token_array_size = pp.Group(
            symbol_leftbracket +
            pp.Optional(pp.DelimitedList(token_array_dimension, symbol_comma))('size') +
            symbol_rightbracket
        )
        token_array_size.set_parse_action(action)

        return token_array_size

    @staticmethod
    def _token_type_suffix(symbol_pointer: pp.ParserElement, token_array_size: pp.ParserElement) -> pp.ParserElement:
        def action(s, loc, toks: pp.ParseResults) -> list[ParsedNumber | ParsedQualifiedMemberName | ParsedDynamicArraySizeSuffix | ParsedPointerSuffix]:
            suffixes: list[ParsedNumber | ParsedQualifiedMemberName | ParsedDynamicArraySizeSuffix | ParsedPointerSuffix] = []

            for suffixlist in toks.as_list():
                for suffix in suffixlist:
                    if isinstance(suffix, str) or suffix == '*':
                        suffixes.append(ParsedPointerSuffix(s, loc, toks)) # TODO : fix incorrect location
                    elif isinstance(suffix, ParsedNumber) or \
                         isinstance(suffix, ParsedQualifiedMemberName) or \
                         isinstance(suffix, ParsedDynamicArraySizeSuffix):
                        suffixes.append(suffix)
                    else:
                        raise pp.ParseException(s, loc, f'Invalid type suffix: {suffix}')

            return suffixes

        token_type_suffix = pp.ZeroOrMore(pp.Group(symbol_pointer | token_array_size))
        token_type_suffix.set_parse_action(action)

        return token_type_suffix

    @staticmethod
    def _token_inline_struct_definition(keyword_struct: pp.ParserElement, keyword_union: pp.ParserElement, token_struct_body: pp.ParserElement) -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedStructDefinition:
            body: ParsedStructBody = toks[0].body
            type: StructType = StructType(toks[0].type)

            return ParsedStructDefinition(
                s, loc, toks,
                False,
                type,
                str(uuid.uuid4()), # anonymous struct/union
                True,
                body,
                None,
                None,
                None
            )

        token_inline_struct_definition = pp.Group((keyword_struct | keyword_union)('type') + token_struct_body('body'))
        token_inline_struct_definition.set_parse_action(action)

        return token_inline_struct_definition

    @staticmethod
    def _token_struct_member(
            token_typename_userdef: pp.ParserElement,
            symbol_colon: pp.ParserElement,
            token_modifier_endianess: pp.ParserElement,
            token_modifier_addrsize: pp.ParserElement,
            token_type_identifier: pp.ParserElement,
            token_fixed_size_constraint: pp.ParserElement,
            symbol_semicolon: pp.ParserElement
    ) -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedStructMember:
            name: ParsedUserDefinedTypename = toks[0].name
            type: ParsedType = toks[0].type
            endianess: ParsedEndianess | None = toks[0].get('endianess')
            addrsize: ParsedAddressSize | None = toks[0].get('addrsize')
            fixedsize: ParsedFixedSize | None = toks[0].fixedsize[0] if 'fixedsize' in toks[0] else None

            return ParsedStructMember(
                s,
                loc,
                toks,
                name,
                type,
                endianess,
                addrsize,
                fixedsize
            )

        token_struct_member = pp.Group(
            token_typename_userdef('name') +
            symbol_colon +
            pp.Optional(token_modifier_endianess)('endianess') +
            pp.Optional(token_modifier_addrsize)('addrsize') +
            token_type_identifier('type') +
            pp.Optional(token_fixed_size_constraint)('fixedsize') +
            symbol_semicolon
        )
        token_struct_member.set_parse_action(action)

        return token_struct_member

    @staticmethod
    def _token_struct_body(token_struct_member: pp.ParserElement, symbol_leftbrace: pp.ParserElement, symbol_rightbrace: pp.ParserElement) -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedStructBody:
            members: list[ParsedStructMember] = toks[0].members.as_list()
            return ParsedStructBody(s, loc, toks, members)

        token_struct_members = pp.ZeroOrMore(token_struct_member)
        token_struct_body = pp.Group(symbol_leftbrace + token_struct_members('members') + symbol_rightbrace)
        token_struct_body.set_parse_action(action)

        return token_struct_body

    @staticmethod
    def _token_type_identifier(
            token_type_identifier: pp.Forward,
            token_inline_struct_definition: pp.ParserElement,
            token_typename: pp.ParserElement,
            token_type_suffix: pp.ParserElement
    ) -> pp.Forward:
        def action(s, loc, toks) -> ParsedType:
            basetype: ParsedType

            if inline := toks[0].get('inline'):
                inline: ParsedStructDefinition
                basetype = inline
            elif base := toks[0].get('base'):
                base: ParsedTypename
                basetype = ParsedScalarType(s, loc, toks, base)
            else:
                raise pp.ParseException(s, loc, f'Invalid type identifier: {toks[0]}')

            suffixes: list[ParsedNumber | ParsedQualifiedMemberName | ParsedDynamicArraySizeSuffix | ParsedPointerSuffix] = toks[0].get('suffix', [])

            for suffix in suffixes:
                if isinstance(suffix, ParsedPointerSuffix):
                    basetype = ParsedPointerType(suffix._source_code, suffix._source_location, suffix._source_token, basetype)
                elif isinstance(suffix, ParsedDynamicArraySizeSuffix) or isinstance(suffix, ParsedNumber) or isinstance(suffix, ParsedQualifiedMemberName):
                    basetype = ParsedArrayType(suffix._source_code, suffix._source_location, suffix._source_token, basetype, suffix)
                else:
                    raise pp.ParseException(s, loc, f'Invalid type suffix: {suffix}')

            return basetype

        token_type_identifier <<= pp.Group((token_inline_struct_definition('inline') | token_typename('base')) + token_type_suffix('suffix'))
        token_type_identifier.set_parse_action(action)

        return token_type_identifier

    @staticmethod
    def _token_struct_definition(
            keyword_parse: pp.ParserElement,
            token_modifier_endianess: pp.ParserElement,
            token_modifier_addrsize: pp.ParserElement,
            keyword_struct: pp.ParserElement,
            keyword_union: pp.ParserElement,
            token_typename_userdef: pp.ParserElement,
            token_fixed_size_constraint: pp.ParserElement,
            token_struct_body: pp.ParserElement,
            symbol_semicolon: pp.ParserElement
    ) -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedStructDefinition:
            parse: bool = 'parse' in toks[0]
            endianess: ParsedEndianess | None = toks[0].get('endianess')
            addrsize: ParsedAddressSize | None = toks[0].get('addrsize')
            fixedsize: ParsedFixedSize | None = toks[0].get('fixedsize')
            type: StructType = StructType(toks[0].type)
            name: ParsedUserDefinedTypename = toks[0].name
            body: ParsedStructBody = toks[0].body

            return ParsedStructDefinition(s, loc, toks, parse, type, name.name, False, body, addrsize, endianess, fixedsize)

        token_struct_definition: pp.ParserElement = pp.Group(
            pp.Optional(keyword_parse)('parse') +
            pp.Optional(token_modifier_endianess)('endianess') +
            pp.Optional(token_modifier_addrsize)('addrsize') +
            (keyword_struct | keyword_union)('type') +
            token_typename_userdef('name') +
            pp.Optional(token_fixed_size_constraint)('fixedsize') +
            token_struct_body('body') +
            symbol_semicolon
        )
        token_struct_definition.set_parse_action(action)

        return token_struct_definition

    @staticmethod
    def _token_enum_member(token_typename_userdef: pp.ParserElement, symbol_equal: pp.ParserElement, token_number: pp.ParserElement, symbol_semicolon: pp.ParserElement) -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedEnumMember:
            name: str = toks[0].name
            value: ParsedNumber | None = toks[0].value if 'value' in toks[0] else None

            print('ENUM MEMBER',_dumps(toks[0]))
            return ParsedEnumMember(s, loc, toks, name, value)

        token_enum_member = pp.Group(
            token_typename_userdef('name') +
            pp.Optional(symbol_equal + token_number('value')) +
            symbol_semicolon
        )
        token_enum_member.set_parse_action(action)

        return token_enum_member

    @staticmethod
    def _token_enum_body(token_enum_member: pp.ParserElement, symbol_leftbrace: pp.ParserElement, symbol_rightbrace: pp.ParserElement) -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedEnumBody:
            members: list[ParsedEnumMember] = toks[0].members.as_list()
            return ParsedEnumBody(s, loc, toks, members)

        token_enum_members = pp.ZeroOrMore(token_enum_member)
        token_enum_body = pp.Group(symbol_leftbrace + token_enum_members('members') + symbol_rightbrace)
        token_enum_body.set_parse_action(action)

        return token_enum_body

    @staticmethod
    def _token_enum_definition(
            token_modifier_endianess: pp.ParserElement,
            token_modifier_addrsize: pp.ParserElement,
            keyword_flags: pp.ParserElement,
            keyword_enum: pp.ParserElement,
            token_typename: pp.ParserElement,
            token_typename_userdef: pp.ParserElement,
            token_enum_body: pp.ParserElement,
            symbol_colon: pp.ParserElement,
            symbol_semicolon: pp.ParserElement
    ) -> pp.ParserElement:
        def action(s, loc, toks) -> ParsedEnumDefinition:
            flags: bool = 'flags' in toks[0]
            endianess: ParsedEndianess | None = toks[0].get('endianess')
            addrsize: ParsedAddressSize | None = toks[0].get('addrsize')
            name: ParsedUserDefinedTypename = toks[0].name
            base: ParsedTypename | None = toks[0].get('base_type')
            body: ParsedEnumBody = toks[0].body

            return ParsedEnumDefinition(s, loc, toks, flags, name.name, base, body, addrsize, endianess)

        token_enum_definition: pp.ParserElement = pp.Group(
            pp.Optional(token_modifier_endianess)('endianess') +
            pp.Optional(token_modifier_addrsize)('addrsize') +
            pp.Optional(keyword_flags)('flags') +
            keyword_enum('type') +
            token_typename_userdef('name') +
            pp.Optional(
                symbol_colon + token_typename('base_type')
            ) +
            token_enum_body('body') +
            symbol_semicolon
        )
        token_enum_definition.set_parse_action(action)

        return token_enum_definition

    @staticmethod
    def _token_code_file(token_struct_definition: pp.ParserElement, token_enum_definition: pp.ParserElement) -> pp.ParserElement:
        def action(s: str, loc: int, toks: pp.ParseResults) -> ParsedFile:
            definitions: list[ParsedStructDefinition | ParsedEnumDefinition] = toks.as_list()
            return ParsedFile(s, loc, toks, definitions)

        token_code_file = pp.ZeroOrMore(token_struct_definition | token_enum_definition)
        token_code_file.set_parse_action(action)

        return token_code_file


# Grammar: see README.md
class LayoutParser():
    def __init__(self: 'LayoutParser') -> None:
        comment: pp.ParserElement = pp.cpp_style_comment | pp.python_style_comment

        token_number: pp.ParserElement = ParserConstructor._token_number()
        token_modifier_endianess: pp.ParserElement = ParserConstructor._token_modifier_endianess()
        token_modifier_addrsize: pp.ParserElement = ParserConstructor._token_modifier_addrsize()

        symbol_dot = pp.Suppress(MEMBER_DELIMITER)
        symbol_comma = pp.Suppress(',')
        symbol_pointer = pp.Word('*', exact = 1)
        symbol_colon = pp.Suppress(':')
        symbol_equal = pp.Suppress('=')
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
        keyword_enum = pp.Keyword('enum')
        keyword_flags = pp.Keyword('flags')
        keyword_parse = pp.Keyword('parse')

        token_identifier = pp.Word(pp.alphas + '_', pp.alphanums + '_')
        token_type_identifier = pp.Forward()

        token_typename_userdef: pp.ParserElement = ParserConstructor._token_typename_userdef(token_identifier)
        token_typename: pp.ParserElement = ParserConstructor._token_typename(token_typename_userdef)
        token_qualified_membername: pp.ParserElement = ParserConstructor._token_qualified_membername(token_typename_userdef, symbol_dot)
        token_fixed_size_constraint: pp.ParserElement = ParserConstructor._token_constraint_fixedsize(symbol_leftangle, token_number, symbol_rightangle)
        token_struct_member: pp.ParserElement = ParserConstructor._token_struct_member(
            token_typename_userdef,
            symbol_colon,
            token_modifier_endianess,
            token_modifier_addrsize,
            token_type_identifier,
            token_fixed_size_constraint,
            symbol_semicolon
        )
        token_struct_body: pp.ParserElement = ParserConstructor._token_struct_body(token_struct_member, symbol_leftbrace, symbol_rightbrace)
        token_struct_definition: pp.ParserElement = ParserConstructor._token_struct_definition(
            keyword_parse,
            token_modifier_endianess,
            token_modifier_addrsize,
            keyword_struct,
            keyword_union,
            token_typename_userdef,
            token_fixed_size_constraint,
            token_struct_body,
            symbol_semicolon
        )

        token_enum_member: pp.ParserElement = ParserConstructor._token_enum_member(token_typename_userdef, symbol_equal, token_number, symbol_semicolon)
        token_enum_body: pp.ParserElement = ParserConstructor._token_enum_body(token_enum_member, symbol_leftbrace, symbol_rightbrace)
        token_enum_definition: pp.ParserElement = ParserConstructor._token_enum_definition(
            token_modifier_endianess,
            token_modifier_addrsize,
            keyword_flags,
            keyword_enum,
            token_typename,
            token_typename_userdef,
            token_enum_body,
            symbol_colon,
            symbol_semicolon
        )

        token_inline_struct_definition: pp.ParserElement = ParserConstructor._token_inline_struct_definition(keyword_struct, keyword_union, token_struct_body)
        token_array_dimension: pp.ParserElement = ParserConstructor._token_array_dimension(token_number, token_qualified_membername)
        token_array_size: pp.ParserElement = ParserConstructor._token_array_size(symbol_leftbracket, token_array_dimension, symbol_comma, symbol_rightbracket)
        token_type_suffix: pp.ParserElement = ParserConstructor._token_type_suffix(symbol_pointer, token_array_size)
        token_type_identifier: pp.Forward = ParserConstructor._token_type_identifier(token_type_identifier, token_inline_struct_definition, token_typename, token_type_suffix)

        self.parser: pp.ParserElement = ParserConstructor._token_code_file(token_struct_definition, token_enum_definition)
        self.parser.ignore_whitespace()
        self.parser.ignore(comment)
        self.parser.mayIndexError = True


    def __call__(self: 'LayoutParser', string: str) -> ParsedFile | None:
        raw: pp.ParseResults = self.parser.parseString(string, parse_all = True)
        parsed: list[ParsedFile] = raw.as_list()

        if len(parsed) == 0:
            return None
        elif len(parsed) == 1:
            return parsed[0]
        else:
            raise pp.ParseException(string, 0, f'Multiple ({len(parsed)}) instances of "{type(ParsedFile)}" parsed.')
