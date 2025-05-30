# Pythia

> [!CAUTION]
> This project is currently work in progress.
> It is not yet a finished product and therefore not ready for usage.

**Pythia** aims to be a light-weight, platform-agnostic analysis and reverse engineering tool for binary data.
(TODO : add description)


## Pythia coding language

In order to decode a given binary data blob, one has to provide the semantic structure of the binary data using a custom C-like programming language.


### Grammar

The language has the following grammar:

```bison
identifier          := /[a-z_]\w*/

number              := /-?[0-9]+/
                     | /-?0b[01]+/
                     | /-?0x[0-9a-f]+/

type_name_userdef   := identifier

type_name_builtin   := 'bool'
                     | 'int8'
                     | 'uint8'
                     | 'int16'
                     | 'uint16'
                     | 'int32'
                     | 'uint32'
                     | 'int128'
                     | 'uint128'
                     | 'float16'
                     | 'float32'
                     | 'float64'
                     | 'float128'
                     | 'uuid'
                     | 'time32'
                     | 'char8'
                     | 'char16'
                     | 'char32'
                     | 'str'
                     | 'cstr'
                    ...

type_name           := type_name_userdef
                     | type_name_builtin

type_definition     := 'struct' type_name_userdef type_body
                     | 'union' type_name_userdef type_body

type_body           := '{' type_fields '}'

type_fields         := [type_fields] type_field

type_field          := [] identifier ':' type_identifier ';'

type_identifier     := type_name
                     | type_identifier '[' array_size ']'
                     | type_identifier '*'

array_dimension     := <empty>
                     | number
                     | type_name_userdef

array_size          := array_dimension
                     | array_size ',' array_dimension
```
