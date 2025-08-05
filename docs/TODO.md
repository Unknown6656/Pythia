# Open TODOs

- [x] `x86`/`x64` assembly
- [x] better error messages, esp. incl. code line/token/symbol
- [x] mapping of symbol to code line/token
- [ ] `float16` support
- [ ] `float128` support
- [ ] `utf32` support
- [ ] `ustr`/`custr`/`ucstr` support
- [ ] length-prefixed string support
- [ ] error on out of range pointer
- [ ] error on recursive types (or clamp to max depth)
- [ ] array of structs/unions
- [ ] enum support
- [ ] seo tags
- [ ] file management (e.g. upload, select, etc.)
- [ ] auto-scroll in inspector
- [ ] range select in inspector
- [ ] jump to address in inspector
- [ ] jump by 1/2/4/8/16/... bytes in inspector
- [ ] performance improvements
- [ ] fix the following:
        ```
        parse __x8 struct S {
            x : int[10];
        };
        ```
        does not parse `int` as 8-bit integer
- [ ] fix the following:
        ```
        __le enum E : int32 {
            A = 0;
            B;
            C;
            ELF = 0x7f454c46;
            NOPE;
        };

        parse __le struct S {
            x : E[10];
        };
        ```
        throws the syntax error `10` times, but interprets everything correctly.