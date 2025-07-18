import React from 'react';
import { Buffer } from 'buffer';

import { Editor } from 'prism-react-editor';
import { languages } from 'prism-react-editor/prism';
import { BasicSetup } from 'prism-react-editor/setups';
// import { matchBrackets } from 'prism-react-editor/match-brackets';

import 'prism-react-editor/languages/common';
import 'prism-react-editor/prism/languages/cpp';

import 'prism-react-editor/layout.css';
import 'prism-react-editor/themes/github-dark.css';
import 'prism-react-editor/search.css';
import 'prism-react-editor/invisibles.css';



const uuid4 = () => "10000000-1000-4000-8000-100000000000".replace(/[018]/g, c =>
    (+c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> +c / 4).toString(16)
);

const btoa = data => Buffer.from(data).toString('base64');

const atob = data => Buffer.from(data, 'base64');

const hex = (value, length = 2) => Number(value).toString(16).padStart(length, '0');

const ascii8 = value =>
{
    if (value === null || value === undefined)
        return '';

    value = Number(value);

    if (value < 0 || value > 255)
        return <span className="error">?</span>;
    else if (value <= 32)
        return <span className="control">{'␀␁␂␃␄␅␆␇␈␉␊␋␌␍␎␏␐␑␒␓␔␕␖␗␘␙␚␛␜␝␞␟␠'[value]}</span>;
    else if (value === 127)
        return <span className="control">␡</span>;
    else
        return String.fromCharCode(value);
}

function* chunk_into(arr, n)
{
    const count = Math.ceil(arr.length / n);

    for (let i = 0; i < count; ++i)
    {
        const chunk = arr.slice(i * n, (i + 1) * n);
        const end = Array(n - chunk.length).fill(null);

        yield [...chunk, ...end];
    }
}

function useVariable(initial_value)
{
    const [value, set_value] = React.useState(initial_value);

    return {
        value: value,
        initial: initial_value,
        set: set_value,
        trigger_update: () => set_value(value),
        get: () => value,
    };
}

async function CallAPI(url, data)
{
    url = `${window.location.origin}/api/${url}`;

    const id = uuid4();
    const payload = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Request-ID': id,
            'X-Request-Source': 'pythia',
        },
        body: JSON.stringify(data),
    };

    console.log(`${id} >>> ${url}`, data);

    const response = await fetch(url, payload);

    if (!response.ok)
    {
        const error = await response.text();

        console.error(`${id} <<< ${url}: error ${response.status}`, error);

        throw new Error(`API call failed: (${response.status}) ${error}`);
    }
    else
    {
        data = await response.json();

        console.log(`${id} <<< ${url}: success`, data);

        return data;
    }
}



const INITIAL_CODE = `// example Pythia code for parsing an ELF binary file

__le __x64 struct ELF_HEADER
{
    e_ident: struct
    {
        ei_magic:       char[4];
        ei_class:       uint8;
        ei_data:        uint8;
        ei_version:     uint8;
        ei_osabi:       uint8;
        ei_abiversion:  uint8;
        ei_pad:         void<6>;
        ei_nident:      uint8;
    };
    e_type:         uint16;
    e_machine:      uint16;
    e_version:      uint32;
    e_entry:        void*;
    e_phoff:        ELF_PROGRAM_HEADER*;
    e_shoff:        ELF_SECTION_HEADER*;
    e_flags:        uint32;
    e_ehsize:       uint16;
    e_phentsize:    uint16;
    e_phnum:        uint16;
    e_shentsize:    uint16;
    e_shnum:        uint16;
    e_shstrndx:     uint16;
};

skip __le __x64 struct ELF_PROGRAM_HEADER {
    p_type:         uint32;
    p_flags:        uint32;
    p_offset:       ptr;
    p_vaddr:        ptr;
    p_paddr:        ptr;
    p_filesz:       uint64;
    p_memsz:        uint64;
    p_align:        uint64;
};

skip __le __x64 struct ELF_SECTION_HEADER {
    sh_name:        uint32;
    sh_type:        uint32;
    sh_flags:       uint64;
    sh_addr:        ptr;
    sh_offset:      ptr;
    sh_size:        uint64;
    sh_link:        uint32;
    sh_info:        uint32;
    sh_addralign:   uint64;
    sh_entsize:     uint64;
};
`;
const FileContext = React.createContext(null);
const CodeContext = React.createContext(null);
const SettingsContext = React.createContext(null);


function FileProvider({ children })
{
    const cursor_pos = useVariable(0);
    const cursor_len = useVariable(1);
    const file = useVariable(null);

    const set_current_file = async id_or_name =>
    {
        const data = await CallAPI('file/info', {
            name: id_or_name,
            full: true,
        });

        data.data = atob(data.data || '', );

        file.set(data);
        set_cursor(0);
    };
    const upload_file = async (name, bytes, mime = 'application/octet-stream') =>
    {
        const data = await CallAPI('file/upload', {
            name: name,
            data: btoa(String.fromCharCode(...bytes)),
            mime: mime,
        });

        await set_current_file(data.id);
    };
    const set_cursor = (pos, len = 1) =>
    {
        if (pos === cursor_pos.value && len === cursor_len.value)
            return;

        pos = Math.max(0, pos || 0);
        len = Math.max(1, len || 1);

        if (file.value && pos + len > file.value.data.length)
        {
            if (pos >= file.value.data.length)
                pos = file.value.data.length - 1;
            else
                len = file.value.data.length - pos;
        }

        cursor_pos.set(pos);
        cursor_len.set(len);
    }

    return <FileContext.Provider value={{
        current_file: file,
        set_current_file,
        upload_file,
        set_cursor,
        offset: cursor_pos.value,
        length: cursor_len.value,
    }}>
        {children}
    </FileContext.Provider>;
}

function CodeProvider({ children })
{
    const code = useVariable(null);
    const parsed = useVariable(null);
    const error_list = useVariable(null);

    const set_code = async code_text =>
    {
        if (code_text === code.value)
            return;

        code.set(code_text);

        const data = await CallAPI('code/parse', { code: code_text });

        if (data.success)
        {
            parsed.set(data.parsed);
            error_list.set(null);
        }
        else
        {
            const error_data = data.error || {
                'type': '(unknown)',
                'message': 'An unknown error occurred while parsing the code.',
                'line': 0,
                'column': 0,
                'text': null,
            };

            error_data.length = (error_data.text || '').length;
            parsed.set(null);
            error_list.set([error_data]);
        }
    }

    return <CodeContext.Provider value={{
        code,
        parsed,
        error_list,
        set_code
    }}>
        {children}
    </CodeContext.Provider>;
}

function SettingsProvider({ children })
{
    const little_endian = useVariable(true);
    const pointer_size = useVariable(8);

    const set_endianness = value =>
    {
        value = value.toUpperCase();

        const be = value === 'BE' || value === 'BIG';

        little_endian.set(!be);
    }
    const set_pointer_size = value =>
    {
        value = +value;

        if (value == 1 || value == 2 || value == 4 || value == 8)
            pointer_size.set(value);
        else
            console.warn(`Invalid pointer size: ${value}. Must be one of 1, 2, 4, or 8.`);
    }

    return <SettingsContext.Provider value={{
        little_endian: {
            get: () => little_endian.value,
            set: set_endianness,
        },
        pointer_size: {
            get: () => pointer_size.value,
            set: set_pointer_size,
        },
    }}>
        {children}
    </SettingsContext.Provider>;
}

function BinaryViewer()
{
    const { little_endian, pointer_size } = React.useContext(SettingsContext);
    const { current_file, offset, length, set_cursor } = React.useContext(FileContext);
    const inspected = useVariable(null);
    const ptr_size = pointer_size.get();
    const le = little_endian.get();

    React.useEffect(() =>
    {
        (async () => {
            if (current_file.value && current_file.value.id)
                inspected.set(await CallAPI('file/inspect', {
                    name: current_file.value.id,
                    offset: offset,
                    length: length,
                    pointer_size: ptr_size,
                    little_endian: le,
                }));
        })();
    }, [current_file.value, offset, ptr_size, le]);

    if (!current_file.value || !current_file.value.data)
        return <div className="error">No file selected or file has no data.</div>;

    const data = current_file.value.data;
    const chunk_size = 16;
    const chunks = chunk_into(data, chunk_size);
    const active_row = Math.floor(offset / chunk_size);
    const active_col = offset % chunk_size;

    function viewer_tb(label, val, width = 1, readonly = true, change_handler = null)
    {
        val = val === null || val === undefined ? '' : String(val);

        return <>
            <th>{label}:</th>
            <td colSpan={width}>
                <input type="text"
                       name={label.toLowerCase().replace(/[^\w]/g, '_')}
                       readOnly={!!readonly || null}
                       onChange={readonly ? null : change_handler}
                       autoComplete="off"
                       autoCorrect="off"
                       spellCheck="false"
                       value={val}/>
            </td>
        </>;
    };

    return <binary-viewer>
        <binary-data>
            <table>
                <thead>
                    <tr>
                        <th>Offset {'\xa0'.repeat(11)}</th>
                        <th spacer/>
                        {Array.from({ length: chunk_size }, (_, i) =>
                            <th key={i} active={active_col == i ? '' : null}>{hex(i, 2)}</th>
                        )}
                        <th spacer/>
                        <th spacer/>
                        {Array.from({ length: chunk_size }, (_, i) =>
                            <th key={i} active={active_col == i ? '' : null}>{hex(i, 1)}</th>
                        )}
                    </tr>
                </thead>
                <tbody>
                    {chunks.map((chunk, row) =>
                    {
                        return <tr key={row} active={active_row == row ? '' : null}>
                            <th>0x{hex(row * chunk_size, 16)}</th>
                            <th spacer/>
                            {chunk.map((byte, col) =>
                            {
                                const index = row * chunk_size + col;

                                if (byte === null)
                                    return <td key={index} empty=""/>;
                                else
                                    return <td key={index}
                                               active={active_col == col ? '' : null}
                                               selected={active_col == col && active_row == row ? '' : null}
                                               inspected={index >= offset && index < offset + length ? '' : null}
                                               onClick={() => set_cursor(index,16)}
                                               onContextMenu={e =>
                                               {
                                                    e.preventDefault();
                                                    set_cursor(index, 1);
                                               }}>
                                        {hex(byte, 2)}
                                    </td>;
                            })}
                            <th spacer/>
                            <th spacer/>
                            {chunk.map((byte, col) =>
                            {
                                const index = row * chunk_size + col;

                                if (byte === null)
                                    return <td key={index} empty=""/>;
                                else
                                    return <td key={index}
                                               active={active_col == col ? '' : null}
                                               selected={active_col == col && active_row == row ? '' : null}
                                               onClick={() => set_cursor(index,16)}
                                               onContextMenu={e =>
                                               {
                                                    e.preventDefault();
                                                    set_cursor(index, 1);
                                               }}>
                                        {ascii8(byte)}
                                    </td>;
                            })}
                        </tr>;
                    })}
                </tbody>
            </table>
        </binary-data>
        <binary-inspector>
            {/*
                - jump one byte to the left/right
                - jump one row up/down
                - jump to beginning/end of row
                - jump to next 4 bytes
                - jump to next 8 bytes
                - switch endianness
            */}

            {inspected.value ?
            <table>
                <tbody>
                    <tr>
                        {viewer_tb('Offset', `0x${hex(offset, ptr_size * 2)}:0x${hex(offset + length, ptr_size * 2)}`, 3)}
                        {viewer_tb('Length', inspected.value.length)}
                    </tr>
                    <tr>
                        {viewer_tb('Value', inspected.value.hex, 3)}
                        {viewer_tb('Base64', inspected.value.base64)}
                    </tr>
                    <tr>
                        {viewer_tb('Binary', inspected.value.binary, 5)}
                    </tr>
                    <tr>
                        {viewer_tb('ASCII', inspected.value.ascii[0])}
                        {viewer_tb('UTF-8', inspected.value.utf8[0])}
                        {viewer_tb('UTF-16', inspected.value.utf16[0])}
                    </tr>
                    <tr>
                        {viewer_tb('int8', inspected.value.int8)}
                        {/* todo: jump to address */}
                        {viewer_tb('uint8', inspected.value.uint8)}
                        {viewer_tb('bool8', !!inspected.value.uint8)}
                    </tr>
                    <tr>
                        {viewer_tb('int16', inspected.value.int16)}
                        {/* todo: jump to address */}
                        {viewer_tb('uint16', inspected.value.uint16)}
                        {viewer_tb('float16', inspected.value.float16)}
                    </tr>
                    <tr>
                        {viewer_tb('int32', inspected.value.int32)}
                        {/* todo: jump to address */}
                        {viewer_tb('uint32', inspected.value.uint32)}
                        {viewer_tb('float32', inspected.value.float32)}
                    </tr>
                    <tr>
                        {viewer_tb('int64', inspected.value.int64)}
                        {/* todo: jump to address */}
                        {viewer_tb('uint64', inspected.value.uint64)}
                        {viewer_tb('float64', inspected.value.float64)}
                    </tr>
                    <tr>
                        {viewer_tb('int128', inspected.value.int128)}
                        {/* todo: jump to address */}
                        {viewer_tb('uint128', inspected.value.uint128)}
                        {viewer_tb('float128', inspected.value.float128)}
                    </tr>
                    <tr>
                        {viewer_tb('MAC', inspected.value.mac)}
                        {viewer_tb('IPv4', inspected.value.ipv4)}
                        {viewer_tb('IPv4:P.', inspected.value.ipv4port)}
                    </tr>
                    <tr>
                        <th/>
                        <td/>
                        {viewer_tb('IPv6', inspected.value.ipv6, 3)}
                    </tr>
                    <tr>
                        {viewer_tb('time_32t', inspected.value.time32, true)}
                        {viewer_tb('UUID', inspected.value.uuid, 3)}
                    </tr>
                    <tr>
                        <th>x86-64:</th>
                        <td colSpan="5"><input type="text" readOnly/></td>
                    </tr>
                </tbody>
            </table>
            : <div className="error">No data inspected yet.</div>}
        </binary-inspector>
    </binary-viewer>;
}

function CodeEditorExtensions(editor)
{
    // React.useLayoutEffect(() =>
    // {
    //     return editor.on("selectionChange", selection =>
    //     {
    //         console.log("EDITOR > EXTENSIONS > selectionChange", selection);
    //     });
    // }, []);
    React.useEffect(() =>
    {
        editor.textarea.focus();
    }, []);
    const { error_list } = React.useContext(CodeContext);
    const error = (error_list.value || []).length ? error_list.value[0] : null;
    let line = -1, column = -1, length = 0;

    if (error && error.type == 'ParseException')
    {
        line = error.line || 0;
        column = error.column || 0;
        length = error.length || 0;
    }

    return <>
        <error-indicator style={{
            top: `${(line - 1)}lh`,
            left: `${(column - 1)}ch`,
            width: `${length - column + 1}ch`,
            display: error_list.value ? 'block' : 'none',
        }}/>
        <BasicSetup editor={editor}/>
    </>;
}

function CodeEditor()
{
    const { code, set_code } = React.useContext(CodeContext);
    const ready = useVariable(false);

    React.useEffect(() =>
    {
        (async () =>
        {
            const response = await CallAPI('code/syntax', { });

            languages.cpp.keyword = new RegExp(response.keywords);
            languages.cpp.comment.pattern = new RegExp(response.comments);
            languages.cpp.char = undefined;
            languages.cpp.string = undefined;
            languages.cpp.module = undefined;
            languages.cpp.macro = undefined;
            languages.cpp.function = undefined;
            languages.cpp.constant = undefined;
            languages.cpp['raw-string'] = undefined;
            languages.cpp['double-colon'] = undefined;
            languages.cpp['generic-function'] = undefined;

            ready.set(true);
            console.log(languages.cpp);
        })();
    }, []);

    if (!ready.value)
        return <div className="loading">Loading code editor...</div>;
    else
        return <Editor language="cpp"
                       tabSize={4}
                       insertSpaces={true}
                       value={INITIAL_CODE}
                       onChange={set_code}
                       onUpdate={(value, editor) => set_code(value)}
                       children={CodeEditorExtensions}/>;
}

function CodeErrorWindow()
{
    const { error_list } = React.useContext(CodeContext);
    const errors = error_list.value || [];

    return <pythia-error-status status={errors.length ? 'error' : 'ok'}>
        {errors.length ? <>
            {errors.length} error(s) found:
            <ul>
                {errors.map((error, i) =>
                    <li key={i}>
                        <span className="error-type">{error.type}</span>:
                        <span className="error-message">{error.message}</span>
                        {error.line > 0 ? ` at line ${error.line}, column ${error.column}` : ''}
                        {error.text ? ` in "${error.text}"` : ''}
                    </li>
                )}
            </ul>
        </> : 'No errors found'}
    </pythia-error-status>;
}

function OutputWindow()
{
    const { little_endian, pointer_size } = React.useContext(SettingsContext);
    const { parsed, error_list } = React.useContext(CodeContext);
    const { current_file } = React.useContext(FileContext);
    const interpreted = useVariable(null);
    const ptr_size = pointer_size.get();
    const le = little_endian.get();

    React.useEffect(() =>
    {
        if (parsed.value && current_file.value && current_file.value.id)
            (async () =>
            {
                const data = await CallAPI('file/interpret', {
                    code: parsed.value,
                    name: current_file.value.id,
                    offset: 0,
                    little_endian: le,
                    pointer_size: ptr_size,
                });
                const errors = [];

                if (!data.success)
                    (data.errors || []).map(e => errors.push({
                        message: e.message || 'An error occurred while interpreting the binary file.',
                        type: e.type || 'InterpretationError',
                        line: -1,
                        text: data.path,
                        column: -1,
                        length: 0,
                    }));

                error_list.set(errors);
                interpreted.set(data.data || []);
            })();
    }, [
        le,
        ptr_size,
        parsed.value,
        (current_file.value || { id: null }).id
    ]);

    return <output-window>
        <OutputStructure structure={interpreted.value}/>
        {/* <br/>
        <hr/>
        <br/>
        {<$ interpreted={interpreted.value} parsed={parsed.value}/>} */}
    </output-window>;
}

function process_structure(structure)
{
    let max_name_width = 0;
    let max_repr_width = 0;

    function process_element(element, level)
    {
        if (!element)
            return null;

        const children = element.members || [];
        const name = '\xa0'.repeat(level * 4) + element.name;
        const repr = element.repr || '';

        if (max_name_width < name.length)
            max_name_width = name.length;

        if (max_repr_width < repr.length)
            max_repr_width = repr.length;

        return {
            ...element,
            bytes: element.raw ? [...atob(element.raw)] : [],
            name: name,
            repr: repr,
            level: level,
            members: children.map(m => process_element(m, level + 1)),
        };
    }

    return {
        data: (structure || []).map(e => process_element(e, 0)),
        max_name_width: max_name_width,
        max_repr_width: max_repr_width,
    }
}

function OutputStructure({ structure })
{
    structure = process_structure(structure);

    const { pointer_size } = React.useContext(SettingsContext);
    const { set_cursor } = React.useContext(FileContext);
    const collapsed = useVariable({ });
    const ptr_size = pointer_size.get();
    const chunk_size = 16;

    function RenderElement({ element })
    {
        const skipped = element.skip || false;
        let _coll = collapsed.value[element.path];

        if (_coll === undefined)
            collapsed.set({ ...collapsed.value, [element.path]: false });

        _coll = !!_coll;

        if (!element)
            return <tr skipped={skipped ? '' : null}>
                <td/>
                <td colSpan="4">Invalid element</td>
            </tr>;
        else
            return <>
                <tr className="output-element" skipped={skipped ? '' : null}>
                    <th>
                        <element-name displayname={element.name}
                                      indent={element.level}
                                      state={element.members.length ? _coll ? 'closed' : 'open': 'none'}
                                      onClick={() => collapsed.set(() => ({ ...collapsed.value, [element.path]: !_coll }))}/>
                    </th>
                    <td>{element.repr}</td>
                    <td>{element.size}</td>
                    <td>
                        <a onClick={() => set_cursor(element.offset, element.size)}>
                            0x{hex(element.offset, ptr_size * 2)}:0x{hex(element.offset + element.size, ptr_size * 2)}
                        </a>
                    </td>
                    <td>
                        {element.bytes.slice(0, chunk_size).map((byte, i) =>
                            <>
                                <a key={i} onClick={() => set_cursor(element.offset + i)}>
                                    {hex(byte)}
                                </a>
                                &nbsp;
                            </>
                        )}
                        {element.size > chunk_size ? "..." : null}
                    </td>
                </tr>
                {_coll ? null : element.members.map((m, i) =>
                    <RenderElement element={m} key={i}/>
                )}
            </>;
    }

    return <table className="output-structure">
        <thead>
            <tr>
                <th>
                    <element-name displayname={'\xa0'.repeat(structure.max_name_width)} state="none"/>
                </th>
                <th>
                    {'\xa0'.repeat(structure.max_repr_width)}
                </th>
                <th>Size</th>
                <th>Offset</th>
                <th>Bytes</th>
            </tr>
        </thead>
        <tbody>
            {structure.data.map((element, i) =>
                <RenderElement element={element} key={i}/>
            )}
        </tbody>
    </table>;
}

function MainPage()
{
    const { current_file, set_current_file, upload_file } = React.useContext(FileContext);
    const { little_endian, pointer_size } = React.useContext(SettingsContext);

    React.useEffect(() =>
    {
        if (!current_file.value || !current_file.value.id)
            set_current_file('test');
    }, [current_file.value]);

    return <>
        <header>
            <h1>Pythia &mdash; A binary data reverse engineering application</h1>
        </header>
        <pythia-options>
            <input type="file"/>
            <separator/>
            Endianess:
            <select defaultValue={little_endian.get() ? 'LE' : 'BE'}
                    onChange={e => little_endian.set(e.target.value)}>
                <option value="LE">Little Endian</option>
                <option value="BE">Big Endian</option>
            </select>
            <separator/>
            Pointer/Address Size:
            <select defaultValue={`x${pointer_size.get() << 3}`}
                    onChange={e => pointer_size.set(+e.target.value.slice(1) >> 3)}>
                <option value="x8">8 Bit (1 Byte)</option>
                <option value="x16">16 Bit (2 Bytes)</option>
                <option value="x32">32 Bit (4 Bytes)</option>
                <option value="x64">64 Bit (8 Bytes)</option>
            </select>
            <separator/>
        </pythia-options>
        <main>
            <pythia-input>
                <BinaryViewer/>
            </pythia-input>
            <pythia-code>
                <CodeEditor/>
            </pythia-code>
            <pythia-error>
                <CodeErrorWindow/>
            </pythia-error>
            <pythia-output>
                <OutputWindow/>
            </pythia-output>
            <separator v=""/>
            <separator h="1"/>
            <separator h="2"/>
        </main>
        {/* <footer/> */}
    </>;
}

export const MainPageWrapper = () => <SettingsProvider>
                                        <FileProvider>
                                            <CodeProvider>
                                                <MainPage/>
                                            </CodeProvider>
                                        </FileProvider>
                                    </SettingsProvider>;

const $ = element => <pre><code>{JSON.stringify(element, null, 4)}</code></pre> 
