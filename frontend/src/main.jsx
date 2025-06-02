import React from 'react';
import { Buffer } from 'buffer';


import { Editor } from 'prism-react-editor';
import { BasicSetup } from 'prism-react-editor/setups'
// import { matchBrackets } from 'prism-react-editor/match-brackets';

import 'prism-react-editor/prism/languages/cpp'
import 'prism-react-editor/languages/common'

import 'prism-react-editor/layout.css'
import 'prism-react-editor/themes/github-dark.css'
import 'prism-react-editor/search.css'
import 'prism-react-editor/invisibles.css'



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




const INITIAL_CODE = `// example code for Pythia

struct TEST
{
    length : uint8;
    text : char[length];
    composite : struct
    {
        value : int32;
        pointer : int32*;
    };
};
`;
const FileContext = React.createContext(null);
const CodeContext = React.createContext(null);

function FileProvider({ children })
{
    const file = useVariable(null);
    const set_current_file = async id_or_name =>
    {
        const data = await CallAPI('file/info', { name: id_or_name, full: true });

        data.data = atob(data.data || '', );

        file.set(data);
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

    return <FileContext.Provider value={{
        current_file: file,
        set_current_file,
        upload_file
    }}>
        {children}
    </FileContext.Provider>;
}

function CodeProvider({ children })
{
    const code = useVariable(INITIAL_CODE);
    const parsed = useVariable(null);
    const error = useVariable(null);

    const set_code = async code_text =>
    {
        code_text = code_text.trim();

        console.log('#################### SET CODE', code_text);

        if (code_text === code.value)
            return;

        code.set(code_text);

        const data = await CallAPI('code/parse', { code: code_text });

        if (data.success)
        {
            parsed.set(data.parsed);
            error.set(null);
        }
        else
        {
            parsed.set(null);
            error.set(data.error || {
                'type': '(unknown)',
                'message': 'An unknown error occurred while parsing the code.',
                'line': 0,
                'column': 0,
                'text': null,
            });
        }
    }

    return <CodeContext.Provider value={{
        code,
        parsed,
        error,
        set_code
    }}>
        {children}
    </CodeContext.Provider>;
}

function BinaryViewer()
{
    const { current_file } = React.useContext(FileContext);
    const offset = useVariable(0);
    const inspected = useVariable(null);

    React.useEffect(() =>
    {
        (async () => {
            if (current_file.value && current_file.value.id)
                inspected.set(await CallAPI('file/inspect', {
                    name: current_file.value.id,
                    offset: offset.value,
                    length: 16,
                }));
        })();
    }, [current_file.value, offset.value]);


    if (!current_file.value || !current_file.value.data)
        return <div className="error">No file selected or file has no data.</div>;

    const data = current_file.value.data;
    const chunk_size = 16;
    const chunks = chunk_into(data, chunk_size);
    const active_row = Math.floor(offset.value / chunk_size);
    const active_col = offset.value % chunk_size;

    function viewer_tb(label, val, readonly = true, change_handler = null)
    {
        val = val === null || val === undefined ? '' : String(val);

        return <>
            <th>{label}:</th>
            <td>
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
                        <th>Offset</th>
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
                            <th>{hex(row * chunk_size, 8)}</th>
                            <th spacer/>
                            {chunk.map((byte, col) =>
                            {
                                if (byte === null)
                                    return <td key={col} empty=""/>;
                                else
                                    return <td key={col}
                                               active={active_col == col ? '' : null}
                                               selected={active_col == col && active_row == row ? '' : null}
                                               onClick={() => offset.set(row * chunk_size + col)}>
                                        {hex(byte, 2)}
                                    </td>;
                            })}
                            <th spacer/>
                            <th spacer/>
                            {chunk.map((byte, col) =>
                            {
                                if (byte === null)
                                    return <td key={col} empty=""/>;
                                else
                                    return <td key={col}
                                               active={active_col == col ? '' : null}
                                               selected={active_col == col && active_row == row ? '' : null}
                                               onClick={() => offset.set(row * chunk_size + col)}>
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
                        <th>Offset:</th>
                        <td><input type="text" name="start" value={hex(offset.value, 8)} onChange={e =>
                        {
                            // TODO
                        }}/></td>
                        {viewer_tb('Value', inspected.value.value, true)}
                        {viewer_tb('Binary', inspected.value.binary, true)}
                    </tr>
                    <tr>
                        {viewer_tb('ASCII', inspected.value.ascii[0], true)}
                        {viewer_tb('UTF-8', inspected.value.utf8[0], true)}
                        {viewer_tb('UTF-16', inspected.value.utf16[0], true)}
                    </tr>
                    <tr>
                        {viewer_tb('int8', inspected.value.int8, true)}
                        {/* todo: jump to address */}
                        {viewer_tb('uint8', inspected.value.uint8, true)}
                        {viewer_tb('bool8', !!inspected.value.uint8, true)}
                    </tr>
                    <tr>
                        {viewer_tb('int16', inspected.value.int16, true)}
                        {/* todo: jump to address */}
                        {viewer_tb('uint16', inspected.value.uint16, true)}
                        {viewer_tb('float16', inspected.value.float16, true)}
                    </tr>
                    <tr>
                        {viewer_tb('int32', inspected.value.int32, true)}
                        {/* todo: jump to address */}
                        {viewer_tb('uint32', inspected.value.uint32, true)}
                        {viewer_tb('float32', inspected.value.float32, true)}
                    </tr>
                    <tr>
                        {viewer_tb('int64', inspected.value.int64, true)}
                        {/* todo: jump to address */}
                        {viewer_tb('uint64', inspected.value.uint64, true)}
                        {viewer_tb('float64', inspected.value.float64, true)}
                    </tr>
                    <tr>
                        {viewer_tb('int128', inspected.value.int128, true)}
                        {/* todo: jump to address */}
                        {viewer_tb('uint128', inspected.value.uint128, true)}
                        {viewer_tb('float128', inspected.value.float128, true)}
                    </tr>
                    <tr>
                        {viewer_tb('IPv4', inspected.value.ipv4, true)}
                        <th>IPv6:</th>
                        <td colSpan="3">
                            <input type="text" name="dec" readOnly value={inspected.value.ipv6}/>
                        </td>
                    </tr>
                    <tr>
                        {viewer_tb('time_32t', inspected.value.time32, true)}

                        <th>UUID:</th>
                        <td colSpan="3">
                            <input type="text" name="dec" readOnly value={inspected.value.uuid}/>
                        </td>
                    </tr>
                    <tr>
                        <th>x86-32:</th>
                        <td colSpan="3"><input type="text" name="dec" readOnly/></td>
                    </tr>
                    <tr>
                        <th>x86-64:</th>
                        <td colSpan="3"><input type="text" name="dec" readOnly/></td>
                    </tr>
                </tbody>
            </table>
            : <div className="error">No data inspected yet.</div>}
        </binary-inspector>
    </binary-viewer>;
}

function CodeEditor()
{
    const { code, set_code } = React.useContext(CodeContext);

    return <Editor language="cpp"
                   tabSize={4}
                   insertSpaces={true}
                   value={INITIAL_CODE}
                   onChange={set_code}
                   onUpdate={(value, editor) => set_code(value)}>
        {editor => <BasicSetup editor={editor} />}
    </Editor>
}

function CodeErrorWindow()
{
    const { error } = React.useContext(CodeContext);

    return <code-error-window>
        <$ error={error.value}/>
    </code-error-window>;
}

function OutputWindow()
{
    const { parsed } = React.useContext(CodeContext);
    const { current_file } = React.useContext(FileContext);
    const interpreted = useVariable(null);

    React.useEffect(() =>
    {
        if (parsed.value && current_file.value && current_file.value.id)
            (async () =>
            {
                const data = await CallAPI('file/interpret', {
                    code: parsed.value,
                    name: current_file.value.id,
                    offset: 0,
                });

                interpreted.set(data);
            })();
    }, [parsed.value, (current_file.value || { id: null }).id]);

    function RenderElement({ element })
    {
        return <parsed-item>
            <span>{element.name} : {element.repr}</span>
            {element.members.map((m, i) => <RenderElement element={m} key={i}/>)}
        </parsed-item>;
    }

    return <output-window>
        
        {interpreted.value && interpreted.value.success ? <RenderElement element={interpreted.value.data}/> : null}


        <br/>
        <hr/>
        <br/>
        {<$ interpreted={interpreted.value} parsed={parsed.value}/>}
    </output-window>;
}

function MainPage()
{
    const { current_file, set_current_file, upload_file } = React.useContext(FileContext);

    React.useEffect(() =>
    {
        if (!current_file.value || !current_file.value.id)
            set_current_file('test');
    }, [current_file.value]);


    const bytes = new Uint8Array(2048);
    crypto.getRandomValues(bytes);


    return <>
        <header>
            <h1>Pythia &mdash; A binary data reverse engineering application</h1>
        </header>
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

export const MainPageWrapper = () => <FileProvider>
                                        <CodeProvider>
                                            <MainPage/>
                                        </CodeProvider>
                                     </FileProvider>;

const $ = element => <pre><code>{JSON.stringify(element, null, 4)}</code></pre> 
