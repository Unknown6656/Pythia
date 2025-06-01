/* global BigInt */

import React from 'react';
import { Buffer } from 'buffer';
import ipaddr from 'ipaddr.js';





const hex = (value, length = 2) => Number(value).toString(16).padStart(length, '0');

const bin = (value, length = 8) => (Number(value) >>> 0).toString(2).padStart(length, '0');

const uuid = array => `{${hex(array[0])}${hex(array[1])}${hex(array[2])}${hex(array[3])}-${hex(array[4])}${hex(array[5])}-${hex(array[6])}${hex(array[7])}-${hex(array[8])}${hex(array[9])}-${hex(array[10])}${hex(array[11])}${hex(array[12])}${hex(array[13])}${hex(array[14])}${hex(array[15])}}`;

const ascii8 = value =>
{
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

function toint(array, bitwidth, signed)
{
    if (array.length === 0)
        return 0;

    let value = 0n;

    for (let i = 0; i < (bitwidth >> 3); i++)
    {
        value <<= 8n;
        value |= BigInt(array[i]) & 0xFFn;
    }

    if (signed)
        value = uncomplement(value, bitwidth);
    // else
        // value = value >>> 0;

    return value.toString().replace(/\B(?=(\d{3})+(?!\d))/g, "'");
}

function uncomplement(val, bitwidth)
{
    val = BigInt(val);
    bitwidth = BigInt(bitwidth);

    const isnegative = val & (1n << (bitwidth - 1n));
    const boundary = (1n << bitwidth);
    const minval = -boundary;
    const mask = boundary - 1n;

    return isnegative ? minval + (val & mask) : val;
}

function to_ISO_date(date = null)
{
    date = date || new Date();

    // TODO : fix this timezone shite!
    const timezone = 0; // -date.getTimezoneOffset();
    const diff = timezone >= 0 ? '+' : '-';
    const pad = num => (num < 10 ? '0' : '') + num;

    const year = date.getFullYear();
    const mon = date.getMonth() + 1;
    const day = date.getDate();
    const hou = date.getHours() + timezone / 60;
    const min = date.getMinutes() + timezone % 60;
    const sec = date.getSeconds();

    return `${year}-${pad(mon)}-${pad(day)} ${pad(hou)}:${pad(min)}:${pad(sec)}`;
}

function unix_to_ISO_date(unix)
{
    const date = new Date(0);

    unix = unix.replace(/[^0-9]/g, '');
    date.setUTCSeconds(Number(unix));

    return to_ISO_date(date);
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





const uuid4 = () => "10000000-1000-4000-8000-100000000000".replace(/[018]/g, c =>
    (+c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> +c / 4).toString(16)
);

const btoa = data => Buffer.from(data).toString('base64');

const atob = data => Buffer.from(data, 'base64');

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

    console.log(`API call: ${url} (${id})`, data);

    const response = await fetch(url, payload);

    if (!response.ok)
    {
        const error = await response.text();

        console.error(`API call: ${url} (${id}) status ${response.status}`, error);

        throw new Error(`API call failed: (${response.status}) ${error}`);
    }
    else
    {
        data = await response.json();

        console.log(`API call: ${url} (${id}) success`, data);

        return data;
    }
}




const FileContext = React.createContext(null);

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
        if (readonly)
            change_handler = null;

        return <>
            <th>{label}:</th>
            <td>
                <input type="text"
                       name={label.toLowerCase().replace(/[^\w]/g, '_')}
                       readOnly={readonly ? '' : null}
                       onChange={change_handler}
                       autoComplete="off"
                       autoCorrect="off"
                       spellCheck="false"
                       value={val}
                       defaultValue={val}/>
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
                                    return <td key={col} empty="">--</td>;
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
                        <input type="text" name="dec" readonly value={inspected.value.ipv6}/>
                    </td>
                </tr>
                <tr>
                    {viewer_tb('time_32t', inspected.value.time32, true)}

                    <th>UUID:</th>
                    <td colSpan="3">
                        <input type="text" name="dec" readonly value={inspected.value.uuid}/>
                    </td>
                </tr>
                <tr>
                    <th>x86-32:</th>
                    <td colSpan="3"><input type="text" name="dec" readonly/></td>
                </tr>
                <tr>
                    <th>x86-64:</th>
                    <td colSpan="3"><input type="text" name="dec" readonly/></td>
                </tr>
            </table>
            : <div className="error">No data inspected yet.</div>}
        </binary-inspector>
    </binary-viewer>;
}


function CodeWindow({ data })
{
    const structure = useVariable(null);

    return <code-window>
        <pre><code>{`
        // TODO : implement coding window, so that the user can write code to parse the binary data
        // e.g.:

        struct _IMAGE_DOS_HEADER {  // DOS .EXE header
            WORD   e_magic;         // Magic number
            WORD   e_cblp;          // Bytes on last page of file
            WORD   e_cp;            // Pages in file
            WORD   e_crlc;          // Relocations
            WORD   e_cparhdr;       // Size of header in paragraphs
            WORD   e_minalloc;      // Minimum extra paragraphs needed
            WORD   e_maxalloc;      // Maximum extra paragraphs needed
            WORD   e_ss;            // Initial (relative) SS value
            WORD   e_sp;            // Initial SP value
            WORD   e_csum;          // Checksum
            WORD   e_ip;            // Initial IP value
            WORD   e_cs;            // Initial (relative) CS value
            WORD   e_lfarlc;        // File address of relocation table
            WORD   e_ovno;          // Overlay number
            WORD   e_res[4];        // Reserved words
            WORD   e_oemid;         // OEM identifier (for e_oeminfo)
            WORD   e_oeminfo;       // OEM information; e_oemid specific
            WORD   e_res2[10];      // Reserved words
            LONG   e_lfanew;        // File address of new exe header
        };

        struct _IMAGE_NT_HEADERS {
            DWORD Signature;
            IMAGE_FILE_HEADER FileHeader;
            IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        };

        struct _IMAGE_NT_HEADERS64 {
            DWORD Signature;
            IMAGE_FILE_HEADER FileHeader;
            IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        };

        struct _IMAGE_NT_HEADERS {
            DWORD Signature;
            IMAGE_FILE_HEADER FileHeader;
            IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        };

        struct _IMAGE_OPTIONAL_HEADER {
            ...
        };

        `}</code></pre>
    </code-window>;
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
            {/* <$>{current_file.value}</$> */}
        </header>
        <main>
            <pythia-input>
                <BinaryViewer data={bytes}/>
            </pythia-input>
            <pythia-code>
                <CodeWindow data={bytes}/>
            </pythia-code>
            <pythia-output>
                output
            </pythia-output>
            <separator v=""/>
            <separator h=""/>
        </main>
        {/* <footer/> */}
    </>;
}

export const MainPageWrapper = () => <FileProvider>
                                         <MainPage/>
                                     </FileProvider>;

const $ = element => <pre><code>{JSON.stringify(element, null, 4)}</code></pre> 
