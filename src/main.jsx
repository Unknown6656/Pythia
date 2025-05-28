/* global BigInt */

import React from 'react';
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
    for (let i = 0; i < arr.length; i += n)
        yield arr.slice(i, i + n);
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



function BinaryViewer({ data })
{
    if (!(data instanceof Array))
        data = Array.from(data);

    const chunk_size = 16;
    const chunks = chunk_into(data, chunk_size);
    const offset = useVariable(0);

    const active_row = Math.floor(offset.value / chunk_size);
    const active_col = offset.value % chunk_size;

    let value = data.slice(offset.value, offset.value + 16);

    if (value.length < 16)
        value = value.concat(Array(16 - value.length).fill(0));

    const buffer = new ArrayBuffer(value.length);
    const view = new DataView(buffer);

    value.forEach((b, i) =>
    {
        buffer[i] = b;
        view.setUint8(i, b);
    });

    function viewer_tb(label, transformer, readonly = true, change_handler = null)
    {
        let val = transformer ? transformer(value) : value;

        while (val.props && val.props.children)
            val = val.props.children;

        val = String(val);

        if (readonly)
            change_handler = null;

        return <>
            <th>{label}:</th>
            <td>
                <input type="text"
                       name={label.toLowerCase().replace(/[^\w]/g, '_')}
                       transformer={transformer}
                       readOnly={readonly ? '' : null}
                       onChange={change_handler}
                       autocomplete="off"
                       autocorrect="off"
                       spellcheck="false"
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
                            <th>
                                {hex(row * chunk_size, 8)}
                            </th>
                            <th spacer/>
                            {chunk.map((byte, col) =>
                            {
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
            <table>
                <tr>
                    <th>Offset:</th>
                    <td><input type="text" name="start" value={hex(offset.value, 8)} onChange={e =>
                    {
                        // TODO
                    }}/></td>
                    {viewer_tb('Value', v => hex(v[0]), true)}
                    {viewer_tb('Binary', v => bin(v[0]), true)}
                </tr>
                <tr>
                    {viewer_tb('ASCII', v => ascii8(v[0]), true)}
                    {viewer_tb('UTF-8', _ => new TextDecoder("utf-8").decode(buffer)[0], true)}
                    {viewer_tb('UTF-16', _ => new TextDecoder("utf-16").decode(buffer)[0], true)}
                </tr>
                <tr>
                    {viewer_tb('int8', v => uncomplement(v[0], 8), true)}
                    {/* todo: jump to address */}
                    {viewer_tb('uint8', v => v[0], true)}
                    {viewer_tb('bool8', v => !!v[0], true)}
                </tr>
                <tr>
                    {viewer_tb('int16', v => toint(v, 16, true), true)}
                    {/* todo: jump to address */}
                    {viewer_tb('uint16', v => toint(v, 16, false), true)}
                    {viewer_tb('float16', _ => view.getFloat16(0), true)}
                </tr>
                <tr>
                    {viewer_tb('int32', v => toint(v, 32, true), true)}
                    {/* todo: jump to address */}
                    {viewer_tb('uint32', v => toint(v, 32, false), true)}
                    {viewer_tb('float32', _ => view.getFloat32(0), true)}
                </tr>
                <tr>
                    {viewer_tb('int64', v => toint(v, 64, true), true)}
                    {/* todo: jump to address */}
                    {viewer_tb('uint64', v => toint(v, 64, false), true)}
                    {viewer_tb('float64', _ => view.getFloat64(0), true)}
                </tr>
                <tr>
                    {viewer_tb('int128', v => toint(v, 128, true), true)}
                    {/* todo: jump to address */}
                    {viewer_tb('uint128', v => toint(v, 128, false), true)}
                    <th>float128:</th>
                    <td><input type="text" name="bin" readonly value="[TODO]"/></td>
                </tr>
                <tr>
                    {viewer_tb('IPv4', v => `${v[0]}.${v[1]}.${v[2]}.${v[3]}`, true)}
                    <th>IPv6:</th>
                    <td colSpan="3">
                        <input type="text" name="dec" readonly value={`[${ipaddr.fromByteArray(value)}]`}/>
                    </td>
                </tr>
                <tr>
                    {viewer_tb('time_32t', v => unix_to_ISO_date(toint(v, 32, true)), true)}
                    {/* {viewer_tb('time_64t', v => unix_to_ISO_date(toint(v, 64, true)), true)} */}

                    <th>UUID:</th>
                    <td colSpan="3">
                        <input type="text" name="dec" readonly value={uuid(value)}/>
                    </td>
                </tr>
                <tr>
                    <th>x86-32:</th>
                    <td colSpan="3">
                        <input type="text" name="dec" readonly/>
                    </td>
                </tr>
                <tr>
                    <th>x86-64:</th>
                    <td colSpan="3">
                        <input type="text" name="dec" readonly/>
                    </td>
                </tr>
            </table>
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

export default function MainPage()
{
    const bytes = new Uint8Array(2048);
    crypto.getRandomValues(bytes);

    return <>
        <header>
            TEST
            top lel
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

const $ = element => <pre><code>{JSON.stringify(element, null, 4)}</code></pre> 
