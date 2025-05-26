import React from 'react';


function* chunk_into(arr, n)
{
    for (let i = 0; i < arr.length; i += n)
        yield arr.slice(i, i + n);
}

function BinaryViewer({ data })
{
    const chunk_size = 16;
    const chunks = chunk_into(Array.from(data), chunk_size);

    return <binary-viewer>
        <binary-data>
            <table>
                <thead>
                    <tr>
                        <th>Offset</th>
                        {Array.from({ length: chunk_size }, (_, i) =>
                            <th key={i} data-col={i}>
                                {i.toString(16).padStart(2, '0')}
                            </th>
                        )}
                    </tr>
                </thead>
                <tbody>
                    {chunks.map((chunk, row) =>
                    {
                        return <tr key={row} data-row={row}>
                            <th>
                                {(row * chunk_size).toString(16).padStart(8, '0')}
                            </th>
                            {chunk.map((byte, col) =>
                            {
                                const hex = byte.toString(16).padStart(2, '0');

                                return <td key={col}
                                        data-col={col}
                                        data-hex={hex}>
                                    {hex}
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
                    <td><input type="text" name="offset" /></td>

                    <th>Length:</th>
                    <td><input type="text" name="length" /></td>
                    
                    <th>Value:</th>
                    <td><input type="text" name="hex" /></td>
                </tr>
                <tr>
                    <th>Binary:</th>
                    <td><input type="text" name="bin" /></td>

                    <th>ASCII:</th>
                    <td><input type="text" name="bin" /></td>
                </tr>
                <tr>
                    <th>UTF-8:</th>
                    <td><input type="text" name="dec" /></td>

                    <th>UTF-16:</th>
                    <td><input type="text" name="bin" /></td>

                    <th>UTF-32:</th>
                    <td><input type="text" name="bin" /></td>
                </tr>

                <tr>
                    <th>uint16:</th>
                    {/* todo: jump to address */}
                    <td><input type="text" name="dec" /></td>

                    <th>int16:</th>
                    <td><input type="text" name="bin" /></td>

                    <th>float16:</th>
                    <td><input type="text" name="bin" /></td>
                </tr>
                <tr>
                    <th>uint32:</th>
                    {/* todo: jump to address */}
                    <td><input type="text" name="dec" /></td>

                    <th>int32:</th>
                    <td><input type="text" name="bin" /></td>

                    <th>float32:</th>
                    <td><input type="text" name="bin" /></td>
                </tr>
                <tr>
                    <th>uint64:</th>
                    {/* todo: jump to address */}
                    <td><input type="text" name="dec" /></td>

                    <th>int64:</th>
                    <td><input type="text" name="bin" /></td>

                    <th>float64:</th>
                    <td><input type="text" name="bin" /></td>
                </tr>
                <tr>
                    <th>uint128:</th>
                    {/* todo: jump to address */}
                    <td><input type="text" name="dec" /></td>

                    <th>int128:</th>
                    <td><input type="text" name="bin" /></td>

                    <th>float128:</th>
                    <td><input type="text" name="bin" /></td>
                </tr>
                <tr>
                    <th>UUID:</th>
                    <td><input type="text" name="dec" /></td>

                    <th>IPv4:</th>
                    <td><input type="text" name="bin" /></td>

                    <th>IPv6:</th>
                    <td><input type="text" name="bin" /></td>
                </tr>
                <tr>
                    <th>time_t32:</th>
                    <td><input type="text" name="dec" /></td>

                    <th>time_t64:</th>
                    <td><input type="text" name="bin" /></td>

                    <th>:</th>
                    <td><input type="text" name="bin" /></td>
                </tr>
                <tr>
                    <th>:</th>
                    <td><input type="text" name="dec" /></td>

                    <th>disassembly x86-32:</th>
                    <td><input type="text" name="bin" /></td>

                    <th>disassembly x86-64:</th>
                    <td><input type="text" name="bin" /></td>
                </tr>
            </table>
        </binary-inspector>
    </binary-viewer>;
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
                code
            </pythia-code>

            <pythia-output>
                output
            </pythia-output>

            <separator v=""/>
            <separator h=""/>
        </main>
        <footer/>
    </>;
}

const $ = element => <pre><code>{JSON.stringify(element, null, 4)}</code></pre> 
