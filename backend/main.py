from typing import Any
import base64
import json
import uuid

from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse

import pyparsing as pp

from parser import LayoutParser, Endianness, ParserConstructor, ParsedFile
from interpreter import LayoutInterpreter, GlobalInterpreterResult
from files import PythiaFileInfo, PythiaFiles
from common import _dump




print('\x1b[m\x1b[3J\x1b[!p\x1bc', end='')#clear terminal. only for debug reasons


BASE_URL = '/api'

app = FastAPI(
    docs_url = f'{BASE_URL}/docs',
    redoc_url = f'{BASE_URL}/redoc',
    openapi_url = f'{BASE_URL}/openapi.json'
)
parser = LayoutParser()
files = PythiaFiles()


with open('/usr/local/bin/python3', 'rb') as __fs:
    files.create('test', __fs.read()[:1024])


def success(data: Any | None = None) -> Response:
    return Response(json.dumps(data), 200, media_type = 'application/json')


@app.get(BASE_URL)
def root() -> Response:
    return RedirectResponse(f'{BASE_URL}/docs')

@app.post(f'{BASE_URL}/file/upload')
async def file_upload(request: Request) -> Response:
    try:
        reqjson: dict[str, Any] = await request.json()
        name: str | None = reqjson.get('name', None)
        data: str | None = reqjson.get('data', None)

        if not name or not data:
            return Response(None, 400)

        data_bytes: bytes = base64.b64decode(data)
        comment: str | None = reqjson.get('comment', None)
        mime = str(reqjson.get('mime', 'application/octet-stream'))

        file: PythiaFileInfo = files.create(str(name), data_bytes, mime, comment)

        return file_info(request, file.id, False)
    except Exception as e:
        print(f'Error parsing JSON: {e}')
        return Response(None, 400)

@app.post(f'{BASE_URL}/file/upload/raw')
async def file_upload_raw(request: Request) -> Response:
    data: bytes = await request.body()
    name = str(uuid.uuid4())
    files.create(
        request.headers.get('X-Name', name),
        data,
        request.headers.get('Content-Type', 'application/octet-stream'),
        request.headers.get('X-Comment')
    )

    return file_info(request, name, False)

@app.post(f'{BASE_URL}/file/delete')
async def file_delete(request: Request) -> Response:
    reqjson: dict[str, Any] = await request.json()
    name: str | None = reqjson.get('name', None)

    if not name:
        return Response(None, 400)
    elif name not in files:
        return Response(None, 404)
    else:
        del files[name]
        return Response(None, 204)

@app.post(f'{BASE_URL}/file/info')
async def file_info(request: Request) -> Response:
    reqjson: dict[str, Any] = await request.json()
    name: str | None = reqjson.get('name', None)
    full: bool = bool(reqjson.get('full', False))

    if not name:
        return Response(None, 400)

    file: PythiaFileInfo | None = files[name]

    if file is None:
        return Response(None, 404)
    else:
        response: dict[str, Any] = {
            'id': str(file.id),
            'name': file.name,
            'mime': file.mime,
            'size': file.size,
            'created': file.created.isoformat(),
            'sha1': file.sha1,
            'comment': file.comment
        }

        if full:
            response['data'] = base64.b64encode(file.data).decode('utf-8')

        return Response(json.dumps(response), 200, media_type = 'application/json')

@app.post(f'{BASE_URL}/file/view')
async def file_view(request: Request) -> Response:
    reqjson: dict[str, Any] = await request.json()
    name: str | None = reqjson.get('name', None)

    if not name:
        return Response(None, 400)

    file: PythiaFileInfo | None = files[name]

    if file is None:
        return Response(None, 404)
    else:
        return Response(
            file.data,
            200,
            media_type = file.mime,
            headers = {
                'Content-Disposition': f'attachment; filename={file.name}'
            }
        )

@app.post(f'{BASE_URL}/file/inspect')
async def file_inspect(request: Request) -> Response:
    reqjson: dict[str, Any] = await request.json()
    name: str | None = reqjson.get('name', None)
    offset: int = int(reqjson.get('offset', -1))
    length: int = int(reqjson.get('length', 16))
    endianness: Endianness = Endianness.LITTLE if bool(reqjson.get('little_endian', True)) else Endianness.BIG
    pointer_size: int = int(reqjson.get('pointer_size', 8))
    interpreter = LayoutInterpreter({}, endianness, pointer_size)

    if not name or offset < 0 or length <= 0:
        return Response(None, 400)

    file: PythiaFileInfo | None = files[name]

    if file is None:
        return Response(None, 404)
    elif offset >= file.size:
        return Response(None, 400)

    content: bytes = file.data[offset:min(offset + length, file.size)]

    if len(content) < 16:
        content += b'\x00' * (16 - len(content))

    def interpret(type: str) -> str:
        return interpreter.interpret_data(content, type, endianness, pointer_size, None)[0]

    result: dict[str, Any] = {
        'name': name,
        'offset': offset,
        'length': length,
        'value': f'0x{content[0]:02x}',
        'hex': ' '.join(f'{b:02x}' for b in content[0:length]),
        'binary': ' '.join(f'{b:08b}' for b in content[0:length]),
        'base64': base64.b64encode(content).decode('utf-8'),
        'ascii': content.decode('ascii', 'ignore'),
        'utf8': content.decode('utf-8', 'ignore'),
        'utf16': content.decode('utf-16', 'ignore'),
        'utf32': content.decode('utf-32', 'ignore'),
        'int8': interpret('int8'),
        'uint8': interpret('uint8'),
        'int16': interpret('int16'),
        'uint16': interpret('uint16'),
        'int32': interpret('int32'),
        'uint32': interpret('uint32'),
        'int64': interpret('int64'),
        'uint64': interpret('uint64'),
        'int128': interpret('int128'),
        'uint128': interpret('uint128'),
        'time32': interpret('time32'),
        'float16': interpret('float16'),
        'float32': interpret('float32'),
        'float64': interpret('float64'),
        'float128': interpret('float128'),
        'uuid': interpret('uuid'),
        'ipv4': interpret('ipv4'),
        'ipv6': interpret('ipv6'),
        'mac': interpret('mac'),
        'x86': None, # TODO
    }

    if len(content) >= 6:
        result['ipv4port'] = f'{interpret('ipv4')}:{interpreter.interpret_data(content[4:], 'uint16', endianness, pointer_size, None)[0].replace("'", "")}'
    else:
        result['ipv4port'] = f'{result['ipv4']}:0'

    return success(result)

@app.post(f'{BASE_URL}/file/parse')
async def file_parse(request: Request) -> Response:
    response: dict[str, Any] = {
        'success': False,
        'errors': [],
        'data': None
    }

    try:
        reqjson: dict[str, Any] = await request.json()
        code: str = reqjson.get('code', '')
        name: str = reqjson.get('name', '')
        little_endian: bool = bool(reqjson.get('little_endian', True))
        pointer_size: int = int(reqjson.get('pointer_size', 8))

        if not name or not code:
            return Response(None, 400)

        if (file := files[name]) is None:
            return Response(None, 404)
        else:
            if parsed := parser(code):
                interpreter = LayoutInterpreter(parsed, Endianness.LITTLE if little_endian else Endianness.BIG, pointer_size)
                result: GlobalInterpreterResult = interpreter(file.data)

                response = result.to_dict()
    except pp.ParseException as e:
        response['errors'] = [{
            'type': 'ParseException',
            'message': str(e),
            'line': e.lineno,
            'column': e.column,
            'text': e.line,
        }]
    except Exception as e:
        _dump(e)
        response['errors'] = [{
            'type': str(type(e)),
            'message': str(e),
            'line': 0,
            'column': 0,
            'text': None,
        }]

    return success(response)

@app.post(f'{BASE_URL}/code/syntax')
async def code_syntax() -> Response:
    return success({
        'keywords': f'\\b({"|".join(ParserConstructor.KEYWORDS)})\\b',
        'comments': r'(#(?:[^#\n]|#\n?)*|//(?:[^\\\n]|\\\n?)*|/\*[^]*?(?:\*/|$))|\bparse\b',
    })
