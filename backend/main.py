from typing import Any
import base64
import json
import uuid

from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse

import pyparsing as pp

from parser import LayoutParser, LayoutInterpreter, InterpretedLayout, Endianness
from files import PythiaFileInfo, PythiaFiles


BASE_URL = '/api'

app = FastAPI(
    docs_url = f'{BASE_URL}/docs',
    redoc_url = f'{BASE_URL}/redoc',
    openapi_url = f'{BASE_URL}/openapi.json'
)
parser = LayoutParser()
files = PythiaFiles()


# only for testing purposes
files.create('test', b'\0\0\0\0\0\0\0\x08\0\0\0\x2a\x14This is a test file.')


@app.get(BASE_URL)
def root() -> Response:
    return RedirectResponse(f'{BASE_URL}/docs')

@app.post(f'{BASE_URL}/file/upload')
async def file_upload(request : Request) -> Response:
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
async def file_upload_raw(request : Request) -> Response:
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
async def file_delete(request : Request) -> Response:
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
async def file_info(request : Request) -> Response:
    reqjson: dict[str, Any] = await request.json()
    name: str | None = reqjson.get('name', None)
    full: bool = bool(reqjson.get('full', False))

    if not name:
        return Response(None, 400)

    file: PythiaFileInfo | None = files[name]

    if file is None:
        return Response(None, 404)
    else:
        response : dict[str, Any] = {
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
async def file_view(request : Request) -> Response:
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
async def file_inspect(request : Request) -> Response:
    reqjson: dict[str, Any] = await request.json()
    name: str | None = reqjson.get('name', None)
    offset: int = int(reqjson.get('offset', -1))
    length: int = int(reqjson.get('length', 16))

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

    response : dict[str] = {
        'name': name,
        'offset': offset,
        'length': length,
        'value': content[0:1].hex(),
        'ascii': content.decode('ascii', 'ignore'),
        'utf8': content.decode('utf-8', 'ignore'),
        'utf16': content.decode('utf-16', 'ignore'),
        'utf32': content.decode('utf-32', 'ignore'),
        'int8': LayoutInterpreter.interpret(content, 'int8'),
        'uint8': LayoutInterpreter.interpret(content, 'uint8'),
        'int16': LayoutInterpreter.interpret(content, 'int16'),
        'uint16': LayoutInterpreter.interpret(content, 'uint16'),
        'int32': LayoutInterpreter.interpret(content, 'int32'),
        'uint32': LayoutInterpreter.interpret(content, 'uint32'),
        'int64': LayoutInterpreter.interpret(content, 'int64'),
        'uint64': LayoutInterpreter.interpret(content, 'uint64'),
        'int128': LayoutInterpreter.interpret(content, 'int128'),
        'uint128': LayoutInterpreter.interpret(content, 'uint128'),
        'time32': LayoutInterpreter.interpret(content, 'time32'),
        'float16': LayoutInterpreter.interpret(content, 'float16'),
        'float32': LayoutInterpreter.interpret(content, 'float32'),
        'float64': LayoutInterpreter.interpret(content, 'float64'),
        'float128': LayoutInterpreter.interpret(content, 'float128'),
        'uuid': LayoutInterpreter.interpret(content, 'uuid'),
        'ipv4': LayoutInterpreter.interpret(content, 'ipv4'),
        'ipv6': LayoutInterpreter.interpret(content, 'ipv6'),
        'x86_32': None,  # TODO
        'x86_64': None,  # TODO
    }

    return Response(json.dumps(response), 200, media_type = 'application/json')

@app.post(f'{BASE_URL}/file/interpret')
async def file_parse(request : Request) -> Response:
    reqjson: dict[str, Any] = await request.json()
    name: str | None = reqjson.get('name', None)
    code: dict[str, Any] | None = reqjson.get('code', None)

    if not name or not code:
        return Response(None, 400)

    file: PythiaFileInfo | None = files[name]

    if file is None:
        return Response(None, 404)

    interpreter = LayoutInterpreter(code, Endianness.LITTLE)
    result: InterpretedLayout = interpreter(file.data)

    return Response(json.dumps(result.to_dict()), 200)

@app.post(f'{BASE_URL}/code/parse')
async def code_parse(request : Request) -> Response:
    response: dict[str, Any] = {
        'success': False,
        'error': None,
        'parsed': None
    }

    try:
        reqjson: dict[str, Any] = await request.json()
        code: str = reqjson.get('code', '')

        response['parsed'] = parser(code)
        response['success'] = True
    except pp.ParseException as e:
        response['error'] = {
            'type': 'ParseException',
            'message': str(e),
            'line': e.lineno,
            'column': e.column,
            'text': e.line,
        }
    except Exception as e:
        response['error'] = {
            'type': str(type(e)),
            'message': str(e),
            'line': 0,
            'column': 0,
            'text': None,
        }

    return Response(json.dumps(response), 200, media_type = 'application/json')
