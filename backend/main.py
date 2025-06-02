from typing import Any
import ipaddress
import datetime
import base64
import json
import uuid

from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse

import pyparsing as pp

from parser import LayoutParser
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
files.create('test', b'\0\0\0\x2a\x14This is a test file.')


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
        'int8': toint(content, 8, True),
        'uint8': toint(content, 8, False),
        'int16': toint(content, 16, True),
        'uint16': toint(content, 16, False),
        'int32': toint(content, 32, True),
        'uint32': toint(content, 32, False),
        'int64': toint(content, 64, True),
        'uint64': toint(content, 64, False),
        'int128': toint(content, 128, True),
        'uint128': toint(content, 128, False),
        'time32': unix_to_ISO(int.from_bytes(content[0:4], 'little')),
        'float32': str(float.fromhex(content[0:4].hex())),
        'float64': str(float.fromhex(content[0:8].hex())),
        'float128': None, # TODO
        'uuid': str(uuid.UUID(bytes = content[0:16])),
        'ipv4': f'{content[0]}.{content[1]}.{content[2]}.{content[3]}',
        'ipv6': f'[{ipaddress.ip_address(content[0:16]).compressed}]',
        'x86_32': None,  # TODO
        'x86_64': None,  # TODO
    }

    return Response(json.dumps(response), 200, media_type = 'application/json')

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
