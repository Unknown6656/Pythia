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




# const uuid = array => `{${hex(array[0])}${hex(array[1])}${hex(array[2])}${hex(array[3])}-${hex(array[4])}${hex(array[5])}-${hex(array[6])}${hex(array[7])}-${hex(array[8])}${hex(array[9])}-${hex(array[10])}${hex(array[11])}${hex(array[12])}${hex(array[13])}${hex(array[14])}${hex(array[15])}}`;

def uncomplement(value : int, bitwidth : int) -> int:
    if value & (1 << (bitwidth - 1)):
        boundary : int = (1 << bitwidth)
        minval : int = -boundary
        mask : int = boundary - 1

        return minval + (value & mask)
    else:
        return value

def toint(array : bytes, bitwidth : int, signed : bool) -> str:
    if not len(array) or bitwidth <= 0:
        return '0'

    value = 0

    for i in range(bitwidth >> 3):
        value <<= 8
        value |= array[i] & 0xFF

    if signed:
        value = uncomplement(value, bitwidth)

    return f'{value:_d}'.replace('_', "'")

def unix_to_ISO(unix : int) -> str:
    return datetime.datetime.fromtimestamp(unix, datetime.timezone.utc) \
                            .isoformat() \
                            .replace('T', ' ') \
                            [:19]


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
        json: dict[str, Any] = await request.json()
        name: str | None = json.get('name', None)
        data: str | None = json.get('data', None)

        if not name or not data:
            return Response(None, 400)

        data_bytes: bytes = base64.b64decode(data)
        comment: str | None = json.get('comment', None)
        mime = str(json.get('mime', 'application/octet-stream'))

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

@app.get(f'{BASE_URL}/file/delete')
def file_delete(request : Request, name : str | uuid.UUID) -> Response:
    if not name:
        return Response(None, 400)
    elif name not in files:
        return Response(None, 404)
    else:
        del files[name]
        return Response(None, 204)

@app.get(f'{BASE_URL}/file/info')
def file_info(request : Request, name : str | uuid.UUID, full : bool = False) -> Response:
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

@app.get(f'{BASE_URL}/file/view')
def file_view(request : Request, name : str | uuid.UUID) -> Response:
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

@app.get(f'{BASE_URL}/file/inspect')
def file_inspect(request : Request, name : str | uuid.UUID, offset : int, length : int = 16) -> Response:
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
        'ipv6': ipaddress.ip_address(content[0:16]).compressed,
        'x86_32': None,  # TODO
        'x86_64': None,  # TODO
    }

    return Response(json.dumps(response), 200, media_type = 'application/json')

@app.get(f'{BASE_URL}/code/parse')
def code_parse(request : Request, code : str) -> Response:
    try:
        parsed: list[dict[str, Any]] = parser(code)

        return Response(json.dumps(parsed), 200, media_type = 'application/json')
    except pp.ParseException as e:
        return Response(f'Parse error: {e}', 400)
