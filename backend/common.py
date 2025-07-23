from typing import Any, NoReturn
from datetime import datetime, timezone
import functools
import signal
import sys

import pyparsing as pp


def _dumps(obj: pp.ParseResults | list | dict | Any | None, indent: int = 1) -> str:
    spacing: str = '¦   ' * (indent)
    objlist: list = []
    objdict: dict = {}
    result: str = f'({type(obj).__name__}) '

    if obj is None:
        return 'None'
    elif isinstance(obj, pp.ParseResults):
        objlist = obj._toklist
        objdict = obj._tokdict
    elif isinstance(obj, pp.results._ParseResultsWithOffset):
        return _dumps(obj.tup[0], indent)
    elif isinstance(obj, list):
        objlist = obj
    elif isinstance(obj, dict):
        objdict = obj

    if len(objdict) > 0:
        result += ''.join(
            f'\n{spacing}- {key}: {_dumps(value, indent + 1)}'
            for key, value in objdict.items()
        )
    elif len(objlist) > 0:
        result += ''.join(
            f'\n{spacing}[{index}] {_dumps(item, indent + 1)}'
            for index, item in enumerate(objlist)
        )
    else:
        result += str(obj)

    return result

def _dump(obj: Any, indent: int = 1) -> Any:
    print('\n', _dumps(obj, indent), '\n')
    return obj

def timeout(seconds: int = 5, default: Any | None = None):
    if sys.platform == "win32":
        raise NotImplementedError("Timeout decorator is not supported on Windows due to limitations with signal handling.")
    else:
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                def handle_timeout(signum, frame) -> NoReturn:
                    raise TimeoutError()

                signal.signal(signal.SIGALRM, handle_timeout)
                signal.alarm(seconds)
                signal.SIGABRT

                result = func(*args, **kwargs)

                signal.alarm(0)

                return result
            return wrapper
        return decorator

def uncomplement(value: int, bitwidth: int) -> int:
    if value & (1 << (bitwidth - 1)):
        boundary: int = (1 << bitwidth)
        minval: int = -boundary
        mask: int = boundary - 1

        return minval + (value & mask)
    else:
        return value

def toint(array: bytes, bitwidth: int, signed: bool) -> tuple[str, int]:
    if not len(array) or bitwidth <= 0:
        return '0', 0

    value: int = 0

    for i in range(bitwidth >> 3):
        value <<= 8
        value |= array[i] & 0xFF

    if signed:
        value = uncomplement(value, bitwidth)

    return f'{value:_d}'.replace('_', "'"), value

def unix_to_ISO(unix: int) -> tuple[str, datetime]:
    date: datetime = datetime.fromtimestamp(unix, timezone.utc)

    return date.isoformat().replace('T', ' ')[:19], date
