from datetime import datetime, timezone


def uncomplement(value : int, bitwidth : int) -> int:
    if value & (1 << (bitwidth - 1)):
        boundary : int = (1 << bitwidth)
        minval : int = -boundary
        mask : int = boundary - 1

        return minval + (value & mask)
    else:
        return value

def toint(array : bytes, bitwidth : int, signed : bool) -> tuple[str, int]:
    if not len(array) or bitwidth <= 0:
        return '0', 0

    value : int = 0

    for i in range(bitwidth >> 3):
        value <<= 8
        value |= array[i] & 0xFF

    if signed:
        value = uncomplement(value, bitwidth)

    return f'{value:_d}'.replace('_', "'"), value

def unix_to_ISO(unix : int) -> tuple[str, datetime]:
    date: datetime = datetime.fromtimestamp(unix, timezone.utc)

    return date.isoformat().replace('T', ' ')[:19], date
