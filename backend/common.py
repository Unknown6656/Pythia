import datetime


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
