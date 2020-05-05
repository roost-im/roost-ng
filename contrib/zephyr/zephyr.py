import functools
import sys

# pylint: disable=ungrouped-imports
try:
    from . import _zephyr as _z
except ImportError:
    from . import _zephyr_cffi
    _zephyr_cffi.ffibuilder.compile()
    from . import _zephyr as _z
# pylint: enable=ungrouped-imports


class ZephyrError(Exception):
    pass


def check_error(func):
    @functools.wraps(func)
    def wrapped(*args):
        ret = func(*args)
        if ret:
            raise ZephyrError(ret)
        return ret
    return wrapped


# pylint: disable=invalid-name
_initialize = check_error(_z.lib.ZInitialize)
_close_port = check_error(_z.lib.ZClosePort)
# pylint: enable=invalid-name


def _open_port(port=0):
    if port and sys.byteorder != 'big':
        port = int.from_bytes(port.to_bytes(2, sys.byteorder), 'big')
    cport = _z.ffi.new('unsigned short *', port)
    ret = _z.lib.ZOpenPort(cport)
    if ret:
        raise ZephyrError(ret)
    port = cport[0]
    if port and sys.byteorder != 'big':
        port = int.from_bytes(port.to_bytes(2, 'big'), sys.byteorder)
    return port


def _get_sender():
    ret = _z.lib.ZGetSender()
    return _z.ffi.string(ret).decode('utf-8')


class Zephyr:
    def __new__(cls):
        """This is a singleton."""
        if '_instance' not in cls.__dict__:
            cls._instance = super().__new__(cls)
            _initialize()
        return cls._instance

    @staticmethod
    def open_port(port=0):
        return _open_port(port)

    @staticmethod
    def close_port():
        return _close_port()

    @staticmethod
    def get_sender():
        return _get_sender()


def _test_main():
    # pylint: disable=invalid-name
    z = Zephyr()
    port = z.open_port()
    print(port)
    print(z.get_sender())
    z.close_port()


if __name__ == '__main__':
    _test_main()
