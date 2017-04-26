import logging
import re
import struct
import sys
import subprocess
from pprint import pprint

import lief
import keystone
import capstone

try:
    import colorlog
except ImportError:
    colorlog = None

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
if "DEBUG" in sys.argv:
    log.setLevel(logging.DEBUG)
    del sys.argv[sys.argv.index("DEBUG")]

if colorlog is not None:
    handler = colorlog.StreamHandler()
    fmt = '%(log_color)s%(levelname)s%(reset)s : %(message)s'
    fmter = colorlog.ColoredFormatter(fmt)
    handler.setFormatter(fmter)
    log.addHandler(handler)
else:
    fmt = '%(levelname)s : %(message)s'
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt))
    log.addHandler(handler)


def u8(x):
    return struct.unpack("B", x)[0]


def p8(x):
    return struct.pack("B", x)


def u16(x):
    return struct.unpack("H", x)[0]


def p16(x):
    return struct.pack("H", x)


def load_binary(path):
    return lief.parse(path)


def get_functions(binary):
    functions = {}
    for sym in binary.exported_symbols:
        log.debug("got symbol: {!r}".format(sym))
        functions[sym.name] = sym.addr
    return functions


def load_blobs(binary):
    subprocess.check_call("cd hooks && make", shell=True)
    entryhook = lief.parse('./hooks/setup_shadowmem')
    eh = binary.insert_content(entryhook.segments[0].content)
    verifier = lief.parse('./hooks/call_verifier')
    vh = binary.insert_content(verifier.segments[0].content)
    log.debug("inserted setup function at 0x{:x} and verifier at 0x{:x}"
              .format(eh[0], vh[0]))
    return eh, vh


def ks_asm(code):
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    encoding, _ = ks.asm(code)
    return encoding


def hook_entrypoint(binary, hook):
    asm = """
    call 0x{:x}
    jmp 0x{:x}
    """
    ep = binary.entrypoint
    log.debug("hooking entrypoint 0x{:x}".format(ep))
    asm = asm.format(hook[0], ep)
    ephook = ks_asm(asm)
    newep, _ = binary.insert_content(ephook)
    binary.entrypoint = newep
    log.debug("new entrypoint is 0x{:x}".format(newep))


def find_calls(binary, func):
    pass


def instrument_call(binary, call):
    pass


def main():
    # 0. load binary
    binary = load_binary(sys.argv[1])
    # 1. find functions in binary
    #   - iterate over symbols in binary
    #   - gather a map symbols <-> address
    functions = get_functions(binary)
    # 2. hook entry point to setup shadow memory
    hook_entrypoint(binary)
    # 3. instrument call instructions
    #   - iterate over functions
    #   - disassemble functions (capstone)
    #   - for each call instruction
    #     - add hook to call verifier
    for func in functions:
        calls = find_calls(binary, func)
        for call in calls:
            instrument_call(binary, call)
