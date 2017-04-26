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

_ks = None


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
    for sym in binary.static_symbols:
        if sym.type == lief.ELF.SYMBOL_TYPES.FUNC:
            log.debug("got function symbol: {!r} 0x{:x}"
                      .format(sym.name, sym.value))
            functions[sym.name] = sym.value
    return functions


def load_blobs(binary):
    subprocess.check_call("cd hooks && make", shell=True)

    entryhook = lief.parse('./hooks/setup_shadowmem')
    # FIXME: insert_content returns the same offset every time
    eh = binary.insert_content(entryhook.segments[0].data)
    # FIXME: symbol adding doesn't seem to work
    sym = lief.ELF.Symbol()
    sym.name = "__ceflif_setup"
    sym.value, sym.size = eh
    binary.add_static_symbol(sym)

    verifier = lief.parse('./hooks/call_verifier')
    vh = binary.insert_content(verifier.segments[0].data)
    sym = lief.ELF.Symbol()
    sym.name = "__ceflif_verify"
    sym.value, sym.size = eh
    binary.add_static_symbol(sym)

    init = lief.parse('./hooks/shadow_init')
    ih = binary.insert_content(init.segments[0].data)
    sym = lief.ELF.Symbol()
    sym.name = "__ceflif_init"
    sym.value, sym.size = eh
    binary.add_static_symbol(sym)

    x = {'init': ih[0], 'setup': eh[0], 'verify': vh[0]}
    log.debug(", ".join("{}: 0x{:x}".format(k, v) for k, v in x.iteritems()))
    return x


def ks_asm(code):
    global _ks
    if not _ks:
        _ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    # log.debug(code)
    encoding, _ = _ks.asm(code)
    return encoding


def create_init_asm(funcs, initfunc):
    tmpl = """
    mov rdi, 0x{:x};
    call 0x{:x};
    """
    x = []
    for func in funcs:
        a = funcs[func]
        if a > 0:
            x.append(tmpl.format(a, initfunc))
    return "".join(x)


def hook_entrypoint(binary, hooks, funcs):
    hook_virt = hooks['setup']
    asm = """
    call 0x{:x};
    {}
    jmp 0x{:x};
    """
    init_code = create_init_asm(funcs, hooks['init'])
    ep = binary.entrypoint
    log.debug("hooking entrypoint 0x{:x}".format(ep))
    asm = asm.format(hook_virt, init_code, ep)
    log.debug(asm)
    log.debug("assembling entry hook")
    ephook = ks_asm(asm)
    log.debug("got {!r}".format(ephook))
    newep, _ = binary.insert_content(ephook)
    # newep += 0x00400000
    startsym = next(
        iter(filter(lambda s: s.name == "_start", binary.static_symbols)))
    startsym.value = newep
    log.debug("new entrypoint is 0x{:x}".format(newep))


def find_calls(binary, func):
    return []


def instrument_call(binary, call):
    pass


def list_symbols(binary):
    for sym in binary.static_symbols:
        if sym.type == lief.ELF.SYMBOL_TYPES.FUNC:
            log.info("{} / 0x{:x}".format(sym.name, sym.value))


def main():
    # load binary
    binary = load_binary(sys.argv[1])
    list_symbols(binary)
    # insert hooks
    hooks = load_blobs(binary)
    # find functions in binary
    # - iterate over symbols in binary
    # - gather a map symbols <-> address
    functions = get_functions(binary)
    # hook entry point to setup shadow memory
    hook_entrypoint(binary, hooks, functions)
    # instrument call instructions
    # - iterate over functions
    # - disassemble functions (capstone)
    # - for each call instruction
    #     - add hook to call verifier
    for func in functions:
        calls = find_calls(binary, func)
        for call in calls:
            instrument_call(binary, call)

    list_symbols(binary)
    log.info("saving result")
    binary.write("tests/out")


if __name__ == "__main__":
    main()
