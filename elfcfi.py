import logging
import re
import ctypes
import struct
import sys
import subprocess
import os
from pprint import pprint

import lief
import keystone
import capstone

from pprint import pprint

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
_cs = None


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
            if sym.name == "_init":
                continue
            if sym.value > 0:
                functions[sym.name] = sym.value  # ^ 0x3000
    if binary.entrypoint not in functions.values():
        functions['entry0'] = binary.entrypoint
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


def cs_disasm(code):
    code = "".join(map(chr, code))
    global _cs
    if not _cs:
        _cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return _cs.disasm(code, 0)


def ks_asm(code):
    global _ks
    if not _ks:
        _ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
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
        a = func
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
    # log.debug("got {!r}".format(ephook))
    newep, _ = binary.insert_content(ephook)
    # newep += 0x00400000
    startsym = next(
        iter(filter(lambda s: s.name == "_start", binary.static_symbols)))
    startsym.value = newep
    log.debug("new entrypoint is 0x{:x}".format(newep))


def find_calls(binary, functions):
    funcaddrs = sorted(v for v in functions.values() if v > 0)
    # last function, probably spans till end of the text section?
    txtsection = binary.get_section(".text")
    seg = next(txtsection.segments)
    text_end = seg.virtual_address + seg.virtual_size
    func_ranges = zip(funcaddrs, funcaddrs[1:] + [text_end])
    log.debug("identified functions {!r}"
              .format(map(lambda x: (hex(x[0]), hex(x[1])), func_ranges)))

    callsites = {}
    for fn_begin, fn_end in func_ranges:
        log.debug("starting disassembly at 0x{:x} until 0x{:x}"
                  .format(fn_begin, fn_end))
        assert fn_begin < fn_end, "invalid function range"
        code = binary.get_content_from_virtual_address(fn_begin,
                                                       fn_end - fn_begin)
        insts = cs_disasm(code)
        for inst in insts:
            # log.debug(
            #     "0x{:x} {} {}"
            #     .format(inst.address + fn_begin, inst.mnemonic, inst.op_str))
            if inst.insn_name() == "call" or inst.insn_name() == "jmp":
                log.debug("got call '{} {}'"
                          .format(inst.insn_name(), inst.op_str))
                target = None
                try:
                    target = int(inst.op_str, 16)
                except ValueError:
                    try:
                        target = int(inst.op_str)
                    except ValueError:
                        target = None

                old_target = target
                if target:
                    if (1 << 63) & target != 0:
                        signed_number = ctypes.c_long(target).value
                        target = fn_begin + inst.address + signed_number
                        log.debug(
                            "call at 0x{:x} old target: 0x{:x} new target: 0x{:x}"
                            .format(fn_begin + inst.address, old_target,
                                    target))

                callsites[fn_begin + inst.address] = {
                    'target': target,
                    'inst': inst
                }
    return callsites


def instrument_call(binary, calladdr, call):
    log.debug("instrumenting call @ 0x{:x} to {!r}"
              .format(calladdr, call['target']))
    pass


def list_symbols(binary):
    for sym in binary.static_symbols:
        if sym.type == lief.ELF.SYMBOL_TYPES.FUNC:
            log.info("{} / 0x{:x}".format(sym.name, sym.value))


def main():
    # load binary
    binary = load_binary(sys.argv[1])
    list_symbols(binary)

    # find functions in binary
    # - iterate over symbols in binary
    # - gather a map symbols <-> address
    functions = get_functions(binary)
    callsites = find_calls(binary, functions)
    pprint(callsites)
    fn_addrs = ([v for v in functions.values() if v > 0] +
                [cs['target'] for cs in callsites.values() if cs['target']])

    # insert hooks
    hooks = load_blobs(binary)
    # hook entry point to setup shadow memory
    hook_entrypoint(binary, hooks, fn_addrs)

    # instrument call instructions
    # - iterate over functions
    # - disassemble functions (capstone)
    # - for each call instruction
    #     - add hook to call verifier
    for call in callsites:
        instrument_call(binary, call, callsites[call])

    # list_symbols(binary)
    log.info("saving result")
    binary.write("tests/out")
    os.chmod("tests/out", 777)


if __name__ == "__main__":
    main()
