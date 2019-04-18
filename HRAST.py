# -*- coding: utf-8 -*-

import ctypes
import sys
import re
import importlib
import idaapi
idaapi.require("Patterns")
idaapi.require("Matcher")
idaapi.require("ast_helper")
idaapi.require("traverse")
import ready_patterns

EVENTS_HEXR = {
    0: 'hxe_flowchart',
    1: 'hxe_prolog',
    2: 'hxe_preoptimized',
    3: 'hxe_locopt',
    4: 'hxe_prealloc',
    5: 'hxe_glbopt',
    6: 'hxe_structural',
    7: 'hxe_maturity',
    8: 'hxe_interr',
    9: 'hxe_combine',
    10: 'hxe_print_func',
    11: 'hxe_func_printed',
    12: 'hxe_resolve_stkaddrs',
    100: 'hxe_open_pseudocode',
    101: 'hxe_switch_pseudocode',
    102: 'hxe_refresh_pseudocode',
    103: 'hxe_close_pseudocode',
    104: 'hxe_keyboard',
    105: 'hxe_right_click',
    106: 'hxe_double_click',
    107: 'hxe_curpos',
    108: 'hxe_create_hint',
    109: 'hxe_text_ready',
    110: 'hxe_populating_popup'
}

CMAT_LEVEL = {
    0: 'CMAT_ZERO',
    1: 'CMAT_BUILT',
    2: 'CMAT_TRANS1',
    3: 'CMAT_NICE',
    4: 'CMAT_TRANS2',
    5: 'CMAT_CPA',
    6: 'CMAT_TRANS3',
    7: 'CMAT_CASTED',
    8: 'CMAT_FINAL'
}

LEV = 0
NAME = 'log'

used_pats = []
DEBUG = False


def reLOAD():
    global used_pats
    # For tesing now I just rewrite "ready_patterns.py" and call reLOAD
    reload(ready_patterns)
    used_pats = []
    for i in ready_patterns.PATTERNS:
        print i.pattern
        used_pats.append((eval(i.pattern, globals(), locals()), i.process, i.is_chain))


def unLOAD():
    global used_pats
    used_pats = []


def deBUG():
    global DEBUG
    DEBUG = not DEBUG


def hexrays_events_callback_m(*args):
    global LEV
    global NAME
    ev = args[0]
    if ev == idaapi.hxe_maturity:
        fcn = args[1]
        level = args[2]
        if level == idaapi.CMAT_FINAL:
            for i in used_pats:
                func_proc = traverse.FuncProcessor(fcn)
                matcher = Matcher.Matcher(func_proc.fcn, None)
                matcher.set_pattern(i[0])
                matcher.chain = i[2]
                matcher.replacer = i[1]
                func_proc.pattern = matcher
                func_proc.DEBUG = DEBUG
                func_proc.traverse_function()
    return 0


def hr_remove():
    idaapi.remove_hexrays_callback(hexrays_events_callback_m)


if __name__ == "__main__":    
    print idaapi.install_hexrays_callback(hexrays_events_callback_m)
