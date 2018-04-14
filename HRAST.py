import ctypes
import sys
import re
import importlib
import idaapi
idaapi.require("Patterns.__init__")
idaapi.require("Patterns.Instructions")
idaapi.require("Patterns.Expressions")
idaapi.require("Patterns.Pattern")
idaapi.require("Matcher")
idaapi.require("ast_helper")
from Matcher import *
from ast_helper import *
from Patterns.Instructions import *
from Patterns.Expressions import *
from traverse import *
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

def reLOAD():
    global used_pats
    #For tesing now I just rewrite "ready_patterns.py" and call reLOAD
    reload(ready_patterns)
    used_pats = []
    for i in ready_patterns.PATTERNS:
        print i[0]
        used_pats.append((eval(i[0], globals(), locals()), i[1]))

def hexrays_events_callback_m(*args):
    global LEV
    global NAME
    ev = args[0]
    #print "Got {}:".format(EVENTS_HEXR[ev])
    if ev == idaapi.hxe_maturity:
        fcn = args[1]
        level = args[2]
        #print "Got level {}".format(CMAT_LEVEL[level])
        if level == idaapi.CMAT_FINAL:
            print used_pats
            for i in used_pats:
                fcnProc = FuncProcesser(fcn)
                matcher = Matcher(fcnProc.fcn, None)
                matcher.set_pattern(i[0])
                matcher.chain = True
                matcher.replacer = i[1]
                fcnProc.pattern = matcher
                fcnProc.DEBUG = True
                fcnProc.traverse_function()
    return 0

def hr_remove():
	idaapi.remove_hexrays_callback(hexrays_events_callback_m)

if __name__ == "__main__":
	print "yay"
	print idaapi.install_hexrays_callback(hexrays_events_callback_m)
