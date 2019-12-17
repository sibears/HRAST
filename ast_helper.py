# -*- coding: utf-8 -*-

import ida_hexrays


def make_call_expr(fcnexpr, args):
    expr = ida_hexrays.cexpr_t()
    expr.op = ida_hexrays.cot_call
    expr.x = fcnexpr
    expr.a = ida_hexrays.carglist_t()
    return expr


def make_helper_insn(ea, name):
    return make_cexpr_insn(ea, make_helper_expr(name))


def make_helper_expr(name, typ=False):
    obj = ida_hexrays.cexpr_t()
    obj.op = ida_hexrays.cot_helper
    obj.exflags |= ida_hexrays.EXFL_ALONE
    obj.helper = name
    if typ is not False:
        obj.type = typ
    return obj


def make_number_expr(val):
    expr = ida_hexrays.cexpr_t()
    expr.op = ida_hexrays.cot_num
    expr.n = ida_hexrays.cnumber_t()
    expr.n._value = val
    expr.type = ida_hexrays.dummy_ptrtype(4, False)
    return expr


def make_obj_expr(ea, type=None, arg=False):
    if arg is False:
        expr = ida_hexrays.cexpr_t()
    else:
        expr = ida_hexrays.carg_t()
    expr.op = ida_hexrays.cot_obj
    expr.obj_ea = ea
    if type is None:
        expr.type = ida_hexrays.dummy_ptrtype(4, False)
    else:
        expr.type = type
    return expr


def make_var_expr(number, type, m, arg=False):
    if arg is False:
        expr = ida_hexrays.cexpr_t()
    else:
        expr = ida_hexrays.carg_t()
    expr.op = ida_hexrays.cot_var
    expr.v = ida_hexrays.var_ref_t()
    expr.v.idx = number
    expr.type = type
    expr.v.mba = m
    return expr


def make_asgn_expr(left, right):
    expr = ida_hexrays.cexpr_t()
    expr.op = ida_hexrays.cot_asg
    expr.x = left
    expr.y = right
    expr.type = left.type
    return expr


def make_cexpr_insn(ea, obj):
    insn = ida_hexrays.cinsn_t()
    insn.ea = ea
    insn.op = ida_hexrays.cit_expr
    insn.cexpr = obj
    return insn

def make_comment(fcn, obj, comm):
    tl = ida_hexrays.treeloc_t()
    tl.ea = obj.ea
    tl.itp = ida_hexrays.ITP_SEMI
    fcn.set_user_cmt(tl, comm)
    fcn.save_user_cmts()


def extract_number(expr):
    return expr.n._value

def get_var_offset(fcn, var_idx):
    return fcn.lvars[var_idx].location.get_ea()


def make_cblock_insn(ea, blk):
    insn = ida_hexrays.cinsn_t()
    insn.ea = ea
    insn.op = ida_hexrays.cit_block
    insn.cblock = blk
    return insn

def make_cblk(insts):
    blk = ida_hexrays.cblock_t()
    for i in insts:
        blk.push_back(i)
    return blk

def make_if(ea, cond, if_clause):
    insn = ida_hexrays.cinsn_t()
    insn.ea = ea
    insn.op = ida_hexrays.cit_if
    insn.cexpr = cond
    ifc = ida_hexrays.cif_t()
    ifc.ithen = if_clause
    insn.cif = ifc
    return insn

def make_asgn_var_number(ea, var, number):
    nexpr = make_number_expr(number)
    vexpr = make_var_expr(var.idx, var.typ, var.mba)
    aexpr = make_asgn_expr(vexpr, nexpr)
    return make_cexpr_insn(ea, aexpr)

def make_memref_expr(vexpr, offset):
    expr = ida_hexrays.cexpr_t()
    expr.op = ida_hexrays.cot_memref
    expr.x = vexpr
    expr.m = offset
    expr.type =  ida_hexrays.dummy_ptrtype(4, False)
    return expr

def make_asgn_refvar_number(ea, var, offset, number):
    nexpr = make_number_expr(number)
    vexpr = make_var_expr(var.idx, var.typ, var.mba)
    rexpr = make_memref_expr(vexpr, offset)
    aexpr = make_asgn_expr(rexpr, nexpr)
    return make_cexpr_insn(ea, aexpr)