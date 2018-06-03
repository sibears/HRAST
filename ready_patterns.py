# -*- coding: utf-8 -*-

from ast_helper import *
import idaapi
import ida_name

strlen_global = """Patterns.ChainPattern([
    Patterns.ExprPattern(Patterns.AsgnPattern(Patterns.VarBind("t1"), Patterns.ObjBind("strlenarg"))),
    Patterns.DoPattern(Patterns.LnotPattern(Patterns.VarBind("t2")),Patterns.BlockPattern([
        Patterns.ExprPattern(Patterns.AsgnPattern(Patterns.VarBind("t3"), Patterns.PtrPattern(Patterns.AnyPattern()))),
        Patterns.ExprPattern(Patterns.AsgAddPattern(Patterns.VarBind("t1"),Patterns.NumberPattern(Patterns.NumberConcrete(4)))),
        Patterns.ExprPattern(Patterns.AsgnPattern(Patterns.VarBind("t2"),
                Patterns.BAndPattern(
                    Patterns.BAndPattern(
                        Patterns.BnotPattern(Patterns.VarBind("t3")),
                        Patterns.SubPattern(Patterns.VarBind("t3"), Patterns.NumberPattern(Patterns.NumberConcrete(0x1010101)))
                    ),
                    Patterns.NumberPattern(Patterns.NumberConcrete(0x80808080))
                )
            )
        ),
        ], False)
    ),
    Patterns.ExprPattern(Patterns.AsgnPattern(Patterns.AnyPattern(), Patterns.AnyPattern())),
    Patterns.IfPattern(Patterns.AnyPattern(), Patterns.AnyPattern()),
    Patterns.IfPattern(Patterns.AnyPattern(), Patterns.AnyPattern()),
    Patterns.ExprPattern(Patterns.AsgnPattern(Patterns.VarBind("res"), Patterns.AnyPattern()))
])"""


def replacer_strlen_global(idx, ctx):
    var = ctx.get_var("res")
    varname = ctx.get_var_name(var.idx)
    obj = ctx.get_obj("strlenarg")

    varexp = make_var_expr(var.idx, var.typ, var.mba)
    arg1 = make_obj_expr(obj.addr, obj.type, arg=True)
    arglist = ida_hexrays.carglist_t()
    arglist.push_back(arg1)
    val = ida_hexrays.call_helper(ida_hexrays.dummy_ptrtype(4, False), arglist, "strlen_inlined")
    insn = make_cexpr_insn(idx.ea, make_asgn_expr(varexp, val))

    idx.cleanup()
    idaapi.qswap(idx, insn)
    # del original inst because we swapped them on previous line
    del insn


# Third arg - is chain
PATTERNS = [(strlen_global, replacer_strlen_global, True)]
get_proc_addr = """Patterns.ExprPattern(
    Patterns.AsgnPattern(
        Patterns.ObjBind("fcnPtr"),
        Patterns.CastPattern(
            Patterns.CallExpr(
                Patterns.ObjConcrete(0x{:x}),
                [Patterns.AnyPattern(), Patterns.ObjBind("fcnName")]
            )
        )
    )
)
""".format(0x3)  # 0x3 - replace by addr of getProcAddr


def getProc_addr(idx, ctx):
    import ida_bytes
    obj = ctx.get_obj("fcnPtr")
    print "%x" % obj.addr
    name = ctx.get_obj("fcnName")
    name_str = ida_bytes.get_strlit_contents(name.addr, -1, -1)
    ida_name.set_name(obj.addr, name_str)


# PATTERNS = [(get_proc_addr, getProc_addr, False)]
global_struct_fields_sub = """
Patterns.ExprPattern(
    Patterns.AsgnPattern(
        Patterns.MemRefGlobalBind('stroff'),
        Patterns.CastPattern(
            Patterns.ObjBind('fcn'),
        )
    )
)"""


def _f1(idx, ctx):
    import idc
    import ida_bytes
    obj = ctx.get_memref('stroff')
    print "%x" % obj.ea
    ti = idaapi.opinfo_t()
    f = idc.GetFlags(obj.ea)
    if idaapi.get_opinfo(obj.ea, 0, f, ti):
        print("tid=%08x - %s" % (ti.tid, idaapi.get_struc_name(ti.tid)))
    print "Offset: {}".format(obj.offset)
    import ida_struct
    obj2 = ctx.get_obj('fcn')
    print "%x" % obj2.addr
    name_str = ida_name.get_name(obj2.addr)
    print "Name {}".format(name_str)
    ida_struct.set_member_name(ida_struct.get_struc(ti.tid), obj.offset, name_str)

# PATTERNS = [(global_struct_fields_sub, _f1, False)]

test_bind_expr = """Patterns.IfPattern(Patterns.BindExpr('if_cond', Patterns.AnyPattern()), Patterns.AnyPattern())"""

def test_bind(idx, ctx):
    exprs = ctx.get_expr('if_cond')
    for i in exprs:
        print i

PATTERNS = [(test_bind_expr, test_bind, False)]