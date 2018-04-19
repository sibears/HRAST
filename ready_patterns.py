from ast_helper import *
import idaapi
import ida_name

strlen_global = """ChainPattern([
    ExprPattern(AsgnPattern(VarBind("t1"), ObjBind("strlenarg"))),
    DoPattern(LnotPattern(VarBind("t2")),BlockPattern([
        ExprPattern(AsgnPattern(VarBind("t3"), PtrPattern(AnyPattern()))),
        ExprPattern(AsgAddPattern(VarBind("t1"),NumberPattern(NumberConcrete(4)))),
        ExprPattern(AsgnPattern(VarBind("t2"),
                BAndPattern(
                    BAndPattern(
                        BnotPattern(VarBind("t3")),
                        SubPattern(VarBind("t3"), NumberPattern(NumberConcrete(0x1010101)))
                    ),
                    NumberPattern(NumberConcrete(0x80808080))
                )
            )
        ),
        ], False)
    ),
    ExprPattern(AsgnPattern(AnyPattern(), AnyPattern())),
    IfPattern(AnyPattern(), AnyPattern()),
    IfPattern(AnyPattern(), AnyPattern()),
    ExprPattern(AsgnPattern(VarBind("res"), AnyPattern()))
])"""

def replacer_strlen_global(idx, ctx):
    var = ctx.get_var("res")
    varname = ctx.get_name(var.idx)
    obj = ctx.get_obj("strlenarg")

    varexp = make_var_expr(var.idx, var.typ, var.mba)
    arg1 = make_obj_expr(obj.addr, obj.type, arg = True)
    arglist = ida_hexrays.carglist_t()
    arglist.push_back(arg1)
    val = ida_hexrays.call_helper(ida_hexrays.dummy_ptrtype(4, False), arglist, "strlen_inlined")
    insn = make_cexpr_insn(idx.ea, make_asgn_expr(varexp, val))

    idx.cleanup()
    idaapi.qswap(idx, insn)
    #del original inst because we swapped them on previous line
    del insn

#Third arg - is chain
PATTERNS = [(strlen_global, replacer_strlen_global, True)]
get_proc_addr = """ExprPattern(
    AsgnPattern(
        ObjBind("fcnPtr"),
        CastPattern(
            CallExpr(
                ObjConcrete(0x{:x}),
                [AnyPattern(), ObjBind("fcnName")]
            )
        )
    )
)
""".format(0/0) # 0/0 - addr of getProcAddr

def getProc_addr(idx, ctx):
    import ida_bytes
    obj = ctx.get_obj("fcnPtr")
    print "%x" % obj.addr
    name = ctx.get_obj("fcnName")
    name_str = ida_bytes.get_strlit_contents(name.addr, -1, -1)
    ida_name.set_name(obj.addr, name_str)



PATTERNS = [(get_proc_addr, getProc_addr, False)]