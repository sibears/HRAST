# -*- coding: utf-8 -*-

from ast_helper import *
import idaapi
import ida_name
import ida_bytes
import ida_struct
import ida_typeinf
import idc

strlen_global = """Patterns.ChainPattern([
    Patterns.ExprInst(Patterns.AsgnExpr(Patterns.VarBind("t1"), Patterns.ObjBind("strlenarg"))),
    Patterns.DoInst(Patterns.LnotExpr(Patterns.VarBind("t2")),Patterns.BlockInst([
        Patterns.ExprInst(Patterns.AsgnExpr(Patterns.VarBind("t3"), Patterns.PtrExpr(Patterns.AnyPattern()))),
        Patterns.ExprInst(Patterns.AsgAddExpr(Patterns.VarBind("t1"),Patterns.NumberExpr(Patterns.NumberConcrete(4)))),
        Patterns.ExprInst(Patterns.AsgnExpr(Patterns.VarBind("t2"),
                Patterns.BAndExpr(
                    Patterns.BAndExpr(
                        Patterns.BnotExpr(Patterns.VarBind("t3")),
                        Patterns.SubExpr(Patterns.VarBind("t3"), Patterns.NumberExpr(Patterns.NumberConcrete(0x1010101)))
                    ),
                    Patterns.NumberExpr(Patterns.NumberConcrete(0x80808080))
                )
            )
        ),
        ], False)
    ),
    Patterns.ExprInst(Patterns.AsgnExpr(Patterns.AnyPattern(), Patterns.AnyPattern())),
    Patterns.IfInst(Patterns.AnyPattern(), Patterns.AnyPattern()),
    Patterns.IfInst(Patterns.AnyPattern(), Patterns.AnyPattern()),
    Patterns.ExprInst(Patterns.AsgnExpr(Patterns.VarBind("res"), Patterns.AnyPattern()))
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
    return True

#=======================================
# This pattern is works with following case
#  dword_XXXX = (anytype)GetProcAddr(<anyArg>, 'funcName1')
#  dword_XXXY = (anytype)GetProcAddr(<anyArg>, 'funcName2')
#  ....
# After running this code if we decompile function where such pattern exist we will
#  automatically get:
#  funcName1 = (anytype)GetProcAddr(<anyArg>, 'funcName1')
#  funcName2 = (anytype)GetProcAddr(<anyArg>, 'funcName2')
#
#=======================================
get_proc_addr = """Patterns.ExprInst(
    Patterns.AsgnExpr(
        Patterns.ObjBind("fcnPtr"),
        Patterns.CastExpr(
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
    return False




#========================================
# This pattern will replace code like that
#   struct_XXX.field_X = (anytype)sub_XXXX
#   struct_XXX.field_Y = (anytype)sub_YYYY
# by
#   struct_XXX.sub_XXXX = (anytype)sub_XXXX
#   struct_XXX.sub_YYYY = (anytype)sub_YYYY
# where struct_XXX - global variable
# So, it's just renames structure fields
#========================================

global_struct_fields_sub = """
Patterns.ExprInst(
    Patterns.AsgnExpr(
        Patterns.MemRefGlobalBind('stroff'),
        Patterns.CastExpr(
            Patterns.ObjBind('fcn'),
        )
    )
)"""

def rename_struct_field_as_func_name(idx, ctx):
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
    return False




#==============================
# Test case for BindExpr
# So it just saves all condition expressions from
# all if without else
#==============================


test_bind_expr = """Patterns.IfInst(Patterns.BindExpr('if_cond', Patterns.AnyPattern()), Patterns.AnyPattern())"""

def test_bind(idx, ctx):
    exprs = ctx.get_expr('if_cond')
    for i in exprs:
        print i
    return False


#==============================================================
# Dummy example for switching vptr union based on variable type
# Here we have union like that
# union a{
#    vptr1_1 *class1;
#    struc_5 *class2;   
# }
#==============================================================

test_deep = """
Patterns.ExprInst(
    Patterns.CallExpr(
        Patterns.CastExpr(
            Patterns.MemptrExpr(
                Patterns.BindExpr(
                    'union_type',
                    Patterns.MemrefExpr(
                        Patterns.DeepExprPattern(
                            Patterns.MemptrExpr(Patterns.VarBind('v1'), 0, 8)
                        )
                    )
                )
            )
        ),
        [Patterns.AnyPattern() for i in range(12)]
    )
)
"""

test_deep_without_cast = """Patterns.ExprInst(
    Patterns.CallExpr(
        Patterns.MemptrExpr(
            Patterns.BindExpr(
                'union_type',
                Patterns.MemrefExpr(
                    Patterns.DeepExprPattern(
                        Patterns.MemptrExpr(Patterns.VarBind('v1'), 0, 8)
                    )
                )
            )
        ),
        [Patterns.AnyPattern() for i in range(12)]
    )
)
"""

def test_xx(idx, ctx):
    import ida_typeinf
    uni = ctx.get_expr('union_type')
    var = ctx.get_var('v1')
    tname =  var.typ.dstr().split(' ')[0]
    tinfo = idaapi.tinfo_t()
    if tname == 'class1':
        idaapi.parse_decl2(idaapi.cvar.idati, 'vptr1_1 *;', tinfo, idaapi.PT_TYP)
        uni[0].type = tinfo
        uni[0].m = 0
    elif tname == "class2":
        idaapi.parse_decl2(idaapi.cvar.idati, 'struc_5 *;', tinfo, idaapi.PT_TYP)
        uni[0].type = tinfo
        uni[0].m = 1
    else:
        return False
    return True

str_asgn = """Patterns.ExprInst(
    Patterns.AsgnExpr(Patterns.VarBind('r'),
                     Patterns.BindExpr('n',Patterns.NumberExpr())
                     )
)"""
GLOBAL = {}
MAX = 0
LAST_FCN_EA = None

def xx(inst, ctx):
    global MAX
    global GLOBAL
    global LAST_FCN_EA
    if LAST_FCN_EA is None:
        LAST_FCN_EA = ctx.fcn.entry_ea
    if LAST_FCN_EA != ctx.fcn.entry_ea:
        GLOBAL = {}
        MAX = 0
        LAST_FCN_EA = ctx.fcn.entry_ea
    print "{:x}".format(inst.ea)
    v = ctx.get_var('r')
    n = ctx.get_expr('n')[0]
    val = n.n._value & 0xff
    v_o = get_var_offset(ctx.fcn, v.idx)
    print "Var offset from stack:", v_o
    print val 
    if v_o > MAX:
        MAX = v_o
    if val < 256:
        if val == 0:
            GLOBAL[v_o] = "\\x00"
        else:
            GLOBAL[v_o] = chr(val)
    ret = ''
    for i in range(MAX+1):
        if i not in GLOBAL:
            ret += '_'
        else:

            ret += GLOBAL[i]
    print ret



#Example for inplace simplifications cpp operators (see pics on readme)
#Not really tested yet - I did it for concrete binary, so it may not work from the box for you
operator_replacing = """Patterns.ExprInst(
        Patterns.AsgnExpr(Patterns.VarBind('res'),
        Patterns.CallExprExactArgs(
                Patterns.ObjBind("function"),
                [Patterns.BindExpr("arg1", Patterns.AnyPattern()), Patterns.BindExpr("arg2", Patterns.AnyPattern())]
        )
    )
)"""

def get_string_repr(obj, ctx):
    if obj.opname == "cast":
        obj = obj.x
    else:
        pass
    if obj.opname == "obj":
        if obj.type.dstr() == "char *":
            return repr(ida_bytes.get_strlit_contents(obj.obj_ea, 256, -1))
        else:
            name = ida_name.get_name(obj.obj_ea).split("@@")[0]
            print name
            if name[0] == ".":
                name = name[1:]
            if "endl" in name:
                return "std::endl"
            return ida_name.demangle_name(name, 0)
    elif obj.opname == "ref":
        return "&"+get_string_repr(obj.x, ctx)
    elif obj.opname == "var":
        return ctx.get_var_name(obj.v.idx)
    # elif
    else:
        print obj.opname
    return ""
    

def react_operator(idx, ctx):
    print '%x' % (idx.ea)
    fcn_object = ctx.get_obj("function")
    """next line was working on ELF"""
    demangled = ida_name.demangle_name(ida_name.get_name(fcn_object.addr)[1:], 0)
    """next line was working on MACH-O"""
    #demangled = ida_name.demangle_name(ida_name.get_name(fcn_object.addr), 0)
    
    print demangled
    if "operator<<" in demangled:
        arg2 = ctx.get_expr('arg2')[0]
        arg1 = ctx.get_expr('arg1')[0]
        arg1_repr = get_string_repr(arg1, ctx)
        arg2_repr =  get_string_repr(arg2, ctx)
        var = ctx.get_var("res")
        #varname = ctx.get_var_name(var.idx)
        varexp = make_var_expr(var.idx, var.typ, var.mba)
        #varexp = make_var_expr(var2.idx, var2.typ, var2.mba, arg=True)
        arglist = ida_hexrays.carglist_t()
        arglist.push_back(arg2)
        helper = ida_hexrays.call_helper(ida_hexrays.dummy_ptrtype(4, False), arglist, "{} << ".format(arg1_repr))
        insn = make_cexpr_insn(idx.ea, make_asgn_expr(varexp, helper))
        idx.cleanup()
        idaapi.qswap(idx, insn)
        # del original inst because we swapped them on previous line
        del insn


operator_replacing2 = """Patterns.ExprInst(
        Patterns.CallExpr(
                Patterns.ObjBind("function"),
                [Patterns.BindExpr("arg1", Patterns.AnyPattern()), Patterns.BindExpr("arg2", Patterns.AnyPattern())]
        )
)"""

def react_operator2(idx, ctx):
    print '%x' % (idx.ea)
    fcn_object = ctx.get_obj("function")
    """next line was working on ELF"""
    demangled = ida_name.demangle_name(ida_name.get_name(fcn_object.addr)[1:], 0)
    """next line was working on MACH-O"""
    #demangled = ida_name.demangle_name(ida_name.get_name(fcn_object.addr), 0)
    print demangled
    if "operator<<" in demangled:
        arg1 = ctx.get_expr('arg1')[0]
        arg1_repr = get_string_repr(arg1, ctx)
        arg2 = ctx.get_expr('arg2')[0]
        #varexp = make_var_expr(var2.idx, var2.typ, var2.mba, arg=True)
        arglist = ida_hexrays.carglist_t()
        arglist.push_back(arg2)
        val = ida_hexrays.call_helper(ida_hexrays.dummy_ptrtype(4, False), arglist, "{} << ".format(arg1_repr))
        insn = make_cexpr_insn(idx.ea, val)
        idx.cleanup()
        idaapi.qswap(idx, insn)
        del insn




string_deleter = """Patterns.IfInst(
                        Patterns.UgeExpr(
                            Patterns.VarBind('len'),
                            Patterns.NumberExpr(Patterns.NumberConcrete(0x10))
                        ),
                        Patterns.BlockInst([
                            Patterns.ExprInst(
                                Patterns.AsgnExpr(
                                    Patterns.AnyPattern(),
                                    Patterns.VarBind('ptr')
                                )
                            ),
                            Patterns.IfInst(
                                Patterns.UgeExpr(
                                    Patterns.AddExpr(
                                        Patterns.VarBind('len'),
                                        Patterns.NumberExpr(Patterns.NumberConcrete(1))
                                    ),
                                    Patterns.NumberExpr(Patterns.NumberConcrete(0x1000)) 
                                ),
                                Patterns.AnyPattern()
                            ),
                            Patterns.ExprInst(
                                Patterns.CallExpr(
                                    Patterns.ObjConcrete(0x{:x}),
                                    [Patterns.AnyPattern()]
                                )
                            )
                        ], False)
)""".format(ida_name.get_name_ea(0, "free_0"))

def handle_string_destr(idx, ctx):
    print '%x' % (idx.ea)
    var = ctx.get_var('len')
    var2 = ctx.get_var('ptr')
    print var
    off1 = get_var_offset(ctx.fcn, var.idx)
    off2 = get_var_offset(ctx.fcn, var2.idx)
    print off1 - off2
    if off1 - off2 == 20:
        print "[+] Found string destructor"
        varexp = make_var_expr(var2.idx, var2.typ, var2.mba, arg=True)
        arglist = ida_hexrays.carglist_t()
        arglist.push_back(varexp)
        val = ida_hexrays.call_helper(ida_hexrays.dummy_ptrtype(4, False), arglist, "std::string::destructor")
        insn = make_cexpr_insn(idx.ea, val)
        idx.cleanup()
        idaapi.qswap(idx, insn)
        del insn

DWORD_STRUCT = """
Patterns.ExprInst(
    Patterns.AsgnExpr(
        Patterns.PtrExpr(
            Patterns.CastExpr(
                Patterns.RefExpr(
                    Patterns.BindExpr(
                        'struct_part',
                        Patterns.MemrefExpr(
                            Patterns.VarBind(
                                'struct_var'
                            )
                        )
                    )
                )                            
            ),
            4 #PTRSIZE
        ),
        Patterns.BindExpr(
            'values',
            Patterns.NumberExpr(
                Patterns.AnyPattern()
            )
        )
    )
)
"""

def replace_dword_in_struct(idx, ctx):
    print '%x' % idx.ea
    struct_expr = ctx.get_expr('struct_part')[0]
    var = ctx.get_var("struct_var")
    values = ctx.get_expr('values')[0]
    offset = struct_expr.m
    vals = []
    N = extract_number(values)
    typename = struct_expr.x.type.dstr()
    s_id = ida_struct.get_struc_id(typename)
    if s_id == idc.BADADDR:
        return
    sptr = ida_struct.get_struc(s_id)
    is_suits = True
    fields = []
    inner_offset = 0
    while inner_offset < 4:
        memb = ida_struct.get_member(sptr, offset+inner_offset)
        if memb is None:
            print "Not enought members!"
            is_suits = False
            break
        size = ida_struct.get_member_size(memb)
        if inner_offset + size  > 4:
            print "Size fail!(%d bytes lenft but member size is %d)" % (4 - inner_offset, size)
            is_suits = False
            break
        if size == 1:
            val = N & 0xff
            N = N >> 8
        elif size == 2:
            val = N & 0xffff
            N = N >> 16
        else:
            print "Unkn size"
            is_suits = False
            break
        fields.append((inner_offset, val))
        inner_offset += size
        
    if is_suits is False:
        print "Not suitable!"
        return
    inslist = []
    for i in fields:
        ins = make_asgn_refvar_number(idx.ea, var, offset+i[0], i[1])
        inslist.append(ins)
    #########
    # Not foldable
    #########    
    blk = make_cblk(inslist)
    cblk = make_cblock_insn(idx.ea, blk)
    idx.cleanup()
    idaapi.qswap(idx, cblk)
    del cblk
    ##########################
    # Foldable - not working - IDA crashes at exit idk why;[
    ##########################
    #fake_cond =  make_helper_expr("fold")
    #blk = make_cblk(inslist)
    #cblk = make_cblock_insn(idx.ea, blk)
    #cif = make_if(idx.ea, fake_cond, cblk)
    #idx.cleanup()
    #idaapi.qswap(idx, cif)
    #del cif
    return True



# Third arg - is chain
#PATTERNS = [(strlen_global, replacer_strlen_global, True)]
#PATTERNS = [(get_proc_addr, getProc_addr, False)]
#PATTERNS = [(test_deep, test_xx, False), (test_deep_without_cast, test_xx, False)]
#PATTERNS = [(global_struct_fields_sub, rename_struct_field_as_func_name, False)]
#PATTERNS = [(test_bind_expr, test_bind, False)]
#PATTERNS = [(str_asgn, xx, False)]
#PATTERNS = [(operator_replacing, react_operator, False), (operator_replacing2, react_operator2, False)]
#PATTERNS = [(string_deleter, handle_string_destr, False)]
PATTERNS = [(DWORD_STRUCT, replace_dword_in_struct, False)]