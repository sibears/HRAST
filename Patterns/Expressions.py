# -*- coding: utf-8 -*-

import sys
import Patterns as p
import Nodes


class BindExpr(p.Pattern):

    def __init__(self, type, expr_pattern):
        super(BindExpr, self).__init__()
        self.type = type
        self.pattern = expr_pattern

    def check(self, expr, ctx):
        if self.pattern.check(expr, ctx):
            ctx.ctx.save_expr(self.type, expr)
            return True
        return False

class VarName(p.Pattern):

    def __init__(self, name):
        super(VarName, self).__init__()
        self.name = name

    def check(self, expr, ctx):
        return ctx.ctx.get_var_name(expr.idx) == self.name


class VarExpr(p.UnaryExpr):

    def __init__(self, name=p.AnyPattern()):
        super(VarExpr, self).__init__(name)

    def check(self, expr, ctx):
        return expr.opname == "var" and super(VarExpr, self).check(expr.v, ctx)


class MemRefGlobalBind(p.Pattern):

    def __init__(self, name):
        super(MemRefGlobalBind, self).__init__()
        self.name = name

    def check(self, expr, ctx):
        if expr.opname == "memref":
            if expr.x.opname == "obj":
                if ctx.ctx.has_memref(self.name):
                    return ctx.ctx.get_memref(self.name).idx == expr.x.obj_ea
                else:
                    ctx.ctx.save_memref(self.name, expr.x.obj_ea, expr.m)
                    return True
        return False


class MemptrExpr(p.Pattern):
    
    def __init__(self, x, offset = -1, size = -1):
        super(MemptrExpr, self).__init__()
        self.x = x
        self.offset = offset
        self.size = size

    def check(self, expr, ctx):
        if expr.opname == "memptr":
            if self.offset != -1 and self.offset != expr.m:
                return False
            if self.size != -1 and self.size != expr.ptrsize:
                return False
            return self.x.check(expr.x, ctx)
        return False

class MemrefExpr(p.Pattern):
    
    def __init__(self, x, offset = -1):
        super(MemrefExpr, self).__init__()
        self.x = x
        self.offset = offset

    def check(self, expr, ctx):
        if expr.opname == "memref":
            if self.offset != -1 and self.offset != expr.m:
                return False
            return self.x.check(expr.x, ctx)
        return False

class PtrExpr(p.Pattern):
    
    def __init__(self, x, size = -1):
        super(PtrExpr, self).__init__()
        self.x = x
        self.size = size

    def check(self, expr, ctx):
        if expr.opname == "ptr":
            if self.size != -1 and self.size != expr.ptrsize:
                return False
            return self.x.check(expr.x, ctx)
        return False

class MemRefIdxGlobalBind(p.Pattern):

    def __init__(self, name):
        super(MemRefIdxGlobalBind, self).__init__()
        self.name = name

    def check(self, expr, ctx):
        if expr.opname == "memref":
            if expr.x.opname == "idx" and expr.x.x.opname =="obj":
                if ctx.ctx.has_memref(self.name):
                    return ctx.ctx.get_memref(self.name).idx == expr.x.x.obj_ea
                else:
                    ctx.ctx.save_memref(self.name, expr.x.x.obj_ea, expr.m)
                    return True
        return False

class VarBind(p.UnaryExpr):

    def __init__(self, name):
        super(VarBind, self).__init__(p.AnyPattern())
        self.name = name

    def check(self, expr, ctx):
        if expr.opname == "var":
            if ctx.ctx.has_var(self.name):
                return ctx.ctx.get_var(self.name).idx == expr.v.idx
            else:
                ctx.ctx.save_var(self.name, expr.v.idx, expr.type, expr.v.mba)
                return True
        return False


class ObjBind(p.UnaryExpr):

    def __init__(self, name):
        super(ObjBind, self).__init__(p.AnyPattern())
        self.name = name

    def check(self, expr, ctx):
        if expr.opname == "obj":
            if ctx.ctx.has_obj(self.name):
                return ctx.ctx.get_obj(self.name).addr == expr.obj_ea
            else:
                ctx.ctx.save_obj(self.name, expr.obj_ea, expr.type)
                return True
        return False


class CallExpr(p.Pattern):

    def __init__(self, fcn, args):
        super(CallExpr, self).__init__()
        self.fcn = fcn
        self.args = args

    def check(self, expr, ctx):
        if expr.opname == "call" and self.fcn.check(expr.x, ctx):
            res = True
            ln = len(self.args)
            idx = 0
            for i in expr.a:
                if idx >= ln:
                    return False
                res = res and self.args[idx].check(i, ctx)
                idx += 1
            return res
        return False
    
class CallExprExactArgs(p.Pattern):

    def __init__(self, fcn, args):
        super(CallExprExactArgs, self).__init__()
        self.fcn = fcn
        self.args = args

    def check(self, expr, ctx):
        if expr.opname == "call" and self.fcn.check(expr.x, ctx):
            res = True
            ln = len(self.args)
            idx = 0
            for i in expr.a:
                if idx >= ln:
                    return False
                res = res and self.args[idx].check(i, ctx)
                idx += 1
            if idx == ln:
                return res
        return False


class ObjConcrete(p.Pattern):

    def __init__(self, addr):
        super(ObjConcrete, self).__init__()
        self.addr = addr

    def check(self, expr, ctx):
        if expr.opname == "obj":
            if expr.obj_ea == self.addr:
                return True
        return False


class NumberConcrete(p.Pattern):

    def __init__(self, num):
        super(NumberConcrete, self).__init__()
        self.val = num

    def check(self, expr, ctx):
        return expr._value == self.val


class NumberExpr(p.UnaryExpr):

    def __init__(self, num=p.AnyPattern()):
        super(NumberExpr, self).__init__(num)

    def check(self, expr, ctx):
        if expr.opname == "num":
            return super(NumberExpr, self).check(expr.n, ctx)
        return False


class HelperExpr(p.Pattern):

    def __init__(self, name = None):
        super(HelperExpr, self).__init__()
        self.name = name
    
    def check(self, expr, ctx):
        if expr.opname == "helper":
            if self.name is not None:
                return expr.helper == self.name
            return True
        return False

class CastExpr(p.Pattern):

    def __init__(self, inner, cast_type=None):
        super(CastExpr, self).__init__()
        self.cast_type = cast_type
        self.inner = inner

    def check(self, expr, ctx):
        if expr.opname == "cast":
            if self.cast_type is not None and expr.type.dstr() != self.cast_type:
                return False
            res = self.inner.check(expr.x, ctx)
            return res
        return False


def BinaryGen(name, opname, BaseClass=p.BinaryExpr):

    def check(self, expr, ctx):
        return expr.opname == opname and super(type(self), self).check(expr, ctx)

    newclass = type(name, (BaseClass,), {"check": check})
    return newclass

def UnaryGen(name, opname, BaseClass=p.UnaryExpr):

    def check(self, expr, ctx):
        return expr.opname == opname and super(type(self), self).check(expr.x, ctx)

    newclass = type(name, (BaseClass,), {"check": check})
    return newclass

module = sys.modules[__name__]
for i in Nodes.TWO_OP:
    setattr(module, i[0] + "Expr", BinaryGen(i[0] + "Expr", i[1]))
for i in Nodes.ONE_OP:
    setattr(module, i[0] + "Expr", UnaryGen(i[0] + "Expr", i[1]))
