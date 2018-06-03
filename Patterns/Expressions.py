# -*- coding: utf-8 -*-

import sys
import Patterns as p


class VarName(p.Pattern):

    def __init__(self, name):
        super(VarName, self).__init__()
        self.name = name

    def check(self, expr, ctx):
        return ctx.get_name(expr.idx) == self.name


class VarPattern(p.UnaryExpr):

    def __init__(self, name=p.AnyPattern()):
        super(VarPattern, self).__init__(name)

    def check(self, expr, ctx):
        return expr.opname == "var" and super(VarPattern, self).check(expr.v, ctx)


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
    

class ObjConcrete(p.Pattern):

    def __init__(self, addr):
        super(ObjConcrete, self).__init__()
        self.addr = addr

    def check(self, expr, ctx):
        if expr.opname == "obj":
            print "{:x}".format(expr.obj_ea)
            print "{:x}".format(self.addr)
            if expr.obj_ea == self.addr:
                return True
        return False


class NumberConcrete(p.Pattern):

    def __init__(self, num):
        super(NumberConcrete, self).__init__()
        self.val = num

    def check(self, expr, ctx):
        return expr._value == self.val


class NumberPattern(p.UnaryExpr):

    def __init__(self, num=p.AnyPattern()):
        super(NumberPattern, self).__init__(num)

    def check(self, expr, ctx):
        if expr.opname == "num":
            return super(NumberPattern, self).check(expr.n, ctx)
        return False


class CastPattern(p.Pattern):

    def __init__(self, inner, cast_type=None):
        super(CastPattern, self).__init__()
        self.cast_type = cast_type
        self.inner = inner

    def check(self, expr, ctx):
        if expr.opname == "cast":
            if self.cast_type is not None and expr.type.dstr() != self.cast_type:
                return False
            res = self.inner.check(expr.x, ctx)
            print "Cast check ret {}".format(res)
            return res
        return False


TWO_OP = [
    ('Asgn', 'asg'), ('Idx', 'idx'), ('Sub', 'sub'), ('Mul', 'mul'),
    ('Add', 'add'), ('Land', 'land'), ('Lor', 'lor'), ('Ult', 'ult'),
    ('Ule', 'ule'), ('Ugt', 'ugt'), ('Uge', 'uge'), ('Sle', 'sle'), ('Slt', 'slt'),
    ('Sgt', 'sgt'), ('Sge', 'sge'), ('Eq', 'eq'), ('Comma', 'comma'), ('Sshr', 'sshr'),
    ('Ushr', 'ushr'), ('Bor', 'bor'), ('AsgUShr', 'asgushr'), ('Smod', 'smod'),
    ('Xor', 'xor'), ('AsgAdd', 'asgadd'), ('AsgSub', 'asgsub'), ('BAnd', 'band'), ('AsgBor', 'asgbor'),
    ('AsgBAnd', 'asgband')
]


def BinaryGen(name, opname, BaseClass=p.BinaryExpr):

    def check(self, expr, ctx):
        return expr.opname == opname and super(type(self), self).check(expr, ctx)

    newclass = type(name, (BaseClass,), {"check": check})
    return newclass


ONE_OP = [
    ('Preinc', 'preinc'), ('Predec', 'predec'), ('Ne', 'ne'), ('Lnot', 'lnot'),
    ('Ref', 'ref'), ('Bnot', 'bnot'), ('Postinc', 'postinc'), ('Postdec', 'postdec'), ('Ptr', 'ptr'),
]


def UnaryGen(name, opname, BaseClass=p.UnaryExpr):

    def check(self, expr, ctx):
        return expr.opname == opname and super(type(self), self).check(expr.x, ctx)

    newclass = type(name, (BaseClass,), {"check": check})
    return newclass


module = sys.modules[__name__]
for i in TWO_OP:
    setattr(module, i[0] + "Pattern", BinaryGen(i[0] + "Pattern", i[1]))
for i in ONE_OP:
    setattr(module, i[0] + "Pattern", UnaryGen(i[0] + "Pattern", i[1]))
