from Pattern import *

class VarName(Pattern):

    def __init__(self, name):
        self.name = name

    def check(self, expr, ctx):
        return ctx.get_name(expr.idx) == self.name

class VarPattern(UnaryExpr):

    def __init__(self, name=AnyPattern()):
        super(VarPattern, self).__init__(name)

    def check(self, expr, ctx):
        return expr.opname == "var" and super(VarPattern, self).check(expr.v, ctx)


class VarBind(UnaryExpr):

    def __init__(self, name):
        super(VarBind, self).__init__(AnyPattern())
        self.name = name

    def check(self, expr, ctx):
        #print "Checking binded"
        if expr.opname == "var":
            if ctx.has_var(self.name):
                return ctx.get_var(self.name).idx == expr.v.idx
            else:
                ctx.save_var(self.name, expr.v.idx, expr.type, expr.v.mba)
                return True
        return False

class ObjBind(UnaryExpr):

    def __init__(self, name):
        super(ObjBind, self).__init__(AnyPattern())
        self.name = name

    def check(self, expr, ctx):
        if expr.opname == "obj":
            if ctx.has_obj(self.name):
                return ctx.get_obj(self.name).addr == expr.obj_ea
            else:
                ctx.save_obj(self.name, expr.obj_ea, expr.type)
                return True
        return False

class NumberConcrete(Pattern):

    def __init__(self, num):
        super(NumberConcrete, self).__init__()
        self.val = num

    def check(self, expr, ctx):
        return expr._value == self.val

class NumberPattern(UnaryExpr):

    def __init__(self, num=AnyPattern()):
        super(NumberPattern, self).__init__(num)

    def check(self, expr, ctx):
        if expr.opname == "num":
            return super(NumberPattern, self).check(expr.n, ctx)
        return False


TWO_OP = [('Asgn','asg'), ('Idx','idx'), ('Sub','sub'), ('Mul', 'mul'),
          ('Add','add'), ('Land','land'), ('Lor','lor'), ('Ult','ult'),
          ('Ule','ule'), ('Ugt','ugt'), ('Uge','uge'), ('Sle','sle'), ('Slt','slt'),
          ('Sgt','sgt'), ('Sge','sge'), ('Eq','eq'), ('Comma','comma'), ('Sshr','sshr'),
          ('Ushr', 'ushr'), ('Bor','bor'), ('AsgUShr','asgushr'), ('Smod','smod'),
          ('Xor','xor'), ('AsgAdd','asgadd'), ('AsgSub', 'asgsub'), ('BAnd','band')]

def BinaryGen(name, opname, BaseClass = BinaryExpr):
    def check(self, expr, ctx):
        return expr.opname == opname and super(type(self), self).check(expr, ctx)
    newclass = type(name, (BaseClass,), {"check":check})
    return newclass


ONE_OP = [('Preinc','preinc'), ('Predec','predec'), ('Ne','ne'), ('Lnot','lnot'), 
          ('Ref','ref'),('Bnot','bnot'),('Postinc','postinc'),('Postdec','postdec'), ('Ptr', 'ptr')]

def UnaryGen(name, opname, BaseClass = UnaryExpr):
    def check(self, expr, ctx):
        return expr.opname == opname and super(type(self), self).check(expr.x, ctx)
    newclass = type(name, (BaseClass,), {"check":check})
    return newclass

import sys
module = sys.modules[__name__]
for i in TWO_OP:
    setattr(module, i[0]+"Pattern", BinaryGen(i[0]+"Pattern", i[1]))
for i in ONE_OP:
    setattr(module, i[0]+"Pattern", UnaryGen(i[0]+"Pattern", i[1]))
