# -*- coding: utf-8 -*-

from Patterns import *


class IfInst(object):

    def __init__(self, cond, then, els=None):

        self.cond = cond
        self.then = then
        self.els = els

    def check(self, insn, ctx):
        if insn.opname == "if" and self.cond.check(insn.cif.expr, ctx):
            if self.then.check(insn.cif.ithen, ctx):
                if self.els is not None:
                    if insn.cif.ielse is not None:
                        return self.els.check(insn.cif.ielse, ctx)
                    else:
                        return False
                else:
                    return insn.cif.ielse is None
        return False

class SingleInst(object):

    def __init__(self, inner):
        self.inner = inner

    def check(self, insn, ctx):
        #TODO: hmmm... isn't it a ExprInst?
        #TODO: maybe will be good to rename class and add checking inside conditions
        if insn.opname in ['block', 'if', 'for', 'while', 'do']:
            return False
        return self.inner.check(insn, ctx)

class EmptyInst(object):

    def check(self, insn, ctx):
        return insn.opname == "empty"


class BlockInst(object):

    def __init__(self, nodes, strict=True):
        self.nodes = nodes
        self.strict = strict

    def check_strict(self, inst, ctx):
        if len(self.nodes) == len(inst.cblock):
            same = True
            for i in zip(self.nodes, inst.cblock):
                same = same and i[0].check(i[1], ctx)
                if not same:
                    break
            return same
        return False

    def check(self, inst, ctx):
        if inst.opname != "block":
            return False
        if self.strict:
            return self.check_strict(inst, ctx)
        ln = len(inst.cblock)
        lnpat = len(self.nodes)
        pos = 0
        pospat = 0
        flag = True
        currpat = self.nodes[pospat]
        nodes = [i for i in inst.cblock]
        while pos < ln:
            i = nodes[pos]
            if type(currpat) == GreedyPattern:
                if not currpat.check_greedy(i, ctx):
                    pos += 1
                    continue
            else:
                if not currpat.check(i, ctx):
                    flag = False
                    break
            pospat += 1
            if pospat == lnpat:
                if pos + 1 == ln:
                    return True
                else:
                    return False

            currpat = self.nodes[pospat]
            pos += 1
        return flag


class SwitchInst(object):

    def __init__(self, expr, cases):
        self.expr = expr
        self.cases = cases

    def check(self, insn, ctx):
        if insn.opname == "switch" and self.expr.check(insn.cswitch.expr, ctx):
            # TODO: add properly checking of cases
            return True
        return False


class WhileInst(object):

    def __init__(self, cond, body):
        self.cond = cond
        self.body = body

    def check(self, insn, ctx):
        if insn.opname == "while" and self.cond.check(insn.cwhile.expr, ctx):
            return self.body.check(insn.cwhile.body, ctx)
        return False


class DoInst(object):
    def __init__(self, cond, body):
        self.cond = cond
        self.body = body

    def check(self, insn, ctx):
        if insn.opname == "do" and self.cond.check(insn.cdo.expr, ctx):
            return self.body.check(insn.cdo.body, ctx)
        return False


class ReturnInst(object):

    def __init__(self, exp):
        self.expr = exp

    def check(self, insn, ctx):
        return insn.opname == 'return' and self.expr.check(insn.creturn.expr, ctx)

class ExprInst(object):

    def __init__(self, exp):
        self.expr = exp

    def check(self, expr, ctx):
        return expr.opname == "expr" and self.expr.check(expr.cexpr, ctx)


class ForInst(object):

    def __init__(self, init, expr, step, body):
        self.init = init
        self.expr = expr
        self.step = step
        self.body = body

    def check(self, insn, ctx):
        if insn.opname == "for" and self.init.check(insn.cfor.init, ctx):
            return self.expr.check(insn.cfor.expr, ctx) and self.step.check(insn.cfor.step, ctx) \
                   and self.body.check(insn.cfor.body, ctx)
        return False
