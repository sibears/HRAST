# -*- coding: utf-8 -*-


class Pattern(object):

    def __init__(self):
        pass

    def check(self, expr, ctx):
        pass


class AnyPattern(Pattern):

    def check(self, expr, ctx):
        return True


class BinaryExpr(Pattern):

    def __init__(self, left, rigth, simmetric=False):
        super(BinaryExpr, self).__init__()
        self.left = left
        self.rigth = rigth
        self.simmetric = simmetric

    def check(self, expr, ctx):
        left_x_right_y = self.left.check(expr.x, ctx) and self.rigth.check(expr.y, ctx)
        if self.simmetric:
            left_y_right_x = self.left.check(expr.y, ctx) and self.rigth.check(expr.x, ctx)
            return left_x_right_y or left_y_right_x
        else:
            return left_x_right_y


class UnaryExpr(Pattern):

    def __init__(self, operand):
        super(UnaryExpr, self).__init__()
        self.op = operand

    def check(self, expr, ctx):
        return self.op.check(expr, ctx)


class ChainPattern(object):

    def __init__(self, array):
        self._list = array
        self.pos = 0

    def check(self, inst, ctx):
        ret_val = self._list[self.pos].check(inst, ctx)
        if ret_val:
            if self.pos + 1 == len(self._list):
                ctx.save_cnt(self.pos + 1)
                self.pos = 0
            else:
                self.pos += 1
        else:
            self.pos = 0
        return ret_val


class GreedyPattern(object):
    """This class matches several instructions ended by stopper"""

    def __init__(self, stopper):
        self.stopper = stopper

    def check_greedy(self, inst, ctx):
        if self.stopper.check(inst, ctx):
            return True
        else:
            return False
