import ida_hexrays
import Nodes

def is_inst(node):
    return type(node) == type(ida_hexrays.cinsn_t())

def is_expr(node):
    return type(node) == type(ida_hexrays.cexpr_t())

def get_inner_expr_to_check(node):
    if is_inst(node):
        inners = get_inner_entities_list(node)
    else:
        inners = [node]
    expressions = filter(is_expr, inners)
    insns = filter(is_inst, inners)
    assert(len(insns) + len(expressions) == len(inners))
    for j in insns:
        expressions += get_inner_expr_to_check(j)
    inner = []
    for i in expressions:
        inner += get_inner_entities_list_expr(i)
    return expressions + inner

def get_inner_entities_list(node):
    opname = node.opname
    if opname == "block":
        return [x for x in node.cblock]
    elif opname == "expr":
        return [node.cexpr]
    elif opname == "if":
        ret = [node.cif.expr, node.cif.ithen]
        if node.cif.ielse is not None:
            ret.append(node.cif.ielse)
        return ret
    elif opname == "do":
        return [node.cdo.expr, node.cdo.body]
    elif opname == "return":
        return [node.creturn.expr]
    elif opname == "goto":
        return []
    elif opname == "while":
        return [node.cwhile.expr, node.cwhile.body]
    elif opname == "break":
        return []
    elif opname == "switch":
        #TODO: do something
        return []
    elif opname == "for":
        return filter(lambda x : x is not None, [node.cfor.init, node.cfor.expr, node.cfor.step, node.cfor.body])
    elif opname == "empty":
        return []
    else:
        raise Exception('Got unexpected opname {}'.format(node.opname))

def get_inner_entities_list_expr(exp):
    opname = exp.opname
    if opname == 'var':
        """There is no expressions inside var"""
        return []
    elif opname == "memptr":
        return [exp.x] + get_inner_entities_list_expr(exp.x)
    elif opname == "memref":
        return [exp.x] + get_inner_entities_list_expr(exp.x)
    elif opname == "ptr":
        return [exp.x] + get_inner_entities_list_expr(exp.x)
    elif opname == "tern":
        return [exp.x, exp.y, exp.z] + get_inner_entities_list_expr(exp.x) + get_inner_entities_list_expr(exp.y) + get_inner_entities_list_expr(exp.z)
    elif opname == "call":
        return [exp.x] + [i for i in exp.a] + get_inner_entities_list_expr(exp.x) + sum([get_inner_entities_list_expr(i) for i in exp.a], [])
    elif opname == "helper":
        return []
    elif opname in ["obj", "num", "fnum"]:
        return []
    elif opname == "cast":
        return [exp.x] + get_inner_entities_list_expr(exp.x)
    elif opname in Nodes.ONE_OP_N:
        return [exp.x] + get_inner_entities_list_expr(exp.x)
    elif opname in Nodes.TWO_OP_N:
        return [exp.x, exp.y] + get_inner_entities_list_expr(exp.x) + get_inner_entities_list_expr(exp.y)

'''
if opname == "var":
            if self.DEBUG:
                print "{}[+] Varname: {}".format(" " * ((shift + 1) * TAB_SPACES), self.fcn.lvars[exp.v.idx].name)
        elif opname == "memptr":
            self.traverse_expr(exp.x, shift + 1)
            if self.DEBUG:
                print "{}[+] Offset: {}".format(" " * ((shift + 1) * TAB_SPACES), exp.m)
                print "{}[+] Size: {}".format(" " * ((shift + 1) * TAB_SPACES), exp.ptrsize)
        elif opname == "memref":
            self.traverse_expr(exp.x, shift + 1)
            if self.DEBUG:
                print "{}[+] Offset: {}".format(" " * ((shift + 1) * TAB_SPACES), exp.m)
        elif opname == "ptr":
            self.traverse_expr(exp.x, shift + 1)
            if self.DEBUG:
                print "{}[+] Size: {}".format(" " * ((shift + 1) * TAB_SPACES), exp.ptrsize)
        elif opname in FuncProcessor.TWO_OP:
            self.traverse_expr(exp.x, shift + 1)
            self.traverse_expr(exp.y, shift + 1)
        elif opname in FuncProcessor.ONE_OP:
            self.traverse_expr(exp.x, shift + 1)
        elif opname == "tern":
            self.traverse_expr(exp.x, shift + 1)
            self.traverse_expr(exp.y, shift + 1)
            self.traverse_expr(exp.z, shift + 1)
        elif opname == "call":
            self.traverse_expr(exp.x, shift + 1)
            for i in exp.a:
                self.traverse_args(i, shift + 1)
        elif opname == "helper":
            if self.DEBUG:
                print "{}[+] Helper: {}".format(" " * ((shift + 1) * TAB_SPACES), exp.helper)
        elif opname == "obj":
            if self.DEBUG:
                print "{}[+] EA: {:x}".format(" " * ((shift + 1) * TAB_SPACES), exp.obj_ea)
        elif opname == "num":
            if self.DEBUG:
                print "{}[+] Number: {:x}".format(" " * ((shift + 1) * TAB_SPACES), exp.n._value)
        elif opname == "fnum":
            if self.DEBUG:
                print "{}[+] Float number {}".format(" "* ((shift+1) * TAB_SPACES), ["{:x}".format(x) for x in exp.fpc.fnum])
        elif opname == "cast":
            if self.DEBUG:
                print "{}[+] CastTo: {}".format(" " * ((shift + 1) * TAB_SPACES), exp.type.dstr())
            self.traverse_expr(exp.x, shift + 1)
        elif opname == "empty":
            pass
        else:
            print "[-] Got unknown expr {}".format(opname)
            raise Exception('Got unknown expr {}'.format(opname))

def process_case(self, cas, shift):
        if type(cas) != ida_hexrays.ccase_t:
            print "[-] Not an case!"
            return
        vals = []
        for i in cas.values:
            vals.append(i)
        if not vals:
            vals = "default"
        if self.DEBUG:
            print "{}[+]Got case {} num {}".format(" " * (shift * TAB_SPACES), cas.opname, str(vals))
        fields = self.process_exprs_and_get_next(cas, shift)
        if fields is None:
            return
        for i in fields:
            self.traverse_node(i, shift + 1)

    def traverse_function(self):
        fcnbody = self.fcn.body
        if type(fcnbody) != ida_hexrays.cinsn_t:
            print "[-] Function body not an instruction!"
            return
        self.traverse_node(fcnbody)

    def traverse_node(self, node, shift=0):
        fired = False
        if type(node) != ida_hexrays.cinsn_t:
            print "{}[-] Got not an instruction {}".format(" " * (shift * TAB_SPACES), node.opname)
            return
        if self.DEBUG:
            print "{}[+]Got instruction {}".format(" " * (shift * TAB_SPACES), node.opname)
        if node.opname == "block":
            self.curr_cblock.append(node)
            self.need_reanalyze_cblock = False
        if self.pattern is not None:
            if self.pattern.is_chain():
                if self.pattern.check_chain(node):
                    # TODO: possible inner hiding?
                    if self.pattern.is_finished():
                        print "[+] Found pattern chain {}".format(node.opname)
                        self.pattern.set_cblk_and_node(self.curr_cblock[-1], node)
                        self.pattern.replace_if_need()
                        # This variable need to overcome situation with deleting instructions from
                        # cblock. I guess fields list from line 129 are actually some kind of pointers
                        # which can be invalidated during cblock body replacement process
                        self.need_reanalyze_cblock = True
                    return
            else:
                if self.pattern.check(node):
                    print "[+] Found unary pattern!"
                    self.pattern.set_node(node)
                    self.pattern.replace_if_need()
                    return
        fields = self.process_exprs_and_get_next(node, shift)
        if fields is None:
            return
        for i in fields:
            self.traverse_node(i, shift + 1)
            if node.opname == "block" and self.need_reanalyze_cblock:
                break
        if node.opname == "block":
            self.curr_cblock.pop()
            if self.pattern is not None:
                self.pattern.finish_cblock()
        if self.need_reanalyze_cblock:
            if self.DEBUG:
                print "{}[+] Reanalyzing cblock after replacement".format(" " * (shift * TAB_SPACES))
            self.traverse_node(node, shift)
            '''