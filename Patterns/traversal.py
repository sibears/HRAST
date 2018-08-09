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
    elif opname == "asm":
        return []
    elif opname == "switch":
        #TODO: do something
        return []
    elif opname == "continue":
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
    elif opname in ["obj", "num", "fnum", "sizeof", "str", "empty"]:
        return []
    elif opname == "cast":
        return [exp.x] + get_inner_entities_list_expr(exp.x)
    elif opname in Nodes.ONE_OP_N:
        return [exp.x] + get_inner_entities_list_expr(exp.x)
    elif opname in Nodes.TWO_OP_N:
        return [exp.x, exp.y] + get_inner_entities_list_expr(exp.x) + get_inner_entities_list_expr(exp.y)
    elif:
        raise Exception('Got unexpected opname {}'.format(opname))