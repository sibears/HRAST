import ida_hexrays

BLOCK_TYPES = ["casm", "cblock", "cdo", "cexpr", "cfor", "cgoto", "cif", "creturn",
               "cswitch", "cwhile"
              ]


def dump_function(fcn):
    val = dump_entry(fcn.body)
    print val
    for i in fcn.body.cblock:
        print dump_entry(i)
        inner = getattr(i, "c"+i.opname)
        if inner is not None:
            print dump_entry(inner, 2)
        

def dump_entry(entry, lvl=1):
    res = ""
    try:
        res = "{}OP: {}".format("\t"*(lvl-1),entry.opname)
        for i in BLOCK_TYPES:
            if getattr(entry, i) is not None:
                res += "\n{}Have {}".format("\t"*lvl, i)
    except:
        print dir(entry)
    return res


def run():
    fcn = ida_hexrays.decompile(here())
    dump_function(fcn)
