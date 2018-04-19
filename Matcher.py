import idaapi
idaapi.require("Patterns.__init__")
idaapi.require("Patterns.Pattern")
from Patterns.Pattern import *

class SavedObj(object):

    def __init__(self, typ, addr):
        self.addr = addr
        self.type = typ

class SavedVar(object):
    def __init__(self, idx, typ, mba):
        self.idx = idx
        self.typ = typ
        self.mba = mba

class SavedMemRef(object):

    def __init__(self, ea, offset):
        self.ea = ea
        self.offset = offset

class Matcher(object):

    def __init__(self, fcn, pattern):
        self.names = fcn.lvars
        self.pattern = pattern 
        self.node = 0
        self.replacer = None    
        self.cnt = None   
        self.ctx = {}
        self.obj = {}
        self.memref = {}
        self.chain = False
        self.fcn = fcn

    def set_pattern(self, patt):
        self.pattern = patt

    def has_var(self, idx):
        return idx in self.ctx
        
    def get_var(self, idx):
        return self.ctx[idx]

    def save_var(self, idx, val, typ, mb):
        #val is index in fcn.lvars
        #print "[saving var]"
        self.ctx[idx] = SavedVar(val, typ, mb)

    def check(self, expr):
        self.ctx = {}
        self.obj = {}
        return self.pattern.check(expr, self)

    def check_chain(self, node):
        ret = self.pattern.check(node, self)
        if ret is False:
            self.ctx = {}
            self.obj = {}
        else:
            if self.is_finished():
                pass
        return ret

    def get_name(self, idx):
        return self.names[idx].name
    
    def has_obj(self, key):
        return key in self.obj

    def save_obj(self, key, ea, type):
        self.obj[key] = SavedObj(type, ea)

    def save_memref(self, key, ea, offset):
        self.memref[key] = SavedMemRef(ea, offset)

    def get_memref(self, key):
        return self.memref[key]

    def get_obj(self, key):
        return self.obj[key]

    def set_node(self, node):
        self.node = node
    
    def set_cblk_and_node(self, blk, node):
        self.blk = blk
        self.node = node

    def save_cnt(self, val):
        self.cnt = val
        
    def finish_cblock(self):
        if self.is_chain():
            self.pattern.pos = 0

    def is_chain(self):
        return self.chain

    def is_finished(self):
        return self.cnt is not None

    def replace_if_need(self):

        cnt = self.cnt
        self.cnt = None
        if self.replacer is not None:
            if not self.is_chain():
                #we're replacing single instruction
                self.replacer(self.node, self)
            else:
                #we're replacing chain
                size = len(self.blk.cblock)
                idx = None
                #print self.node.opname
                for i in range(size):
                    #print self.blk.cblock.at(i).opname
                    if self.blk.cblock.at(i) == self.node:
                        idx = i
                        break
                #idx = idx - cnt
                while cnt != 1:
                    self.blk.cblock.remove(self.blk.cblock.at(idx))
                    #idaapi.qswap(self.blk.cblock.at(idx), inst)
                    #del inst
                    idx -= 1
                    cnt -= 1
                self.replacer(self.blk.cblock.at(idx), self)
        self.ctx = {}