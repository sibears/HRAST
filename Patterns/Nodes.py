TWO_OP = [
    ('Asgn', 'asg'), ('Idx', 'idx'), ('Sub', 'sub'), ('Mul', 'mul'),
    ('Add', 'add'), ('Land', 'land'), ('Lor', 'lor'), ('Ult', 'ult'),
    ('Ule', 'ule'), ('Ugt', 'ugt'), ('Uge', 'uge'), ('Sle', 'sle'), ('Slt', 'slt'),
    ('Sgt', 'sgt'), ('Sge', 'sge'), ('Eq', 'eq'), ('Comma', 'comma'), ('Sshr', 'sshr'),
    ('Ushr', 'ushr'), ('Bor', 'bor'), ('AsgUShr', 'asgushr'), ('Smod', 'smod'),
    ('Xor', 'xor'), ('AsgAdd', 'asgadd'), ('AsgSub', 'asgsub'), ('BAnd', 'band'), 
    ('AsgBor', 'asgbor'),('AsgBAnd', 'asgband'), ('Ne', 'ne'), ('Shl', 'shl'),
    ('Fdiv', 'fdiv'), ('Sdiv', 'sdiv'), ('Fmul', 'fmul'),('Udiv', 'udiv'), ('AsgSshr','asgsshr'),
    ('AsgShl','asgshl'),('AsgMul','asgmul'), ('AsgXor','asgxor'), ('Fsub','fsub'),('AsgSDiv', 'asgsdiv'),
    ('AsgUDiv', 'asgudiv'),('AsgUMod', 'asgumod'),('AsgSMod', 'asgsmod'), ('UMod' ,'umod'), ('Fadd','fadd')
]


ONE_OP = [
    ('Preinc', 'preinc'), ('Predec', 'predec'), ('Lnot', 'lnot'),
    ('Ref', 'ref'), ('Bnot', 'bnot'), ('Postinc', 'postinc'), ('Postdec', 'postdec'), ('Ptr', 'ptr'),
    ('Neg', 'neg'), ('Fneg', 'fneg'), ('Str', 'str')
]

TWO_OP_N = ['asg', 'idx', 'sub', 'mul', 'add', 'land', 'lor', 'ult', 'ule', 'ugt', 
'uge', 'sle', 'slt', 'sgt', 'sge', 'eq', 'comma', 'sshr', 'ushr', 'bor', 'asgushr',
'smod', 'xor', 'asgadd', 'asgsub', 'band', 'asgbor', 'asgband', 'ne', 'shl', 'shr',
'fdiv', 'sdiv', 'fmul', 'udiv', 'asgsshr', 'asgshl', 'asgmul', 'asgxor', 'fsub',
 'asgsdiv', 'asgudiv', 'asgumod', 'asgsmod', 'umod', 'fadd']

ONE_OP_N = ['preinc', 'predec', 'lnot', 'ref', 'bnot', 'postinc', 'postdec', 'ptr', 'neg', 'fneg', 'str']