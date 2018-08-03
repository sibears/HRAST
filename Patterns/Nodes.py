TWO_OP = [
    ('Asgn', 'asg'), ('Idx', 'idx'), ('Sub', 'sub'), ('Mul', 'mul'),
    ('Add', 'add'), ('Land', 'land'), ('Lor', 'lor'), ('Ult', 'ult'),
    ('Ule', 'ule'), ('Ugt', 'ugt'), ('Uge', 'uge'), ('Sle', 'sle'), ('Slt', 'slt'),
    ('Sgt', 'sgt'), ('Sge', 'sge'), ('Eq', 'eq'), ('Comma', 'comma'), ('Sshr', 'sshr'),
    ('Ushr', 'ushr'), ('Bor', 'bor'), ('AsgUShr', 'asgushr'), ('Smod', 'smod'),
    ('Xor', 'xor'), ('AsgAdd', 'asgadd'), ('AsgSub', 'asgsub'), ('BAnd', 'band'), ('AsgBor', 'asgbor'),
    ('AsgBAnd', 'asgband'), ('Ne', 'ne'), ('Shl', 'shl'), ('Shr', 'shr'), ('Fdiv', 'fdiv'), ('Sdiv', 'sdiv'), ('Fmul', 'fmul')
]


ONE_OP = [
    ('Preinc', 'preinc'), ('Predec', 'predec'), ('Lnot', 'lnot'),
    ('Ref', 'ref'), ('Bnot', 'bnot'), ('Postinc', 'postinc'), ('Postdec', 'postdec'), ('Ptr', 'ptr'),
]

TWO_OP_N = ['asg', 'idx', 'sub', 'mul', 'add', 'land', 'lor', 'ult', 'ule', 'ugt', 
'uge', 'sle', 'slt', 'sgt', 'sge', 'eq', 'comma', 'sshr', 'ushr', 'bor', 'asgushr',
'smod', 'xor', 'asgadd', 'asgsub', 'band', 'asgbor', 'asgband', 'ne', 'shl', 'shr',
'fdiv', 'sdiv', 'fmul']

ONE_OP_N = ['preinc', 'predec', 'lnot', 'ref', 'bnot', 'postinc', 'postdec', 'ptr']