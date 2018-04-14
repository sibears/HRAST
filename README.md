HexRaysAST modifier

this is simple PoC for replacing ast subtree in HexRays decompiler window

Current code contains template for replacing inlined strlen called on global variable

ast_helper.py contains some functions that helps creating ctree items

if you got some interr like 50680 etc you should check IDADIR/hexrays_sdk/verifier/cverify.cpp from 7.1 for locating error reason
