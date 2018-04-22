# HexRaysAST modifier

[![MIT license](http://img.shields.io/badge/license-MIT-brightgreen.svg)](https://github.com/sibears/HRAST/blob/master/LICENSE)

This is simple PoC for replacing AST subtree in HexRays decompiler window

### Current code contains templates for:
1.  Replacing inlined `strlen` called on global variable
2.  Auto renaming globals in expressions like `global_var = func(arg1, "newglobalname")`
3.  Auto renaming structure fields like `glob_str.f0 = sub_cafebabe` to `glob_str.sub_cafebabe = sub_cafebabe`

Scripts are not fully tested (e.g. it can fail on some ctree elements), but you can already make some useful things.

`ast_helper.py` contains some functions that help to create ctree items

*If you got some interr like 50680 etc after yours changes to ctree you should check IDADIR/hexrays_sdk/verifier/cverify.cpp (you need to have IDA 7.1+)*

### Usage:
1. Load **HRAST.py** into IDA
1. Write your patterns in **read_patterns.py**. You should define `PATTERNS` list with tuples (`template_code`, `replacement_fcn`, `is_chain`) as elements
1. Call `reLOAD()` function from IDAPython
1. Reload decompiler window
1. You can call `unLOAD()` function to disable modifications
1. Also `deBUG()` method switches DEBUG mode on/off
1. If you want to reload **HRAST.py** or remove hex-rays callback call `hr_remove()`

### Examples:

**Before**
![before screen](pics/before.png)


**After**
![after screen](pics/after.png)

### License:
Released under [The MIT License](https://github.com/sibears/HRAST/blob/master/LICENSE)
