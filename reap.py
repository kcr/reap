#!/usr/bin/python3

import enum

class Op(enum.IntEnum):
    lparen = 1
    rparen = 2
    altern = 3
    concat = 4
    star = 5
    plus = 6
    maybe = 7

    def __repr__(self):
        return str(self)[3:]

opmap = {
    '(': Op.lparen,
    ')': Op.rparen,
    '|': Op.altern,
    '*': Op.star,
    '+': Op.plus,
    '?': Op.maybe,
    Op.concat: Op.concat, # surprise
    }


def parse_2rp(string):
    work = ['']
    for c in string:
        if c in ')*?+':
            work.append(c)
        elif c in '(|':
            if c == '(':
                work.append(Op.concat)
            work.append(c)
            work.append('')
            continue
        else:
            work.append(Op.concat)
            work.append(c)
        dprint(work)

    dprint()

    stack = []
    output = []

    for c in work:
        if c in opmap:
            op = opmap[c]
            dprint('        ', op, c)
            if op == Op.lparen:
                dprint('        ', '(')
                stack.append(op)
            elif op == Op.rparen:
                dprint('        ', ')')
                top = stack.pop()
                ## if top[0] == Op.lparen:
                ##     output.append('')

                # will raise IndexError if there are too many )s
                while top != Op.lparen:
                    output.append(top)
                    top = stack.pop()
            else:
                dprint('        ', '-')
                # will Indexerror if there aren't enough operands ?
                # XXX: | ?
                while stack and op < stack[-1]:
                    output.append(stack.pop())
                stack.append(op)
        else:
            output.append(c)

        dprint('%-8s' % (repr(c),), stack, output)
    output += reversed(stack)

    return output

def generate(rp):
    stack = []
    for token in rp:
        if not isinstance(token, Op):
            if token:
                stack.append([('match', token)])
            else:
                stack.append([])
        elif token == Op.concat:
            b = stack.pop()
            a = stack.pop()
            stack.append(a + b)
        elif token == Op.maybe:
            if stack[-1]: # ()? -> ()
                a = stack.pop()
                stack.append([('skip', 1, len(a) + 1)] + a)
        elif token == Op.plus:
            if stack[-1]: # ()+ -> ()
                a = stack.pop()
                stack.append(a + [('skip', -len(a), 1)])
        elif token == Op.star:
            if stack[-1]: # ()* -> ()
                a = stack.pop()
                stack.append([('skip', 1, len(a) + 2)] + a + [('skip', -len(a))])
        elif token == Op.altern:
            b = stack.pop()
            a = stack.pop()
            if not a and not b:
                stack.append([])
            elif not a or not b: # and b
                c = a or b
                stack.append([('skip', 1, len(c) + 1)] + c)
            else:
                stack.append([('skip', 1, len(a) + 2)] + a + [('skip', len(b) + 1)] + b)

    (result,) = stack
    return result


def execute_backtrack(codelet, string, ip = 0, level = 0):
    state = None
    for i, c in enumerate(string + '$'):#XXX need a better end sigil
        process = True
        while process:
            if ip >= len(codelet): # ran off the end
                dprint(level*' ', ip, '>=', len(codelet), '-> True')
                return True

            f = codelet[ip]
            dprint (level*' ', ip, f, state, i, c)

            action, rest = f[0], f[1:]
            if action == 'match':
                if c != rest[0]:
                    dprint(level*' ', ip, c,'!=', rest[0:], '-> False')
                    return False
                process = False
            elif action == 'skip':
                for target in rest[:-1]:
                    if execute_backtrack(codelet, string[i:], ip + target, level + 1):
                        return True
                ip = ip + rest[-1]
                continue
            else:
                raise Exception('unknown action', action)

            ip += 1

    if ip < len(codelet):
        dprint (level * ' ', ip, 'did not satisfy the pattern -> False')
        # unconsumed
        return False

    dprint (level * ' ', ip, 'everythign consumed -> True')
    return True

def dprint(*args, **kw):
    if False:
        return print(*args, **kw)

def trycode(codelet, ostensible, string, expected):
    print('Trying', string,'against the ostensible', ostensible)
    r = execute_backtrack(codelet, string)
    if r == expected:
        print('Got', r)
    else:
        print('Got', r, 'expected', expected)
    print()


if __name__ == '__main__':
    codelet0 = [
        ('match', 'c'),
        ('match', 'a'),
        ('match', 't'),
        ]

    trycode(codelet0, 'cat', 'cat', True)
    trycode(codelet0, 'cat', 'dog', False)
    trycode(codelet0, 'cat', 'dot', False)

    codelet1 = [
        ('skip', 1, 5),
        ('match', 'c'),
        ('match', 'a'),
        ('match', 't'),
        ('skip', 4),
        ('match', 'd'),
        ('match', 'o'),
        ('match', 'g'),
        ]

    trycode(codelet1, 'cat|dog', 'cat', True)
    trycode(codelet1, 'cat|dog', 'dog', True)
    trycode(codelet1, 'cat|dog', 'dot', False)
    trycode(codelet1, 'cat|dog', 'catx', True)
    trycode(codelet1, 'cat|dog', 'ca', False)

