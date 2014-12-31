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


def execute_backtrack(codelet, string, ip = 0, level = 0, been = None):
    if been is None:
        been = set()
    state = None
    tick = 0
    if level > 32:
        raise Exception('too much recursion')
    for i, c in enumerate(string + '$'):#XXX need a better end sigil
        process = True
        while process:
            if tick > 100:
                raise Exception ('execution expired')
            tick += 1

            if ip in been:
                return False

            if ip >= len(codelet): # ran off the end
                dprint(level*' ', ip, '>=', len(codelet), '-> True')
                return True

            f = codelet[ip]
            dprint (level*' ', ip, f, state, i, c, been)

            action, rest = f[0], f[1:]
            if action == 'match':
                if c != rest[0]:
                    dprint(level*' ', ip, c,'!=', rest[0:], '-> False')
                    return False
                process = False
            elif action == 'skip':
                been.add(ip)
                for target in rest[:-1]:
                    if execute_backtrack(codelet, string[i:], ip + target, level + 1, been):
                        return True
                ip = ip + rest[-1]
                continue
            else:
                raise Exception('unknown action', action)

            ip += 1

        been = set()

    if ip < len(codelet):
        dprint (level * ' ', ip, 'did not satisfy the pattern -> False')
        # unconsumed
        return False

    dprint (level * ' ', ip, 'everythign consumed -> True')
    return True


def execute_threaded(codelet, string):
    dprint()
    dprint(codelet)
    currentthreads = [0] # one thread starting at the beginning

    for c in string + '$':
        dprint()
        dprint(repr(c))
        nextthreads = []
        for ip in currentthreads:
            if ip >= len(codelet): # ran off the end
                return True
            action, rest = codelet[ip][0], codelet[ip][1:]
            dprint(repr(c), ip, action, rest)
            if action == 'match':
                if c == rest[0]:
                    nextthreads.append(ip + 1)
                # else failure, thread dies
            elif action == 'skip':
                currentthreads += [ip + target for target in rest]

        dprint(nextthreads)
        if not nextthreads: # all my threads are dead
            return False

        currentthreads = nextthreads

    return not [ip for ip in threads if ip < len(codelet)]

def dprint(*args, **kw):
    if False:
        return print(*args, **kw)


def trycode(codelet, ostensible, string, expected):
    print('Trying', string, 'against the ostensible', ostensible)
    r = execute_backtrack(codelet, string)
    if r == expected:
        print('Got', r)
    else:
        print('Got', r, 'expected', expected)
    print()


def tryre(execute, re, string, expected):
    print('Trying', string, 'against', re, 'with', execute.__name__)
    r = execute(generate(parse_2rp(re)), string)
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

    tryre(execute_backtrack, 'cat', 'cat', True)
    tryre(execute_backtrack, 'cat', 'dog', False)
    tryre(execute_backtrack, 'cat', 'dot', False)
    tryre(execute_backtrack, 'cat|dog', 'cat', True)
    tryre(execute_backtrack, 'cat|dog', 'dog', True)
    tryre(execute_backtrack, 'cat|dog', 'dot', False)
    tryre(execute_backtrack, 'cat|dog', 'catx', True)
    tryre(execute_backtrack, 'cat|dog', 'ca', False)

    tryre(execute_backtrack, 'ab(gh|)', 'ab', True)
    tryre(execute_backtrack, 'ab(gh|)', 'abxgh', True)
    tryre(execute_backtrack, 'ab(gh|)', 'abgh', True)
    tryre(execute_backtrack, 'ab(gh|xy)', 'ab', False)
    tryre(execute_backtrack, 'ab(gh|xy)', 'abgh', True)
    tryre(execute_backtrack, 'ab(gh|xy)', 'abxy', True)

    # should complete and not hang or bomb out
    tryre(execute_backtrack, 'a**', 'a', True)

    tryre(execute_threaded, 'cat', 'cat', True)
    tryre(execute_threaded, 'cat', 'dog', False)
    tryre(execute_threaded, 'cat', 'dot', False)
    tryre(execute_threaded, 'cat|dog', 'cat', True)
    tryre(execute_threaded, 'cat|dog', 'dog', True)
    tryre(execute_threaded, 'cat|dog', 'dot', False)
    tryre(execute_threaded, 'cat|dog', 'catx', True)
    tryre(execute_threaded, 'cat|dog', 'ca', False)

    tryre(execute_threaded, 'ab(gh|)', 'ab', True)
    tryre(execute_threaded, 'ab(gh|)', 'abxgh', True)
    tryre(execute_threaded, 'ab(gh|)', 'abgh', True)
    tryre(execute_threaded, 'ab(gh|xy)', 'ab', False)
    tryre(execute_threaded, 'ab(gh|xy)', 'abgh', True)
    tryre(execute_threaded, 'ab(gh|xy)', 'abxy', True)

    tryre(execute_threaded, 'a**', 'a', True)
