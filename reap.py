#!/usr/bin/python3
# Copyright © 2014 Karl Ramm
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials provided
# with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


import enum


class Op(enum.IntEnum):
    lparen = 1
    rparen = 2
    altern = 3
    concat = 4
    star = 5
    plus = 6
    maybe = 7
    capture = 99

    def __str__(self):
        return super().__str__()[3:]

    __repr__ = __str__


class LParen:
    def __init__(self, capture):
        self.capture = capture

    def __int__(self):
        return int(Op.lparen)


class Instruction:
    def __init__(self, action, *rest):
        self.action = action
        self.rest = rest
        self.tick = None

    def __repr__(self):
        return '<%s %s>' % (self.action, ' '.join(repr(x) for x in self.rest))


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
    for c in '(' + string + ')':
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

    capture = 0
    for c in work:
        if c in opmap:
            op = opmap[c]
            dprint('        ', op, c)
            if op == Op.lparen:
                dprint('        ', '(')
                stack.append(LParen(capture))
                capture += 1
            elif op == Op.rparen:
                dprint('        ', ')')
                top = stack.pop()
                ## if top[0] == Op.lparen:
                ##     output.append('')

                # will raise IndexError if there are too many )s
                while not isinstance(top, LParen):
                    output.append(top)
                    top = stack.pop()
                output.append(top.capture)
                output.append(Op.capture)
            else:
                dprint('        ', '-')
                # will Indexerror if there aren't enough operands ?
                # XXX: | ?
                while stack and int(stack[-1]) > int(op):
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
            if token == '':
                stack.append([])
            elif isinstance(token, str):
                stack.append(
                    [Instruction('exact', token)]
                    )
            else:
                stack.append(token)
        elif token == Op.capture:
            slot = stack.pop()
            a = stack.pop()
            stack.append(
                [Instruction('save', 2 * slot)]
                + a +
                [Instruction('save', 2 * slot + 1)]
                )
        elif token == Op.concat:
            b = stack.pop()
            a = stack.pop()
            stack.append(a + b)
        elif token == Op.maybe:
            if stack[-1]: # ()? -> ()
                a = stack.pop()
                stack.append(
                    [Instruction('skip', 1, len(a) + 1)]
                    + a
                    )
        elif token == Op.plus:
            if stack[-1]: # ()+ -> ()
                a = stack.pop()
                stack.append(
                    a +
                    [Instruction('skip', -len(a), 1)]
                    )
        elif token == Op.star:
            if stack[-1]: # ()* -> ()
                a = stack.pop()
                stack.append(
                    [Instruction('skip', 1, len(a) + 2)]
                    + a +
                    [Instruction('skip', -len(a) - 1)]
                    )
        elif token == Op.altern:
            b = stack.pop()
            a = stack.pop()
            if not a and not b:
                stack.append([])
            elif not a or not b: # and b
                c = a or b
                stack.append(
                    [Instruction('skip', 1, len(c) + 1)]
                    + c
                    )
            else:
                stack.append(
                    [Instruction('skip', 1, len(a) + 2)]
                    + a +
                    [Instruction('skip', len(b) + 1)]
                    + b
                    )

    (result,) = stack
    return result


def execute_backtrack(codelet, string, off = 0, ip = 0, level = 0, scoreboard=None, tick=None, saved=None):
    if saved is None:
        saved = {}
    if tick is None:
        tick = 0
    if scoreboard is None:
        scoreboard = [None] * len(codelet)

    for i, c in enumerate(string + '$'):#XXX need a better end sigil
        process = True
        while process:
            if ip >= len(codelet): # ran off the end
                dprint(level*' ', ip, '>=', len(codelet), '-> saved')
                return saved

            if scoreboard[ip] == tick:
                return False

            instruction = codelet[ip]
            action = instruction.action
            dprint (level*' ', i, repr(c), ip, instruction, saved, tick)

            if action == 'exact':
                if c != instruction.rest[0]:
                    dprint(level*' ', ip, c,'!=', instruction.rest, '-> False')
                    return False
                process = False
            elif action == 'skip':
                scoreboard[ip] = tick
                for target in instruction.rest[:-1]:
                    r = execute_backtrack(
                        codelet, string[i:], i + off,
                        ip + target, level + 1, scoreboard, tick, dict(saved))
                    if r:
                        return r
                ip = ip + instruction.rest[-1]
                continue
            elif action == 'save':
                saved[instruction.rest[0]] = i + off
            else:
                raise Exception('unknown action', action)

            ip += 1

        tick += 1

    if ip < len(codelet):
        dprint (level * ' ', ip, 'did not satisfy the pattern -> False')
        # unconsumed
        return False

    dprint (level * ' ', ip, 'everythign consumed -> saved')
    return saved


def execute_threaded(codelet, string):
    dprint()
    dprint(codelet)
    currentthreads = []
    tick = 0
    scoreboard = [None] * len(codelet)
    i = 0
    match = False

    def addthread(pool, ip, cp, saved):
        if ip < len(codelet) and scoreboard[ip] == tick:
            return

        if ip < len(codelet):
            scoreboard[ip] = tick

            instruction = codelet[ip]
            action = instruction.action
            if action == 'skip':
                for target in codelet[ip].rest:
                    addthread(pool, ip + target, cp, saved)
            elif action == 'save':
                d = dict(saved)
                d[instruction.rest[0]] = cp
                addthread(pool, ip + 1, cp, d)
            else:
                pool.append((ip, saved))
            dprint(i, tick, ip, instruction, saved)
        else:
            pool.append((ip, saved)) # so we can hit the victory condition *gag*

    addthread(currentthreads, 0, 0, {})  # one thread starting at the beginning

    dprint(currentthreads)
    for i, c in enumerate(string + '$'):
        tick += 1
        dprint()
        dprint(repr(c))
        nextthreads = []
        for ip, saved in currentthreads:
            if ip >= len(codelet): # ran off the end
                match = saved
                break # need to let any threads that are still running continue
            instruction = codelet[ip]
            action = instruction.action
            dprint(i, tick, repr(c), ip, instruction, saved)
            if action == 'exact':
                if c == instruction.rest[0]:
                    addthread(nextthreads, ip + 1, i + 1, saved)
                # else failure, thread dies

        dprint(nextthreads)
        if not nextthreads: # all my threads are dead
            return match

        currentthreads = nextthreads

    return False # really, something went wrong


debugging = False
def dprint(*args, **kw):
    if debugging:
        return print(*args, **kw)


def trycode(execute, codelet, ostensible, string, expected):
    print('Trying', string, 'against the ostensible', ostensible, 'with', execute.__name__, end=': ')
    dprint()
    r = execute(codelet, string)
    if isinstance(expected, bool):
        r = bool(r)
    if r == expected:
        print('Got', r)
    else:
        print('Got', r, 'expected', expected)
    dprint()


def tryre(execute, re, string, expected):
    print('Trying', string, 'against', re, 'with', execute.__name__, end=': ')
    dprint()
    r = execute(generate(parse_2rp(re)), string)
    if isinstance(expected, bool):
        r = bool(r)
    if r == expected:
        print('Got', r)
    else:
        print('Got', r, 'expected', expected)
    dprint()


if __name__ == '__main__':
    codelet0 = [
        Instruction('save', 0),
        Instruction('exact', 'c'),
        Instruction('exact', 'a'),
        Instruction('exact', 't'),
        Instruction('save', 1),
        ]

    trycode(execute_backtrack, codelet0, 'cat', 'cat', True)
    trycode(execute_backtrack, codelet0, 'cat', 'dog', False)
    trycode(execute_backtrack, codelet0, 'cat', 'dot', False)
    trycode(execute_threaded, codelet0, 'cat', 'cat', True)
    trycode(execute_threaded, codelet0, 'cat', 'dog', False)
    trycode(execute_threaded, codelet0, 'cat', 'dot', False)

    codelet1 = [
        Instruction('save', 0),
        Instruction('skip', 1, 5),
        Instruction('exact', 'c'),
        Instruction('exact', 'a'),
        Instruction('exact', 't'),
        Instruction('skip', 4),
        Instruction('exact', 'd'),
        Instruction('exact', 'o'),
        Instruction('exact', 'g'),
        Instruction('save', 1),
        ]

    trycode(execute_backtrack, codelet1, 'cat|dog', 'cat', True)
    trycode(execute_backtrack, codelet1, 'cat|dog', 'dog', True)
    trycode(execute_backtrack, codelet1, 'cat|dog', 'dot', False)
    trycode(execute_backtrack, codelet1, 'cat|dog', 'catx', True)
    trycode(execute_backtrack, codelet1, 'cat|dog', 'ca', False)
    trycode(execute_threaded, codelet1, 'cat|dog', 'cat', True)
    trycode(execute_threaded, codelet1, 'cat|dog', 'dog', True)
    trycode(execute_threaded, codelet1, 'cat|dog', 'dot', False)
    trycode(execute_threaded, codelet1, 'cat|dog', 'catx', True)
    trycode(execute_threaded, codelet1, 'cat|dog', 'ca', False)

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

    tryre(execute_backtrack, 'a*x', 'x', True)
    tryre(execute_backtrack, 'a*x', 'ax', True)
    tryre(execute_backtrack, 'a*x', 'aax', True)
    tryre(execute_backtrack, 'a*x', 'aaax', True)
    tryre(execute_backtrack, 'a*x', 'aaaaaaaaaaaaaaax', True)

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

    tryre(execute_threaded, 'a*x', 'x', True)
    tryre(execute_threaded, 'a*x', 'ax', True)
    tryre(execute_threaded, 'a*x', 'aax', True)
    tryre(execute_threaded, 'a*x', 'aaax', True)
    tryre(execute_threaded, 'a*x', 'aaaaaaaaaaaaaaax', True)

    tryre(execute_threaded, 'a**', 'a', True)

    # greed, capturing
    tryre(execute_backtrack, 'a*a', 'aaaaaa', {0: 0, 1: 6})
    tryre(execute_threaded, 'a*a', 'aaaaaa', {0: 0, 1: 6})
