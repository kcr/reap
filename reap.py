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

import sys

import collections
import itertools

import rply
import rply.token


class Instruction:
    __slots__ = ['action', 'rest', 'tick']
    def __init__(self, action, *rest):
        self.action = action
        self.rest = rest
        self.tick = None

    def __repr__(self):
        return '<' + str(self) + '>'

    def __str__(self):
        return ' '.join([self.action] + [repr(x) for x in self.rest])


def maybe(codelet):
    return [Instruction('skip', 1, len(codelet) + 1)] + codelet


def save(n, codelet):
    return (
        [Instruction('save', 2 * n)]
        + codelet
        + [Instruction('save', 2 * n + 1)]
        )


def kleene(codelet):
    return (
        [Instruction('skip', 1, len(codelet) + 2)]
        + codelet
        + [Instruction('skip', -len(codelet) - 1)]
        )


class MyLexer:
    syntax = r'\()|*+?.$[^-]'
    default = 'CHAR'
    terminals = list(syntax) + [default]

    def lex(self, s):
        line, off, parenc = 0, 0, 0
        for (i, c) in enumerate(s):
            pos = rply.token.SourcePosition(i, line, i - off)
            t = rply.token.Token(c if c in self.syntax else self.default, c, pos)
            if c == '(':
                parenc += 1
                t.parenc = parenc
            yield t
            if c == '\n':
                off = i + 1
                line += 1

lexer = MyLexer()


class ParseState:
    def __init__(self):
        self.unparen = 0


class AST:
    static = []

    def __init__(self, *args):
        self.children = args

    def forward_realize(self, flags):
        return [c.forward(flags) for c in self.children]

    def forward(self, flags):
        return self.do(self.forward_realize(flags), flags)

    def backward_realize(self, flags):
        return [c.backward(flags) for c in reversed(self.children)]

    def backward(self, flags):
        return self.do(self.backward_realize(flags), flags)

    def do(self, children, flags):
        return self.static

    def __repr__(self):
        return '%s(%s)' % (
            self.__class__.__name__,
            ', '.join(repr(c) for c in self.children),
            )


class AST0(AST):
    def __init__(self):
        super().__init__()


class AST1(AST):
    def __init__(self, a):
        super().__init__(a)


class AST2(AST):
    def __init__(self, a, b):
        super().__init__(a, b)


class Nowt(AST0):
    pass


class Concat(AST2):
    def forward(self, flags):
        return list(itertools.chain.from_iterable(self.forward_realize(flags)))

    def backward(self, flags):
        return list(itertools.chain.from_iterable(self.backward_realize(flags)))


class Alternative(AST2):
    def do(self, c, flags):
        return (
            [Instruction('skip', 1, len(c[0]) + 2)]
            + c[0]
            + [Instruction('skip', len(c[1]) + 1)]
            + c[1])


class Question(AST1):
    def do(self, c, flags):
        return maybe(c[0])


class Save(AST):
    def __init__(self, n, child):
        self.n = n
        super().__init__(child)

    def do(self, c, flags):
        return save(self.n, c[0])

    def __repr__(self):
        return '%s(%d, %s)' % (
            self.__class__.__name__,
            self.n,
            repr(self.children[0]),
            )


class AssertEnd(AST0):
    static = [Instruction('assert_end')]


class AssertStart(AST0):
    static = [Instruction('assert_start')]


class Char(AST):
    def __init__(self, char):
        self.char = char
        super().__init__()

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, repr(self.char))

    def do(self, c, flags):
        if flags & IGNORECASE:
            return [Instruction('inexact', self.char)]
        else:
            return [Instruction('exact', self.char)]


class Any(AST0):
    static = [Instruction('any')]


class Star(AST1):
    def do(self, c, flags):
        return kleene(c[0])


class Plus(AST1):
    def do(self, c, flags):
        return c[0] + [Instruction('skip', -len(c[0]), 1)]


class Class(AST):
    def __init__(self, classdef):
        self.classdef = classdef
        super().__init__()

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, repr(self.classdef))

    def do(self, c, flags):
        if self.classdef == '^':
            expansion = expandclass(self.classdef[1:])
        else:
            expansion = expandclass(self.classdef)

        if flags & IGNORECASE:
            expansion = ''.join(
                sorted(set(expansion.lower() + expansion.upper())))

        if self.classdef[0] == '^':
            return [Instruction('-class', expansion)]
        else:
            return [Instruction('+class', expansion)]


rpg = rply.ParserGenerator(lexer.terminals)

@rpg.production('top :')
def top_nothing(state, p):
    return Nowt()

@rpg.production('top : re')
def top_re(state, p):
    return p[0]

@rpg.production('re : concat')
def re_concat(state, p):
    return p[0]

@rpg.production('re : re | concat')
def re_alternate(state, p):
    return Alternative(p[0], p[2])

@rpg.production('re : | concat')
def re_leftmaybe(state, p):
    return Question(p[1])

@rpg.production('re : re |')
def re_rightmaybe(state, p):
    return Question(p[0])

@rpg.production('concat : repeat')
def concat_1(state, p):
    return p[0]

@rpg.production('concat : concat repeat')
def concat_2(state, p):
    return Concat(p[0], p[1])

@rpg.production('exciting_syntax_char : (')
@rpg.production('exciting_syntax_char : )')
@rpg.production('exciting_syntax_char : |')
@rpg.production('exciting_syntax_char : *')
@rpg.production('exciting_syntax_char : +')
@rpg.production('exciting_syntax_char : ?')
@rpg.production('exciting_syntax_char : .')
@rpg.production('exciting_syntax_char : \\')
@rpg.production('exciting_syntax_char : $')
@rpg.production('exciting_syntax_char : [')
@rpg.production('boring_syntax_char : ]')
@rpg.production('boring_syntax_char : -')
@rpg.production('syntax_char : exciting_syntax_char')
@rpg.production('syntax_char : boring_syntax_char')
def syntax_char(state, p):
    return p[0]

@rpg.production('single : ( re )')
def single_parens(state, p):
    return Save(p[0].parenc - state.unparen, p[1])

@rpg.production('single : ( )')
def single_parens_empty(state, p):
    return Save(p[0].parenc - state.unparen, Nowt())

@rpg.production('single : $')
def single_assert_end(state, p):
    return AssertEnd()

@rpg.production('single : ^')
def single_assert_start(state, p):
    return AssertStart()

@rpg.production('single : CHAR')
@rpg.production('single : boring_syntax_char')
def single_char(state, p):
    return Char(p[0].value)

@rpg.production('single : \\ syntax_char')
def single_escaped_syntax(state, p):
    if p[1].value == '(':
        state.unparen += 1
    return Char(p[1].value)

@rpg.production('single : \\ CHAR')
def single_escaped_boring(state, p):
    return Char(p[1].value)

@rpg.production('single : .')
def single_dot(state, p):
    return Any()

@rpg.production('single : bracket_expression')
@rpg.production('repeat : single')
def repeat_single(state, p):
    return p[0]

@rpg.production('repeat : single *')
def repeat_star(state, p):
    return Star(p[0])

@rpg.production('repeat : single +')
def repeat_plus(state, p):
    return Plus(p[0])

@rpg.production('repeat : single ?')
def repeat_maybe(state, p):
    return Question(p[0])

@rpg.production('bracket_expression : [ bracket_list ]')
def bracket_expression(state, p):
    return Class(p[1])

@rpg.production('bracket_list_boring_start : CHAR')
@rpg.production('bracket_list_boring_start : exciting_syntax_char')
@rpg.production('bracket_list_boring_start : -')
def bracket_list_boring_start(state, p):
    return p[0].value

@rpg.production('bracket_list : bracket_list_boring_start follow_list')
def bracket_list(state, p):
    return p[0] + p[1]

@rpg.production('bracket_list : ] follow_list')
@rpg.production('bracket_list : ^ follow_list')
def bracket_list_brack(state, p):
    return p[0].value + p[1]

@rpg.production('bracket_list : ^ ] follow_list')
def bracket_list_brack(state, p):
    return p[0].value + p[1].value + p[2]

@rpg.production('follow_list_single : CHAR')
@rpg.production('follow_list_single : exciting_syntax_char')
@rpg.production('follow_list_single : -')
@rpg.production('follow_list_single : ^')
def follow_list_single(state, p):
    return p[0].value

@rpg.production('follow_list : follow_list_single follow_list')
def follow_list_recurse(state, p):
    return p[0] + p[1]

@rpg.production('follow_list : follow_list_single')
def follow_list_tail(state, p):
    return p[0]

parser = rpg.build()


def expandclass(s):
    r = ''
    for i, c in enumerate(s):
        if c != '-' or i == 0 or i == len(s) - 1:
            r += c
        else: # -
            a, b = ord(s[i - 1]), ord(s[i + 1])
            r += ''.join(chr(j) for j in range(min(a + 1, b + 1), max(a, b)))
    return r


def execute_backtrack(codelet, string, off = 0, ip = 0, level = 0, scoreboard=None, tick=None, saved=None):
    if saved is None:
        saved = {}
    if tick is None:
        tick = 0
    if scoreboard is None:
        scoreboard = [None] * len(codelet)

    for i, c in enumerate(itertools.chain(string, [''])):
        process = True
        while process:
            if scoreboard[ip] == tick:
                return False

            instruction = codelet[ip]
            action = instruction.action
            dprint (level*' ', i, repr(c), ip, instruction, saved, tick)

            if action == 'match':
                return saved
            elif action == 'exact':
                if c != instruction.rest[0]:
                    dprint(level*' ', ip, c,'!=', instruction.rest, '-> False')
                    return False
                process = False
            elif action == 'inexact':
                if c.lower() != instruction.rest[0].lower():
                    return False
                process = False
            elif action == 'any':
                process = False
            elif action == '+class':
                if c not in instruction.rest[0]:
                    return False
                process = False
            elif action == '-class':
                if c in instruction.rest[0]:
                    return False
                process = False
            elif action == 'assert_end':
                if c != '':
                    return False
            elif action == 'assert_start':
                if i != 0:
                    return False
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
    currentthreads = collections.deque()
    tick = 0
    scoreboard = [None] * len(codelet)
    i = 0
    match = False

    def addthread(add, ip, cp, saved, level=0):
        if scoreboard[ip] == tick:
            return

        scoreboard[ip] = tick

        instruction = codelet[ip]
        action = instruction.action
        dprint(level*' ', '\\', i, tick, ip, instruction, saved)
        if action == 'skip':
            for target in codelet[ip].rest:
                addthread(add, ip + target, cp, saved, level + 1)
        elif action == 'save':
            d = dict(saved)
            d[instruction.rest[0]] = cp
            addthread(add, ip + 1, cp, d, level + 1)
        else:
            dprint(level*' ', '+', i, tick, ip, instruction, saved)
            add((ip, saved))
        #dprint('+', i, tick, ip, instruction, saved)

    addthread(currentthreads.append, 0, 0, {})  # one thread starting at the beginning

    dprint(currentthreads)
    for i, c in enumerate(itertools.chain(string, [''])):
        tick += 1
        dprint()
        dprint(repr(c))
        nextthreads = collections.deque()

        def nextthread():
            while currentthreads:
                dprint (currentthreads)
                yield currentthreads.popleft()

        for ip, saved in nextthread():
            instruction = codelet[ip]
            action = instruction.action
            dprint(i, tick, repr(c), ip, instruction, saved)
            if action == 'exact':
                if c == instruction.rest[0]:
                    addthread(nextthreads.append, ip + 1, i + 1, saved)
                # else failure, thread dies
            if action == 'inexact':
                if c.lower() == instruction.rest[0].lower():
                    addthread(nextthreads.append, ip + 1, i + 1, saved)
            elif action == 'any':
                addthread(nextthreads.append, ip + 1, i + 1, saved)
            elif action == 'assert_end':
                if c == '':
                    addthread(currentthreads.appendleft, ip + 1, i + 1, saved)
            elif action == 'assert_start':
                if i == 0:
                    addthread(currentthreads.appendleft, ip + 1, i + 1, saved)
            elif action == '+class':
                if c in instruction.rest[0]:
                    addthread(nextthreads.append, ip + 1, i + 1, saved)
            elif action == '-class':
                if c not in instruction.rest[0]:
                    addthread(nextthreads.append, ip + 1, i + 1, saved)
            elif action == 'match':
                match = saved
                break

        dprint(nextthreads)
        if not nextthreads: # all my threads are dead
            return match

        currentthreads = nextthreads

    return match

BACKTRACK  = 1<<0
DEBUG      = 1<<1
IGNORECASE = 1<<2 ; I = IGNORECASE


class ReapPattern:
    def __init__(self, pattern, flags = 0):
        self.pattern = pattern
        self.flags = flags
        self.ast = parser.parse(
            lexer.lex(pattern), state=ParseState())
        self.forward = self.ast.forward(flags)
        if flags & DEBUG:
            for i in self.forward:
                print(i)

    def match(self, string): # pos, endpos
        return self.execute(
            string,
            save(0, self.forward) + [Instruction('match')])

    def search(self, string): # pos, endpos
        return self.execute(
            string,
            kleene([Instruction('any')])
            + save(0, self.forward)
            + [Instruction('match')])

    def execute(self, string, codelet):
        x = execute_threaded
        if self.flags & BACKTRACK:
            x = execute_backtrack
        result = x(codelet, string)
        if result:
            return ReapMatch(string, result)
        return None

#compile=ReapPattern


class ReapMatch:
    def __init__(self, string, result):
        self.string = string
        self.result = result

    def __repr__(self):
        return (
            'ReapMatch(' +
            ', '.join(str(x) for x in (self.string, self.result))
            + ')')


debugging = False
def dprint(*args, **kw):
    if debugging:
        return print(*args, **kw)

def nprint(*args, **kw):
    if not debugging:
        return print(*args, **kw)


def trycode(execute, codelet, ostensible, string, expected):
    try:
        sys.stdout.write('.')
        sys.stdout.flush()
        dprint('Trying', string, 'against the ostensible', ostensible, 'with', execute.__name__, end=': ')
        r = execute(codelet, string)
        if isinstance(expected, bool):
            r = bool(r)
        if r == expected:
            dprint('Got ', r)
        else:
            nprint('Trying', string, 'against the ostensible', ostensible, 'with', execute.__name__, end =': ')
            print('Got', r, 'expected', expected)
        dprint()
    except:
        print('while trying', string, 'against the ostensible', ostensible, 'with', execute.__name__, end=': ')
        raise


def tryre(flags, re, string, expected):
    try:
        sys.stdout.write('.')
        sys.stdout.flush()
        dprint('Trying', string, 'against', re, 'with', hex(flags), end=': ')
        dprint()
        r = ReapPattern(re, flags)
        m = r.match(string)
        if isinstance(expected, bool):
            result = bool(m) == expected
        else:
            result = m.result == expected
        if result:
            dprint('Got ', m)
        else:
            nprint('Trying', string, 'against', re, 'with', hex(flags), end=': ')
            print('Got', m, 'expected', expected)
        dprint()
    except:
        print('while trying', string, 'against', re, 'with', hex(flags), ':')
        raise

if __name__ == '__main__':
    print()
    print('pre-compiled codelets:', end='')
    codelet0 = [
        Instruction('save', 0),
        Instruction('exact', 'c'),
        Instruction('exact', 'a'),
        Instruction('exact', 't'),
        Instruction('save', 1),
        Instruction('match'),
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
        Instruction('match'),
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

    print()

    print('patterns:', end='')
    for oflags in [BACKTRACK, 0]:
        for (regex, flags, string, expected) in [
                ('cat', 0, 'cat', True),
                ('cat', 0, 'dog', False),
                ('cat', 0, 'dot', False),
                ('cat|dog', 0, 'cat', True),
                ('cat|dog', 0, 'dog', True),
                ('cat|dog', 0, 'dot', False),
                ('cat|dog', 0, 'catx', True),
                ('cat|dog', 0, 'ca', False),

                ('ab(gh|)', 0, 'ab', True),
                ('ab(gh|)', 0, 'abxgh', True),
                ('ab(gh|)', 0, 'abgh', True),
                ('ab(gh|xy)', 0, 'ab', False),
                ('ab(gh|xy)', 0, 'abgh', True),
                ('ab(gh|xy)', 0, 'abxy', True),

                ('a*x', 0, 'x', True),
                ('a*x', 0, 'ax', True),
                ('a*x', 0, 'aax', True),
                ('a*x', 0, 'aaax', True),
                ('a*x', 0, 'aaaaaaaaaaaaaaax', True),

                ('(a*)*', 0, 'a', True), # should complete and not hang or bomb out
                ('a*a', 0, 'aaaaaa', {0: 0, 1: 6}), # greed, capturing

                # . !
                ('a.c', 0, 'abc', True),
                ('a.c', 0, 'adc', True),
                ('a.c', 0, 'abb', False),
                ('a.c', 0, 'ac', False),

                ('.*abc', 0, 'abc', True),
                ('.*abc', 0, 'xxxxxxxxxxabc', True),
                ('.*abc', 0, 'xxxxxxxxxxab', False),

                # \
                (r'a\.c', 0, 'a.c', True),
                (r'a\.c', 0, 'abc', False),
                (r'ab\c', 0, 'abc', True),
                (r'\(abc', 0, '(abc', True),
                (r'\(abc', 0, r'\(abc', False),
                (r'\(ab(c)', 0, '(abc', {0: 0, 1: 4, 2: 3, 3: 4}),

                # []
                (r'x[abc]y', 0, 'xay', True),
                (r'x[abc]y', 0, 'xby', True),
                (r'x[abc]y', 0, 'xcy', True),
                (r'x[abc]y', 0, 'xdy', False),
                (r'x[abc]y', 0, 'x]y', False),
                (r'x[]abc]y', 0, 'xay', True),
                (r'x[]abc]y', 0, 'xby', True),
                (r'x[]abc]y', 0, 'xcy', True),
                (r'x[]abc]y', 0, 'xdy', False),
                (r'x[]abc]y', 0, 'x]y', True),
                (r'x[^abc]ya', 0, 'xaya', False),
                (r'x[^abc]ya', 0, 'xbya', False),
                (r'x[^abc]ya', 0, 'xcya', False),
                (r'x[^abc]ya', 0, 'xdya', True),
                (r'x[^abc]ya', 0, 'x]ya', True),
                (r'x[^]abc]ya', 0, 'xaya', False),
                (r'x[^]abc]ya', 0, 'xbya', False),
                (r'x[^]abc]ya', 0, 'xcya', False),
                (r'x[^]abc]ya', 0, 'xdya', True),
                (r'x[^]abc]ya', 0, 'x]ya', False),
                (r'x[a-z]ya', 0, 'xgya', True),
                (r'x[^a-z]ya', 0, 'xXya', True),
                (r'x[^^]y', 0, 'x^y', False),
                (r'x[a^]y', 0, 'x^y', True),

                # $
                (r'abc$', 0, 'abcd', False),
                (r'abcd$', 0, 'abcd', True),

                # ^
                (r'^abcd', 0, 'abcdef', True),
                (r'a^bcd', 0, 'abcdef', False),

                # IGNORECASE
                (r'a', IGNORECASE, 'a', True),
                (r'a', IGNORECASE, 'A', True),
                (r'b', IGNORECASE, 'A', False),
                (r'a+', IGNORECASE, 'aAAAaa', True),
                (r'[ab]', IGNORECASE, 'b', True),
                (r'[ab]', IGNORECASE, 'A', True),
                ]:
            tryre(oflags|flags, regex, string, expected)
    print()

