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


import rply
import rply.token


class Instruction:
    __slots__ = ['action', 'rest', 'tick']
    def __init__(self, action, *rest):
        self.action = action
        self.rest = rest
        self.tick = None

    def __repr__(self):
        return '<%s%s>' % (self.action, ''.join(' ' + repr(x) for x in self.rest))


def maybe(codelet):
    return [Instruction('skip', 1, len(codelet) + 1)] + codelet


class MyLexer:
    syntax = r'\()|*+?.[^-]'
    default = 'CHAR'
    terminals = list(syntax) + [default]

    def lex(self, s):
        line, off, parenth = 0, 0, 0
        for (i, c) in enumerate(s):
            pos = rply.token.SourcePosition(i, line, i - off)
            t = rply.token.Token(c if c in self.syntax else self.default, c, pos)
            if c == '(':
                parenth += 1
                t.parenth = parenth
            yield t
            if c == '\n':
                off = i + 1
                line += 1

lexer = MyLexer()


rpg = rply.ParserGenerator(lexer.terminals)

@rpg.production('top :')
def top_nothing(p):
    return []

@rpg.production('top : re')
def top_re(p):
    return p[0]

@rpg.production('re : concat')
def re_concat(p):
    return p[0]

@rpg.production('re : re | concat')
def re_alternate(p):
    return (
        [Instruction('skip', 1, len(p[0]) + 2)]
        + p[0]
        + [Instruction('skip', len(p[2]) + 1)]
        + p[2])

@rpg.production('re : | concat')
def re_leftmaybe(p):
    return maybe(p[1])

@rpg.production('re : re |')
def re_rightmaybe(p):
    return maybe(p[0])

@rpg.production('concat : repeat')
def concat_1(p):
    return p[0]

@rpg.production('concat : concat repeat')
def concat_2(p):
    return p[0] + p[1]

@rpg.production('exciting_syntax_char : (')
@rpg.production('exciting_syntax_char : )')
@rpg.production('exciting_syntax_char : |')
@rpg.production('exciting_syntax_char : *')
@rpg.production('exciting_syntax_char : +')
@rpg.production('exciting_syntax_char : ?')
@rpg.production('exciting_syntax_char : .')
@rpg.production('exciting_syntax_char : \\')
@rpg.production('exciting_syntax_char : [')
@rpg.production('boring_syntax_char : ]')
@rpg.production('boring_syntax_char : -')
@rpg.production('boring_syntax_char : ^') # this will of course be exciting someday
@rpg.production('syntax_char : exciting_syntax_char')
@rpg.production('syntax_char : boring_syntax_char')
def syntax_char(p):
    return p[0]

@rpg.production('single : ( re )')
def single_parens(p):
    return (
        [Instruction('save', 2 * p[0].parenth)]
        + p[1]
        + [Instruction('save', 2 * p[0].parenth + 1)]
        )

@rpg.production('single : ( )')
def single_parens_empty(p):
    return [
        Instruction('save', 2 * p[0].parenth),
        Instruction('save', 2 * p[0].parenth + 1),
        ]

@rpg.production('single : CHAR')
@rpg.production('single : boring_syntax_char')
def single_char(p):
    return [Instruction('exact', p[0].value)]

@rpg.production('single : \\ syntax_char')
def single_escaped_syntax(p):
    codelet = [Instruction('exact', p[1].value)]
    if p[1].value == '(':
        codelet.append(Instruction('unsave')) #sigh
    return codelet

@rpg.production('single : \\ CHAR')
def single_escaped_boring(p):
    return [Instruction('exact', p[1].value)]

@rpg.production('single : .')
def single_dot(p):
    return [Instruction('any')]

@rpg.production('single : bracket_expression')
@rpg.production('repeat : single')
def repeat_single(p):
    return p[0]

@rpg.production('repeat : single *')
def repeat_star(p):
    return (
        [Instruction('skip', 1, len(p[0]) + 2)]
        + p[0]
        + [Instruction('skip', -len(p[0]) - 1)]
        )

@rpg.production('repeat : single +')
def repeat_plus(p):
    return (
        p[0]
        + [Instruction('skip', -len(p[0]), 1)]
        )

@rpg.production('repeat : single ?')
def repeat_maybe(p):
    return ([Instruction('skip', 1, len(p[0]) + 1)]
            + p[0])

@rpg.production('bracket_expression : [ bracket_list ]')
def bracket_expression(p):
    charset = p[1]
    if charset[0] == '^':
        return [Instruction('-set', expandset(charset[1:]))]
    else:
        return [Instruction('+set', expandset(charset))]

@rpg.production('bracket_list_boring_start : CHAR')
@rpg.production('bracket_list_boring_start : exciting_syntax_char')
@rpg.production('bracket_list_boring_start : -')
def bracket_list_boring_start(p):
    return p[0].value

@rpg.production('bracket_list : bracket_list_boring_start follow_list')
def bracket_list(p):
    return p[0] + p[1]

@rpg.production('bracket_list : ] follow_list')
@rpg.production('bracket_list : ^ follow_list')
def bracket_list_brack(p):
    return p[0].value + p[1]

@rpg.production('bracket_list : ^ ] follow_list')
def bracket_list_brack(p):
    return p[0].value + p[1].value + p[2]

@rpg.production('follow_list_single : CHAR')
@rpg.production('follow_list_single : exciting_syntax_char')
@rpg.production('follow_list_single : -')
@rpg.production('follow_list_single : ^')
def follow_list_single(p):
    return p[0].value

@rpg.production('follow_list : follow_list_single follow_list')
def follow_list_recurse(p):
    return p[0] + p[1]

@rpg.production('follow_list : follow_list_single')
def follow_list_tail(p):
    return p[0]


parser = rpg.build()

def re_compile(s):
    codelet = parser.parse(lexer.lex(s))
    off = 0
    thresh = 0
    for insn in codelet:
        if insn.action == 'save':
            target = insn.rest[0]
            if insn.rest[0] > thresh:
                insn.rest = (insn.rest[0] - off,)
            thresh = target | 1
        if insn.action == 'unsave':
            off += 2
            insn.action='nop'
    return (
        [Instruction('save', 0)]
        + codelet
        + [Instruction('save', 1)]
        + [Instruction('match')]
        )


def expandset(s):
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

    for i, c in enumerate(string + '$'):#XXX need a better end sigil
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
            elif action == 'any':
                process = False
            elif action == '+set':
                if c not in instruction.rest[0]:
                    return False
                process = False
            elif action == '-set':
                if c in instruction.rest[0]:
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
            elif action == 'nop':
                pass
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

    def addthread(pool, ip, cp, saved, level=0):
        if scoreboard[ip] == tick:
            return

        scoreboard[ip] = tick

        instruction = codelet[ip]
        action = instruction.action
        dprint(level*' ', '\\', i, tick, ip, instruction, saved)
        if action == 'skip':
            for target in codelet[ip].rest:
                addthread(pool, ip + target, cp, saved, level + 1)
        elif action == 'save':
            d = dict(saved)
            d[instruction.rest[0]] = cp
            addthread(pool, ip + 1, cp, d, level + 1)
        elif action == 'nop':
            addthread(pool, ip + 1, cp, saved, level + 1)
        else:
            dprint(level*' ', '+', i, tick, ip, instruction, saved)
            pool.append((ip, saved))
        #dprint('+', i, tick, ip, instruction, saved)

    addthread(currentthreads, 0, 0, {})  # one thread starting at the beginning

    dprint(currentthreads)
    for i, c in enumerate(string + '$'):
        tick += 1
        dprint()
        dprint(repr(c))
        nextthreads = []
        for ip, saved in currentthreads:
            instruction = codelet[ip]
            action = instruction.action
            dprint(i, tick, repr(c), ip, instruction, saved)
            if action == 'exact':
                if c == instruction.rest[0]:
                    addthread(nextthreads, ip + 1, i + 1, saved)
                # else failure, thread dies
            elif action == '+set':
                if c in instruction.rest[0]:
                    addthread(nextthreads, ip + 1, i + 1, saved)
            elif action == '-set':
                if c not in instruction.rest[0]:
                    addthread(nextthreads, ip + 1, i + 1, saved)
            elif action == 'any':
                addthread(nextthreads, ip + 1, i + 1, saved)
            elif action == 'match':
                match = saved
                break

        dprint(nextthreads)
        if not nextthreads: # all my threads are dead
            return match

        currentthreads = nextthreads

    return match


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
    r = execute(re_compile(re), string)
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

    for execute in [execute_backtrack, execute_threaded]:
        for (regex, string, expected) in [
                ('cat', 'cat', True),
                ('cat', 'dog', False),
                ('cat', 'dot', False),
                ('cat|dog', 'cat', True),
                ('cat|dog', 'dog', True),
                ('cat|dog', 'dot', False),
                ('cat|dog', 'catx', True),
                ('cat|dog', 'ca', False),

                ('ab(gh|)', 'ab', True),
                ('ab(gh|)', 'abxgh', True),
                ('ab(gh|)', 'abgh', True),
                ('ab(gh|xy)', 'ab', False),
                ('ab(gh|xy)', 'abgh', True),
                ('ab(gh|xy)', 'abxy', True),

                ('a*x', 'x', True),
                ('a*x', 'ax', True),
                ('a*x', 'aax', True),
                ('a*x', 'aaax', True),
                ('a*x', 'aaaaaaaaaaaaaaax', True),

                ('(a*)*', 'a', True), # should complete and not hang or bomb out
                ('a*a', 'aaaaaa', {0: 0, 1: 6}), # greed, capturing

                # . !
                ('a.c', 'abc', True),
                ('a.c', 'adc', True),
                ('a.c', 'abb', False),
                ('a.c', 'ac', False),

                ('.*abc', 'abc', True),
                ('.*abc', 'xxxxxxxxxxabc', True),
                ('.*abc', 'xxxxxxxxxxab', False),

                # \
                (r'a\.c', 'a.c', True),
                (r'a\.c', 'abc', False),
                (r'ab\c', 'abc', True),
                (r'\(abc', '(abc', True),
                (r'\(abc', r'\(abc', False),
                (r'\(ab(c)', '(abc', {0: 0, 1: 4, 2: 3, 5: 4}),

                # []
                (r'x[abc]y', 'xay', True),
                (r'x[abc]y', 'xby', True),
                (r'x[abc]y', 'xcy', True),
                (r'x[abc]y', 'xdy', False),
                (r'x[abc]y', 'x]y', False),
                (r'x[]abc]y', 'xay', True),
                (r'x[]abc]y', 'xby', True),
                (r'x[]abc]y', 'xcy', True),
                (r'x[]abc]y', 'xdy', False),
                (r'x[]abc]y', 'x]y', True),
                (r'x[^abc]ya', 'xaya', False),
                (r'x[^abc]ya', 'xbya', False),
                (r'x[^abc]ya', 'xcya', False),
                (r'x[^abc]ya', 'xdya', True),
                (r'x[^abc]ya', 'x]ya', True),
                (r'x[^]abc]ya', 'xaya', False),
                (r'x[^]abc]ya', 'xbya', False),
                (r'x[^]abc]ya', 'xcya', False),
                (r'x[^]abc]ya', 'xdya', True),
                (r'x[^]abc]ya', 'x]ya', False),
                (r'x[a-z]ya', 'xgya', True),
                (r'x[^a-z]ya', 'xXya', True),
                ]:
            tryre(execute, regex, string, expected)
