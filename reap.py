#!/usr/bin/python3

FAILURE = 'failure'
NEXT = 'next'
FORK = 'fork'
JUMP = 'jump'


class Operation:
    def __init__(self, *args):
        self.args = args

    def __call__(self, state, index, char):
        return None, None

    def __repr__(self):
        return '%s(%s)' % (
            self.__class__.__name__,
            ', '.join(repr(a) for a in self.args),
            )


class Exactly(Operation):
    def __init__(self, char):
        super().__init__(char)
        self.char = char

    def __call__(self, state, index, char):
        if char != self.char:
            return FAILURE, ()
        return NEXT, ()


class Fork(Operation):
    def __init__(self, ip):
        super().__init__(ip)
        self.ip = ip

    def __call__(self, state, index, char):
        return FORK, (self.ip,)


class Jump(Operation):
    def __init__(self, ip):
        super().__init__(ip)
        self.ip = ip

    def __call__(self, state, index, char):
        return JUMP, (self.ip,)


def execute_backtrack(codelet, string, ip = 0):
    state = None
    for i, c in enumerate(string):
        action = None
        while action != NEXT:
            f = codelet[ip]
            #print (ip, f, state, i, c)
            action, rest = f(state, i, c)
            #print (ip, action, rest)
            if action == FAILURE:
                return False
            elif action == FORK:
                for target in rest:
                    if execute_backtrack(codelet, string[i:], target):
                        return True
            elif action == NEXT:
                pass
            elif action == JUMP:
                (ip,) = rest
            else:
                raise Exception('unknown action', action)

            ip += 1
            if ip > len(codelet): # ran off the end
                break

    return True

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
        Exactly('c'),
        Exactly('a'),
        Exactly('t'),
        ]

    trycode(codelet0, 'cat', 'cat', True)
    trycode(codelet0, 'cat', 'dog', False)
    trycode(codelet0, 'cat', 'dot', False)

    codelet1 = [
        Fork(5),
        Exactly('c'),
        Exactly('a'),
        Exactly('t'),
        Jump(8),
        Exactly('d'),
        Exactly('o'),
        Exactly('g'),
        ]

    trycode(codelet1, 'cat|dog', 'cat', True)
    trycode(codelet1, 'cat|dog', 'dog', True)
    trycode(codelet1, 'cat|dog', 'dot', False)

