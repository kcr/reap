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
    iterator = enumerate(string)
    i, c = next(iterator)
    while True:
        try:
            f = codelet[ip]
            print (ip, f, state, i, c)
            action, rest = f(state, i, c)
            print (ip, action, rest)
            if action == FAILURE:
                return False
            elif action == FORK:
                for target in rest:
                    if execute_backtrack(codelet, string[i:], target):
                        return True
            elif action == NEXT:
                i, c = next(iterator)
            elif action == JUMP:
                (ip,) = rest
            else:
                raise Exception('unknown action', action)

            ip += 1
            if ip > len(codelet): # ran off the end
                break
        except StopIteration:
            break

    return True


if __name__ == '__main__':
    codelet0 = [
        Exactly('c'),
        Exactly('a'),
        Exactly('t'),
        ]

    print()
    print(
        execute_backtrack(codelet0, 'cat'),
        )
    print()
    print(
        execute_backtrack(codelet0, 'dog'),
        )
    print()
    print(
        execute_backtrack(codelet0, 'dot'),
        )

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

    print()
    print('cat|dog cat')
    print(
        execute_backtrack(codelet1, 'cat'),
        )
    print()
    print('cat|dog dog')
    print(
        execute_backtrack(codelet1, 'dog'),
        )
    print()
    print('cat|dog dot')
    print(
        execute_backtrack(codelet1, 'dot'),
        )

