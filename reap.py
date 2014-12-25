#!/usr/bin/python3

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

