#!/usr/bin/python3

def execute_backtrack(codelet, string, ip = 0):
    state = None
    for i, c in enumerate(string):
        process = True
        while process:
            f = codelet[ip]
            print (ip, f, state, i, c)

            action, rest = f[0], f[1:]
            if action == 'match':
                if c != rest[0]:
                    return False
                process = False
            elif action == 'fork':
                for target in rest:
                    if execute_backtrack(codelet, string[i:], target):
                        return True
            elif action == 'jump':
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
        ('match', 'c'),
        ('match', 'a'),
        ('match', 't'),
        ]

    trycode(codelet0, 'cat', 'cat', True)
    trycode(codelet0, 'cat', 'dog', False)
    trycode(codelet0, 'cat', 'dot', False)

    codelet1 = [
        ('fork', 5),
        ('match', 'c'),
        ('match', 'a'),
        ('match', 't'),
        ('jump', 8),
        ('match', 'd'),
        ('match', 'o'),
        ('match', 'g'),
        ]

    trycode(codelet1, 'cat|dog', 'cat', True)
    trycode(codelet1, 'cat|dog', 'dog', True)
    trycode(codelet1, 'cat|dog', 'dot', False)

