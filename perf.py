#!/usr/bin/python3


import contextlib
import time
import re

import reap

COUNT=100


def match(re, string):
    return reap.execute_threaded(reap.generate(reap.parse_2rp(re)), string)


@contextlib.contextmanager
def timer():
    t0 = time.clock()
    yield
    print('duration', time.clock() - t0, 'seconds')


def main():
    for i in range(20):
        tre = 'a?'*i + 'a'*i
        s = 'a'*i
        print()
        print(i, repr(tre), 'against', repr(s))
        print('re   ', end='')
        c = re.compile(tre)
        with timer():
            for _ in range(COUNT):
                c.match(s)

        print('reap ', end='')
        c = reap.generate(reap.parse_2rp(tre))
        with timer():
            for _ in range(COUNT):
                reap.execute_threaded(c, s)


if __name__ == '__main__':
    main()
