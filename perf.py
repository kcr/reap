#!/usr/bin/python3


import contextlib
import time
import re

import reap


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
        with timer():
            re.compile(tre).match(s)

        print('reap ', end='')
        with timer():
            match(tre, s)


if __name__ == '__main__':
    main()
