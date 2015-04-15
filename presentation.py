
#
# Pure Python Regular Expression Matching
#
# Regular Expression Automatons in Python
#
# Karl Ramm
#
# github.com/kcr/reap
#
# 2015-04-11 (not given)

#!/usr/bin/python3

import re

class foo:
    """Kinda sort not really string-y object"""

    def __init__(self, val):
        self.val = val

    def __iter__(self):
        for x in self.val:
            yield x

print(re.compile('foo').match(foo('foo')))

#!/usr/bin/python3

class bar(foo):
    """slightly stringier but not object"""

    def __getitem__(self, n):
        return x[n]

print(re.compile('bar').match(foo('bar')))

# Really this might be, saaay, a buffer-gap backed writable string

#!/usr/bin/python3

import reap

print(reap.compile('foo').match(foo('foo')))

#!/usr/bin/python3

print(reap.compile('A?' * 33 + 'A' * 33).match('A' * 33))

#!/usr/bin/python3

print('This may take a while')
print(re.compile('A?' * 33 + 'A' * 33).match('A' * 33))

#
#
# 871 lines (right now)
# Only supports the most of subset of regular expresions that I use
#   (so far)
#   (I got distracted from the thing that I needed it for)
# I hope to pass eventually the tests for the re module
# Could be faster (DFAs, etc.)
# should have better error reporting (parsley instead of rply?)
# "what is a regular expression anyway"
# could fall back to a recursive matcher for backreferences

# github.com/kcr/reap

