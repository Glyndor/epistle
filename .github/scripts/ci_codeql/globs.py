"""The path patterns of a CodeQL configuration, read the way CodeQL reads them.

`*` is any run of characters except `/`; `**` is any run of characters including
`/`; a pattern with no `/` in it matches a file name or a directory of that name
anywhere (as `*.test.js` does in the documentation's example). The characters
`? + [ ] !` are not special: they are matched literally.
"""

import re


def to_regex(pattern):
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"(?:/.*)?")


def matches(pattern, path):
    return to_regex(pattern).fullmatch(path) is not None
