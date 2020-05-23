#!/usr/bin/env python
# Filter out only matching files from preprocessor output
# Omit blank lines

DEBUG = False

import re, sys

comment = re.compile(r'^# (?P<lineno>\d+) "(?P<filename>[^\"]+)"')

# include stdint.h also?
allowed_filenames = re.compile(".*(<stdin>)$")


def filter_by_file(input):
    filename = ""
    allowed = True
    for line in input:
        match = comment.match(line)
        if match:
            filename = match.group("filename")
            allowed = bool(allowed_filenames.match(filename))
        if not line.strip():
            continue
        if not allowed:
            continue
        if line[0] == "#":
            continue
        yield line


struct = re.compile(r"\s*(?P<kind>\w+)\s+(?P<name>\w+)\s*{")
declaration = re.compile(r"\s*(?P<kind>(struct )?\w+)\s+(?P<name>\w+)\s*")
matchers = {
    None: struct,
    "struct": declaration,
    "enum": None,
    "union": None,
    "skip": None,
}
end = re.compile(".*}.*;")

# types that for whatever reason we don't want to deal with
avoid_types = set(
    (
        "pthread_key_t",
        "pthread_mutex_t",
        "pthread_attr_t",
        "pthread_t",
        "ino_t",
        "off_t",
        "mode_t",
        "struct msghdr",
        "struct termios",
        "struct rlimit",
        "struct timeval",
        "struct sockaddr_un",
    )
)

# skip lines containing these strings:
avoid_names = set(("mode_t", "uwsgi_recv_cred"))

# declared in uwsgi.h but not included in the base profile:
avoid_names.update(
    (
        "uwsgi_amqp_consume",
        "uwsgi_hooks_setns_run",
        "uwsgi_legion_i_am_the_lord",
        "uwsgi_legion_lord_scroll",
        "uwsgi_legion_scrolls",
    )
)


def output(string):
    if not DEBUG:
        return
    sys.stderr.write(string)


# well-formatted uwsgi.h admits semi-simple parsing.
def filter_structs(lines):
    stack = [None]
    for line in lines:
        skipline = False
        state = stack[-1]
        matcher = matchers[state]
        if any(name in line for name in avoid_names):
            skipline = True
        if end.match(line):
            if state == "struct":
                yield "...;\n"
            if state:
                stack.pop()
        elif matcher:
            match = matcher.match(line)
            if match:
                output(str(match.groups()) + "\n")
                if state == None:
                    kind = match.group("kind")
                    if kind == "union":
                        skipline = True
                        if not line.strip().endswith(";"):
                            stack.append("skip")
                    else:
                        stack.append(match.group("kind"))
                elif state == "struct":
                    kind = match.group("kind")
                    output(str(match.groupdict()) + "\n")
                    if kind in avoid_types:
                        skipline = True
                    if kind == "union":  # sockaddr_t?
                        skipline = True
                        if not line.strip().endswith(";"):
                            stack.append("skip")

        if skipline or state == "skip":
            yield "//" + line.strip() + "\n"
        else:
            yield line.strip() + "\n"


if __name__ == "__main__":
    pipeline = filter_structs(filter_by_file(open(sys.argv[1])))
    sys.stdout.writelines(pipeline)
