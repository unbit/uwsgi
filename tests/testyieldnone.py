"""
Regression test for #2185.

This started to rightfully log the following line:

    [ERROR] Unhandled object from iterator: None (0x7f7e552eac30)

But in 2.0.18 this was silently swallowed and that's the expectation
for 2.0.19 as well.
"""
def application(env, start_response):
    start_response('200', [])
    yield None
