import time
import sys

def application(e, sr):
    time.sleep(3)
    print("3 seconds elapsed")
    sr('200 Ok', [('Content-Type', 'text/html')])

    time.sleep(2)
    print("2 seconds elapsed")

    yield "part1"

    try:
        time.sleep(2)
    except:
        print("CLIENT DISCONNECTED !!!")
    print("2 seconds elapsed")

    yield "part2"

    try:
        time.sleep(2)
    except:
        print("CLIENT DISCONNECTED !!!")
    print("2 seconds elapsed")

    yield "part3"

    time.sleep(2)
    print("2 seconds elapsed")

    yield "part4"

    print("end of request")
