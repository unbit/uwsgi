# uwsgi --wsgi-file t/python/timers.py --http :8080 --master
from uwsgidecorators import mstimer

@mstimer(500)
def ms_timer(signum):
    print("500 ms timer")
