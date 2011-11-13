from uwsgidecorators import *

@timer(3, target='mule1')
def hello_timer(signum):
    print "3 seconds elapsed"


@mulefunc
def conto_fino_a_dieci(uno, due, tre):
    print "MULE ID %d: conto_fino_a_dieci" % uwsgi.mule_id(),uno,due,tre

@mulefunc(2)
def conto_fino_a_venti(uno, due, tre):
    print "MULE ID %d: conto_fino_a_venti" % uwsgi.mule_id(),uno,due,tre

@mulefunc('topogigio')
def conto_fino_a_trenta(uno, due, tre):
    print "MULE ID %d: conto_fino_a_trenta" % uwsgi.mule_id(),uno,due,tre



def application(e, sr):
   conto_fino_a_dieci(1,2,3)
   conto_fino_a_venti(4,5,6)
   conto_fino_a_trenta(7,8,9)
   sr('200 OK', [('Content-Type','text/html')])
   return "MULE !!!"
