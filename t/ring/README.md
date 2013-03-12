Ring Test Suite
================

how to build and run
---------------------

* cd UWSGIROOT
* cd t/ring
* lein uberjar
* cd ../..
* uwsgi t/ring/config.ini
* open http://localhost:9090 in your browser

run cases in jetty
-------------------

* lein ring server
* open http://localhost:3000 in your browser



