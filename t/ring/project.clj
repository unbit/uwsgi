(defproject unbit/uwsgi-ring-tests "0.0.1"
  :description "uwsgi-ring-tests: test cases for uwsgi ring server"
  :dependencies [[org.clojure/clojure "1.4.0"]
                 [compojure "1.1.5"]
                 [ring/ring "1.1.0"]]

  :source-paths ["src"]

  :aot [uwsgi.ring.tests.app]
)
