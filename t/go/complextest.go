package main

import "uwsgi"
import "fmt"
import "net/http"
import "time"

func postfork() {
	if uwsgi.WorkerId() == 0 {
		fmt.Println("PoSt FoRk on mule", uwsgi.MuleId(), "!!!")
	} else {
		fmt.Println("PoSt FoRk on worker", uwsgi.WorkerId(), "!!!")
	}
}

func request_handler(w http.ResponseWriter, r *http.Request) {
	uwsgi.Signal(17)
	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
	fmt.Fprintf(w, "<h1>Hi there, I love %s!</h1>", r.URL.Path[1:])
	fmt.Println("LOGSIZE: ", uwsgi.LogSize())
        uwsgi.Alarm("jabber", "Hello")
	go slow()
}

func hello(signum int) {
	fmt.Println("Ciao, 3 seconds elapsed or RequestHandler() called")
}

func hello2(signum int) {
	fmt.Println("I am an rb_timer running on mule", uwsgi.MuleId())
}

func slow() {
	time.Sleep(8 * time.Second)
	fmt.Println("8 seconds ELAPSED !!!")
}

func postinit() {
	uwsgi.RegisterSignal(17, "", hello)
	uwsgi.AddTimer(17, 3)

	uwsgi.RegisterSignal(30, "mule1", hello2)
	uwsgi.AddTimer(30, 5)
}


func main() {
	uwsgi.PostInit(postinit)
	uwsgi.PostFork(postfork)
	uwsgi.RequestHandler(request_handler)
	uwsgi.Run()
}
