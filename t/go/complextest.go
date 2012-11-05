package main

import "uwsgi"
import "fmt"
import "net/http"
import "time"

type App struct {
	uwsgi.App
}

func (app *App) Banner() {
	fmt.Println("I am GO !!!")
}

func (app *App) PostFork() {
	if app.WorkerId() == 0 {
		fmt.Println("PoSt FoRk on mule", app.MuleId(), "!!!")
	} else {
		fmt.Println("PoSt FoRk on worker", app.WorkerId(), "!!!")
	}
}

func (app *App) RequestHandler(w http.ResponseWriter, r *http.Request) {
	app.Signal(17)
	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
	fmt.Fprintf(w, "<h1>Hi there, I love %s!</h1>", r.URL.Path[1:])
	fmt.Println("LOGSIZE: ", app.LogSize())
	go slow()
}

func hello(signum int) {
	fmt.Println("Ciao, 3 seconds elapsed or RequestHandler() called")
}

func hello2(signum int) {
	fmt.Println("I am an rb_timer running on mule", u.MuleId())
}

func slow() {
	time.Sleep(8 * time.Second)
	fmt.Println("8 seconds ELAPSED !!!")
}

func (app *App) PostInit() {
	app.RegisterSignal(17, "", hello)
	app.AddTimer(17, 3)

	app.RegisterSignal(30, "mule1", hello2)
	app.AddTimer(30, 5)
}

var u App

func main() {
	uwsgi.Run(&u)
}
