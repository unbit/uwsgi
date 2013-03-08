package main

import "uwsgi"
import "net/http"
import "fmt"


func getHandler(w http.ResponseWriter, r *http.Request) {
	p := uwsgi.CacheGet("foobar", "")
	if p == nil {
		fmt.Fprintf(w, "<h1>item not found</h1>")
		return
	}
	fmt.Fprintf(w, "<h1>" + string(p) + "</h1>")
}

func setHandler(w http.ResponseWriter, r *http.Request) {
	if uwsgi.CacheSet("foobar", []byte("Hello World !"), 0, "") == false {
		fmt.Fprintf(w, "<h1>unable to set cache item</h1>")
                return
	}
	fmt.Fprintf(w, "<h1>item set</h1>")
}

func updateHandler(w http.ResponseWriter, r *http.Request) {
	if uwsgi.CacheUpdate("foobar", []byte("Hello World ! [updated]"), 0, "") == false {
		fmt.Fprintf(w, "<h1>unable to update cache item</h1>")
                return
	}
	fmt.Fprintf(w, "<h1>item updated</h1>")
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
        if uwsgi.CacheDel("foobar", "") == false {
                fmt.Fprintf(w, "<h1>unable to delete cache item</h1>")
                return
        }
        fmt.Fprintf(w, "<h1>item deleted</h1>")
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
        if !uwsgi.CacheExists("foobar", "")  {
                fmt.Fprintf(w, "<h1>item does not exist</h1>")
                return
        }
        fmt.Fprintf(w, "<h1>item exists</h1>")
}


func main() {
	http.HandleFunc("/get/", getHandler)
	http.HandleFunc("/update/", updateHandler)
	http.HandleFunc("/set/", setHandler)
	http.HandleFunc("/delete/", deleteHandler)
	http.HandleFunc("/check/", checkHandler)
	uwsgi.Run()
}
