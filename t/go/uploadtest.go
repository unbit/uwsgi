package main

import "uwsgi"
import "net/http"
import "fmt"
import "io/ioutil"
import "os"


func viewHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<form enctype=\"multipart/form-data\" method=\"POST\" action=\"/post/\"><input type=\"text\" name=\"foo\" /><input type=\"file\" name=\"bar\" /><input type=\"submit\" value=\"go\" /></form>")
}

func postHandler(w http.ResponseWriter, r *http.Request) {
	foo := r.FormValue("foo")
	bar, handler, err := r.FormFile("bar")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	bar_data, err := ioutil.ReadAll(bar)
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Server", "uWSGI")
	fmt.Fprintf(w, foo + "\n\n" + handler.Filename + "\n\n" + string(bar_data))
}

func signal30(sig uint8) {
	fmt.Println("ciao")
}

func main() {
	fmt.Println(os.Args)
	uwsgi.RegisterSignal(30, "", signal30)
	http.HandleFunc("/view/", viewHandler)
	http.HandleFunc("/post/", postHandler)
	uwsgi.Run()
}
