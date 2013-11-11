package uwsgi

/*

this is a very low-level module, full of performance hacks
do not take it as a good example of go coding...

*/

import (
	"strings"
	"net/http"
	"net/http/cgi"
	"io"
)


//extern uwsgi_takeover
func uwsgi_takeover()
//extern uwsgi_response_write_body_do
func uwsgi_response_write_body_do(*interface{}, *byte, uint64) int
//extern uwsgi_response_prepare_headers_int
func uwsgi_response_prepare_headers_int(*interface{}, int) int
//extern uwsgi_response_add_header
func uwsgi_response_add_header(*interface{}, *byte, uint16, *byte, uint16) int
//extern uwsgi_gccgo_helper_request_body_read
func uwsgi_request_body_read(*interface{}, *byte, uint64) int
//extern uwsgi_gccgo_helper_register_signal
func uwsgi_register_signal(uint8, *byte, func(uint8)) int
//extern uwsgi_cache_magic_get
func uwsgi_cache_magic_get(*byte, uint16, *uint64, *uint64, *byte) *byte;
//extern __go_byte_array_to_string
func __go_byte_array_to_string(*byte, int) string
//extern free
func free(* byte)

var uwsgi_signals_gc [256]func(uint8)
var uwsgi_env_gc map[interface{}]interface{}

func Env(wsgi_req *interface{}) *map[string]string {
	var env map[string]string
        env = make(map[string]string)
	uwsgi_env_gc[wsgi_req] = &env
	return &env
}

func EnvAdd(env *map[string]string, k *byte, kl uint16, v *byte, vl uint16) {
	s_k := __go_byte_array_to_string(k, int(kl))
	s_v := __go_byte_array_to_string(v, int(vl))
	(*env)[ s_k ] = s_v
}

type ResponseWriter struct {
        r       *http.Request
        wsgi_req *interface{}
        headers      http.Header
        wroteHeader bool
}

func (w *ResponseWriter) Write(p []byte) (n int, err error) {
        if !w.wroteHeader {
                w.WriteHeader(http.StatusOK)
        }
        uwsgi_response_write_body_do(w.wsgi_req, &p[0], uint64(len(p)))
        return len(p), err
}

func (w *ResponseWriter) WriteHeader(status int) {
        uwsgi_response_prepare_headers_int(w.wsgi_req, status )
        if w.headers.Get("Content-Type") == "" {
                w.headers.Set("Content-Type", "text/html; charset=utf-8")
        }
        for k := range w.headers {
                for _, v := range w.headers[k] {
                        v = strings.NewReplacer("\n", " ", "\r", " ").Replace(v)
                        v = strings.TrimSpace(v)
			kb := []byte(k)
			vb := []byte(v)
                        uwsgi_response_add_header(w.wsgi_req, &kb[0], uint16(len(k)), &vb[0], uint16(len(v)))
                }
        }
        w.wroteHeader = true
}

func (w *ResponseWriter) Header() http.Header {
        return w.headers
}


type BodyReader struct {
        wsgi_req *interface{}
}

// there is no close in request body
func (br *BodyReader) Close() error {
        return nil
}

func (br *BodyReader) Read(p []byte) (n int, err error) {
	var rlen int = uwsgi_request_body_read(br.wsgi_req, &p[0], uint64(len(p)))
	if (rlen == 0) {
		err = io.EOF;
		return 0, err
	} else if (rlen == -1) {
		err = io.ErrUnexpectedEOF
		return 0, err
	}
	return rlen, err
}

func RequestHandler(env *map[string]string, wsgi_req *interface{}) {
        httpReq, err := cgi.RequestFromMap(*env)
        if err == nil {
                httpReq.Body = &BodyReader{wsgi_req}
                w := ResponseWriter{httpReq, wsgi_req,http.Header{},false}
                http.DefaultServeMux.ServeHTTP(&w, httpReq)
        }
	delete(uwsgi_env_gc, wsgi_req)
}

func RegisterSignal(signum uint8, receiver string, handler func(uint8)) bool {
	if (receiver == "") {
		receiver = "worker"
	}
	var b []byte = []byte(receiver)
	if (uwsgi_register_signal(signum, &b[0], handler) < 0) {
		return false
	}
	uwsgi_signals_gc[signum] = handler
	return true
}

// get an item from the cache
func CacheGet(key string, cache string) string {

	var b_key []byte = []byte(key)
	var v_len uint64 = 0
	var expires uint64 = 0
	var value *byte

	if (cache == "") {
		value = uwsgi_cache_magic_get(&b_key[0], uint16(len(b_key)), &v_len, &expires, nil)
	} else {
		b_cache := []byte(cache)
		value = uwsgi_cache_magic_get(&b_key[0], uint16(len(b_key)), &v_len, &expires, &b_cache[0])
	}

	ret := __go_byte_array_to_string(value, int(v_len))
	free(value)
	return ret
}


func SignalHandler(handler func(uint8), signum uint8) {
	handler(signum)
}

func Run() {
	uwsgi_env_gc = make(map[interface{}]interface{})
	uwsgi_takeover()
}
