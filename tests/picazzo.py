from picasso import *


def home(req):
    if not req["session"].get("user"):
        return redirect("/login")
    return "<h1>Welcome back, %s!</h1>" % req["session"]["user"]


def login(req):
    return "<form method='post'><input type='submit' name='foo' value='login' /></form>"


def login_post(req):
    print(req)
    req["session"]["user"] = "James"
    return redirect("/")

routes = setup_routes(
    GET("/", home),
    GET("/login", login),
    POST("/login", login_post),
    routing.not_found("<h1>Not Found</h1>")
)

app = setup_app(routes)
