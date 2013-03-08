public class rpc {
	public static Object[] application(java.util.HashMap env) {
		String rpc_out = uwsgi.rpc("", "reverse", (String) env.get("REQUEST_URI"));

                java.util.HashMap<String, Object> headers = new java.util.HashMap<String, Object>();
		headers.put("Content-Type", "text/html");

		Object[] response = { 200, headers, "<h1>" + rpc_out + "</h1>"};
		return response;
	}
}
