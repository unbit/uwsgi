import java.util.Hashtable;
import java.lang.Integer;
import java.util.ArrayList;
import java.io.FileDescriptor;
import java.io.FileInputStream;

public class utest {

	public static void main (String args[]) {
		System.out.println("I am the main() method");
	}

	void HelloWorld() {
		System.out.println("Hello World!");
	}


	public static Object[] jwsgi(Hashtable env) throws java.io.IOException {

		if (env.containsKey("CONTENT_LENGTH")) {
			String s = (String) env.get("CONTENT_LENGTH");
			if (s.length() > 0) {
				Integer cl = Integer.parseInt( s );
				FileInputStream f = new FileInputStream( (FileDescriptor) env.get("jwsgi.input") );	
				byte[] b = new byte[cl];
		
				if (f.read(b) > 0) {
					String postdata = new String(b);
					System.out.println( postdata );
				}
			}
		}
		
		String status = "200 Ok";

		ArrayList<Object> headers = new ArrayList<Object>();

		String[] header = { "Content-type", "text/html" } ;
		headers.add(header);
		String[] header2 = { "Server", "uWSGI" } ;
		headers.add(header2);
	
		System.out.println( env.get("REQUEST_URI") );

		String body = "<form method=\"POST\"><input type=\"text\" name=\"nome\"/><input type=\"submit\" value=\"send\" /></form>" + env.get("REQUEST_URI");

		Object[] response = { status, headers, body };

		return response;
	}
}
