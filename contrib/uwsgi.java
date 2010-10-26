import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.Enumeration;
import org.apache.catalina.util.IOTools;

public class uwsgi extends HttpServlet {
	private String mountpoint = null;

	public void init(ServletConfig config) throws ServletException {
		super.init(config);

		String servletName = getServletConfig().getServletName();
		if (servletName == null)
			servletName = "";
		if (servletName.startsWith("org.apache.catalina.INVOKER."))
			throw new UnavailableException
				("Cannot invoke uWSGIServlet through the invoker");

		if (getServletConfig().getInitParameter("mountpoint") != null) {
			mountpoint = getServletConfig().getInitParameter("mountpoint");
			if (mountpoint.length() <= 1) {
				mountpoint = null;
			}
		}
	}


	public void doPost(HttpServletRequest request, HttpServletResponse response)
		throws IOException, ServletException {
		uWSGIHandler(request, response);
	}

	public void doGet(HttpServletRequest request, HttpServletResponse response)
		throws IOException, ServletException {
		uWSGIHandler(request, response);
	}


	private void uWSGIHandler(HttpServletRequest request, HttpServletResponse response)
		throws IOException, ServletException {

		Socket client = new Socket("localhost",3017);
		ByteArrayOutputStream uwsgi_request = new ByteArrayOutputStream();
		DataOutputStream wos = new DataOutputStream(uwsgi_request); 

		DataOutputStream os = new DataOutputStream(client.getOutputStream());
		DataInputStream is = new DataInputStream( client.getInputStream() );


		ServletOutputStream out = response.getOutputStream();

		boolean hasBody = false;

		wos.writeShort(swapShort( (short) 14));
		wos.writeBytes("REQUEST_METHOD");
		wos.writeShort(swapShort( (short) request.getMethod().length() ) );
		wos.writeBytes( request.getMethod() );

		wos.writeShort(swapShort( (short) 12));
		wos.writeBytes("QUERY_STRING");
		if (request.getQueryString() != null) {
			wos.writeShort(swapShort( (short) request.getQueryString().length() ) );
			wos.writeBytes( request.getQueryString() );
		}
		else {
			wos.writeShort(0);
		}

		wos.writeShort(swapShort( (short) 11));
		wos.writeBytes("SERVER_NAME");
		wos.writeShort(swapShort( (short) request.getServerName().length() ) );
		wos.writeBytes( request.getServerName() );

		wos.writeShort(swapShort( (short) 11));
		wos.writeBytes("SERVER_PORT");
		wos.writeShort(swapShort( (short) Integer.toString(request.getServerPort()).length() ) );
		wos.writeBytes( Integer.toString(request.getServerPort()) );

		wos.writeShort(swapShort( (short) 15));
		wos.writeBytes("SERVER_PROTOCOL");
		wos.writeShort(swapShort( (short) request.getProtocol().length() ) );
		wos.writeBytes( request.getProtocol() );

		wos.writeShort(swapShort( (short) 11));
		wos.writeBytes("REQUEST_URI");
		if (request.getQueryString() != null) {
			if (request.getQueryString().length() > 0) {
				wos.writeShort(swapShort( (short) (request.getRequestURI().length()+1+request.getQueryString().length()) ) );
				wos.writeBytes( request.getRequestURI()+"?"+request.getQueryString() );
			}
			else {
				wos.writeShort(swapShort( (short) request.getRequestURI().length() ) );
				wos.writeBytes( request.getRequestURI() );
			}
		}
		else {
			wos.writeShort(swapShort( (short) request.getRequestURI().length() ) );
			wos.writeBytes( request.getRequestURI() );
		}


		if (mountpoint != null) {
			wos.writeShort(swapShort( (short) 11));
			wos.writeBytes("SCRIPT_NAME");
			wos.writeShort(swapShort( (short) mountpoint.length() ) );
			wos.writeBytes( mountpoint );
		}


		wos.writeShort(swapShort( (short) 9));
		wos.writeBytes("PATH_INFO");
		if (mountpoint != null) {
			wos.writeShort(swapShort( (short) (request.getRequestURI().length() - mountpoint.length()) ) );
			wos.writeBytes( request.getRequestURI().substring(mountpoint.length())  );
		}
		else {
			wos.writeShort(swapShort( (short) request.getRequestURI().length() ) );
			wos.writeBytes( request.getRequestURI() );
		}

		wos.writeShort(swapShort( (short) 11));
		wos.writeBytes("REMOTE_ADDR");
		wos.writeShort(swapShort( (short) request.getRemoteAddr().length() ) );
		wos.writeBytes( request.getRemoteAddr() );

		if (request.getRemoteUser() != null) {
			wos.writeShort(swapShort( (short) 11));
			wos.writeBytes("REMOTE_USER");
			wos.writeShort(swapShort( (short) request.getRemoteUser().length() ) );
			wos.writeBytes( request.getRemoteUser() );
		}

		if (request.getContentType() != null) {
			wos.writeShort(swapShort( (short) 12));
			wos.writeBytes("CONTENT_TYPE");
			wos.writeShort(swapShort( (short) request.getContentType().length() ) );
			wos.writeBytes( request.getContentType() );
		}

		if (request.getContentLength() > 0) {
			wos.writeShort(swapShort( (short) 14));
			wos.writeBytes("CONTENT_LENGTH");
			String sContentLength = new Integer(request.getContentLength()).toString();
			wos.writeShort(swapShort( (short) sContentLength.length() ) );
			wos.writeBytes( sContentLength );
			hasBody = true;
		}


		// taken from CGI servlet

		Enumeration headers = request.getHeaderNames();
		String header = null;
		while (headers.hasMoreElements()) {
			header = null;
			header = ((String) headers.nextElement()).toUpperCase();
			wos.writeShort(swapShort( (short) ("HTTP_" + header.replace('-', '_')).length() ));
			wos.writeBytes("HTTP_" + header.replace('-', '_'));
			wos.writeShort(swapShort( (short) request.getHeader(header).length() ));
			wos.writeBytes( request.getHeader(header) );
		}


		os.writeByte(0);
		os.writeShort( swapShort( (short) wos.size() ) );
		os.writeByte(0);

		uwsgi_request.writeTo( os );


		if (hasBody) {
			IOTools.flow(request.getInputStream(), os);
		}

		boolean statusParsed = false;
		for(;;) {
			String line = byte_readline(is);
			if (line == "") {
				break;
			}
			if (statusParsed == false) {
				String[] status = line.split(" ",3);
				response.setStatus( Integer.parseInt(status[1]) );
				statusParsed = true;
			}
			else {
				String[] keyval = line.split(": ",2);
				if (keyval.length == 2) {
					response.addHeader(keyval[0], keyval[1]);
				}
				else {
					break;
				}
			}
		}

		byte cb[] = new byte[4096];
		int len = 0;
		for(;;) {
			len = is.read(cb,0,4096);
			if ( len > 0) {
				out.write(cb,0,len);	
			}
			else {
				break;
			}
		}


	}

	private String byte_readline(DataInputStream is) throws IOException {

		ByteArrayOutputStream line = new ByteArrayOutputStream();
		for(;;) {
			byte b = is.readByte();
			if (b == 10) {
				break;
			}
			line.write(b);
		}

		return line.toString("ASCII").replaceAll("\\n","").replaceAll("\\r","");
	}

	private short swapShort(short x) {

		short tmp1 = (short) (x>>8);
		short tmp2 = (short) (x<<8);
		return (short) (tmp1 | tmp2);
	}	

}
