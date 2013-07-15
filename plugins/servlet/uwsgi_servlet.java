import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;
import java.io.*;

/*

uWSGI Servlet 2.5 Container implementation

*/

class uWSGIServletContext implements ServletContext {
	public Object getAttribute(String name) {
		System.out.println("uWSGIServletContext getAttribute " + name);
		return null;
	}

	public void log(java.lang.String message, java.lang.Throwable throwable) {
		System.out.println("LOG " + message);
	}

	public String getRealPath(java.lang.String path) {
		System.out.println("uWSGIServletContext getRealPath " + path);
		return path;
	}

	public String getServerInfo() {
		return "uWSGI";
	}

	public String getInitParameter(java.lang.String name) {
		return null;
	}

	public Enumeration getInitParameterNames() {
		return null;
	}

	public java.util.Enumeration getAttributeNames() {
		System.out.println("uWSGIServletContext getAttributeNames");
		return null;
	}

	public String getServletContextName() {
		System.out.println("uWSGIServletContext getServletContextName");
		return "/jsp";
	}

	public void removeAttribute(java.lang.String name) {
	}

	public void setAttribute(java.lang.String name, java.lang.Object object) {
		System.out.println("uWSGIServletContext setAttribute " + name);
	}

}

class uWSGIServletConfig implements ServletConfig {

	uWSGIServletContext context;

	public uWSGIServletConfig() {
		this.context = new uWSGIServletContext();
	}

	public String getInitParameter(String name) {
		System.out.println("ServletConfig getInitParameter " + name);
		return null;
	}

	public Enumeration<java.lang.String> getInitParameterNames() {
		return null;
	}

	public ServletContext getServletContext() {
		return this.context;
	}

	public String getServletName() {
		return "/jsp";
	}
}

class uWSGIServletOutputStream extends ServletOutputStream {

	// append a byte to the writing buffer
	public void write(int n) {
		System.out.println("char " + n);
	}

	// send them to the client
	public void flush() {
		System.out.println("FLUSHING");
	}
	
}

class uWSGIServletRequest implements HttpServletRequest {

	public Object getAttribute(String name) {
		System.out.println("getAttribute " + name);		
		return null;
	}

	public Enumeration getAttributeNames() {
		return null;
	}

	public String getCharacterEncoding() {
		return "utf-8";
	}

	public void setCharacterEncoding(String env) {
	}

	public String getParameter(String name) {
		System.out.println("getParameter " + name);
		return null;
	}

	public Enumeration getParameterNames() {
		return null;
	}

	public String[] getParameterValues(String name) {
		return null;
	}

	public int  getContentLength() {
		return 0;
	}

	public String  getContentType() {
		return "text/plain";
	}


	public ServletInputStream getInputStream() {
		return null;
	}	


	public Map getParameterMap() {
		return null;
	}

	public String getProtocol() {
		return "HTTP/1.0";
	}

	public String getScheme() {
		System.out.println("getScheme");
		return "http";
	}

	public String getServerName() {
		return "quantal64.local";
	}

	public int getServerPort() {
		return 80;
	}

	public BufferedReader getReader() {
		return null;
	}

	public String getRemoteAddr() {
		return "127.0.0.1";
	}

	public String getRemoteHost() {
		return "localhost";
	}

	public void setAttribute(String name, Object o) {
	}

	public void removeAttribute(String name) {
	}

	public Locale getLocale() {
		return null;
	}

	public Enumeration getLocales() {
		return null;
	}

	public boolean isSecure() {
		return false;
	}

	public RequestDispatcher getRequestDispatcher(String path) {
		return null;
	}

	public String getRealPath(String path) {
		System.out.println("getRealPath " + path);
		return "/tmp";
	}

	public int getRemotePort() {
		return 1717;
	}

	public String getLocalName() {
		return "localhost";
	}

	public String getLocalAddr() {
		return "127.0.0.1";
	}

	public int getLocalPort() {
		return 80;
	}

	public String getAuthType() {
		return null;
	}

	public Cookie[] getCookies() {
		return null;
	}

	public long getDateHeader(String name) {
		return -1;
	}

	public String getHeader(String name) {
		System.out.println("getHeader " + name);
		return null;
	}

	public Enumeration getHeaders(String name) {
		System.out.println("getHeaders " + name);
		return null;
	}

	public Enumeration getHeaderNames() {
		return null;
	}

	public int getIntHeader(String name) {
		return -1;
	}

	public String getMethod() {
		System.out.println("getMethod");
		return "GET";
	}

	public String getPathInfo() {
		System.out.println("getPathInfo");
		return "";
	}

	public String getPathTranslated() {
		System.out.println("getPathTranslated");
		return null;
	}

	public String getContextPath() {
		return "";
	}

	public String getQueryString() {
		return "r=17";
	}

	public String getRemoteUser() {
		return "kratos";
	}

	public boolean isUserInRole(String role) {
		return false;
	}

	public java.security.Principal getUserPrincipal() {
		return null;
	}

	public String getRequestedSessionId() {
		return null;
	}

	public String getRequestURI() {
		System.out.println("getRequestURI");
		return "/foobar";
	}

	public StringBuffer getRequestURL() {
		System.out.println("getRequestURL");
		//return "http://quantal64.local/roberta?r=17";
		return null;
	}

	public String getServletPath() {
		System.out.println("getServletPath");
		return "/foobar";
	}

	public HttpSession getSession(boolean create) {
		return null;
	}

	public HttpSession getSession() {
		return null;
	}

	public boolean isRequestedSessionIdFromURL() {
		return false;
	}

	public boolean isRequestedSessionIdFromUrl() {
		return false;
	}

	public boolean isRequestedSessionIdFromCookie() {
		return false;
	}

	public boolean isRequestedSessionIdValid() {
		return false;
	}

}

class uWSGIServletResponse implements HttpServletResponse {

	public void addCookie(Cookie cookie) {
	}

	public boolean containsHeader(String name) {
		return false;
	}

	public String encodeURL(String url) {
		System.out.println("URL = " + url);
		return url;
	}

	public String encodeRedirectURL(String url) {
		return url;
	}

	public String encodeUrl(String url) {
                return url;
        }

	public String encodeRedirectUrl(String url) {
                return url;
        }

	public void sendError(int sc, String msg) {
	}

	public void sendError(int sc) {
	}

	public void sendRedirect(String location) {
	}

	public void setDateHeader(String name, long date) {
	}

	public void addDateHeader(String name, long date) {
	}

	public void setHeader(String name, String value) {
		System.out.println("SET_HEADER " + name + " = " + value);
	}

	public void addHeader(String name, String value) {
		System.out.println("ADD_HEADER " + name + " = " + value);
	}

	public void setIntHeader(String name, int value) {
	}

	public void addIntHeader(String name, int value) {
	}

	public void setStatus(int sc) {
		System.out.println("STATUS " + sc);
	}

	public void setStatus(int sc, String sm) {
		System.out.println("STATUS " + sc + " " + sm);
	}

	public void flushBuffer() {
	}

	public void resetBuffer() {
	}

	public boolean isCommitted() {
		return true;
	}

	public void reset() {
	}

	public void setLocale(Locale loc) {
	}

	public Locale getLocale() {
		return null;	
	}

	public int getBufferSize() {
		return 4096;
	}

	public void setBufferSize(int size) {
	}

	public void setContentType(String type) {
		System.out.println("setContentType " + type);
	}

	public void setContentLength(int len) {
	}

	public void setCharacterEncoding(String charset) {
	}

	public PrintWriter getWriter() {
		System.out.println("getWriter()");
		PrintWriter pw = new PrintWriter(new uWSGIServletOutputStream());
		return pw;
	}

	public ServletOutputStream getOutputStream() {
		System.out.println("getOutputStream()");
		return null;
	}

	public String getContentType() {
		return "text/plain";
	}

	public String getCharacterEncoding() {
		return "utf-8";
	}
}
