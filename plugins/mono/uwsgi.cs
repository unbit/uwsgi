using System;
using System.IO;
using System.Net;
using System.Web;
using System.Web.Hosting;
using System.Text;
using System.Runtime.CompilerServices;

namespace uwsgi {

class uwsgi_req: HttpWorkerRequest {

	public override string GetAppPath() {
		return "/";
	}

	public override string GetServerVariable(string name) {
		Console.WriteLine(name);
		return string.Empty;
	}

	public override bool IsEntireEntityBodyIsPreloaded() {
		return false;
	}

	public override string GetUnknownRequestHeader(string name) {
		return GetHeaderByName(name);
	}

	public override byte[] GetPreloadedEntityBody() {
		return null;
	}


	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public string GetHeaderByName(string name);
	

	public override string GetKnownRequestHeader(int index) {
		return GetHeaderByName(GetKnownRequestHeaderName(index));
	}

	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public override int GetTotalEntityBodyLength();

	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public override int ReadEntityBody(byte[] buffer, int size);

	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public override string GetFilePath();

	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public override string MapPath(string virtualPath);

	public override void EndOfRequest() {
	}

	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public override void FlushResponse(bool finalFlush);

	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public override string GetHttpVerbName();

	public override string GetHttpVersion() {
		return "HTTP/1.1";
	}

	public override string GetLocalAddress() {
		return "127.0.0.1";
	}

	public override int GetLocalPort() {
		return 8080;
	}

	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public override string GetQueryString();

	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public override string GetRawUrl();

	public override string GetRemoteAddress() {
		return "127.0.0.1";
	}

	public override int GetRemotePort() {
		return 8081;
	}

	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public override string GetUriPath();

	public override void SendKnownResponseHeader (int index, string value) {
		string headerName = HttpWorkerRequest.GetKnownResponseHeaderName (index);
                SendUnknownResponseHeader (headerName, value);
	}

	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public override void SendResponseFromMemory(byte[] chunk, int length);

	public override void SendResponseFromFile (IntPtr handle, long offset, long length) {
		Console.WriteLine("sending a file");
	}

	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public override void SendResponseFromFile(string filename, long offset, long length);
	
	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public override void SendStatus(int status, string msg);

	[MethodImplAttribute(MethodImplOptions.InternalCall)]
	extern public override void SendUnknownResponseHeader (string name, string value);

}

	public class uWSGIApplicationHost: MarshalByRefObject {
		public void ProcessRequest() {
			uwsgi_req ur = new uwsgi_req();
			HttpRuntime.ProcessRequest(ur);
		}
	}

	public class uWSGIApplication {

		public uWSGIApplicationHost appHost;

		public uWSGIApplication(string virtualPath, string physicalPath) {
			appHost = (uWSGIApplicationHost)ApplicationHost.CreateApplicationHost(typeof(uWSGIApplicationHost), virtualPath, physicalPath);
		}

		public void Request() {
			appHost.ProcessRequest();
		}
	}

}
