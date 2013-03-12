using System;
using System.IO;
using System.Net;
using System.Web;
using System.Web.Hosting;
using System.Text;
using System.Runtime.CompilerServices;

[assembly: System.Reflection.AssemblyVersion ("0.0.0.1")]

namespace uwsgi {

	public delegate void uWSGIHook();
	public delegate void uWSGIHook1(int signum);

	public class api {
		static uWSGIHook postfork_hook = null;

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public static void RegisterSignal(int signum, string target, uWSGIHook1 func);

		public static void PostFork(uWSGIHook func) {
			postfork_hook = func;
		}

		public static void RunPostForkHook() {
			if (postfork_hook != null) {
				postfork_hook();
			}
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public static int WorkerId();

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public static void Signal(int signum);

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
                extern public static byte[] CacheGet(string key, string cache=null);
	}

	class uWSGIRequest: HttpWorkerRequest {

		private String filepath = null;

		public override string GetAppPath() {
			return "/";
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public override string GetServerVariable(string name);

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

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public override string GetHttpVersion();

		public override string GetLocalAddress() {
			return GetServerVariable("SERVER_ADDR");
		}

		public override int GetLocalPort() {
			return Convert.ToInt32(GetServerVariable("SERVER_PORT"));
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public override string GetQueryString();

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public override string GetRawUrl();

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public override string GetRemoteAddress();

		public override int GetRemotePort() {
			return Convert.ToInt32(GetServerVariable("REMOTE_PORT"));
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public override string GetUriPath();

		public override void SendKnownResponseHeader (int index, string value) {
			string headerName = HttpWorkerRequest.GetKnownResponseHeaderName (index);
                	SendUnknownResponseHeader (headerName, value);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public override void SendResponseFromMemory(byte[] chunk, int length);

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public void SendResponseFromFd(int fd, long offset, long length);

		public override void SendResponseFromFile (IntPtr handle, long offset, long length) {
			SendResponseFromFd(handle.ToInt32(), offset, length);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public override void SendResponseFromFile(string filename, long offset, long length);
	
		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public override void SendStatus(int status, string msg);

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern public override void SendUnknownResponseHeader (string name, string value);

		public string hack_current_filename() {
			return filepath;
		}
	}

	public class uWSGIApplicationHost: MarshalByRefObject {
		public void ProcessRequest() {
			uWSGIRequest ur = new uWSGIRequest();
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
