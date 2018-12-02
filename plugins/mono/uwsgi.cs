using System;
using System.IO;
using System.Net;
using System.Web;
using System.Web.Hosting;
using System.Text;
using System.Runtime.CompilerServices;
using System.Configuration;
using System.Security.Permissions;
using System.Security.Policy;
using System.Web.Configuration;
using System.Reflection;

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
		
		public override string GetServerName() {
			return GetServerVariable("SERVER_NAME");
		}
		
		public override string GetProtocol() {
			return GetServerVariable("REQUEST_SCHEME");
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
			appHost = (uWSGIApplicationHost)CreateApplicationHost(typeof(uWSGIApplicationHost), virtualPath, physicalPath);
		}

		public void Request() {
			appHost.ProcessRequest();
		}


        // The code below is mostly a copy of System.Web.Hosting.ApplicationHost class from Mono source 
	    // with some quirks to access some internal parameters
        // We need this to add to binDirpath the path to the uwsgi.dll so it would load successfully
	    // in the new appdomain without being registered to the GAC
        // This is hacky, but it seems there is no real other way other than this
        #region ApplicationHostImpl

        const string DEFAULT_WEB_CONFIG_NAME = "web.config";
        internal const string MonoHostedDataKey = ".:!MonoAspNetHostedApp!:.";

        static object create_dir = new object();

        internal static string FindWebConfig(string basedir)
        {
            if (String.IsNullOrEmpty(basedir) || !Directory.Exists(basedir))
                return null;

            string[] files = Directory.GetFileSystemEntries(basedir, "?eb.?onfig");
            if (files == null || files.Length == 0)
                return null;
            return files[0];
        }

        internal static bool ClearDynamicBaseDirectory(string directory)
        {
            string[] entries = null;

            try
            {
                entries = Directory.GetDirectories(directory);
            }
            catch
            {
                // ignore
            }

            bool dirEmpty = true;
            if (entries != null && entries.Length > 0)
            {
                foreach (string e in entries)
                {
                    if (ClearDynamicBaseDirectory(e))
                    {
                        try
                        {
                            Directory.Delete(e);
                        }
                        catch
                        {
                            dirEmpty = false;
                        }
                    }
                }
            }

            try
            {
                entries = Directory.GetFiles(directory);
            }
            catch
            {
                entries = null;
            }

            if (entries != null && entries.Length > 0)
            {
                foreach (string e in entries)
                {
                    try
                    {
                        File.Delete(e);
                    }
                    catch
                    {
                        dirEmpty = false;
                    }
                }
            }

            return dirEmpty;
        }

        static bool CreateDirectory(string directory)
        {
            lock (create_dir)
            {
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                    return false;
                }
                else
                    return true;
            }
        }

        static string BuildPrivateBinPath(string physicalPath, string[] dirs)
        {
            int len = dirs.Length;
            string[] ret = new string[len];
            for (int i = 0; i < len; i++)
                ret[i] = Path.Combine(physicalPath, dirs[i]);
            return String.Join(";", ret);
        }

        //
        // For further details see `Hosting the ASP.NET runtime'
        //
        //    http://www.west-wind.com/presentations/aspnetruntime/aspnetruntime.asp
        // 
        public static object CreateApplicationHost(Type hostType, string virtualDir, string physicalDir)
        {
            if (physicalDir == null)
                throw new NullReferenceException();

            // Make sure physicalDir has file system semantics
            // and not uri semantics ( '\' and not '/' ).
            physicalDir = Path.GetFullPath(physicalDir);

            if (hostType == null)
                throw new ArgumentException("hostType can't be null");

            if (virtualDir == null)
                throw new ArgumentNullException("virtualDir");

            Evidence evidence = new Evidence(AppDomain.CurrentDomain.Evidence);

            //
            // Setup
            //
            AppDomainSetup setup = new AppDomainSetup();

            setup.ApplicationBase = physicalDir;

            string webConfig = FindWebConfig(physicalDir);

            if (webConfig == null)
                webConfig = Path.Combine(physicalDir, DEFAULT_WEB_CONFIG_NAME);
            setup.ConfigurationFile = webConfig;
            setup.DisallowCodeDownload = true;

            string[] bindirPath = new string[]
            {
                Path.Combine(physicalDir, "bin"),
                Path.GetDirectoryName(Uri.UnescapeDataString(new UriBuilder(hostType.Module.Assembly.CodeBase).Path))
            };
            string bindir;

            foreach (string dir in new string[]{"Bin", "bin"})
            {
                bindir = Path.Combine(physicalDir, dir);

                if (Directory.Exists(bindir))
                {
                    bindirPath[0] = bindir;
                    break;
                }
            }

            setup.PrivateBinPath = BuildPrivateBinPath(physicalDir, bindirPath);
            setup.PrivateBinPathProbe = "*";
            string dynamic_dir = null;
            string user = Environment.UserName;
            int tempDirTag = 0;
            string dirPrefix = String.Concat(user, "-temp-aspnet-");

            for (int i = 0; ; i++)
            {
                string d = Path.Combine(Path.GetTempPath(), String.Concat(dirPrefix, i.ToString("x")));

                try
                {
                    CreateDirectory(d);
                    string stamp = Path.Combine(d, "stamp");
                    CreateDirectory(stamp);
                    dynamic_dir = d;
                    try
                    {
                        Directory.Delete(stamp);
                    }
                    catch (Exception)
                    {
                        // ignore
                    }

                    tempDirTag = i.GetHashCode();
                    break;
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }
            }
            // 
            // Unique Domain ID
            //
            string domain_id = (virtualDir.GetHashCode() + 1 ^ physicalDir.GetHashCode() + 2 ^ tempDirTag).ToString("x");

            // This is used by mod_mono's fail-over support
            string domain_id_suffix = Environment.GetEnvironmentVariable("__MONO_DOMAIN_ID_SUFFIX");
            if (domain_id_suffix != null && domain_id_suffix.Length > 0)
                domain_id += domain_id_suffix;

            setup.ApplicationName = domain_id;
            setup.DynamicBase = dynamic_dir;
            setup.CachePath = dynamic_dir;

            string dynamic_base = setup.DynamicBase;
            if (CreateDirectory(dynamic_base) && (Environment.GetEnvironmentVariable("MONO_ASPNET_NODELETE") == null))
                ClearDynamicBaseDirectory(dynamic_base);

            //
            // Create app domain
            //
            AppDomain appdomain;
            appdomain = AppDomain.CreateDomain(domain_id, evidence, setup);

            //
            // Populate with the AppDomain data keys expected, Mono only uses a
            // few, but third party apps might use others:
            //
            appdomain.SetData(".appDomain", "*");
            int l = physicalDir.Length;
            if (physicalDir[l - 1] != Path.DirectorySeparatorChar)
                physicalDir += Path.DirectorySeparatorChar;
            appdomain.SetData(".appPath", physicalDir);
            appdomain.SetData(".appVPath", virtualDir);
            appdomain.SetData(".appId", domain_id);
            appdomain.SetData(".domainId", domain_id);
            appdomain.SetData(".hostingVirtualPath", virtualDir);
            appdomain.SetData(".hostingInstallDir", Path.GetDirectoryName(typeof(Object).Assembly.CodeBase));
            appdomain.SetData("DataDirectory", Path.Combine(physicalDir, "App_Data"));
            appdomain.SetData(MonoHostedDataKey, "yes");

            appdomain.DoCallBack(SetHostingEnvironment);
            return appdomain.CreateInstanceAndUnwrap(hostType.Module.Assembly.FullName, hostType.FullName);
        }

        static void SetHostingEnvironment()
        {
            bool shadow_copy_enabled = true;
            HostingEnvironmentSection he = WebConfigurationManager.GetWebApplicationSection("system.web/hostingEnvironment") as HostingEnvironmentSection;
            if (he != null)
                shadow_copy_enabled = he.ShadowCopyBinAssemblies;

            if (shadow_copy_enabled)
            {
                AppDomain current = AppDomain.CurrentDomain;
                
                // We disable the obsolete warnings here, because we want to keep this code as close to the original one
                // We got theese obsolete methods in the original one, so we keep it
#pragma warning disable 0618
                current.SetShadowCopyFiles();
                current.SetShadowCopyPath(current.SetupInformation.PrivateBinPath);
#pragma warning restore 0618
            }

            // Black magic below to access internal setters
            // This MAY break with future Mono releases, but the related code wasn't changed in the last 8 years, so highly unlikely it will break

            // HostingEnvironment.IsHosted = true;
            PropertyInfo property = typeof(HostingEnvironment).GetProperty("IsHosted");
            property.DeclaringType.GetProperty("IsHosted");
            property.GetSetMethod(true).Invoke(null, new object[] { true });

            // HostingEnvironment.SiteName = HostingEnvironment.ApplicationID;
            property = typeof(HostingEnvironment).GetProperty("SiteName");
            property.DeclaringType.GetProperty("SiteName");
            property.GetSetMethod(true).Invoke(null, new object[] { HostingEnvironment.ApplicationID });
        }

	    #endregion
    }
}
