import java.io.*;

public class uwsgi {

	public static class RequestBody extends InputStream {
		public native int read();
		public native int read(byte[] b);
		public native int available();
	}

	public interface SignalHandler {
		void function(int signum);
	}

	public interface RpcFunction {
		String function(String... args);
	}

	public static native int worker_id();
	public static native void register_signal(int signum, String target, SignalHandler sh);
	public static native void register_rpc(String name, RpcFunction rf);

}
