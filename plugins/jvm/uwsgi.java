import java.io.*;
import java.util.*;

public class uwsgi {

	static HashMap<String,Object> opt;	

	public static class RequestBody extends InputStream {
		public native int read();
		public native int read(byte[] b);
		public native int readLine(byte[] b);
		public native int available();
		public native void seek(int pos);
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

	public static native void lock();
	public static native void unlock();
	public static native void lock(int locknum);
	public static native void unlock(int locknum);

	public static native byte[] cache_get(String key);
	public static native byte[] cache_get(String key, String cache);
	public static native void cache_set(String key, byte[] value);
	public static native void cache_update(String key, byte[] value);
	public static native void cache_set(String key, byte[] value, int expires);
	public static native void cache_update(String key, byte[] value, int expires);
	public static native void cache_set(String key, byte[] value, int expires, String cache);
	public static native void cache_update(String key, byte[] value, int expires, String cache);

	public static native void alarm(String alarm, String msg);

	public static native String rpc(String... args);

}
