// these may not be portable...
typedef int32_t pid_t;
typedef int32_t uid_t;
typedef int32_t gid_t;
typedef long time_t;
typedef unsigned int socklen_t;
typedef long off_t;
typedef uint64_t rlim_t;

struct iovec {
  void *iov_base;
  size_t iov_len;
  ...;
};