#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

static struct uwsgi_lock_item *uwsgi_register_lock(char *id, int rw) {

	struct uwsgi_lock_item *uli = uwsgi.registered_locks;
	if (!uli) {
		uwsgi.registered_locks = uwsgi_malloc_shared(sizeof(struct uwsgi_lock_item));
		uwsgi.registered_locks->id = id;
		uwsgi.registered_locks->pid = 0;
		uwsgi.registered_locks->lock_ptr = uwsgi_mmap_shared_lock();;
		uwsgi.registered_locks->rw = rw;
		uwsgi.registered_locks->next = NULL;
		return uwsgi.registered_locks;
	}

	while(uli) {
		if (!uli->next) {
			uli->next = uwsgi_malloc_shared(sizeof(struct uwsgi_lock_item));
			uli->next->lock_ptr = uwsgi_mmap_shared_lock();;
			uli->next->id = id;
			uli->next->pid = 0;
			uli->next->rw = rw;
			uli->next->next = NULL;
			return uli->next;
		}
		uli = uli->next;
	}

	uwsgi_log("*** DANGER: unable to allocate lock %s ***\n", id);
	exit(1);

}


#ifdef UWSGI_LOCK_USE_MUTEX

#define UWSGI_LOCK_SIZE	sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t)

#ifdef OBSOLETE_LINUX_KERNEL
#define UWSGI_RWLOCK_SIZE	sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t)
#else
#define UWSGI_RWLOCK_SIZE	sizeof(pthread_rwlockattr_t) + sizeof(pthread_rwlock_t)
#endif

// REMEMBER lock must contains space for both pthread_mutex_t and pthread_mutexattr_t !!! 
struct uwsgi_lock_item *uwsgi_lock_init(char *id) {
	
        struct uwsgi_lock_item *uli = uwsgi_register_lock(id, 0);

	if (pthread_mutexattr_init((pthread_mutexattr_t *) uli->lock_ptr)) {
        	uwsgi_log("unable to allocate mutexattr structure\n");
                exit(1);
	}
        if (pthread_mutexattr_setpshared((pthread_mutexattr_t *) uli->lock_ptr, PTHREAD_PROCESS_SHARED)) {
        	uwsgi_log("unable to share mutex\n");
                exit(1);
        }

        if (pthread_mutex_init((pthread_mutex_t *) (uli->lock_ptr + sizeof(pthread_mutexattr_t)), (pthread_mutexattr_t *) uli->lock_ptr)) {
        	uwsgi_log("unable to initialize mutex\n");
                exit(1);
        }

	return uli;
}

pid_t uwsgi_lock_check(struct uwsgi_lock_item *uli) {

	if (pthread_mutex_trylock((pthread_mutex_t *) (uli->lock_ptr + sizeof(pthread_mutexattr_t))) == 0 ) {
		pthread_mutex_unlock((pthread_mutex_t *) (uli->lock_ptr + sizeof(pthread_mutexattr_t)));	
		return 0;
	}
	return uli->pid;
}

pid_t uwsgi_rwlock_check(struct uwsgi_lock_item *uli) {
#ifdef OBSOLETE_LINUX_KERNEL
	return uwsgi_lock_check(uli);
#else

	if (pthread_rwlock_trywrlock((pthread_rwlock_t *) (uli->lock_ptr + sizeof(pthread_mutexattr_t)) ) == 0 ) {
		pthread_rwlock_unlock((pthread_rwlock_t *) (uli->lock_ptr + sizeof(pthread_mutexattr_t)));	
		return 0;
	}
        return uli->pid;
#endif
}

void uwsgi_rlock(struct uwsgi_lock_item *uli) {
#ifdef OBSOLETE_LINUX_KERNEL
	uwsgi_lock(uli);
#else
	pthread_rwlock_rdlock((pthread_rwlock_t *) (uli->lock_ptr + sizeof(pthread_rwlockattr_t)));
        uli->pid = uwsgi.mypid;
#endif
}

void uwsgi_wlock(struct uwsgi_lock_item *uli) {
#ifdef OBSOLETE_LINUX_KERNEL
	uwsgi_lock(uli);
#else
	pthread_rwlock_wrlock((pthread_rwlock_t *) (uli->lock_ptr + sizeof(pthread_rwlockattr_t)));
        uli->pid = uwsgi.mypid;
#endif
}

void uwsgi_rwunlock(struct uwsgi_lock_item *uli) {
#ifdef OBSOLETE_LINUX_KERNEL
	uwsgi_unlock(uli);
#else
	pthread_rwlock_unlock((pthread_rwlock_t *) (uli->lock_ptr + sizeof(pthread_rwlockattr_t)));
        uli->pid = 0;
#endif
}

void uwsgi_lock(struct uwsgi_lock_item *uli) {

	pthread_mutex_lock((pthread_mutex_t *) (uli->lock_ptr + sizeof(pthread_mutexattr_t)));
        uli->pid = uwsgi.mypid;
}

void uwsgi_unlock(struct uwsgi_lock_item *uli) {

	pthread_mutex_unlock((pthread_mutex_t *) (uli->lock_ptr + sizeof(pthread_mutexattr_t)));
	uli->pid = 0;

}

struct uwsgi_lock_item *uwsgi_rwlock_init(char *id) {

#ifdef OBSOLETE_LINUX_KERNEL
	return uwsgi_lock_init(uli);
#else

	struct uwsgi_lock_item *uli = uwsgi_register_lock(id, 1);

        if (pthread_rwlockattr_init((pthread_rwlockattr_t *) uli->lock_ptr)) {
                uwsgi_log("unable to allocate rwlock structure\n");
                exit(1);
        }
        if (pthread_rwlockattr_setpshared((pthread_rwlockattr_t *) uli->lock_ptr, PTHREAD_PROCESS_SHARED)) {
                uwsgi_log("unable to share rwlock\n");
                exit(1);
        }

        if (pthread_rwlock_init((pthread_rwlock_t *) (uli->lock_ptr + sizeof(pthread_rwlockattr_t)), (pthread_rwlockattr_t *) uli->lock_ptr)) {
                uwsgi_log("unable to initialize rwlock\n");
                exit(1);
        }

	return uli;
#endif



}



#endif

#ifdef UWSGI_LOCK_USE_UMTX

#include <machine/atomic.h>
#include <sys/umtx.h>

#define UWSGI_LOCK_SIZE		sizeof(struct umtx) + sizeof(pid_t)
#define UWSGI_RWLOCK_SIZE	sizeof(struct umtx) + sizeof(pid_t)

void uwsgi_rwlock_init(void *lock) { uwsgi_lock_init(lock) ;}
void uwsgi_rlock(void *lock) { uwsgi_lock(lock);}
void uwsgi_wlock(void *lock) { uwsgi_lock(lock);}
void uwsgi_rwunlock(void *lock) { uwsgi_unlock(lock); }

void uwsgi_lock_init(void *lock) {
	umtx_init((struct umtx*) lock);
	uwsgi_register_lock(lock, 0);
}

void uwsgi_lock(void *lock) {
	umtx_lock(lock, 1);
	pid_t *pid = (pid_t *) (lock + sizeof(struct umtx));
	*pid = uwsgi.mypid;
}

void uwsgi_unlock(void *lock) {
	umtx_unlock(lock, 1);
	pid_t *pid = (pid_t *) (lock + sizeof(struct umtx));
	*pid = 0;
}

pid_t uwsgi_lock_check(void *lock) {
	if (umtx_trylock(lock, 1)) {
		umtx_unlock(lock, 1);
		return 0;
	}
	pid_t *pid = (pid_t *) (lock + sizeof(struct umtx));	
	return *pid;
}

pid_t uwsgi_rwlock_check(void *lock) { return uwsgi_lock_check(lock); }

#endif


#ifdef UWSGI_LOCK_USE_OSX_SPINLOCK

#define UWSGI_LOCK_SIZE		sizeof(OSSpinLock) + sizeof(pid_t)
#define UWSGI_RWLOCK_SIZE	sizeof(OSSpinLock) + sizeof(pid_t)


void uwsgi_lock_init(void *lock) {

	memset(lock, 0, UWSGI_LOCK_SIZE);
	uwsgi_register_lock(lock, 0);
}

void uwsgi_lock(void *lock) {

	OSSpinLockLock((OSSpinLock *) lock);
	pid_t *pid = (pid_t *) (lock + sizeof(OSSpinLock));
	*pid = uwsgi.mypid;
}

void uwsgi_unlock(void *lock) {

	OSSpinLockUnlock((OSSpinLock *) lock);
	pid_t *pid = (pid_t *) (lock + sizeof(OSSpinLock));
	*pid = 0;
}

pid_t uwsgi_lock_check(void *lock) {
	if (OSSpinLockTry((OSSpinLock *) lock)) {
		OSSpinLockUnlock((OSSpinLock *) lock);
		return 0;
	}
	pid_t *pid = (pid_t *) (lock + sizeof(OSSpinLock));	
	return *pid;
}

void uwsgi_rwlock_init(void *lock) { 
	memset(lock, 0, UWSGI_LOCK_SIZE);
        uwsgi_register_lock(lock, 1);
}

void uwsgi_rlock(void *lock) { uwsgi_lock(lock);}
void uwsgi_wlock(void *lock) { uwsgi_lock(lock);}

pid_t uwsgi_rwlock_check(void *lock) { return uwsgi_lock_check(lock); }

void uwsgi_rwunlock(void *lock) { uwsgi_unlock(lock); }



#endif


#ifdef UWSGI_LOCK_USE_FLOCK

#define UWSGI_LOCK_SIZE 8
#define UWSGI_RWLOCK_SIZE 8

void uwsgi_lock_init(void *lock) {

	FILE *tf = tmpfile();
	int fd;

	if (!tf) {
		uwsgi_error_open("temp lock file");
		exit(1);
	}
	
	fd = fileno(tf);

	memcpy(lock, &fd, sizeof(int));
}

void uwsgi_lock(void *lock) {

	int fd;
	memcpy(&fd, lock, sizeof(int));
	if (flock(fd, LOCK_EX)) { uwsgi_error("flock()"); }
}

void uwsgi_unlock(void *lock) {
	int fd;
	memcpy(&fd, lock, sizeof(int));
	if (flock(fd, LOCK_UN)) { uwsgi_error("flock()"); }
}

void uwsgi_rwlock_init(void *lock) { uwsgi_lock_init(lock) ;}
void uwsgi_rlock(void *lock) { uwsgi_lock(lock);}
void uwsgi_wlock(void *lock) { uwsgi_lock(lock);}
void uwsgi_rwunlock(void *lock) { uwsgi_unlock(lock); }

#endif


void *uwsgi_mmap_shared_lock() {
	void *addr = NULL;
	addr = mmap(NULL, UWSGI_LOCK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);

	if (addr == NULL) {
		uwsgi_error("mmap()");
		exit(1);
	}

	return addr;
}

void *uwsgi_mmap_shared_rwlock() {
	void *addr = NULL;
	addr = mmap(NULL, UWSGI_RWLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);

	if (addr == NULL) {
		uwsgi_error("mmap()");
		exit(1);
	}

	return addr;
}
