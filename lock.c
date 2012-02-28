#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

static struct uwsgi_lock_item *uwsgi_register_lock(char *id, int rw) {

	struct uwsgi_lock_item *uli = uwsgi.registered_locks;
	if (!uli) {
		uwsgi.registered_locks = uwsgi_malloc_shared(sizeof(struct uwsgi_lock_item));
		uwsgi.registered_locks->id = id;
		uwsgi.registered_locks->pid = 0;
		if (rw) {
			uwsgi.registered_locks->lock_ptr = uwsgi_malloc_shared(uwsgi.rwlock_size);
		}
		else {
			uwsgi.registered_locks->lock_ptr = uwsgi_malloc_shared(uwsgi.lock_size);
		}
		uwsgi.registered_locks->rw = rw;
		uwsgi.registered_locks->next = NULL;
		return uwsgi.registered_locks;
	}

	while(uli) {
		if (!uli->next) {
			uli->next = uwsgi_malloc_shared(sizeof(struct uwsgi_lock_item));
			if (rw) {
				uwsgi_malloc_shared(uwsgi.rwlock_size);
			}
			else {
				uli->next->lock_ptr = uwsgi_malloc_shared(uwsgi.lock_size);
			}
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

#define UWSGI_LOCK_ENGINE_NAME "pthread mutexes"

#define UWSGI_LOCK_SIZE	sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t)

#ifdef OBSOLETE_LINUX_KERNEL
#define UWSGI_RWLOCK_SIZE	sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t)
#else
#define UWSGI_RWLOCK_SIZE	sizeof(pthread_rwlockattr_t) + sizeof(pthread_rwlock_t)
#endif

// REMEMBER lock must contains space for both pthread_mutex_t and pthread_mutexattr_t !!! 
struct uwsgi_lock_item *uwsgi_lock_fast_init(char *id) {
	
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

	uli->can_deadlock = 1;

	return uli;
}

pid_t uwsgi_lock_fast_check(struct uwsgi_lock_item *uli) {

	if (pthread_mutex_trylock((pthread_mutex_t *) (uli->lock_ptr + sizeof(pthread_mutexattr_t))) == 0 ) {
		pthread_mutex_unlock((pthread_mutex_t *) (uli->lock_ptr + sizeof(pthread_mutexattr_t)));	
		return 0;
	}
	return uli->pid;
}

pid_t uwsgi_rwlock_fast_check(struct uwsgi_lock_item *uli) {
#ifdef OBSOLETE_LINUX_KERNEL
	return uwsgi_lock_fast_check(uli);
#else

	if (pthread_rwlock_trywrlock((pthread_rwlock_t *) (uli->lock_ptr + sizeof(pthread_rwlockattr_t)) ) == 0 ) {
		pthread_rwlock_unlock((pthread_rwlock_t *) (uli->lock_ptr + sizeof(pthread_rwlockattr_t)));	
		return 0;
	}
        return uli->pid;
#endif
}

void uwsgi_rlock_fast(struct uwsgi_lock_item *uli) {
#ifdef OBSOLETE_LINUX_KERNEL
	uwsgi_lock_fast(uli);
#else
	pthread_rwlock_rdlock((pthread_rwlock_t *) (uli->lock_ptr + sizeof(pthread_rwlockattr_t)));
        uli->pid = uwsgi.mypid;
#endif
}

void uwsgi_wlock_fast(struct uwsgi_lock_item *uli) {
#ifdef OBSOLETE_LINUX_KERNEL
	uwsgi_lock_fast(uli);
#else
	pthread_rwlock_wrlock((pthread_rwlock_t *) (uli->lock_ptr + sizeof(pthread_rwlockattr_t)));
        uli->pid = uwsgi.mypid;
#endif
}

void uwsgi_rwunlock_fast(struct uwsgi_lock_item *uli) {
#ifdef OBSOLETE_LINUX_KERNEL
	uwsgi_unlock_fast(uli);
#else
	pthread_rwlock_unlock((pthread_rwlock_t *) (uli->lock_ptr + sizeof(pthread_rwlockattr_t)));
        uli->pid = 0;
#endif
}

void uwsgi_lock_fast(struct uwsgi_lock_item *uli) {

	pthread_mutex_lock((pthread_mutex_t *) (uli->lock_ptr + sizeof(pthread_mutexattr_t)));
        uli->pid = uwsgi.mypid;
}

void uwsgi_unlock_fast(struct uwsgi_lock_item *uli) {

	pthread_mutex_unlock((pthread_mutex_t *) (uli->lock_ptr + sizeof(pthread_mutexattr_t)));
	uli->pid = 0;

}

struct uwsgi_lock_item *uwsgi_rwlock_fast_init(char *id) {

#ifdef OBSOLETE_LINUX_KERNEL
	return uwsgi_lock_fast_init(uli);
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

	uli->can_deadlock = 1;

	return uli;
#endif



}



#elif defined(UWSGI_LOCK_USE_UMTX)

/* Warning: FreeBSD is still not ready for process-shared UMTX */

#include <machine/atomic.h>
#include <sys/umtx.h>

#define UWSGI_LOCK_SIZE		sizeof(struct umtx)
#define UWSGI_RWLOCK_SIZE	sizeof(struct umtx)

struct uwsgi_lock_item *uwsgi_rwlock_init(char *id) { return uwsgi_lock_init(id) ;}
void uwsgi_rlock(struct uwsgi_lock_item *uli) { uwsgi_lock(uli);}
void uwsgi_wlock(struct uwsgi_lock_item *uli) { uwsgi_lock(uli);}
void uwsgi_rwunlock(struct uwsgi_lock_item *uli) { uwsgi_unlock(uli); }

struct uwsgi_lock_item *uwsgi_lock_init(char *id) {
	struct uwsgi_lock_item *uli = uwsgi_register_lock(id, 0);
	umtx_init((struct umtx*) uli->lock_ptr);
	return uli;
}

void uwsgi_lock(struct uwsgi_lock_item *uli) {
	umtx_lock((struct umtx*) uli->lock_ptr, (u_long) getpid() );
	uli->pid = uwsgi.mypid;
}

void uwsgi_unlock(struct uwsgi_lock_item *uli) {
	umtx_unlock((struct umtx*) uli->lock_ptr, (u_long) getpid() );
	uli->pid = 0;
}

pid_t uwsgi_lock_check(struct uwsgi_lock_item *uli) {
	if (umtx_trylock((struct umtx*) uli->lock_ptr, (u_long) getpid() )) {
		umtx_unlock((struct umtx*) uli->lock_ptr, (u_long) getpid() );
		return 0;
	}
	return uli->pid;
}

pid_t uwsgi_rwlock_check(struct uwsgi_lock_item *uli) { return uwsgi_lock_check(uli); }

#elif defined(UWSGI_LOCK_USE_OSX_SPINLOCK)

#define UWSGI_LOCK_ENGINE_NAME "OSX spinlocks"
#define UWSGI_LOCK_SIZE		sizeof(OSSpinLock)
#define UWSGI_RWLOCK_SIZE	sizeof(OSSpinLock)


struct uwsgi_lock_item *uwsgi_lock_fast_init(char *id) {

	struct uwsgi_lock_item *uli = uwsgi_register_lock(id, 0);
	memset(uli->lock_ptr, 0, UWSGI_LOCK_SIZE);
	uli->can_deadlock = 1;
	return uli;
}

void uwsgi_lock_fast(struct uwsgi_lock_item *uli) {

	OSSpinLockLock((OSSpinLock *) uli->lock_ptr);
	uli->pid = uwsgi.mypid;
}

void uwsgi_unlock_fast(struct uwsgi_lock_item *uli) {

	OSSpinLockUnlock((OSSpinLock *) uli->lock_ptr);
	uli->pid = 0;
}

pid_t uwsgi_lock_fast_check(struct uwsgi_lock_item *uli) {
	if (OSSpinLockTry((OSSpinLock *) uli->lock_ptr)) {
		OSSpinLockUnlock((OSSpinLock *) uli->lock_ptr);
		return 0;
	}
	return uli->pid;
}

struct uwsgi_lock_item *uwsgi_rwlock_fast_init(char *id) { 
	struct uwsgi_lock_item *uli = uwsgi_register_lock(id, 1);
	memset(uli->lock_ptr, 0, UWSGI_LOCK_SIZE);
	uli->can_deadlock = 1;
	return uli;
}

void uwsgi_rlock_fast(struct uwsgi_lock_item *uli) { uwsgi_lock_fast(uli);}
void uwsgi_wlock_fast(struct uwsgi_lock_item *uli) { uwsgi_lock_fast(uli);}

pid_t uwsgi_rwlock_fast_check(struct uwsgi_lock_item *uli) { return uwsgi_lock_fast_check(uli); }

void uwsgi_rwunlock_fast(struct uwsgi_lock_item *uli) { uwsgi_unlock_fast(uli); }

#else

#define uwsgi_lock_fast_init uwsgi_lock_flock_init
#define uwsgi_lock_fast_check uwsgi_lock_flock_check
#define uwsgi_lock_fast uwsgi_lock_flock
#define uwsgi_unlock_fast uwsgi_unlock_flock

#define uwsgi_rwlock_fast_init uwsgi_rwlock_flock_init
#define uwsgi_rwlock_fast_check uwsgi_rwlock_flock_check

#define uwsgi_rlock_fast uwsgi_rlock_flock
#define uwsgi_wlock_fast uwsgi_wlock_flock
#define uwsgi_rwunlock_fast uwsgi_rwunlock_flock

#define UWSGI_LOCK_SIZE 8
#define UWSGI_RWLOCK_SIZE 8

#define UWSGI_LOCK_ENGINE_NAME "flock"

#endif


struct uwsgi_lock_item *uwsgi_lock_flock_init(char *id) {

	struct uwsgi_lock_item *uli = uwsgi_register_lock(id, 0);
	FILE *tf = tmpfile();
	int fd;

	if (!tf) {
		uwsgi_error_open("temp lock file");
		exit(1);
	}
	
	fd = fileno(tf);
	memcpy(uli->lock_ptr, &fd, sizeof(int));
	return uli;
}

void uwsgi_lock_flock(struct uwsgi_lock_item *uli) {

	int fd;
	memcpy(&fd, uli->lock_ptr, sizeof(int));
	if (flock(fd, LOCK_EX)) { uwsgi_error("flock()"); }
}

void uwsgi_unlock_flock(struct uwsgi_lock_item *uli) {
	int fd;
	memcpy(&fd, uli->lock_ptr, sizeof(int));
	if (flock(fd, LOCK_UN)) { uwsgi_error("flock()"); }
}

struct uwsgi_lock_item *uwsgi_rwlock_flock_init(char *id) { return uwsgi_lock_flock_init(id);}
void uwsgi_rlock_flock(struct uwsgi_lock_item *uli) { uwsgi_lock_flock(uli);}
void uwsgi_wlock_flock(struct uwsgi_lock_item *uli) { uwsgi_lock_flock(uli);}
void uwsgi_rwunlock_flock(struct uwsgi_lock_item *uli) { uwsgi_unlock_flock(uli); }

pid_t uwsgi_lock_flock_check(struct uwsgi_lock_item *uli) {
	int fd;
	memcpy(&fd, uli->lock_ptr, sizeof(int));
        if (flock(fd, LOCK_EX|LOCK_NB) < 0) {
		if (errno == EWOULDBLOCK) {
        		return uli->pid;
		}
        	return 0;
        }
	
	// unlock
	flock(fd, LOCK_UN);
        return 0;
}


pid_t uwsgi_rwlock_flock_check(struct uwsgi_lock_item *uli) { return uwsgi_lock_flock_check(uli); }


void uwsgi_setup_locking() {

	// use the fastest avaikable locking
	if (uwsgi.lock_engine) {
		if (!strcmp(uwsgi.lock_engine, "flock")) {
			uwsgi_log("lock engine: flock\n");
			uwsgi.lock_ops.lock_init = uwsgi_lock_flock_init;
			uwsgi.lock_ops.lock_check = uwsgi_lock_flock_check;
			uwsgi.lock_ops.lock = uwsgi_lock_fast;
			uwsgi.lock_ops.unlock = uwsgi_unlock_fast;
			uwsgi.lock_ops.rwlock_init = uwsgi_rwlock_flock_init;
			uwsgi.lock_ops.rwlock_check = uwsgi_rwlock_flock_check;
			uwsgi.lock_ops.rlock = uwsgi_rlock_fast;
			uwsgi.lock_ops.wlock = uwsgi_wlock_fast;
			uwsgi.lock_ops.rwunlock = uwsgi_rwunlock_fast;
			uwsgi.lock_size = UWSGI_LOCK_SIZE;
			uwsgi.rwlock_size = UWSGI_RWLOCK_SIZE;
			return;
		}
		else if (!strcmp(uwsgi.lock_engine, "ipcsem")) {
			uwsgi_log("lock engine: ipc semaphores\n");
			uwsgi_log("the requested lock engine is unsupported on this platform\n");
			exit(1);
			return;
		}
	}

	uwsgi_log("lock engine: %s\n", UWSGI_LOCK_ENGINE_NAME);
	uwsgi.lock_ops.lock_init = uwsgi_lock_fast_init;
	uwsgi.lock_ops.lock_check = uwsgi_lock_fast_check;
	uwsgi.lock_ops.lock = uwsgi_lock_fast;
	uwsgi.lock_ops.unlock = uwsgi_unlock_fast;
	uwsgi.lock_ops.rwlock_init = uwsgi_rwlock_fast_init;
	uwsgi.lock_ops.rwlock_check = uwsgi_rwlock_fast_check;
	uwsgi.lock_ops.rlock = uwsgi_rlock_fast;
	uwsgi.lock_ops.wlock = uwsgi_wlock_fast;
	uwsgi.lock_ops.rwunlock = uwsgi_rwunlock_fast;
	uwsgi.lock_size = UWSGI_LOCK_SIZE;
	uwsgi.rwlock_size = UWSGI_RWLOCK_SIZE;
}

