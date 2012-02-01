#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

static void uwsgi_register_lock(void *ptr, int rw) {

	struct uwsgi_lock_item *uli = uwsgi.registered_locks;
	if (!uli) {
		uwsgi.registered_locks = uwsgi_malloc(sizeof(struct uwsgi_lock_item));
		uwsgi.registered_locks->lock_ptr = ptr;
		uwsgi.registered_locks->rw = rw;
		uwsgi.registered_locks->next = NULL;
	}
	else {
		while(uli) {
			if (!uli->next) {
				uli->next = uwsgi_malloc(sizeof(struct uwsgi_lock_item));
				uli->next->lock_ptr = ptr;
				uli->rw = rw;
				uli->next->next = NULL;
				return;
			}
			uli = uli->next;
		}
	}

}


#ifdef UWSGI_LOCK_USE_MUTEX

#define UWSGI_LOCK_SIZE	sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t) + sizeof(pid_t)

#ifdef OBSOLETE_LINUX_KERNEL
#define UWSGI_RWLOCK_SIZE	sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t) + sizeof(pid_t)
#else
#define UWSGI_RWLOCK_SIZE	sizeof(pthread_rwlockattr_t) + sizeof(pthread_rwlock_t) + sizeof(pid_t)
#endif

// REMEMBER lock must contains space for both pthread_mutex_t and pthread_mutexattr_t !!! 
void uwsgi_lock_init(void *lock) {

	if (pthread_mutexattr_init((pthread_mutexattr_t *) lock)) {
        	uwsgi_log("unable to allocate mutexattr structure\n");
                exit(1);
	}
        if (pthread_mutexattr_setpshared((pthread_mutexattr_t *) lock, PTHREAD_PROCESS_SHARED)) {
        	uwsgi_log("unable to share mutex\n");
                exit(1);
        }

        if (pthread_mutex_init((pthread_mutex_t *) lock + sizeof(pthread_mutexattr_t), (pthread_mutexattr_t *) lock)) {
        	uwsgi_log("unable to initialize mutex\n");
                exit(1);
        }
        uwsgi_register_lock(lock, 0);


}

pid_t uwsgi_lock_check(void *lock) {

	if (pthread_mutex_trylock((pthread_mutex_t *) lock + sizeof(pthread_mutexattr_t)) ) {
		pthread_mutex_unlock((pthread_mutex_t *) lock + sizeof(pthread_mutexattr_t));	
		return 0;
	}
	pid_t *pid = (pid_t *) lock + sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t) ;
        return *pid;
}

pid_t uwsgi_rwlock_check(void *lock) {
#ifdef OBSOLETE_LINUX_KERNEL
	return uwsgi_lock_check(lock);
#else

	if (pthread_rwlock_trywrlock((pthread_rwlock_t *) lock + sizeof(pthread_mutexattr_t)) ) {
		pthread_rwlock_unlock((pthread_rwlock_t *) lock + sizeof(pthread_mutexattr_t));	
		return 0;
	}
	pid_t *pid = (pid_t *) lock + sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t) ;
        return *pid;
#endif
}

void uwsgi_rlock(void *lock) {
#ifdef OBSOLETE_LINUX_KERNEL
	uwsgi_lock(lock);
#else
	pthread_rwlock_rdlock((pthread_rwlock_t *) lock + sizeof(pthread_rwlockattr_t));
#endif
}

void uwsgi_wlock(void *lock) {
#ifdef OBSOLETE_LINUX_KERNEL
	uwsgi_lock(lock);
#else
	pthread_rwlock_wrlock((pthread_rwlock_t *) lock + sizeof(pthread_rwlockattr_t));
	pid_t *pid = (pid_t *) lock + sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t) ;
        *pid = uwsgi.mypid;
#endif
}

void uwsgi_rwunlock(void *lock) {
#ifdef OBSOLETE_LINUX_KERNEL
	uwsgi_unlock(lock);
#else
	pthread_rwlock_unlock((pthread_rwlock_t *) lock + sizeof(pthread_rwlockattr_t));
	pid_t *pid = (pid_t *) lock + sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t) ;
        *pid = 0;
#endif
}

void uwsgi_lock(void *lock) {

	pthread_mutex_lock((pthread_mutex_t *) lock + sizeof(pthread_mutexattr_t));
	pid_t *pid = (pid_t *) lock + sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t) ;
        *pid = uwsgi.mypid;
}

void uwsgi_unlock(void *lock) {

	pthread_mutex_unlock((pthread_mutex_t *) lock + sizeof(pthread_mutexattr_t));
	pid_t *pid = (pid_t *) lock + sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t) ;
	*pid = 0;

}

void uwsgi_rwlock_init(void *lock) {

#ifdef OBSOLETE_LINUX_KERNEL
	uwsgi_lock_init(lock);
#else
        if (pthread_rwlockattr_init((pthread_rwlockattr_t *) lock)) {
                uwsgi_log("unable to allocate rwlock structure\n");
                exit(1);
        }
        if (pthread_rwlockattr_setpshared((pthread_rwlockattr_t *) lock, PTHREAD_PROCESS_SHARED)) {
                uwsgi_log("unable to share rwlock\n");
                exit(1);
        }

        if (pthread_rwlock_init((pthread_rwlock_t *) lock + sizeof(pthread_rwlockattr_t), (pthread_rwlockattr_t *) lock)) {
                uwsgi_log("unable to initialize rwlock\n");
                exit(1);
        }
#endif

	uwsgi_register_lock(lock, 1);


}



#endif

#ifdef UWSGI_LOCK_USE_UMTX

#include <machine/atomic.h>
#include <sys/umtx.h>

#define UWSGI_LOCK_SIZE		sizeof(struct umtx)
#define UWSGI_RWLOCK_SIZE	sizeof(struct umtx)

void uwsgi_rwlock_init(void *lock) { uwsgi_lock_init(lock) ;}
void uwsgi_rlock(void *lock) { uwsgi_lock(lock);}
void uwsgi_wlock(void *lock) { uwsgi_lock(lock);}
void uwsgi_rwunlock(void *lock) { uwsgi_unlock(lock); }

void uwsgi_lock_init(void *lock) {
	umtx_init((struct umtx*) lock);
}

void uwsgi_lock(void *lock) {
	umtx_lock(lock, 1);
}

void uwsgi_unlock(void *lock) {
	umtx_unlock(lock, 1);
}

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
	pid_t *pid = (pid_t *) lock + sizeof(OSSpinLock);
	*pid = uwsgi.mypid;
}

void uwsgi_unlock(void *lock) {

	OSSpinLockUnlock((OSSpinLock *) lock);
	pid_t *pid = (pid_t *) lock + sizeof(OSSpinLock);
	*pid = 0;
}

pid_t uwsgi_lock_check(void *lock) {
	if (OSSpinLockTry((OSSpinLock *) lock)) {
		OSSpinLockUnlock((OSSpinLock *) lock);
		return 0;
	}
	pid_t *pid = (pid_t *) lock + sizeof(OSSpinLock);	
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
