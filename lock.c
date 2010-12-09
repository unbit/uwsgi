#include "uwsgi.h"


#ifdef UWSGI_LOCK_USE_MUTEX

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


}

void uwsgi_lock(void *lock) {

	pthread_mutex_lock((pthread_mutex_t *) lock + sizeof(pthread_mutexattr_t));
}

void uwsgi_unlock(void *lock) {

	pthread_mutex_unlock((pthread_mutex_t *) lock + sizeof(pthread_mutexattr_t));
}


#endif


#ifdef UWSGI_LOCK_USE_OSX_SPINLOCK

void uwsgi_lock_init(void *lock) {

	memset(lock, 0, sizeof(OSSpinLock));
}

void uwsgi_lock(void *lock) {

	OSSpinLockLock((OSSpinLock *) lock);
}

void uwsgi_unlock(void *lock) {

	OSSpinLockUnlock((OSSpinLock *) lock);
}


#endif


#ifdef UWSGI_LOCK_USE_FLOCK

void uwsgi_lock_init(void *lock) {}

void uwsgi_lock(void *lock) {
	if (flock((int) *lock, LOCK_EX)) { uwsgi_error("flock()"); }
}

void uwsgi_unlock(void *lock) {
	if (flock((int) *lock, LOCK_UN)) { uwsgi_error("flock()"); }
}

#endif
