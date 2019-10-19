#ifndef THREAD_H
#define THREAD_H

#ifdef _MSC_VER

#include <Windows.h>
#include <synchapi.h>

#define pthread_t   HANDLE
typedef struct {
} pthread_attr_t;

static int pthread_create(pthread_t* thread, const pthread_attr_t* attr, LPTHREAD_START_ROUTINE start_routine, void* arg) {
    *thread = CreateThread(NULL, 0 /* default stack*/, start_routine, arg, 0, 0);
    return (thread == NULL) ? 1 : 0;
}

static int pthread_attr_init(pthread_attr_t* attr) {
    return 0;
}

static int pthread_join(pthread_t thread, void** retval) {
    return WaitForSingleObject(thread, INFINITE);
}

#define pthread_mutex_t        HANDLE
#define PTHREAD_MUTEX_INITIALIZER      NULL

static int pthread_mutex_init(pthread_mutex_t* mutex, int abc) {
    *mutex = CreateMutex(NULL, FALSE, NULL);
    return (*mutex == NULL) ? 1 : 0;
}

static int pthread_mutex_unlock(pthread_mutex_t* mutex) {
    return ReleaseMutex(mutex) == 0;
}

static int emulate_pthread_mutex_lock(volatile pthread_mutex_t* mx)
{
    if (*mx == NULL) /* static initializer? */
    {
        HANDLE p = CreateMutex(NULL, FALSE, NULL);
        if (InterlockedCompareExchangePointer((PVOID*)mx, (PVOID)p, NULL) != NULL)
            CloseHandle(p);
    }
    return WaitForSingleObject(*mx, INFINITE) == WAIT_FAILED;
}

static int pthread_mutex_lock(pthread_mutex_t* mutex) {
    return emulate_pthread_mutex_lock(mutex);
}

#else
#include <pthread.h>
#endif

#endif
