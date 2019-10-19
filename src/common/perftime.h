#ifndef PERFTIME_H
#define PERFTIME_H

#ifdef _MSC_VER
#include <profileapi.h>
#include <cstdint>

typedef struct {
    LARGE_INTEGER count;
} perftime_t;

static int get_time(perftime_t* t) {
    return (int)QueryPerformanceCounter(&t->count);
}

#define TIME_AS_UINT64(time) ((uint64_t)time->count.LowPart | ((uint64_t)time->count.HighPart << 32))

static double get_us(const perftime_t* time) {
    return (double)TIME_AS_UINT64(time);
}

static double get_diff(const perftime_t* start, const perftime_t* end) {
    return (double)(TIME_AS_UINT64(end) - TIME_AS_UINT64(start));
}

#else
#ifdef USE_RDTSC
static inline uint64_t rdtsc()
{
    unsigned int hi, lo;
    __asm__ volatile("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

typedef struct {
    uint64_t count;
} perftime_t;

#elif defined(USE_CLOCK_GETTIME)
#include <time.h>
typedef struct timespec perftime_t;
#else
#include <sys/time.h>
typedef struct timeval perftime_t;
#endif

static int get_time(perftime_t* t) {
#ifdef USE_RDTSC
    t->count = rdtsc();
    return 0;
#elif defined(USE_CLOCK_GETTIME)
    return clock_gettime(CLOCK_MONOTONIC_RAW, t);
    //return clock_gettime(CLOCK_PROCESS_CPUTIME_ID, t);
#else
    return gettimeofday(t, NULL /* timezone */);
#endif
}

static double get_us(const perftime_t* time) {
#ifdef USE_RDTSC
    return time->count;
#elif defined(USE_CLOCK_GETTIME)
    return ((time->tv_nsec/1000) + (double)time->tv_sec * 1000000);
#else
    return (time->tv_usec + (double)time->tv_sec * 1000000);
#endif
}

static double get_diff(const perftime_t* start, const perftime_t* end) {
    return get_us(end) - get_us(start);
}

#endif
#endif
