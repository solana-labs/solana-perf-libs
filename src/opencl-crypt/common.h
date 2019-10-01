#include <stdio.h>

#ifndef COMMON_CU
#define COMMON_CU

#if __APPLE__
   #include <OpenCL/opencl.h>
#else
   #include <CL/cl.h>
#endif

#define BLOCK_SIZE (4 * 1024)

#endif
