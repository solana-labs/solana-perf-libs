#include <assert.h>
#include <stdio.h>
#include <string>

using namespace std;

#ifndef GPU_COMMON_H
#define GPU_COMMON_H

extern bool g_verbose;

#define LOG(...) if (g_verbose) { printf(__VA_ARGS__); }

#define ROUND_UP_DIV(x, y) (((x) + (y) - 1) / (y))

#ifndef UINT64_C
#define UINT64_C uint64_t
#endif

/************************************
* OpenCL compile path
*************************************/

#if __APPLE__
   #include <OpenCL/opencl.h>
#else
   #include <CL/cl.h>
#endif

// runs at the start of any OpenCL entry point crypto function
bool cl_check_init(cl_uint sel_device_type);
bool cl_check_init(void);

// do only 1 init, kernel compilation etc
extern bool cl_is_init;

extern cl_context context;
extern cl_command_queue cmd_queue;
extern cl_program program;

extern cl_kernel CRYPTO_cbc128_encrypt_kernel;
extern cl_kernel AES_cbc_encrypt_kernel;

extern cl_kernel chacha20_ctr_encrypt_kernel;
extern cl_kernel chacha20_cbc128_encrypt_kernel;
extern cl_kernel chacha20_cbc128_encrypt_sample_kernel;
extern cl_kernel chacha_ctr_encrypt_kernel;

extern cl_kernel init_sha256_state_kernel;
extern cl_kernel end_sha256_state_kernel;
extern cl_kernel ed25519_verify_kernel;
extern cl_kernel poh_verify_kernel;

// override any CUDA function qualifiers
#define __host__
#define __device__
#define __global__

#include <iostream>

using namespace std;

// OpenCL utilities
#define CL_ERR(cl_ret) if(cl_ret != CL_SUCCESS){ cout << endl << cl_get_string_err(cl_ret) << " file " << __FILE__ << "@" << __LINE__ << endl; }

int CL_COMPILE_ERR(int cl_ret,
                  cl_program program,
                  cl_device_id device);

const char* cl_get_string_err(cl_int err);
void cl_get_compiler_err_log(cl_program program,
                             cl_device_id device);

void read_kernel(string file_name, string &str_kernel);

#define DIE(assertion, call_description)                    \
do {                                                        \
    if (assertion) {                                        \
            fprintf(stderr, "(%d): ",                       \
                            __LINE__);                      \
            perror(call_description);                       \
            exit(EXIT_FAILURE);                             \
    }                                                       \
} while(0);

#endif