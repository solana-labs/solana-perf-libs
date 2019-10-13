#include <iostream>
#include <limits.h>
#include <stdlib.h>
#include <ctime>
#include <sstream>
#include <string>
#include <fstream>

#include "gpu_common.h"

bool cl_is_init = false;

cl_context context;
cl_command_queue cmd_queue;
cl_program program;

//////////////////////////////////////

#define KERNELS_AES_CBC	1

#ifdef	KERNELS_AES_CBC
	#include "kernels_aes_cbc.h"
#else
	const char *kernels_aes_cbc_src = R""""(
	)"""";
#endif

cl_kernel CRYPTO_cbc128_encrypt_kernel;
cl_kernel AES_cbc_encrypt_kernel;

//////////////////////////////////////

#define KERNELS_CHACHA_CBC	1

#if	KERNELS_CHACHA_CBC
	#include "kernels_chacha_cbc.h"
#else
	const char *kernels_chacha_cbc_src = R""""(
	)"""";
#endif

cl_kernel chacha20_ctr_encrypt_kernel;
cl_kernel chacha20_cbc128_encrypt_kernel;
cl_kernel chacha20_cbc128_encrypt_sample_kernel;
cl_kernel chacha_ctr_encrypt_kernel;

//////////////////////////////////////

#define KERNELS_PRECOMP_DATA	1

#ifdef	KERNELS_PRECOMP_DATA
	#include "kernels_precomp_data.h"
	#include "kernels_verify.h"
#else
	const char *kernels_precomp_data_src = R""""(
	)"""";
	const char *kernels_verify_src = R""""(
	)"""";
#endif

cl_kernel init_sha256_state_kernel;
cl_kernel end_sha256_state_kernel;
cl_kernel ed25519_verify_kernel;
cl_kernel poh_verify_kernel;

/**
 * User/host function, check OpenCL compilation return code
 */
int CL_COMPILE_ERR(int cl_ret,
                  cl_program program,
                  cl_device_id device)
{
	if(cl_ret != CL_SUCCESS){
		cout << endl << cl_get_string_err(cl_ret) << endl;
		cl_get_compiler_err_log(program, device);
		return 1;
	}
	return 0;
}

/**
* Read kernel from file
*/
void read_kernel(string file_name, string &str_kernel)
{
    ifstream in_file(file_name.c_str());
    in_file.open(file_name.c_str());
    DIE( !in_file.is_open(), "ERR OpenCL kernel file. Same directory as binary ?" );

    stringstream str_stream;
    str_stream << in_file.rdbuf();

    str_kernel = str_stream.str();
}

/**
* OpenCL return error message, used by CL_ERR and CL_COMPILE_ERR
*/
const char* cl_get_string_err(cl_int err) {
switch (err) {
    case CL_SUCCESS:                     	return  "Success!";
    case CL_DEVICE_NOT_FOUND:               return  "Device not found.";
    case CL_DEVICE_NOT_AVAILABLE:           return  "Device not available";
    case CL_COMPILER_NOT_AVAILABLE:         return  "Compiler not available";
    case CL_MEM_OBJECT_ALLOCATION_FAILURE:  return  "Memory object alloc fail";
    case CL_OUT_OF_RESOURCES:               return  "Out of resources";
    case CL_OUT_OF_HOST_MEMORY:             return  "Out of host memory";
    case CL_PROFILING_INFO_NOT_AVAILABLE:   return  "Profiling information N/A";
    case CL_MEM_COPY_OVERLAP:               return  "Memory copy overlap";
    case CL_IMAGE_FORMAT_MISMATCH:          return  "Image format mismatch";
    case CL_IMAGE_FORMAT_NOT_SUPPORTED:     return  "Image format no support";
    case CL_BUILD_PROGRAM_FAILURE:          return  "Program build failure";
    case CL_MAP_FAILURE:                    return  "Map failure";
    case CL_INVALID_VALUE:                  return  "Invalid value";
    case CL_INVALID_DEVICE_TYPE:            return  "Invalid device type";
    case CL_INVALID_PLATFORM:               return  "Invalid platform";
    case CL_INVALID_DEVICE:                 return  "Invalid device";
    case CL_INVALID_CONTEXT:                return  "Invalid context";
    case CL_INVALID_QUEUE_PROPERTIES:       return  "Invalid queue properties";
    case CL_INVALID_COMMAND_QUEUE:          return  "Invalid command queue";
    case CL_INVALID_HOST_PTR:               return  "Invalid host pointer";
    case CL_INVALID_MEM_OBJECT:             return  "Invalid memory object";
    case CL_INVALID_IMAGE_FORMAT_DESCRIPTOR:return  "Invalid image format desc";
    case CL_INVALID_IMAGE_SIZE:             return  "Invalid image size";
    case CL_INVALID_SAMPLER:                return  "Invalid sampler";
    case CL_INVALID_BINARY:                 return  "Invalid binary";
    case CL_INVALID_BUILD_OPTIONS:          return  "Invalid build options";
    case CL_INVALID_PROGRAM:                return  "Invalid program";
    case CL_INVALID_PROGRAM_EXECUTABLE:     return  "Invalid program exec";
    case CL_INVALID_KERNEL_NAME:            return  "Invalid kernel name";
    case CL_INVALID_KERNEL_DEFINITION:      return  "Invalid kernel definition";
    case CL_INVALID_KERNEL:                 return  "Invalid kernel";
    case CL_INVALID_ARG_INDEX:              return  "Invalid argument index";
    case CL_INVALID_ARG_VALUE:              return  "Invalid argument value";
    case CL_INVALID_ARG_SIZE:               return  "Invalid argument size";
    case CL_INVALID_KERNEL_ARGS:            return  "Invalid kernel arguments";
    case CL_INVALID_WORK_DIMENSION:         return  "Invalid work dimension";
    case CL_INVALID_WORK_GROUP_SIZE:        return  "Invalid work group size";
    case CL_INVALID_WORK_ITEM_SIZE:         return  "Invalid work item size";
    case CL_INVALID_GLOBAL_OFFSET:          return  "Invalid global offset";
    case CL_INVALID_EVENT_WAIT_LIST:        return  "Invalid event wait list";
    case CL_INVALID_EVENT:                  return  "Invalid event";
    case CL_INVALID_OPERATION:              return  "Invalid operation";
    case CL_INVALID_GL_OBJECT:              return  "Invalid OpenGL object";
    case CL_INVALID_BUFFER_SIZE:            return  "Invalid buffer size";
    case CL_INVALID_MIP_LEVEL:              return  "Invalid mip-map level";
    default:                                return  "Unknown";
  }
}

/**
 * Check compiler return code, used by CL_COMPILE_ERR
 */
void cl_get_compiler_err_log(cl_program program, cl_device_id device)
{
    char* build_log;
    size_t log_size;

    /* first call to know the proper size */
    clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG,
                          0, NULL, &log_size);
    build_log = new char[ log_size + 1 ];

    /* second call to get the log */
    clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG,
                          log_size, build_log, NULL);
    build_log[ log_size ] = '\0';
    cout << endl << build_log << endl;
}


/**
* Retrieve GPU device
*/
bool cl_check_init(void) {

    if(cl_is_init == true) {
        return true;
    }

    int ret;

    string kernel_src;

    cl_device_id device;
    cl_platform_id platform;
    cl_uint platform_num = 0;
    cl_platform_id* platform_list = NULL;

    cl_uint device_num = 0;
    cl_device_id* device_list = NULL;

    size_t attr_size = 0;
    char* attr_data = NULL;

    /* get num of available OpenCL platforms */
    CL_ERR( clGetPlatformIDs(0, NULL, &platform_num));
    platform_list = new cl_platform_id[platform_num];
    DIE(platform_list == NULL, "alloc platform_list");

    /* get all available OpenCL platforms */
    CL_ERR( clGetPlatformIDs(platform_num, platform_list, NULL));
    cout << "Platforms found: " << platform_num << endl;

    /* list all platforms and VENDOR/VERSION properties */
    for(int platf=0; platf<platform_num; platf++)
    {
        /* get attribute CL_PLATFORM_VENDOR */
        CL_ERR( clGetPlatformInfo(platform_list[platf],
                CL_PLATFORM_VENDOR, 0, NULL, &attr_size));
        attr_data = new char[attr_size];
        DIE(attr_data == NULL, "alloc attr_data");

        /* get data CL_PLATFORM_VENDOR */
        CL_ERR( clGetPlatformInfo(platform_list[platf],
                CL_PLATFORM_VENDOR, attr_size, attr_data, NULL));
        cout << "Platform " << platf << " " << attr_data << " ";
        delete[] attr_data;

        /* get attribute size CL_PLATFORM_VERSION */
        CL_ERR( clGetPlatformInfo(platform_list[platf],
                CL_PLATFORM_VERSION, 0, NULL, &attr_size));
        attr_data = new char[attr_size];
        DIE(attr_data == NULL, "alloc attr_data");

        /* get data size CL_PLATFORM_VERSION */
        CL_ERR( clGetPlatformInfo(platform_list[platf],
                CL_PLATFORM_VERSION, attr_size, attr_data, NULL));
        cout << attr_data << endl;
        delete[] attr_data;

        /* get num of available OpenCL devices type ALL on the selected platform */
        if(clGetDeviceIDs(platform_list[platf], 
            CL_DEVICE_TYPE_GPU, 0, NULL, &device_num) != CL_SUCCESS) {
            device_num = 0;
            continue;
        }

        device_list = new cl_device_id[device_num];
        DIE(device_list == NULL, "alloc devices");

        /* get all available OpenCL devices type ALL on the selected platform */
        CL_ERR( clGetDeviceIDs(platform_list[platf], CL_DEVICE_TYPE_GPU,
            device_num, device_list, NULL));
        cout << "\tDevices found " << device_num  << endl;

        /* list all devices and TYPE/VERSION properties */
        for(int dev=0; dev<device_num; dev++)
        {
            /* get attribute size */
            CL_ERR( clGetDeviceInfo(device_list[dev], CL_DEVICE_NAME,
                0, NULL, &attr_size));
            attr_data = new char[attr_size];
            DIE(attr_data == NULL, "alloc attr_data");

            /* get attribute CL_DEVICE_NAME */
            CL_ERR( clGetDeviceInfo(device_list[dev], CL_DEVICE_NAME,
                attr_size, attr_data, NULL));
            cout << "\tDevice " << dev << " " << attr_data << " ";

            /* select device based on cli arguments */
            string tmpAttrData = attr_data;
            
            // TODO adjust this to select on certain criteria
            // always select last device of type GPU
            platform = platform_list[platf];
            device = device_list[dev];

            delete[] attr_data;
            cout << endl;
        }
    }

    // clean
    delete[] platform_list;
    delete[] device_list;

    /* create a context for the device */
    context = clCreateContext(0, 1, &device, NULL, NULL, &ret);
    CL_ERR( ret );

    /* create a command queue for the device in the context */
    cmd_queue = clCreateCommandQueue(context, device, 0, &ret);
    CL_ERR( ret );

	/************************************************
	* OpenCL kernels aes_cbc_enc/dec
	*************************************************/
	
	const char* kernel_src_cstr = NULL;
	
#ifdef KERNELS_AES_CBC
	cout << "Compiling aes-cbc kernels" << endl;

    /* retrieve kernel source */
    kernel_src = kernels_aes_cbc_src;
	
	kernel_src_cstr = kernel_src.c_str();

    /* create kernel program from source */
    program = clCreateProgramWithSource(context, 1,
        &kernel_src_cstr, NULL, &ret);
    CL_ERR( ret );

    /* compile the program for the given set of devices */
    ret = clBuildProgram(program, 1, &device, "", NULL, NULL);
    CL_COMPILE_ERR( ret, program, device );

    /* create kernel associated to compiled source kernel */
	CRYPTO_cbc128_encrypt_kernel = clCreateKernel(program, "CRYPTO_cbc128_encrypt_kernel", &ret);
    CL_ERR( ret );
	
	AES_cbc_encrypt_kernel = clCreateKernel(program, "AES_cbc_encrypt_kernel", &ret);
    CL_ERR( ret );
#endif
	
	/************************************************
	* OpenCL kernels chacha20_cbc128
	*************************************************/
	
#ifdef KERNELS_CHACHA_CBC
	cout << "Compiling chacha_cbc kernels" << endl;

	/* retrieve kernel source */
	kernel_src = kernels_chacha_cbc_src;
	
	kernel_src_cstr = kernel_src.c_str();

    /* create kernel program from source */
    program = clCreateProgramWithSource(context, 1,
        &kernel_src_cstr, NULL, &ret);
    CL_ERR( ret );

    /* compile the program for the given set of devices */
    ret = clBuildProgram(program, 1, &device, "", NULL, NULL);
    CL_COMPILE_ERR( ret, program, device );
	
	chacha20_ctr_encrypt_kernel = clCreateKernel(program, "chacha20_ctr_encrypt_kernel", &ret);
    CL_ERR( ret );
	
	chacha20_cbc128_encrypt_kernel = clCreateKernel(program, "chacha20_cbc128_encrypt_kernel", &ret);
    CL_ERR( ret );

    chacha20_cbc128_encrypt_sample_kernel = clCreateKernel(program, "chacha20_cbc128_encrypt_sample_kernel", &ret);
    CL_ERR( ret );

    chacha_ctr_encrypt_kernel = clCreateKernel(program, "chacha_ctr_encrypt_kernel", &ret);
    CL_ERR( ret );
	
	init_sha256_state_kernel = clCreateKernel(program, "init_sha256_state_kernel", &ret);
    CL_ERR( ret );

    end_sha256_state_kernel = clCreateKernel(program, "end_sha256_state_kernel", &ret);
    CL_ERR( ret );
#endif
	
	/************************************************
	* OpenCL kernels verify
	*************************************************/
	
#ifdef KERNELS_PRECOMP_DATA
	cout << "Compiling verify kernels" << endl;
	
	/* retrieve kernel source */
	kernel_src = kernels_precomp_data_src;
	kernel_src += kernels_verify_src;
	
	kernel_src_cstr = kernel_src.c_str();

    /* create kernel program from source */
    program = clCreateProgramWithSource(context, 1,
        &kernel_src_cstr, NULL, &ret);
    CL_ERR( ret );

    /* compile the program for the given set of devices */
    ret = clBuildProgram(program, 1, &device, "", NULL, NULL);
    CL_COMPILE_ERR( ret, program, device );
	
	ed25519_verify_kernel = clCreateKernel(program, "ed25519_verify_kernel", &ret);
    CL_ERR( ret );
	
	poh_verify_kernel = clCreateKernel(program, "poh_verify_kernel", &ret);
    CL_ERR( ret );
#endif

    // set init to done
    cl_is_init = true;

    return cl_is_init;
}