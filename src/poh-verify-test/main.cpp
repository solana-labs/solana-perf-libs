#include "cl_common.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <pthread.h>

#define USE_CLOCK_GETTIME
#define ROUND_UP_DIV(x, y) (((x) + (y) - 1) / (y))
#define SHA256_BLOCK_SIZE 32

#include "perftime.h"

bool g_verbose = false;

typedef struct input_poh_ {

    uint8_t* hashes;
    uint64_t* num_hashes_arr;
    size_t num_elems;

} input_poh;

void static inline save_out(uint8_t* hashes,
    size_t num_elems, size_t index_thread) {

    FILE * fp;

    const char *file_name = "test_hashes_output";
    char temp_string[50];
    sprintf(temp_string, "%s_%lu", file_name, index_thread);

    fp = fopen (temp_string, "w");
    if (fp == NULL) {
        fprintf(stderr, "Could not create file %s\n", temp_string);
        exit(-1);
    }

    for (size_t i = 0; i < num_elems; ++i) {
        fprintf(fp, "%hhu ", hashes[i]);
    }
    fclose(fp);
}


input_poh* allocate_input_poh(size_t num_elems) {

    input_poh* input_result = (input_poh*)calloc(1, sizeof(input_poh));
    DIE(input_result == NULL, "Error while allocating an input_poh structure");

    input_result->num_elems = num_elems;

    input_result->hashes = (uint8_t*)calloc(input_result->num_elems, sizeof(uint8_t));
    DIE(input_result->hashes == NULL, "Error while allocating input_result->hashes");

    input_result->num_hashes_arr = (uint64_t*)calloc(input_result->num_elems, sizeof(uint64_t));
    DIE(input_result->num_hashes_arr == NULL, "Error while allocating input_result->num_hashes_arr");

    return input_result;
}

void free_input_poh(input_poh** poh) {
    free((*poh)->hashes);
    (*poh)->hashes = NULL;
    free((*poh)->num_hashes_arr);
    (*poh)->num_hashes_arr = NULL;
    free(*poh);
    (*poh) = NULL;

} 

input_poh* get_input(const char* file_hashes, const char* file_hashes_arr, const char* file_num_elems) {
    
    FILE * fp;
    fp = fopen(file_hashes, "r");

    if (fp == NULL) {
        fprintf(stderr, "Could not open file %s\n", file_hashes);
        exit(-1);
    }

    FILE * fp2;
    fp2 = fopen(file_hashes_arr, "r");
    
    if (fp2 == NULL) {
        fprintf(stderr, "Could not open file %s\n", file_hashes_arr);
        exit(-1);
    }

    FILE * fp3;
    fp3 = fopen(file_num_elems, "r");
    
    if (fp3 == NULL) {
        fprintf(stderr, "Could not open file %s\n", file_num_elems);
        exit(-1);
    }

    size_t num_elems;
    DIE( 0 == fscanf(fp3, "%zu", &num_elems), "Error while reading num_elems from file");
    fprintf(stderr, "num_elems read from file %s is %zu\n", file_num_elems, num_elems);

    input_poh* input_result = allocate_input_poh(num_elems);

    for (size_t i=0; i<input_result->num_elems; ++i) {
        if( 0 == fscanf(fp, "%hhu", &input_result->hashes[i])) {
            fprintf(stderr, "Error while reading hashes from file %s at index %lu \n", file_hashes, i);
            exit(-2);
        }
    }    

    for (size_t i=0; i<input_result->num_elems/SHA256_BLOCK_SIZE; ++i) {  
        if( 0 == fscanf(fp2, "%lu", &input_result->num_hashes_arr[i])) {
            fprintf(stderr, "Error while reading input num_hashes_arr from file %s at index %lu \n", file_hashes_arr, i);
            exit(-2);
        }
    }

    fclose(fp);
    fclose(fp2);
    fclose(fp3);

    return input_result;
}

void generate_input(input_poh* input_result) {
    srand(1); // keep the same seed in cuda and opencl variants 
    for (size_t i = 0 ; i < input_result->num_elems; ++i) {
        input_result->hashes[i] = rand() % 100000;
    }

    for (size_t i = 0 ; i < input_result->num_elems/SHA256_BLOCK_SIZE; ++i) {
        input_result->num_hashes_arr[i] = 20000;
    }
}

extern "C" {
    extern int poh_verify_many(uint8_t*, const uint64_t*, size_t, uint8_t);
    void poh_verify_many_set_verbose(bool);
}

void* work(void *param) {
    input_poh* input_result = (input_poh*)param;
    poh_verify_many(input_result->hashes, input_result->num_hashes_arr, input_result->num_elems/SHA256_BLOCK_SIZE, 0);
    return nullptr;
}

int main(int argc, const char* argv[]) {

    if (argc == 1 || argc == 2) {
        printf("usage 1: %s [-v] [-save_output] generate <nr_elements> <nr_inputs>\n", argv[0]);
        printf("usage 2: %s [-v] [-save_output] <file_num_hashes> <file_num_hashes_arr> <file_num_elems>\n", argv[0]);
        printf("usage: argc is %i \n", argc);
        return 1;
    }

    int arg = 1;
    bool verbose = false;
    bool save_output_file = false;
    if (0 == strcmp(argv[arg], "-v")) {
        verbose = true;
        arg++;
    }
    if (0 == strcmp(argv[arg], "-save_output")) {
        save_output_file = true;
        arg++;
    }

    poh_verify_many_set_verbose(verbose);

    if (0 == strcmp(argv[arg], "generate")) {
        ++arg;
        if ((argc - arg) != 2) {
            printf("usage 1: %s [-v] [-save_output] generate <nr_elements> <nr_inputs>\n", argv[0]);
            printf("usage 2: %s [-v] [-save_output] <file_num_hashes> <file_num_hashes_arr> <file_num_elems>\n", argv[0]);
            printf("usage: argc is %i \n", argc);
            return 1;
        }

        if (0 == strcmp(argv[arg], "0")) {
            printf("nr_elements is 0!\n");
            return 1;
        }

        size_t num_elems = strtoul(argv[arg], nullptr, 10);
        if (num_elems == 0) {
            printf("nr_elements is not a number %s!\n", argv[arg]);
            exit(-1);
        }
        ++arg;

        size_t num_threads = strtoul(argv[arg], nullptr, 10);
        if (num_threads == 0) {
            printf("nr_inputs is not a number %s!\n", argv[arg]);
            exit(-1);
        }

        pthread_t *threads;

        num_elems = ROUND_UP_DIV(num_elems, SHA256_BLOCK_SIZE) * SHA256_BLOCK_SIZE;
        printf("nr_elements rounded up to %lu \n", num_elems);

        threads = (pthread_t*)calloc(num_threads, sizeof(pthread_t));
        if (threads == NULL) {
            fprintf(stderr, "Error while allocating threads\n");
            exit(-1);
        }

        input_poh** vinput_result = (input_poh**)calloc(num_threads, sizeof(input_poh));

        for (size_t i = 0; i < num_threads; ++i) {
            vinput_result[i] = allocate_input_poh(num_elems);
            generate_input(vinput_result[i]);
        }
        LOG("Created and filled input_poh with %lu elements for %lu threads\n", num_elems, num_threads);
        
        perftime_t start, end;
        get_time(&start);

        for (size_t i = 0; i < num_threads; ++i) {
            if (pthread_create (&threads[i], NULL, work, (void*)vinput_result[i]) != 0) {
                fprintf(stderr, "Error while creating threads %lu\n", i);
                exit(-1);
            }
        }

        for (size_t i = 0; i < num_threads; ++i) {
            if (pthread_join (threads[i], NULL) != 0) {
                fprintf(stderr, "Error while creating threads %lu\n", i);
                exit(-1);
            }
        } 

        get_time(&end);

        double diff = get_diff(&start, &end);
        printf("Total time hashing diff: %f microSeconds or %f seconds \n", diff, diff/1000000);


        for (size_t i = 0; i < num_threads; ++i) {
            if (save_output_file) {
                save_out(vinput_result[i]->hashes, vinput_result[i]->num_elems, i);
            }
        }

        for (size_t i = 0; i < num_threads; ++i) {
            free_input_poh(&vinput_result[i]);
        }
        free(vinput_result);

    }
    else {
        if ((argc - arg) != 3) {
            printf("usage 1: %s [-v] [-save_output] generate <nr_elements>\n", argv[0]);
            printf("usage 2: %s [-v] [-save_output] <file_num_hashes> <file_num_hashes_arr> <file_num_elems>\n", argv[0]);
            printf("usage: argc is %i \n", argc);
            return 1;
        }

        input_poh* input_result = get_input(argv[arg], argv[arg+1], argv[arg+2]);
        perftime_t start, end;
        
        get_time(&start);
        work(input_result);
        get_time(&end);
        
        double diff = get_diff(&start, &end);
        printf("Total time hashing diff: %f microSeconds or %f seconds \n", diff, diff/1000000);

        if (save_output_file) {
            save_out(input_result->hashes, input_result->num_elems, 0);
        }
        free_input_poh(&input_result);
    }

    return 0;

}
