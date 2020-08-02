#include "cl_common.h"

#include <string.h>
#include <stdio.h>
#include "ed25519.h"
#include <inttypes.h>
#include <assert.h>
#include <vector>
#include <pthread.h>
#include "gpu_common.h"
#include "gpu_ctx.h"
#include "seed.cu"
#include "keypair.cu"

#define USE_CLOCK_GETTIME
#include "perftime.h"

#define PACKET_SIZE 512

extern void ed25519_free_gpu_mem();

bool g_verbose = false;

typedef struct {
    size_t size;
    uint64_t num_retransmits;
    uint16_t addr[8];
    uint16_t port;
    bool v6;
} streamer_Meta;

typedef struct {
    uint8_t data[PACKET_SIZE];
    streamer_Meta meta;
} streamer_Packet;

void print_dwords(unsigned char* ptr, int size) {
    for (int j = 0; j < (size)/(int)sizeof(uint32_t); j++) {
        LOG("%x ", ((uint32_t*)ptr)[j]);
    }
}

typedef struct {
    uint8_t signature[SIG_SIZE];
    uint8_t public_key[PUB_KEY_SIZE];
    uint8_t private_key[PRIV_KEY_SIZE];
    uint32_t message_len;
    uint8_t message[8];
} packet_t;

typedef struct {
    gpu_Elems* elems_h;
    uint32_t num_elems;
    uint32_t total_packets;
    uint32_t total_signatures;
    uint32_t* message_lens;
    uint32_t* public_key_offsets;
    uint32_t* private_key_offsets;
    uint32_t* signature_offsets;
    uint32_t* message_start_offsets;
    uint8_t* out_h;
    int num_iterations;
    uint8_t use_non_default_stream;
} verify_cpu_ctx_t;

static void* verify_proc(void* ctx) {
    verify_cpu_ctx_t* vctx = (verify_cpu_ctx_t*)ctx;
    LOG("Start iterations\n");
    for (int i = 0; i < vctx->num_iterations; i++) {
        ed25519_verify_many(&vctx->elems_h[0],
                            vctx->num_elems,
                            sizeof(streamer_Packet),
                            vctx->total_packets,
                            vctx->total_signatures,
                            vctx->message_lens,
                            vctx->public_key_offsets,
                            vctx->signature_offsets,
                            vctx->message_start_offsets,
                            vctx->out_h,
                            vctx->use_non_default_stream);
    }
    LOG("Done iterations\n");
    return NULL;
}

template<typename T> static void ed25519_alloc(T** ptr, size_t num) {
    *ptr = (T*)calloc(sizeof(T), num);
}

static void ed25519_free(void* ptr) {
    free(ptr);
}

int main(int argc, const char* argv[]) {
    int arg;
    bool verbose = false;
    for (arg = 1; arg < argc; arg++) {
        if (0 == strcmp(argv[arg], "-v")) {
            verbose = true;
        } else {
            break;
        }
    }

    if ((argc - arg) != 6) {
        printf("usage: %s [-v] <num_signatures> <num_elems> <num_sigs_per_packet> <num_threads> <num_iterations> <use_non_default_stream>\n", argv[0]);
        return 1;
    }

    ed25519_set_verbose(verbose);
	
	DIE(cl_check_init(CL_DEVICE_TYPE_GPU) == false, "OpenCL could not be init");

    int num_signatures_per_elem = strtol(argv[arg++], NULL, 10);
    if (num_signatures_per_elem <= 0) {
        printf("num_signatures_per_elem should be > 0! %d\n", num_signatures_per_elem);
        return 1;
    }

    int num_elems = strtol(argv[arg++], NULL, 10);
    if (num_elems <= 0) {
        printf("num_elems should be > 0! %d\n", num_elems);
        return 1;
    }

    int num_sigs_per_packet = strtol(argv[arg++], NULL, 10);
    if (num_sigs_per_packet <= 0) {
        printf("num_sigs_per_packet should be > 0! %d\n", num_sigs_per_packet);
        return 1;
    }

    int num_threads = strtol(argv[arg++], NULL, 10);
    if (num_threads <= 0) {
        printf("num_threads should be > 0! %d\n", num_threads);
        return 1;
    }

    int num_iterations = strtol(argv[arg++], NULL, 10);
    if (num_iterations <= 0) {
        printf("num_iterations should be > 0! %d\n", num_iterations);
        return 1;
    }

    uint8_t use_non_default_stream = (uint8_t)strtol(argv[arg++], NULL, 10);
    if (use_non_default_stream != 0 && use_non_default_stream != 1) {
        printf("non_default_stream should be 0 or 1! %d\n", use_non_default_stream);
        return 1;
    }

    LOG("streamer size: %zu elems size: %zu\n", sizeof(streamer_Packet), sizeof(gpu_Elems));

    std::vector<verify_cpu_ctx_t> vctx = std::vector<verify_cpu_ctx_t>(num_threads);

    // Host allocate
    unsigned char* seed_h = (unsigned char*)calloc(num_signatures_per_elem * SEED_SIZE, sizeof(uint32_t));
    unsigned char message_h[] = "abcd1234";
    uint32_t message_h_len = strlen((char*)message_h);

    uint32_t total_signatures = num_elems * num_signatures_per_elem;

    uint32_t* message_lens = NULL;
    ed25519_alloc(&message_lens, total_signatures);

    uint32_t* signature_offsets = NULL;
    ed25519_alloc(&signature_offsets, total_signatures);

    uint32_t* public_key_offsets = NULL;
    ed25519_alloc(&public_key_offsets, total_signatures);

    uint32_t* message_start_offsets = NULL;
    ed25519_alloc(&message_start_offsets, total_signatures);

    uint32_t* private_key_offsets = NULL;
    ed25519_alloc(&private_key_offsets, total_signatures);

    for (uint32_t i = 0; i < total_signatures; i++) {
        uint32_t base_offset = i * sizeof(streamer_Packet);
        signature_offsets[i] = base_offset + offsetof(packet_t, signature);
        public_key_offsets[i] = base_offset + offsetof(packet_t, public_key);
        private_key_offsets[i] = base_offset + offsetof(packet_t, private_key);
        message_start_offsets[i] = base_offset + offsetof(packet_t, message);
        message_lens[i] = message_h_len;
    }

    for (int i = 0; i < num_threads; i++) {
        vctx[i].message_lens = message_lens;
        vctx[i].signature_offsets = signature_offsets;
        vctx[i].public_key_offsets = public_key_offsets;
        vctx[i].private_key_offsets = private_key_offsets;
        vctx[i].message_start_offsets = message_start_offsets;
        vctx[i].num_iterations = num_iterations;
        vctx[i].use_non_default_stream = use_non_default_stream;
    }

    streamer_Packet* packets_h = NULL;
    ed25519_alloc(&packets_h, num_signatures_per_elem);
    uint32_t total_packets = 0;

    gpu_Elems* elems_h = NULL;
    ed25519_alloc(&elems_h, num_elems);
    for (int i = 0; i < num_elems; i++) {
        elems_h[i].num = num_signatures_per_elem;
        elems_h[i].elems = (uint8_t*)&packets_h[0];

        total_packets += num_signatures_per_elem;
    }

    LOG("initing messages..\n");
    for (int i = 0; i < num_signatures_per_elem; i++) {
        packet_t* packet = (packet_t*)packets_h[i].data;
        memcpy(packet->message, message_h, message_h_len);
    }

    int out_size = total_signatures * sizeof(uint8_t);
    for (int i = 0; i < num_threads; i++) {
        vctx[i].num_elems = num_elems;
        ed25519_alloc(&vctx[i].out_h, out_size);
        vctx[i].elems_h = &elems_h[0];
        vctx[i].total_signatures = total_signatures;
        vctx[i].total_packets = total_packets;
    }

    LOG("creating %d keypairs..\n", num_signatures_per_elem);
    int num_keypairs_to_create = std::min(100, num_signatures_per_elem);
    uint8_t* public_keys = (uint8_t*)calloc(num_keypairs_to_create, PUB_KEY_SIZE);
    uint8_t* private_keys = (uint8_t*)calloc(num_keypairs_to_create, PRIV_KEY_SIZE);
    for (int i = 0; i < num_keypairs_to_create; i++) {
        int ret = ed25519_create_seed(seed_h);
        if (ret != 0) {
            fprintf(stderr, "Invalid seed!");
            exit(1);
        }

        ed25519_create_keypair(&public_keys[PUB_KEY_SIZE * i], &private_keys[PRIV_KEY_SIZE * i], seed_h);
    }

    for (int i = 0; i < num_signatures_per_elem; i++) {
        packet_t* packet = (packet_t*)packets_h[i].data;
        int j = rand() % num_keypairs_to_create;
        memcpy(packet->public_key, &public_keys[j * PUB_KEY_SIZE], PUB_KEY_SIZE);
        memcpy(packet->private_key, &private_keys[j * PRIV_KEY_SIZE], PRIV_KEY_SIZE);
    }

    free(public_keys);
    free(private_keys);

    uint8_t* signatures_h = (uint8_t*)calloc(SIG_SIZE, total_signatures);

    perftime_t start, end;
    get_time(&start);

    ed25519_sign_many(&vctx[0].elems_h[0],
                      vctx[0].num_elems,
                      sizeof(streamer_Packet),
                      vctx[0].total_packets,
                      vctx[0].total_signatures,
                      vctx[0].message_lens,
                      vctx[0].public_key_offsets,
                      vctx[0].private_key_offsets,
                      vctx[0].message_start_offsets,
                      signatures_h,
                      1);
    get_time(&end);

    double diff = get_diff(&start, &end);
    printf("time diff: %f total: %d signs/sec: %f\n",
           diff,
           vctx[0].total_signatures,
           (double)vctx[0].total_signatures / (diff / 1e6));

    for (int i = 0; i < num_signatures_per_elem; i++) {
        packet_t* packet_h = (packet_t*)packets_h[i].data;
        memcpy(packet_h->signature, &signatures_h[i * SIG_SIZE], SIG_SIZE);
    }
    free(signatures_h);

    int num_sigs_to_check = std::min(100, num_signatures_per_elem);
    LOG("checking %d signatures\n", num_sigs_to_check);
    for (int i = 0; i < num_sigs_to_check; i++) {
        int j = rand() % num_signatures_per_elem;
        packet_t* packet = (packet_t*)packets_h[j].data;

        uint8_t signature[SIG_SIZE];
        ed25519_sign(signature, message_h, message_h_len, packet->public_key, packet->private_key);
        if (0 != memcmp(packet->signature, signature, SIG_SIZE)) {
            fprintf(stderr, "Invalid signature!\n");
            exit(1);
        }

        int ret = ed25519_verify(packet->signature, message_h, message_h_len, packet->public_key);
        if (ret != 1) {
            fprintf(stderr, "Invalid signature!\n");
            exit(1);
        }
    }

    std::vector<pthread_t> threads = std::vector<pthread_t>(num_threads);
    pthread_attr_t attr;
    int ret = pthread_attr_init(&attr);
    if (ret != 0) {
        LOG("ERROR: pthread_attr_init: %d\n", ret);
        return 1;
    }

    get_time(&start);
    for (int i = 0; i < num_threads; i++) {
        ret = pthread_create(&threads[i],
                             &attr,
                             verify_proc,
                             &vctx[i]);
        if (ret != 0) {
            LOG("ERROR: pthread_create: %d\n", ret);
            return 1;
        }
    }

    void* res = NULL;
    for (int i = 0; i < num_threads; i++) {
        ret = pthread_join(threads[i], &res);
        if (ret != 0) {
            LOG("ERROR: pthread_join: %d\n", ret);
            return 1;
        }
    }
    get_time(&end);

    int total = (num_threads * total_signatures * num_iterations);
    diff = get_diff(&start, &end);
    printf("time diff: %f total: %d verifies/sec: %f\n",
           diff,
           total,
           (double)total / (diff / 1e6));

    for (int thread = 0; thread < num_threads; thread++) {
        LOG("ret:\n");
        bool verify_failed = false;
        for (int i = 0; i < out_size / (int)sizeof(uint8_t); i++) {
            if (vctx[thread].out_h[i] != 1) {
                verify_failed = true;
            }
        }
        LOG("\n");
        fflush(stdout);
        assert(verify_failed == false);
    }

    ed25519_free(elems_h);
    ed25519_free(packets_h);
    ed25519_free(message_lens);
    ed25519_free(signature_offsets);
    ed25519_free(public_key_offsets);
    ed25519_free(private_key_offsets);
    ed25519_free(message_start_offsets);
    for (int thread = 0; thread < num_threads; thread++) {
        ed25519_free(vctx[thread].out_h);
    }
    free(seed_h);
    ed25519_free_gpu_mem();
    return 0;
}
