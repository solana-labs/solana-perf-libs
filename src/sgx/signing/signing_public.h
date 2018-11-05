#ifndef SIGNING_PUBLIC_H_
#define SIGNING_PUBLIC_H_

#include "sgx_error.h"

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t init_ed25519(const char* enclave_file,
                          uint32_t keylen,
                          uint8_t* pubkey);

sgx_status_t sign_ed25519(uint32_t msg_len,
                          uint8_t* msg,
                          uint32_t sig_len,
                          uint8_t* signature);

#ifdef __cplusplus
}
#endif

#endif