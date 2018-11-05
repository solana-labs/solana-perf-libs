#ifndef SIGNING_PUBLIC_H_
#define SIGNING_PUBLIC_H_

#include "sgx_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This function initializes SGX enclave. It loads enclave_file
   to SGX, which internally creates a new public/private keypair.

   If the platform does not support SGX, it creates a public/private
   keypair in untrusted space. An error is returned in this scenario.
   The user can choose to not use the library if SGX encalve is not
   being used for signing.
*/
sgx_status_t init_ed25519(const char* enclave_file,
                          uint32_t keylen,
                          uint8_t* pubkey);

/* This function signs the msg using the internally stored private
   key. The signature is returned in the output "signature" buffer.

   This function must only be called after init_ed25519() function.
*/
sgx_status_t sign_ed25519(uint32_t msg_len,
                          uint8_t* msg,
                          uint32_t sig_len,
                          uint8_t* signature);

#ifdef __cplusplus
}
#endif

#endif