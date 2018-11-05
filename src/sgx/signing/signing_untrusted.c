/*
 * This file contains Solana's SGX enclave code for signing data.
 */

#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "ed25519.h"
#include "sgx_urts.h"
#include "signing_public.h"
#include "signing_u.h"

static bool initialized = false;
static bool use_enclave = false;
static sgx_enclave_id_t eid;
static uint8_t public_key[32], private_key[64];

/* This function generates a random buffer of size length */
static void untrusted_read_rand(unsigned char* val, size_t length) {
  for (int i = 0; i < length; i++) {
    val[i] = 0;
    int num = rand();
    while (num != 0) {
      val[i] ^= num & 0xff;
      num >>= 8;
    }
  }
}

/* This function creates a private/public keypair in the untrusted space.
   It also initializes the untrusted random number generator using current
   time. It's used only if the platform does not support SGX.
*/
static sgx_status_t init_untrusted(uint32_t keylen, uint8_t* pubkey) {
  if (keylen < sizeof(public_key)) {
    return SGX_ERROR_INVALID_PARAMETER;
  }

  time_t t = time(NULL);
  struct tm* lt = (struct tm*)localtime((const time_t*)&t);
  unsigned int rand_seed =
      lt->tm_sec | lt->tm_min << 8 | lt->tm_hour << 16 | lt->tm_mday << 24;
  srand(rand_seed);

  uint8_t seed[32];
  untrusted_read_rand(seed, sizeof(seed));
  ed25519_create_keypair(public_key, private_key, seed);
  memcpy(pubkey, public_key, sizeof(public_key));

  initialized = true;

  return SGX_SUCCESS;
}

/* This function signs the msg using the private key stored in
   untrusted space. This function is used only if the platform
   does not support SGX.
*/
static sgx_status_t sign_untrusted(uint32_t msg_len,
                                   uint8_t* msg,
                                   uint32_t sig_len,
                                   uint8_t* signature) {
  if (!initialized) {
    return SGX_ERROR_INVALID_STATE;
  }

  if (sig_len < 64) {
    return SGX_ERROR_INVALID_PARAMETER;
  }

  ed25519_sign(signature, msg, msg_len, public_key, private_key);

  return SGX_SUCCESS;
}

/* This function initializes SGX enclave. It loads enclave_file
   to SGX, which internally creates a new public/private keypair.

   If the platform does not support SGX, it creates a public/private
   keypair in untrusted space. An error is returned in this scenario.
   The user can choose to not use the library if SGX encalve is not
   being used for signing.
*/
sgx_status_t init_ed25519(const char* enclave_file,
                          uint32_t keylen,
                          uint8_t* pubkey) {
  int updated = 0;
  sgx_launch_token_t token = {0};

  // Try to load the SGX enclave
  sgx_status_t status =
      sgx_create_enclave(enclave_file, 1, &token, &updated, &eid, NULL);

  if (SGX_SUCCESS != status) {
    // Initialize in untrusted space, if enclave could not be created
    sgx_status_t untrusted_status = init_untrusted(keylen, pubkey);
    if (SGX_SUCCESS != untrusted_status) {
      return untrusted_status;
    }
  } else {
    use_enclave = true;
  }

  return status;
}

/* This function signs the msg using the internally stored private
   key. The signature is returned in the output "signature" buffer.

   This function must only be called after init_ed25519() function.
*/
sgx_status_t sign_ed25519(uint32_t msg_len,
                          uint8_t* msg,
                          uint32_t sig_len,
                          uint8_t* signature) {
  if (use_enclave) {
    // Use enclave, if it was successfully loaded
    sgx_status_t retval = SGX_SUCCESS;
    sgx_status_t status = sign(eid, &retval, msg_len, msg, sig_len, signature);
    if (SGX_SUCCESS != status) {
      return status;
    }

    if (SGX_SUCCESS != retval) {
      return retval;
    }

    return status;
  }
  return sign_untrusted(msg_len, msg, sig_len, signature);
}