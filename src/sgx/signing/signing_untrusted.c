/*
 * This file contains Solana's SGX enclave code for signing data.
 */

#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "ed25519.h"
#include "sgx_urts.h"
#include "signing_u.h"
#include "signing_public.h"

static bool initialized = false;
static bool use_enclave = false;
static sgx_enclave_id_t eid;
static uint8_t public_key[32], private_key[64];

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

sgx_status_t init_ed25519(const char* enclave_file,
                          uint32_t keylen,
                          uint8_t* pubkey) {
  int updated = 0;
  sgx_launch_token_t token = {0};
  sgx_status_t status =
      sgx_create_enclave(enclave_file, 1, &token, &updated, &eid, NULL);

  if (SGX_SUCCESS != status) {
    sgx_status_t untrusted_status = init_untrusted(keylen, pubkey);
    if (SGX_SUCCESS != untrusted_status) {
      return untrusted_status;
    }
  } else {
    use_enclave = true;
  }

  return status;
}

sgx_status_t sign_ed25519(uint32_t msg_len,
                          uint8_t* msg,
                          uint32_t sig_len,
                          uint8_t* signature) {
  if (use_enclave) {
    sgx_status_t retval = SGX_SUCCESS;
    sgx_status_t status = sign(eid, &retval, msg_len, msg, sig_len, signature);
    if (SGX_SUCCESS != status) {
      return status;
    }

    if (SGX_SUCCESS != retval) {
      return retval;
    }
  }
  return sign_untrusted(msg_len, msg, sig_len, signature);
}