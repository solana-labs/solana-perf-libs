/*
 * This file contains Solana's SGX enclave code for signing data.
 */

#include <stdbool.h>
#include <string.h>

#include "ed25519.h"
#include "signing_t.h"

static bool initialized;
static uint8_t public_key[32], private_key[64];

sgx_status_t init(uint32_t keylen, uint8_t* pubkey) {
  if (keylen < sizeof(public_key)) {
    return SGX_ERROR_INVALID_PARAMETER;
  }

  uint8_t seed[32];
  sgx_status_t status = sgx_read_rand(seed, sizeof(seed));
  if (SGX_SUCCESS != status) {
    return status;
  }

  ed25519_create_keypair(public_key, private_key, seed);
  memcpy(pubkey, public_key, sizeof(public_key));

  initialized = true;

  return SGX_SUCCESS;
}

sgx_status_t sign(uint32_t msg_len,
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
