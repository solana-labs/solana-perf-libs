#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

extern "C" {
int poh_verify_many(uint8_t* hashes,
                    const uint64_t* num_hashes_arr,
                    size_t num_elems,
                    uint8_t use_non_default_stream)
{
    fprintf(stderr, "poh_verify_many not implemented.");
    exit(1);
    return 0;
}
}

