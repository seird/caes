#include <stdint.h>

#include "params.h"


#define IV_increment(IV) {\
    for (int i = BLOCKSIZE-1; i >= 0; --i) { \
        if (IV[i] == 0xff) { \
            IV[i] = 0; \
            continue; \
        } \
        IV[i] += 1; \
        break; \
    } \
}
