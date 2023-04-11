#pragma once

#include <stdint.h>
static __always_inline int checkpl(__u8 *pl, void *data_end, __u8 match[], __u16 len)
{
  if (pl + len + 1 > (__u8 *)data_end) {
     return 0;
  }

  for (__u16 i = 0; i < len; i++) {
    // Technically you shouldn't need this check due to the above, but knowing the BPF verifier, you probably do.
    if (pl + i + 1 > (__u8 *)data_end) {
      break;
    }

    if (*(pl + i) != match[i]) {
      goto fail;
    }
  }

  return 1;

  fail:;
  return 0;
}