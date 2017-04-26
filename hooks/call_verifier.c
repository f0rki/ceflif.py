#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "shadow_mem.h"

void call_verifier(void* target)
{
  uint64_t addr = (uint64_t)target;
  uint64_t saddr = (addr >> SHADOW_SCALE) | SHADOW_ADDR;

  char val = *(char*)saddr;
  uint64_t X = (addr & 0xff) >> 3;
  if ((addr & 0xf) != 0) {
    X |= 1;
  }

  uint64_t is_func = (val >> X) & 1;
  if (is_func == 1) {
    // jump from here
    asm("jmp %0\n" : "=r"(target));
  } else {
    fputs("nope...", stderr);
    abort();
  }
}
