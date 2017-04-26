#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "shadow_mem.h"

void shadowmem_init(void* target)
{
  uint64_t addr = (uint64_t)target;
  uint64_t saddr = (addr >> SHADOW_SCALE) | SHADOW_ADDR;

  char val = *(char*)saddr;
  uint64_t X = (addr & 0xff) >> 3;
  if ((addr & 0xf) != 0) {
    X |= 1;
  }

  val |= 1 << X;
  *(char*)saddr = val;
}
