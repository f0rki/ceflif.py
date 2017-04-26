#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "shadow_mem.h"

void setup_shadowmem()
{
  void* shadowMem = mmap((void*)SHADOW_ADDR, SHADOW_SIZE, PROT_READ | PROT_WRITE,
      MAP_ANON | MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE, -1, 0);
  if (shadowMem != (void*)SHADOW_ADDR) {
    fputs("Failed to setup shadow memory. :( ", stderr);
    abort();
  }
}
