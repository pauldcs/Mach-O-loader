#ifndef __PTRAUTH_H__
#define __PTRAUTH_H__

#include <stdint.h>

uint64_t pacia(uint64_t p, uint64_t context);
uint64_t autia(uint64_t p, uint64_t context);

#endif /* __PTRAUTH_H__ */
