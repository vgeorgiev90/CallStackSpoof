#pragma once
#include <windows.h>
#include <stdio.h>
#include <structs.h>
#include <time.h>



// max size of the gadget array
#define GADGETS_MAX 16


#define DEBUG






// Conditional debug
#ifdef DEBUG
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#define WDEBUG_PRINT(...) wprintf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...) do {} while (0)
#define WDEBUG_PRINT(...) do {} while (0)
#endif