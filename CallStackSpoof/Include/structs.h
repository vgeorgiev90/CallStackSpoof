#pragma once
#include <windows.h>
#include <cstdint>



// Struct to hold the exception information for a module
typedef struct _EXCEPT_INFO {
	PBYTE hModule;
	ULONG_PTR pExceptionDirectory;
	DWORD dwRuntimeFuncCount;
} EXCEPT_INFO, *PEXCEPT_INFO;

// Struct to hold information about all found gadgets, address and stack frame size
typedef struct _GADGET_INFO {
    PVOID address;
    DWORD stackFrameSize;
} GADGET_INFO, *PGADGET_INFO;

// Struct to hold information about targets for which spoofed frames will be created
typedef struct _SPOOF_TARGET {
    ULONG_PTR funcAddress;
    DWORD offsetFromStart;
    HMODULE hModule;
} SPOOF_TARGET, *PSPOOF_TARGET;

// Struct to hold all the required information to invoke an API with spoofed call stack
typedef struct _API_CALL_INFO {
    PVOID retVal;
    ULONG_PTR pFuncAddr;
    DWORD apiFuncArgsCount;

    SIZE_T spoofFramesCount;
    PSPOOF_TARGET* spoofFramesTargetsArray;
} API_CALL_INFO, *PAPI_CALL_INFO;


#pragma pack(push, 1)
typedef struct _STACK_FRAME_INFO {
    uint64_t returnRip;
    uint64_t stackFrameSize;
    uint64_t hasSaveNonvol;
    uint64_t maxSaveNonvolOffset;
    uint64_t useFPreg;
} STACK_FRAME_INFO, * PSTACK_FRAME_INFO;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
    //union {
    //    OPTIONAL ULONG ExceptionHandler;
    //    OPTIONAL ULONG FunctionEntry;
    //};
    //OPTIONAL ULONG ExceptionData[];

} UNWIND_INFO, * PUNWIND_INFO;


typedef struct _STACK_INFO
{
    PSTACK_FRAME_INFO pFrames;
    uint64_t FramesCount;
    uint64_t totalFrameSizes;

    uint64_t pGadgetAddr;
    uint64_t dwGadgetSize;

    uint64_t pTargetFunc;
    uint64_t pRbx;
    uint64_t dwNumOfArgs;
    uint64_t pFuncArgs;
    // preserve non volatile registers
    uint64_t oRbx;
    uint64_t oRbp;
    uint64_t oRsi;
    uint64_t oRdi;
    uint64_t oR12;
    uint64_t oR13;
    uint64_t oR14;
    uint64_t oR15;
} STACK_INFO, *PSTACK_INFO;
#pragma pack(pop)

typedef enum _UNWIND_OP {
    UWOP_PUSH_NONVOL = 0,  // push a nonvolatile register onto the stack
    UWOP_ALLOC_LARGE = 1,  // allocate large stack space (>= 128 bytes)
    UWOP_ALLOC_SMALL = 2,  // allocate small stack space (<= 128 bytes)
    UWOP_SET_FPREG = 3,  // establish a frame pointer
    UWOP_SAVE_NONVOL = 4,  // save a nonvolatile register at a fixed offset
    UWOP_SAVE_NONVOL_FAR = 5,  // save a nonvolatile register at a large offset
    UWOP_SAVE_XMM128 = 8,  // save an XMM register at a fixed offset
    UWOP_SAVE_XMM128_FAR = 9,  // save an XMM register at a large offset
    UWOP_PUSH_MACHFRAME = 10  // push a machine frame (used for exception handling)
} UNWIND_OP;
