;;---------------------------------;;
;;       Struct definitions        ;;
;;---------------------------------;;

;; Stack frame information for every frame that will be spoofed 
STACK_FRAME_INFO STRUCT
  returnRip					DQ ?
  stackFrameSize			DQ ?
  hasSaveNonvol				DQ ?
  maxSaveNonvolOffset		DQ ?
  useFPreg					DQ ?
STACK_FRAME_INFO ENDS

;; struct to hold all the required info for spoofing and invoking the target API
STACK_INFO STRUCT
  ;; information about frames to be spoofed
  pFrames					DQ ?
  FramesCount				DQ ?
  totalFrameSizes			DQ ?

  ;; Jump RBX gadget that will be used to restore execution flow
  pGadgetAddr				DQ ?
  dwGadgetSize				DQ ?

  ;; Target API that will be called
  pTargetFunc				DQ ?
  pRbx						DQ ?
  dwNumOfArgs				DQ ?
  pFuncArgs					DQ ?

  ; non volatile registers that must be preserved
  oRbx						DQ ?
  oRbp						DQ ?
  oRsi						DQ ?
  oRdi						DQ ?
  oR12						DQ ?
  oR13						DQ ?
  oR14						DQ ?
  oR15						DQ ?
STACK_INFO ENDS


PUBLIC Spoof

.code
Spoof PROC

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;  As a start save the non-volatile registers   ;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
save_regs:
  mov [rcx].STACK_INFO.oRbx, rbx							; Save RBX
  mov [rcx].STACK_INFO.oRbp, rbp							; Save RBP
  mov [rcx].STACK_INFO.oRsi, rsi							; Save RSI
  mov [rcx].STACK_INFO.oRdi, rdi							; Save RDI
  mov [rcx].STACK_INFO.oR12, r12							; Save R12
  mov [rcx].STACK_INFO.oR13, r13							; Save R13
  mov [rcx].STACK_INFO.oR14, r14							; Save R14
  mov [rcx].STACK_INFO.oR15, r15							; Save R15


  pop r15													; Save the return address of the function that called Spoof
  mov r13, rcx												; Move STACK_INFO from rcx to r13

  ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; 
  ;;;;;  Creating the syntetic frames   ;;;;;
  ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

  push 0													; Terminate the stack unwinding

  ;; First prepare the fake frames
  mov rsi, [r13].STACK_INFO.pFrames							; RSI = pointer to the frames array
  mov rcx, [r13].STACK_INFO.FramesCount						; count of frames that will be spoofed

  test rcx, rcx												;
  jz frames_done											;
  
frames_loop:
  mov r10, [rsi].STACK_FRAME_INFO.stackFrameSize			; size of the syntetic frame
  sub rsp, r10												; reserve space
  mov r10, [rsi].STACK_FRAME_INFO.returnRip					; get the return address
  mov [rsp], r10											; write the return address

  add rsi, SIZEOF STACK_FRAME_INFO							; advance to next frame info
  dec rcx													; Decrement the counter
  jnz frames_loop											; Continue until all frames are processed


frames_done:
  ;; At this point the frame for the jump gadget needs to be created
  mov r10, [r13].STACK_INFO.dwGadgetSize					; size of the stack frame for the gadget
  sub rsp, r10												; reserve
  mov r10, [r13].STACK_INFO.pGadgetAddr						; get the return address
  mov [rsp], r10											; write the return


  ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  ;;;;;  Configure the arguments of the API to be called ;;;;;
  ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  
  ;; First 4 arguments are placed in: RCX, RDX, R8 and R9
  mov r10, [r13].STACK_INFO.pFuncArgs						; move the pointer to the args to r10
  mov rcx, [r10]											; first arg
  mov rdx, [r10 + 8]										; second arg
  mov r8, [r10 + 16]										; third arg
  mov r9, [r10 + 24]										; fourth arg

  mov rbp, [r13].STACK_INFO.dwNumOfArgs						; Total argument count goes to RBP
  sub rbp, 4												; Substract the register arguments count - 4
  jle setup_rbx												; if there are only 4 args in total, continue

  xor rax, rax												; i = 0

;; If there are additional arguments they are placed on the stack
loop_start:
  lea r11, [rax + 4]										; arg index = 4 + i
  mov r11, [r10 + r11*8]									; args[4 + i]
  mov [rsp + 28h + rax*8], r11								; stack slot
  inc rax													; i++
  cmp rax, rbp												; check if all args are processed
  jl loop_start


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;; Configure the restoring of the execution flow and invoke the API ;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
setup_rbx:
  mov r10, restore_stack									; stack restore procedure
  mov [r13].STACK_INFO.pRbx, r10							;
  lea rbx, [r13].STACK_INFO.pRbx							;

  ;; Move the address of the target API to R10 and jump to it
  mov r10, [r13].STACK_INFO.pTargetFunc						;
  jmp r10													;


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; 
;;;;; Restore the stack to the original state before spoof func was called ;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
restore_stack:

  mov r10, [r13].STACK_INFO.totalFrameSizes						;
  add rsp, r10													; reverse the syntetic frames allocation

  ; restore non-volatile registers
  mov rbx, [r13].STACK_INFO.oRbx								; restore rbx
  mov rbp, [r13].STACK_INFO.oRbp								; restore rbp
  mov rsi, [r13].STACK_INFO.oRsi								; restore rsi
  mov rdi, [r13].STACK_INFO.oRdi								; restore rdi
  mov r12, [r13].STACK_INFO.oR12								; restore r12
  mov r14, [r13].STACK_INFO.oR14								; restore r14

  mov rcx, r15													; move the return address to RCX
  mov r15, [r13].STACK_INFO.oR15								; restore r15
  mov r13, [r13].STACK_INFO.oR13								; restore r13

  jmp rcx														; Jump to the original return address to restore execution flow

Spoof ENDP
end