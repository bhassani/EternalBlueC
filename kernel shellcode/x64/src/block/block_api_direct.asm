;
; Windows x64 Direct Export API Call
;
; Author: Sean Dillon <sean.dillon@risksense.com> (@zerosum0x0)
; Copyright: (c) 2017 RiskSense, Inc.
; License: Apache 2.0
;
; Based on Stephen Fewer's direct API calls
;
; Arguments: R15 = module pointer
;            rcx, rdx, r8, r9, stack = normal function call params
;            R11D = hash
;
; Clobbers: RAX, RCX, RDX, R8, R9, R11
; Notes: block_api loads from the PEB. This is more direct. Caller must be sure
;        there is an export in this module. Do not reserve shadow space.
;

block_api_direct:

  mov rax, r15            ; make copy of module

  push r9                  ; Save parameters
  push r8
  push rdx
  push rcx

  mov rdx, rax
  mov eax, dword [rdx+60]  ; Get PE header e_lfanew
  add rax, rdx
  mov eax, dword [rax+136] ; Get export tables RVA
  ;test rax, rax                         ; No test if export address table is present
  ;jz _block_api_not_found                         ; Callers job

  add rax, rdx
  push rax                 ; save EAT

  mov ecx, dword [rax+24]  ; NumberOfFunctions
  mov r8d, dword [rax+32]  ; FunctionNames
  add r8, rdx

_block_api_direct_get_next_func:
                              ; When we reach the start of the EAT (we search backwards), we hang or crash
  dec rcx                     ; decrement NumberOfFunctions
  mov esi, dword [r8+rcx*4]   ; Get rva of next module name
  add rsi, rdx                ; Add the modules base address

  call calc_hash

  cmp r9d, r11d                         ; Compare the hashes
  jnz _block_api_direct_get_next_func   ; try the next function


_block_api_direct_finish:

  pop rax                     ; restore EAT
  mov r8d, dword [rax+36]
  add r8, rdx                 ; ordinate table virtual address
  mov cx, [r8+2*rcx]          ; desired functions ordinal
  mov r8d, dword [rax+28]     ; Get the function addresses table rva
  add r8, rdx                 ; Add the modules base address
  mov eax, dword [r8+4*rcx]   ; Get the desired functions RVA
  add rax, rdx                ; Add the modules base address to get the functions actual VA

  pop rcx
  pop rdx
  pop r8
  pop r9
  pop r11                     ; pop ret addr

  sub rsp, 0x20               ; reserve shadow space
  push r11                    ; push ret addr

  jmp rax
