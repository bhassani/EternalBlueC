;
; Windows x64 Find DLL in PEB
;
; Author: Sean Dillon <sean.dillon@risksense.com> (@zerosum0x0)
; Copyright: (c) 2017 RiskSense, Inc.
; License: Apache 2.0
;
; Based on Stephen Fewer's direct API calls
;
; Arguments: R11D = hash
;
; Clobbers: RAX, r11, rdx, rsi, r9
; Return: RAX = the module or NULL
;

block_find_dll:
  xor edx, edx
  mov rdx, [gs:rdx + 96]
  mov rdx, [rdx + 24]         ; PEB->Ldr
  mov rdx, [rdx + 32]         ; InMemoryOrder list

_block_find_dll_next_mod:
  mov rdx, [rdx]
  mov rsi, [rdx + 80]         ; unicode string
  movzx rcx, word [rdx + 74]  ; rcx = len

  xor r9d, r9d

_block_find_dll_loop_mod_name:
  xor eax, eax
  lodsb
  cmp al, 'a'
  jl _block_find_dll_not_lowercase
  sub al, 0x20

_block_find_dll_not_lowercase:
  ror r9d, 13
  add r9d, eax
  loop _block_find_dll_loop_mod_name

  cmp r9d, r11d
  jnz _block_find_dll_next_mod

  mov rax, [rdx + 32]
  ret
