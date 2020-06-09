;
; Windows x64 Kernel Get NTOSKRNL.EXE Base via KPCR->IdtBase[0]->ISR
;
; Author: Sean Dillon <sean.dillon@risksense.com> (@zerosum0x0)
; Copyright: (c) 2017 RiskSense, Inc.
; License: Apache 2.0
;
; Arguments: None
; Clobbers: RAX, RSI
; Return: RAX will be set to the base address of ntoskrnl.exe MZ header
;

find_nt_idt:
  mov rax, qword [gs:0x38]    ; get IdtBase of KPCR
  mov rax, qword [rax+0x4]    ; get ISR address
  shr rax, 0xc                ; strip to page size
  shl rax, 0xc

_find_nt_idt_walk_page:
  sub rax, 0x1000             ; walk along page size
  mov rsi, qword [rax]
  cmp si, 0x5a4d              ; 'MZ' header
  jne _find_nt_idt_walk_page
