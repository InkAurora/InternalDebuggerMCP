OPTION CASEMAP:NONE

PUBLIC InvokeCallBridge

.code

InvokeCallBridge PROC FRAME
    sub rsp, 38h
    .allocstack 38h
    .endprolog

    mov [rsp+18h], rcx
    mov r11, rcx

    mov rax, [r11+48h]
    mov [rsp+20h], rax
    mov rax, [r11+50h]
    mov [rsp+28h], rax

    mov rcx, [r11+08h]
    mov rdx, [r11+10h]
    mov r8,  [r11+18h]
    mov r9,  [r11+20h]

    movq xmm0, qword ptr [r11+28h]
    movq xmm1, qword ptr [r11+30h]
    movq xmm2, qword ptr [r11+38h]
    movq xmm3, qword ptr [r11+40h]

    mov r10, [r11]
    call r10

    mov r11, [rsp+18h]
    mov [r11+58h], rax
    movq qword ptr [r11+60h], xmm0

    add rsp, 38h
    ret
InvokeCallBridge ENDP

END