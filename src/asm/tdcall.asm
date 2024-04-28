# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023-2024 Intel Corporation.

.section .text

# Arguments offsets in TdVmcallArgs struct
.equ TDCALL_RAX, 0x0
.equ TDCALL_RCX, 0x8
.equ TDCALL_RDX, 0x10
.equ TDCALL_R8,  0x18
.equ TDCALL_R9,  0x20
.equ TDCALL_R10, 0x28
.equ TDCALL_R11, 0x30
.equ TDCALL_R12, 0x38
.equ TDCALL_R13, 0x40

.global asm_td_call
asm_td_call:
        endbr64
        push rbp
        mov rbp, rsp
        push r15
        push r14
        push r13
        push r12
        push rbx

        # Test if input pointer is valid
        test rdi, rdi
        jz td_call_exit

        # Copy the input operands from memory to registers 
        mov rax, [rdi + TDCALL_RAX]
        mov rcx, [rdi + TDCALL_RCX]
        mov rdx, [rdi + TDCALL_RDX]
        mov r8,  [rdi + TDCALL_R8]
        mov r9,  [rdi + TDCALL_R9]
        mov r10, [rdi + TDCALL_R10]
        mov r11, [rdi + TDCALL_R11]
        mov r12, [rdi + TDCALL_R12]
        mov r13, [rdi + TDCALL_R13]

        # tdcall
        .byte 0x66,0x0f,0x01,0xcc

        # Exit if tdcall reports failure.
        test rax, rax
        jnz td_call_exit

        # Copy the output operands from registers to the struct
        mov [rdi + TDCALL_RAX], rax
        mov [rdi + TDCALL_RCX], rcx
        mov [rdi + TDCALL_RDX], rdx
        mov [rdi + TDCALL_R8],  r8
        mov [rdi + TDCALL_R9],  r9
        mov [rdi + TDCALL_R10], r10
        mov [rdi + TDCALL_R11], r11
        mov [rdi + TDCALL_R12], r12
        mov [rdi + TDCALL_R13], r13

td_call_exit:
        # Pop out saved registers from stack
        pop rbx
        pop r12
        pop r13
        pop r14
        pop r15
        pop rbp
        ret
