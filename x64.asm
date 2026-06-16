;
; @file       x64.asm
;
; @brief      All assembly code.
;
; @author     Satoshi Tanda
;
; @copyright  Copyright (c) 2017-2019, Satoshi Tanda. All rights reserved.
;
.const

KTRAP_FRAME_SIZE            equ     190h
MACHINE_FRAME_SIZE          equ     28h

.code

extern SvHandleVmExit : proc

;
;   @brief      Saves all general purpose registers to the stack.
;
;   @details    This macro does not alter the flag register.
;
PUSHAQ macro
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    -1      ; Dummy for rsp.
        push    rbp
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
        endm

;
;   @brief      Loads all general purpose registers from the stack.
;
;   @details    This macro does not alter the flag register.
;
POPAQ macro
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx    ; Dummy for rsp (this value is destroyed by the next pop).
        pop     rbx
        pop     rdx
        pop     rcx
        pop     rax
        endm

;
;   @brief      Enters the loop that executes the guest and handles #VMEXIT.
;
;   @details    This function switches to the host stack pointer, runs the guest
;               and handles #VMEXIT until SvHandleVmExit returns non-zero value.
;               When SvHandleVmExit returned non-zero value, this function
;               returns execution flow to the next instruction of the
;               instruction triggered #VMEXIT after terminating virtualization.
;
;   @param[in]  HostRsp - A stack pointer for the hypervisor.
;
SvLaunchVm proc frame
        ;
        ; Update the current stack pointer with the host RSP. This protects
        ; values stored on stack for the hypervisor from being overwritten by
        ; the guest due to a use of the same stack memory.
        ;
        mov rsp, rcx    ; Rsp <= HostRsp

SvLV10: ;
        ; Run the loop to executed the guest and handle #VMEXIT. Below is the
        ; current stack leyout.
        ; ----
        ; Rsp          => 0x...fd0 GuestVmcbPa       ; HostStackLayout
        ;                 0x...fd8 HostVmcbPa        ;
        ;                 0x...fe0 Self              ;
        ;                 0x...fe8 SharedVpData      ;
        ;                 0x...ff0 Padding1          ;
        ;                 0x...ff8 Reserved1         ;
        ; ----
        ;
        mov rax, [rsp]  ; RAX <= VpData->HostStackLayout.GuestVmcbPa
        vmload rax      ; load previously saved guest state from VMCB

        ;
        ; Start the guest. The VMRUN instruction resumes execution of the guest
        ; with state described in VMCB (specified by RAX by its physical address)
        ; until #VMEXI is triggered. On #VMEXIT, the VMRUN instruction completes
        ; and resumes the next instruction (ie, vmsave in our case).
        ;
        ; The VMRUN instruction does the following things in this order:
        ; - saves some current state (ie. host state) into the host state-save
        ;   area specified in IA32_MSR_VM_HSAVE_PA
        ; - loads guest state from the VMCB state-save area
        ; - enables interrupts by setting the the global interrupt flag (GIF)
        ; - resumes execution of the guest until #VMEXIT occurs
        ; See "Basic Operation" for more details.
        ;
        ; On #VMEXIT:
        ; - disables interrupts by clearing the the global interrupt flag (GIF)
        ; - saves current guest state into and update VMCB to provide information
        ;   to handle #VMEXIT
        ; - loads the host state previously saved by the VMRUN instruction
        ; See "#VMEXIT" in the volume 2 and "VMRUN" in the volume 3 for more
        ; details.
        ;
        vmrun rax       ; Switch to the guest until #VMEXIT

        ;
        ; #VMEXIT occurred. Now, some of guest state has been saved to VMCB, but
        ; not all of it. Save some of unsaved state with the VMSAVE instruction.
        ;
        ; RAX (and some other state like RSP) has been restored from the host
        ; state-save, so it has the same value as before and not guest's one.
        ;
        vmsave rax      ; Save current guest state to VMCB

        ;
        ; Restore host TR / LDTR / FS / GS / KernelGsBase / STAR-MSRs FIRST,
        ; before ANY C code runs. AMD HSAVE preserves CR3 / GDTR / IDTR / CS /
        ; SS / RIP / RSP / RFLAGS / EFER / RAX on VMEXIT, but NOT the segment
        ; bases or system MSRs - those have to come from the host VMCB via an
        ; explicit VMLOAD. Until we do that, the host still has whatever the
        ; guest left in those fields, which after a guest SWAPGS could be a
        ; user-mode TEB pointer. Any C-level access through GS:[...] (the
        ; compiler emits these for stack cookies, __chkstk probes, and KPCR
        ; self-checks) would then walk a user VA on the private host CR3,
        ; take #PF, and cascade through the private IDT. This is the source
        ; of the #GP at the post-VMEXIT entry that the VMware monitor logged
        ; in the very first crash trace - VMX HVs do not have this hazard
        ; because VMCS_HOST_FS_BASE / GS_BASE / TR_BASE are auto-restored on
        ; every VM-exit. RAX must remain GuestVmcbPa for the rest of the loop;
        ; we restore it after VMLOAD consumes HostVmcbPa.
        ;
        mov     rax, [rsp + 8]  ; rax <= HostVmcbPa  (HostStackLayout offset)
        vmload  rax             ; restore host FS / GS / TR / LDTR / Kernel*
        mov     rax, [rsp]      ; rax <= GuestVmcbPa (restore loop invariant)

        ;
        ; Optionally, allocate the trap frame so that Windbg can display stack
        ; trace of the guest while SvHandleVmExit is being executed. The trap
        ; frame fields necessary for this are initialized in SvHandleVmExit.
        ;
        .pushframe
        sub     rsp, KTRAP_FRAME_SIZE
        .allocstack KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE + 100h

        ;
        ; Also save guest's GPRs since those are not saved anywhere by the
        ; processor on #VMEXIT and will be destroyed by subsequent host code.
        ;
        PUSHAQ          ; Stack pointer decreased 8 * 16

        ;
        ; Set parameters for SvHandleVmExit. Below is the current stack layout.
        ; ----
        ; Rsp                             => 0x...dc0 R15               ; GUEST_REGISTERS
        ;                                    0x...dc8 R14               ;
        ;                                             ...               ;
        ;                                    0x...e38 RAX               ;
        ; Rsp + 8 * 16                    => 0x...e40 TrapFrame         ; HostStackLayout
        ;                                             ...               ;
        ; Rsp + 8 * 16 + KTRAP_FRAME_SIZE => 0x...fd0 GuestVmcbPa       ;
        ;                                    0x...fd8 HostVmcbPa        ;
        ; Rsp + 8 * 18 + KTRAP_FRAME_SIZE => 0x...fe0 Self              ;
        ;                                    0x...fe8 SharedVpData      ;
        ;                                    0x...ff0 Padding1          ;
        ;                                    0x...ff8 Reserved1         ;
        ; ----
        ;
        mov rdx, rsp                                ; Rdx <= GuestRegisters
        mov rcx, [rsp + 8 * 18 + KTRAP_FRAME_SIZE]  ; Rcx <= VpData

        ;
        ; Allocate stack for homing space (0x20) and volatile XMM registers
        ; (0x60). Save those registers because subsequent host code may destroy
        ; any of those registers. XMM6-15 are not saved because those should be
        ; preserved (those are non volatile registers). Finally, indicates the
        ; end of the function prolog as stack pointer changes are all done. This
        ; is for Windbg to reconstruct stack trace.
        ;
        sub rsp, 80h
        movaps xmmword ptr [rsp + 20h], xmm0
        movaps xmmword ptr [rsp + 30h], xmm1
        movaps xmmword ptr [rsp + 40h], xmm2
        movaps xmmword ptr [rsp + 50h], xmm3
        movaps xmmword ptr [rsp + 60h], xmm4
        movaps xmmword ptr [rsp + 70h], xmm5
        .endprolog

        ;
        ; Handle #VMEXIT.
        ;
        call SvHandleVmExit

        ;
        ; Restore XMM registers and roll back stack pointer.
        ;
        movaps xmm5, xmmword ptr [rsp + 70h]
        movaps xmm4, xmmword ptr [rsp + 60h]
        movaps xmm3, xmmword ptr [rsp + 50h]
        movaps xmm2, xmmword ptr [rsp + 40h]
        movaps xmm1, xmmword ptr [rsp + 30h]
        movaps xmm0, xmmword ptr [rsp + 20h]
        add rsp, 80h

        ;
        ; Test a return value of SvHandleVmExit (RAX), then POPAQ to restore the
        ; original guest's GPRs.
        ;
        test al, al
        POPAQ

        ;
        ; If non zero value is returned from SvHandleVmExit, this function exits
        ; the loop. Otherwise, continue the loop and resume the guest.
        ;
        jnz SvLV20                  ; if (ExitVm != 0) jmp SvLV20
        add rsp, KTRAP_FRAME_SIZE   ; else, restore RSP and
        jmp SvLV10                  ; jmp SvLV10

SvLV20: ;
        ; Virtualization has been terminated. Restore an original (guest's,
        ; although it is no longer the "guest") stack pointer and return to the
        ; next instruction of CPUID triggered this #VMEXIT.
        ;
        ; Here is contents of certain registers:
        ;   RBX     = An address to return
        ;   RCX     = An original stack pointer to restore
        ;   EDX:EAX = An address of per processor data for this processor
        ;
        mov rsp, rcx

        ;
        ; Update RCX with the magic value indicating that the SimpleSvm
        ; hypervisor has been unloaded.
        ;
        mov ecx, 'SSVM'

        ;
        ; Return to the next instruction of CPUID triggered this #VMEXIT. The
        ; registry values to be returned are:
        ;   EBX     = Undefined
        ;   ECX     = 'SSVM'
        ;   EDX:EAX = An address of per processor data for this processor
        ;
        jmp rbx
SvLaunchVm endp

;
;   @brief      Read the Task Register (TR) selector.
;
;   @return     UINT16 - The TR selector value.
;
SvReadTr proc
        str ax
        ret
SvReadTr endp

;
;   @brief      Issues a signed VMMCALL presence probe.
;
;   @details    Loads the R10/R11/R12 magic signature expected by
;               SvHandleVmmcall, places the probe command code in RAX, and
;               executes VMMCALL. When virtualized, the hypervisor intercepts
;               VMMCALL and writes the ack value into RAX. On bare metal,
;               VMMCALL raises #UD (the C caller wraps this in __try/__except).
;
;               UINT64 SvProbeVmmcall(UINT64 probeCmd);   ; probeCmd in RCX
;
SvProbeVmmcall proc frame
        push    r12                             ; save callee-saved R12 (Windows x64 ABI)
        .pushreg r12
        .endprolog
        mov     rax, rcx                        ; RAX = probe command
        mov     r10, 48564653h                  ; magic sig (R10) "SFVH"
        mov     r11, 564d43414c4ch              ; magic sig (R11) "VMCALL"
        mov     r12, 4e4f485950455256h          ; magic sig (R12)
        vmmcall
        pop     r12                             ; restore callee-saved R12
        ret                                     ; RAX = ack (or untouched if #UD path)
SvProbeVmmcall endp

;
;   @brief      Host #DF (double-fault) handler with dedicated IST stack.
;
;   @details    Runs on IST1 stack to avoid recursive #DF. Captures the
;               fault context and bugchecks with diagnostic information.
;
extern SvHostDoubleFault : proc
SvHostDoubleFaultStub proc
        ;
        ; CPU pushed:  [SS] [RSP] [RFLAGS] [CS] [RIP] [ErrorCode=0]
        ; IST1 stack is active, so we're safe to push more state.
        ;
        PUSHAQ                          ; save GPRs
        mov rcx, rsp                    ; pass stack pointer as first arg
        sub rsp, 20h                    ; home space
        call SvHostDoubleFault          ; never returns
        int 3                           ; shouldn't reach here
SvHostDoubleFaultStub endp

;
;   @brief      Host #PF handler for diagnostics.
;
extern SvHostPageFault : proc
SvHostPageFaultStub proc
        PUSHAQ
        mov rcx, rsp
        sub rsp, 20h
        call SvHostPageFault
        add rsp, 20h
        POPAQ
        add rsp, 8                      ; skip error code
        iretq
SvHostPageFaultStub endp

;
;   @brief      Host #GP handler for diagnostics.
;
extern SvHostGeneralProtection : proc
SvHostGeneralProtectionStub proc
        PUSHAQ
        mov rcx, rsp
        sub rsp, 20h
        call SvHostGeneralProtection
        add rsp, 20h
        POPAQ
        add rsp, 8                      ; skip error code
        iretq
SvHostGeneralProtectionStub endp

;
;   @brief      Default host IDT handler for all unhandled vectors (0-255).
;
;   @details    Vectors without a specific handler use this stub. It does NOT
;               call DbgPrint (that raises INT 0x2D which would re-enter here
;               and triple-fault). Passes the saved-GPR stack pointer to
;               SvHostDefault which bugchecks with the faulting RIP as a
;               parameter.
;
;   Many vectors push no error code; we push a dummy zero to keep the frame
;   layout uniform.  The C handler reads frame[0]=errorCode, frame[1]=RIP.
;
extern SvHostDefault : proc
SvHostDefaultStub proc
        sub rsp, 8                      ; synthetic error code (zero)
        PUSHAQ
        mov rcx, rsp
        sub rsp, 20h
        call SvHostDefault              ; never returns
        int 3
SvHostDefaultStub endp

;
;   @brief      Load Task Register — wraps the LTR instruction which has no
;               MSVC compiler intrinsic.  Selector is passed in CX.
;
SvLoadTr proc
        ltr cx
        ret
SvLoadTr endp

;
;   @brief      Load the GDTR — wrapper around LGDT for callers that need to
;               reload the original GDT after SVM teardown.
;               RCX = pointer to a DESCRIPTOR_TABLE_REGISTER (limit:base).
;
SvLoadGdt proc
        lgdt fword ptr [rcx]
        ret
SvLoadGdt endp

        end