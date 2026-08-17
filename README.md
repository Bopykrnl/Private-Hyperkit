# F-Hyperkit

Experimental AMD SVM hypervisor project for Windows.

This repository was previously private and has been published in its current state. Some parts are unfinished, untested, or only included as examples built to bypass EAC and BE.

## Current Status

- Core hypervisor functionality is generally working.
- The **PML4 injection IOCTL has not been properly tested**.
- The **page-swap implementation does not fully work** and should currently be treated mostly as an example.
- The current page-swap approach will **not work correctly on Windows 11**, even if the existing implementation is cleaned up.
- Windows does not tolerate the current injection method being used in hot-path code reliably.
- The intercept used by the page-swap implementation can interfere with normal execution and break unrelated behavior.
- Expect bugs, crashes, and incomplete functionality.

## Hypervisor Features

- AMD SVM virtualization
- Per-processor VMCB and host-state management
- VMEXIT interception and dispatch
- Nested Page Tables / NPT
- Nested page-fault handling
- CPUID interception
- Pre-virtualization CPUID snapshotting
- CPUID results served from cached tables rather than issuing live CPUID calls in the VMEXIT hot path
- Consistent guest-visible CPUID state
- CPUID timing compensation / calibrated bare-metal CPUID cost
- MSR interception and filtering
- Control-register interception
- CR0 protection
  - prevents the guest from clearing required paging and protection bits
  - preserves PE, NE, WP and PG
- CR4 protection
  - preserves required processor state that was enabled when the hypervisor initialized
  - protects features such as SMEP, SMAP, MCE and OSXSAVE when active
- CR3 interception and handling
- Private host CR3
- Separate host PML4
- Kernel-half PML4 cloning
- User-half PML4 removal from the host address space
- Host address-space isolation from the guest
- Recursive/self-reference PML4 rebasing
- Protection against the guest replacing the hypervisor's top-level host page table through CR3 changes
- Shared lower-level kernel paging structures so the host remains synchronized with live Windows mappings
- Earlier experimental deep-copy page-table implementation
  - PDPT
  - PD
  - PT
- Private per-CPU host GDT
- Private host IDT
- Per-CPU TSS
- Dedicated IST stack for host double-fault handling
- Host exception/fault handling
- VMEXIT-safe diagnostic/debug paths
- Guest register/state preservation across VMEXITs
- SVM feature detection
- ASID/TLB capability detection
- TLB invalidation support
- Multi-core virtualization support
- Hypervisor initialization and teardown support
- Kernel debugging support

The private host paging work is intended to prevent guest-side changes to the top-level paging context from directly replacing the hypervisor's own host address space. The current implementation uses a private PML4 while sharing the live lower-level kernel tables so Windows paging changes remain visible to host-mode code.

The hypervisor also snapshots CPUID state before virtualization and services intercepted CPUID requests from that stored view rather than issuing a new hardware CPUID from the VMEXIT path.

CR0 and CR4 interception preserve required control-register state and prevent the guest from clearing protected processor features that were active when the hypervisor initialized.

## Experimental Kernel Features

- Kernel virtual-memory read helpers
- Kernel virtual-memory write helpers
- PTE manipulation
- PTE hooking experiments
- PML4 injection IOCTL
- PML4 manipulation
- Page-swap experiments
- Process/module walking helpers
- PEB walking

## PML4 Injection

The repository includes a **PML4 injection IOCTL**.

This functionality has not been sufficiently tested and should be considered experimental.

Do not assume it is stable simply because it builds or appears to work during limited testing.

## Page Swap

The page-swap code is currently incomplete and does not fully work.

It is included primarily as an example of the approach being tested rather than as a finished implementation.

The main problems with the current design are related to where and how the injection/interception occurs.

In particular:

- injecting from hot-path code causes problems on Windows
- the intercept can break normal behavior
- the current design is not suitable for Windows 11
- fixing individual bugs in the existing example will not necessarily make the overall approach Windows 11 compatible

The page-swap code should therefore be treated as experimental reference code.

## Credits

The hypervisor is based on **SimpleSvm** by Satoshi Tanda.

This repository contains additional modifications and experimental functionality built on top of that work.

Preserve the original copyright notices included in the source.
