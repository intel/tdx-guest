## Introducing tdx-guest

The tdx-guest provides a Rust implementation of Intel® Trust Domain Extensions (Intel® TDX) Guest APIs, supporting for TDX Guest specific instructions, structures and functions.

## TDCALL Implementation

| Leaf Num | Name in Specification | Description | Is Implemented | Interface Function Name |
|------|--------------|-------------|----------------|-------------------------|
| 0    | TDG.VP.VMCALL | Call a host VM service | ✅ | Please refer [TDVMCALL Implementment](#tdvmcall-implementment) |
| 1    | TDG.VP.INFO | Get TD execution environment information | ✅ | `get_tdinfo` |
| 2    | TDG.MR.RTMR.EXTEND | Extend a TD run-time measurement register | ✅ | `extend_rtmr` |
| 3    | TDG.VP.VEINFO.GET | Get Virtualization Exception Information for the recent #VE exception | ✅ | `get_veinfo` |
| 4    | TDG.MR.REPORT | Creates a cryptographic report of the TD | ✅ | `get_report` |
| 5    | TDG.VP.CPUIDVE.SET | Control delivery of #VE on CPUID instruction execution | ✅ | `set_cpuidve` |
| 6    | TDG.MEM.PAGE.ACCEPT | Accept a pending private page into the TD | ✅ | `accept_page` |
| 7    | TDG.VM.RD | Read a TD-scope metadata field | ✅ | `read_td_metadata` |
| 8    | TDG.VM.WR | Write a TD-scope metadata field | ✅ | `write_td_metadata` |
| 9    | TDG.VP.RD | Read a VCPU-scope metadata field | ❌ | - |
| 10   | TDG.VP.WR | Write a VCPU-scope metadata field | ❌ | - |
| 11   | TDG.SYS.RD | Read a TDX Module global-scope metadata field | ❌ | - |
| 12   | TDG.SYS.RDALL | Read all gust-readable TDX Module global-scope metadata fields | ❌ | - |
| 18   | TDG.SERVTD.RD | Read a target TD metadata field | ❌ | - |
| 20   | TDG.SERVTD.WR | Write a target TD metadata field | ❌ | - |
| 22   | TDG.MR.VERIFYREPORT | Verify a cryptographic report of a TD, generated on the current platform | ✅ | `verify_report` |
| 23   | TDG.MEM.PAGE.ATTR.RD | Read the GPA mapping and attributes of a TD private page | ✅ | `read_page_attr` |
| 24   | TDG.MEM.PAGE.ATTR.WR | Write the attributes of a private page | ✅ | `write_page_attr` |
| 25   | TDG.VP.ENTER | Enter L2 VCPU operation | ❌ | - |
| 26   | TDG.VP.INVEPT | Invalidate cached EPT translations for selected L2 VMs | ❌ | - |
| 27   | TDG.VP.INVVPID | Invalidate cached translations for selected pages in an L2 VM | ❌ | - |

## TDVMCALL Implementation

| Sub-Function Number | Sub-Function Name in Specification | Is Implemented | Interface Function Name           |
|---------------------|------------------------------------|----------------|-----------------------------------|
| 0x10000             | GetTdVmCallInfo                    | ✅             | `get_tdvmcall_info`               |
| 0x10001             | MapGPA                             | ✅             | `map_gpa`                         |
| 0x10002             | GetQuote                           | ✅             | `get_quote`                       |
| 0x10003             | ReportFatalError                   | ❌             | -                                 |
| 0x10004             | SetupEventNotifyInterrupt          | ✅             | `setup_event_notify_interrupt`    |
| 0x10005             | Service                            | ❌             | -                                 |


| Sub-Function Number Bits 15:0 | Sub-Function Name in Specification | Is Implemented | Interface Function Name            |
|-------------------------------|------------------------------------|----------------|------------------------------------|
| 10                            | Instruction.CPUID                  | ✅             | `cpuid`                           |
| 12                            | Instruction.HLT                    | ✅             | `hlt`                             |
| 30                            | Instruction.IO                     | ✅             | `io_read`, `io_write`             |
| 31                            | Instruction.RDMSR                  | ✅             | `rdmsr`                           |
| 32                            | Instruction.WRMSR                  | ✅             | `wrmsr`                           |
| 48                            | #VE.RequestMMIO                    | ✅             | `read_mmio`, `write_mmio`         |
| 54                            | Instruction.WBINVD                 | ✅             | `perform_cache_operation`         |
| 65                            | Instruction.PCONFIG                | ❌             | -                                 |
