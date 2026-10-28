---
title: 'ARTEX 전체 취약점 실행 비교: Claude Haiku 5.5 vs DeepSeek V4.1 Flash (192.168.6.167
  모두뱅크)'
date: 2026-10-28 00:00:00 +0900
categories:
- Pentest
tags:
- pentest
- web
author: mmamm4
---

# ARTEX 전체 취약점 실행 비교: Claude Haiku 5.5 vs DeepSeek V4.1 Flash (192.168.6.167 모두뱅크)

> **Note:** 실습용 가상 대상
> 이 글의 "모두뱅크(modubank)"는 침투 테스트 실습을 위해 직접 구축한 **가상 대상 애플리케이션**입니다. 실재하는 금융기관이나 서비스와는 아무 관련이 없습니다. 모든 작업은 격리된 로컬 랩 환경(사설 IP `192.168.6.167`)에서만 수행했으며, 외부 시스템을 대상으로 하지 않았습니다.

같은 대상(`192.168.6.167`, 모두뱅크 웹 애플리케이션)에 같은 작업 목표("발생할 수 있는 모든 취약점 찾기")로 ARTEX를 돌리되, LLM만 Claude Haiku 5.5(exp9)와 DeepSeek V4.1 Flash(exp10)로 바꾼 두 실행을 나란히 둡니다. 개별 결과는 2026-10-27-artex-claude-haiku-modubank-full-audit와 2026-10-28-artex-deepseek4.1-flash-modubank-full-audit에 있습니다. 발견 사항은 각 실행의 ARTEX 최종 보고서 기준이고(두 실행 모두 요청을 수동으로 재현하지는 않았습니다), 시간·호출·토큰 수치는 kali_mcp로 확인한 ARTEX 트랜스크립트(`exp9-*`, `exp10-*`)에서 집계한 값입니다.

> **Warning:** 통제된 실험이 아님
> 두 실행은 LLM이 주된 차이지만 worker 수(다수 교체 vs 55개), 탐색·종료 범위, 프롬프트 캐시 적용 여부가 함께 달랐습니다. 무엇보다 **같은 서버를 초기화 없이 차례로** 대상으로 삼았고(Haiku exp9가 먼저, DeepSeek exp10이 나중), 앞 실행이 남긴 흔적(업로드 JSP·배포 WAR·변경된 비밀번호·이체 내역)이 뒤 실행에 그대로 남아 있었습니다. 실제로 Haiku 실행 기록에도 "이전 세션이 올린 `shell.jsp`가 남아 있었다"는 서술이 있습니다. 따라서 아래 차이를 모델 능력 차이로 바로 읽기 어렵고, 누적된 서버 상태와 탐색 범위 차이가 섞인 두 번의 실행 기록으로 보아 주시기 바랍니다.

## 실행 지표

| 항목 | Claude Haiku 5.5 (exp9) | DeepSeek V4.1 Flash (exp10) |
|---|---|---|
| 모델 슬러그 | `anthropic/claude-haiku-5.5` | `deepseek/deepseek-v4.1-flash` |
| 트랜스크립트 시간 범위(UTC) | 08:19:45 ~ 08:44:15 | 10-27 23:57:15 ~ 10-28 02:56:53 |
| 걸린 시간 | 약 24분 | 약 2시간 59분 |
| 에이전트 구성 | planner 1 + worker 다수(교체형, i96~i201 범위) | planner 1 + worker 55 |
| LLM 호출 | 430회 | 3,788회 |
| Bash 실행 | 260회 | 3,584회 |
| 입력 토큰 | 약 1,250만 | 약 1억 6,240만 |
| 프롬프트 캐시 | 미적용(read·write 0) | read 약 95%(1억 5,421만) |
| 출력 토큰 | 약 30만 | 약 390만 |
| `report_finding` 호출 | 21회 | 54회 |
| 최종 보고 건수(중복 포함) | 18건 | 53건 |
| 심각도 분포 | C 4 / H 9 / M 3 / L 2 | C 19 / H 21 / M 9 / L 4 |
| 외부 API 비용(추정) | 약 1.40달러 | 약 3.43달러 |

비용은 OpenRouter 목록가(Haiku 입력 0.10·출력 0.50달러, DeepSeek 입력 0.14·캐시 read 0.0042·출력 0.42달러, 모두 100만 토큰당)를 토큰 수에 곱한 추정치이고, 실제 차감액은 OpenRouter Activity 화면에서 확인해야 합니다. DeepSeek은 입력이 Haiku의 약 13배였지만 95%가 캐시 read로 처리돼, 호출·토큰 규모 차이에 비하면 비용 격차(약 2.5배)는 작게 유지됐습니다. 캐시가 없었다면 DeepSeek 입력 비용만 약 22.7달러(출력 포함 총액 약 24.4달러)였을 것으로 계산됩니다.

## 공통으로 보고한 취약점

두 실행이 함께 올린 항목은 다음과 같습니다. 모두뱅크의 핵심 결함으로 보고된 묶음은 두 모델이 겹쳐서 짚었습니다.

- `/bank/connectivity/check` host 파라미터 OS 명령 주입(tomcat uid 990)
- 예측 가능한 순차 `MODU_SID` 쿠키로 인증 우회·세션 사칭
- 로그인 폼 `username` SQL 인젝션(인증 우회)
- `/opt/modubank/scripts/log-cleanup.sh` world-writable + root cron
- 상태 변경 요청 CSRF 토큰 미검증
- 이체 출금계좌 소유권 미검증·음수 금액
- `/admin` 평문 비밀번호 노출 + 일반 사용자 접근(역할 인가 부재)
- `/files/download` 경로 순회 임의 파일 읽기
- 게시판 저장형 XSS
- 로그인 후 JSESSIONID 미갱신(세션 고정)
- `/bank/fx/lookup` SSRF
- 대시보드 DOM XSS
- Spring Boot Actuator 외부 노출
- AJP(8009) 커넥터 노출
- 보안 응답 헤더 미설정

## DeepSeek 실행에만 있던 항목

DeepSeek 실행은 공통 묶음 위에 공격 표면을 더 넓게 보고했습니다. Haiku 보고서에 없던 유형은 다음과 같습니다.

- 파일 업로드 무제한 확장자 → JSP 웹셸, 업로드 파일명 경로 조작(`../../ROOT/`) 배치 RCE
- Tomcat Manager 약한 자격증명(`tomcat-users.xml`에 설정된 admin:tomcat) + WAR 배포 RCE
- 비밀번호 재설정 체인(`/verify` 토큰 미검증·`/request` 무인증·6자리 예측 토큰 브루트포스)
- Thymeleaf SSTI(템플릿 업로드 + `doc` 지정)
- SSH 계정 `bankop`이 DB 비밀번호 재사용 → 원격 로그인 성립, sudo `backup.sh` world-writable privesc
- nginx→Tomcat CL.TE HTTP 요청 스머글링
- 대량이체 XML의 XXE(파일 읽기·내부 SSRF)
- 이체 동시성 제어 부재(TOCTOU/lost update), `check-account` 블라인드 SQLi
- `/mypage/api-key` 평문 노출, 오픈뱅킹 REST API BOLA/IDOR
- Host 헤더 주입, 회원가입 입력 검증 미비, HTTP/0.9 형식 HEAD 요청에 응답 본문 반환, MariaDB FILE 권한, MyBatis SQL 로그→journald

Haiku 보고서에만 있고 DeepSeek 보고서에 없는 유형은 뚜렷하지 않았습니다. Haiku의 18건이 대체로 DeepSeek 53건의 부분집합에 들어갑니다(항목별 대응표 없이 유형 수준에서 비교한 결과입니다). 다만 한 보고서에 없다는 것이 그 모델의 탐지 실패를 뜻하지는 않습니다.

## 검증 수준과 보고 성격의 차이

- **권한 상승 검증**: Haiku는 root cron 경로를 "잠재 경로"로만 남기고 실제 상승은 검증하지 않았으며, 평문 비밀번호로 시도한 SSH 재사용도 실패로 기록했습니다. DeepSeek은 cron 스크립트를 덮어써 다음 주기에 root로 `/etc/shadow`를 읽는 PoC를 제시했고, `bankop` SSH 재사용도 성립으로 보고했습니다. 단, DeepSeek이 뒤에 실행돼 앞 실행이 바꿔 둔 상태(비밀번호·업로드물)를 물려받았을 가능성이 있어, 이 차이를 순수 모델 역량으로 보기는 어렵습니다.
- **중복과 심각도**: DeepSeek 보고서는 같은 결함이 여러 worker에서 중복으로 올라와 53건을 부풀렸고(로그인 SQLi·Actuator·오픈 리다이렉트 등), 같은 결함에 다른 심각도가 붙기도 했습니다. Haiku 18건은 상대적으로 중복이 적었습니다.
- **자격증명 일관성**: DeepSeek 보고서는 관리자 비밀번호·사용자 수가 항목마다 엇갈렸고, 실행 중 서버 상태가 바뀐 영향으로 보입니다(시간순 대조는 하지 않았습니다). Haiku 보고서에서는 이런 편차가 두드러지지 않았으며, 실행 시간이 짧았던 점이 영향을 줬을 수 있습니다.
- **구조**: Haiku 보고서에는 유형별 대응 방안 절이 있었고, DeepSeek 보고서는 ARTEX 원문 중심이라 대응 방안이 별도로 정리돼 있지 않았습니다.

## 정리

이번 비교에서 확인된 점은 두 가지입니다. 첫째, 같은 목표·같은 대상에서 DeepSeek 실행은 약 3시간·3,788회 호출로 53건(중복 포함)을 넓게 보고했고, Haiku 실행은 약 24분·430회 호출로 18건을 보고했습니다. 공통 묶음은 ARTEX가 보고한 모두뱅크의 핵심 결함(명령 주입·예측 세션·로그인 SQLi·root cron·CSRF·이체 로직·평문 노출·경로 순회·XSS·SSRF·Actuator)으로 겹쳤고, 차이는 주로 DeepSeek이 더 넓게 훑어 보고한 추가 표면(Manager RCE·업로드 RCE·재설정 체인·SSTI·SSH 재사용·스머글링·XXE·동시성)에서 났습니다. 둘째, 캐시 적중(DeepSeek 95%) 덕분에 입력 토큰이 13배 차이였는데도 추정 비용 격차는 약 2.5배에 그쳤습니다.

범위는 단일 랩 호스트에서 모델당 1회 실행한 결과이고, 모델 외에 worker 수·탐색 범위·초기화되지 않은 서버 상태·실행 순서가 교란 요인으로 섞여 있습니다. 발견 건수는 모두 ARTEX 최종 보고서 기준이며, 두 실행 다 요청을 수동으로 재현해 확정한 것은 아닙니다. 다음 비교는 VM 스냅샷을 복원해 두 실행이 같은 상태에서 시작하도록 맞추고, 같은 모델을 반복 실행해 편차를 함께 확인하는 방식으로 진행할 예정입니다.
