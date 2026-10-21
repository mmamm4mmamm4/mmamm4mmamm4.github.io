---
title: PHP session.upload_progress UAF 재현 검증
date: 2026-10-21 00:00:00 +0900
categories:
- Exploit Dev
tags:
- exploit/research
- bug/uaf
- target/php
author: mmamm4
---

# PHP session.upload_progress UAF 재현 검증

한 공개 블로그 포스트(문서 끝 출처)가 PHP `session.upload_progress`에 RCE로 이어지는 heap use-after-free가 있다며 익스플로잇 번들을 배포한 것이 이 검증의 출발점입니다. 포스트의 주장만으로는 진위를 판단할 수 없어, 배포된 번들의 취약점을 로컬 ASan 환경에서 직접 재현해 확인한 기록입니다. 포스트는 업로드 진행률 처리 과정의 use-after-free가 원격 코드 실행으로 이어진다고 주장하고, 식별자로 CVE-2026-109618·109619를 제시합니다. 두 번호 모두 공개 CVE 데이터베이스와 PHP 보안 공지에서 확인되지 않고 번들 문서도 "presumed"로 표기하고 있어, 할당된 식별자가 아니라 작성자가 임의 부여한 번호로 판단됩니다.

1차 재현에서 ASan 빌드 PHP 8.4.4에 프레임워크 바디를 16회 전달했으나 use-after-free 리포트도 워커 크래시도 나오지 않았습니다. 이후 "stock PHP에서도 재현됐다"는 외부 주장이 제기되어, 1차 하니스의 사각지대를 좁혀 다시 검증했습니다. 이 문서는 그 재검증 절차와 근거를 다룹니다. 결론은 1차와 같은 음성이나, 하니스의 유효성과 민감도를 끌어올린 만큼 근거가 더 단단해졌습니다. 범위는 로컬 PHP 8.4.4(fpm/cli)이며, 프레임워크가 실제 겨냥하는 LiteSpeed lsphp82 8.2.34는 소스 비공개로 동일 검증하지 못했습니다.

## 좁혀야 할 사각지대

음성 결과를 신뢰하려면 "버그가 실제로 터졌다면 하니스가 반드시 잡아냈을 상태"임을 먼저 보장해야 합니다. 반증 주장을 받아 다음 세 가지를 점검 대상으로 삼았습니다.

- ASan이 PHP의 Zend Memory Manager(`emalloc`) 힙을 실제로 계측하는가. 계측하지 못하면 UAF가 나도 리포트가 없어 음성이 무의미합니다.
- 트리거 조건(진행률 갱신 빈도·타이밍)이 충분히 공격적이었는가.
- FCGI 2-청크 전달이 실제 업로드의 다중 갱신 사이클을 대표하는가.

## 하니스가 Zend 힙을 계측함을 확정

AddressSanitizer는 해제된 메모리를 다시 참조하면 잡아내지만, OS가 직접 내준 할당만 감시합니다. 문제는 PHP가 변수·배열·객체 메모리를 OS에서 매번 받지 않고 자체 메모리 관리자(Zend Memory Manager)가 미리 확보해 둔 풀에서 `emalloc`으로 꺼내 쓴다는 점입니다. 이 풀 내부의 재사용은 ASan 시야 밖이라, PHP 수준의 UAF가 터져도 리포트가 없을 수 있습니다. 음성이 "버그 없음"이 아니라 "감시가 꺼져 있었음"일 가능성입니다.

`USE_ZEND_ALLOC=0`은 이 풀 할당자를 우회시켜 모든 할당을 시스템 `malloc`으로 보냅니다. 할당이 OS를 거치면 ASan이 전부 계측할 수 있습니다. 이 우회가 실제로 적용됐는지를 ASan의 `max_allocation_size_mb` 옵션으로 가렸습니다. 5MB를 할당하는 `str_repeat`를 1MB 상한과 함께 실행했습니다.

```
# pool (ASan이 못 봄) — 조용히 통과
USE_ZEND_ALLOC=1 ASAN_OPTIONS="max_allocation_size_mb=1:..." php bigone.php
  -> alloc ok len=5242880

# malloc (ASan이 가로챔) — 중단
USE_ZEND_ALLOC=0 ASAN_OPTIONS="max_allocation_size_mb=1:..." php bigone.php
  -> ERROR: AddressSanitizer: requested allocation size 0x500020 ... exceeds maximum
       #1 __zend_malloc  Zend/zend_alloc.c:3280
       #2 _emalloc       Zend/zend_alloc.c:2737
       #4 zend_string_safe_alloc
       #5 zif_str_repeat ext/standard/string.c:5486
```

`_emalloc → __zend_malloc → malloc` 경로가 ASan에 잡혔습니다. 즉 이 하니스에서 ASan은 Zend 힙 수준의 오류까지 봅니다. 이 사실이 중요한 이유는, ASan이 heap grooming(해제 영역 재점유)의 성공 여부와 무관하게 **dangling 포인터를 역참조하는 순간** 리포트를 내기 때문입니다. 익스플로잇의 zval forge나 스프레이가 빗나가도, use-after-free로 가는 역참조가 한 번이라도 일어나면 잡힙니다. 따라서 계측이 켜졌음을 확정한 이 상태에서의 음성은 "grooming 미스로 조용히 지나갔다"로 설명하기 어렵습니다.

탐지·로깅 경로 자체는 1차에서 양성 대조로 확인했습니다. 동일 `ASAN_OPTIONS`(`log_path=/tmp/asan_php`)로 일부러 UAF를 낸 C 프로그램이 `/tmp/asan_php.<pid>`에 `heap-use-after-free` 리포트를 정확히 남겼습니다.

또한 php-fpm은 기본값 `clear_env = yes`라 워커가 master 환경을 상속하지 않습니다. 풀 설정에 `env[USE_ZEND_ALLOC]`·`env[ASAN_OPTIONS]`를 명시 주입하고, 스텁의 `getenv()`로 워커가 두 변수를 실제로 받았음을 확인했습니다.

## 공격적 트리거 조건에서 재시도

진행률 갱신의 빈도·시간 게이팅을 제거해 매 rfc1867 이벤트마다 update가 발생하도록 설정했습니다.

```
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
session.upload_progress.freq = "0"       # 바이트 게이팅 제거
session.upload_progress.min_freq = "0"   # 시간 게이팅 제거
upload_max_filesize = 256M
post_max_size = 256M
```

이 설정에서 bug 618/619 × stall(0.0 / 0.5 / 1.2 / 2.0 / 3.0s)로 10회 추가 전달했습니다. 단일 워커(`pm.max_children=1`)로 free→reuse가 같은 프로세스에서 결정적으로 일어나도록 유지했습니다. 결과는 ASan 리포트 0, 워커 사망 0이었습니다. 1차 16회와 합쳐 누적 26회 모두 음성입니다.

## 현실적인 느린 업로드로 재시도

FCGI 2-청크 전달이 실제 업로드의 다중 갱신을 대표하지 못할 가능성을 배제하기 위해, PHP 내장 서버에 실제 HTTP 멀티파트를 느리게 흘려보냈습니다.

```
php -c php-aggr.ini -S 127.0.0.1:8099 -t <webroot>
curl --limit-rate 512k http://127.0.0.1:8099/index.php \
  -b "PHPSESSID=slowtest1" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=probe" \
  -F "file=@/tmp/bigupload.bin"      # 20MB
```

`PHP_SESSION_UPLOAD_PROGRESS` 필드를 선행시키고 세션 쿠키를 동반해, 20MB 본문을 512KB/s로 수십 초에 걸쳐 전송했습니다. 진행률 갱신이 다수 발생하고 세션 진행률 파일(`sess_slowtest1`)도 기록됐지만, ASan 리포트·크래시는 없었습니다. upload_progress 경로가 실행되는 것은 확인되나 use-after-free는 발생하지 않았습니다.

## 검증 종합

| 축 | 1차 | 2차 보강 |
| --- | --- | --- |
| ASan의 Zend 힙 계측 | 미확인(가정) | `max_allocation_size_mb` 판별로 확정 |
| 워커 env 주입 | export만 | 풀 `env[]` 주입 + `getenv()` 확인 |
| 갱신 게이팅 | 기본값 | `freq=0`·`min_freq=0`으로 제거 |
| 전달 경로 | FCGI 2-청크 | FCGI + 현실적 느린 HTTP 업로드 |
| 전달 횟수 | 16회 | 누적 26회 + 대용량 1회 |
| 결과 | 음성 | 음성(동일) |

## 정리

하니스의 유효성(ASan이 Zend 힙 계측)과 탐지 민감도(게이팅 제거·현실적 느린 업로드)를 모두 끌어올렸음에도, 검증된 조건에서 stock PHP 8.4.4의 `session.upload_progress` use-after-free는 재현되지 않았습니다. ASan은 grooming 성공과 무관하게 dangling 역참조 자체를 잡는데 그마저 한 번도 발생하지 않았으므로, "grooming 미스로 조용히 지나갔다"는 설명만으로 이 음성을 돌리기는 어렵습니다.

소스상 근거도 같은 방향입니다. `php_session_rfc1867_update`는 `Z_TRY_ADDREF(progress->data)`로 배열 refcount를 올린 뒤 `$_SESSION`에 넣으므로, 참조가 유지되는 동안 `post_bytes_processed`가 가리키는 슬롯이 해제되지 않습니다. 추정 결함의 핵심인 "배열 해제 후 원시 포인터 역참조"가 이 버전 경로에서는 성립하지 않는 것으로 보입니다. 이는 소스 정적 관찰에 근거한 추정이며 모든 분기를 추적한 결론은 아닙니다.

남는 불확실성은 범위에 있습니다. 검증하지 못한 유일한 표면은 프레임워크가 실제로 겨냥하는 LiteSpeed lsphp82 8.2.34이며, LiteSpeed는 소스 비공개라 동일 ASan 빌드로 확인할 수 없습니다. "PHP에서 재현됐다"는 정보의 출처가 그 lsphp 빌드이거나 작성자 본인의 미검증 주장일 가능성이 있습니다. 해당 재현의 조건(버전·빌드·ASan 트레이스 유무)이 확인되면 그대로 맞춰 재시도할 수 있습니다.

## 출처

- 이 검증의 계기가 된 원본 포스트(익스플로잇 번들 배포): `hxxps://jackalsyn[.]com/posts/php-up-2026[.]html`

> 링크는 defang 처리했습니다. 방문 시 해당 사이트는 공격 프레임워크 tarball을 배포하므로 격리 환경에서만 접근하시기 바랍니다.
