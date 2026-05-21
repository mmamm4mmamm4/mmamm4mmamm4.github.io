# 1분기 DPRK Operation Kimsuky 분석

## 1. 개요

본 보고서는 2026년 상반기 확인된 Kimsuky 공격 그룹이 활용한 4가지 스피어피싱 캠페인을 분석합니다.

각 캠페인은 타깃 맞춤형 미끼 문서를 활용하며, LNK·JSE·PS 등 다양한 초기 실행 벡터를 통해 피해자 시스템에 침투합니다. 주요 공격 대상은 기업 채용 담당자, 암호화폐 투자자·개발자, 군·국방 관계자, 공공기관 및 대기업 직원 등으로 다양합니다.

공격 흐름은 공통적으로 미끼 문서 표시 → 페이로드 드롭 → 지속성 확보 → C2 통신 및 원격 제어 순서로 진행되며, GitHub·VSCode 터널 등 정상 서비스를 악용한 사례도 포함됩니다.
캠페인별 주요 특징은 다음과 같습니다.

캠페인 #1은 이력서·명함·의료 서류로 위장한 LNK 파일을 통해 UAC 우회 및 RAT 설치를 시도합니다. 캠페인 #2는 Solana 기반 밈코인 플랫폼(Pump.fun) 공식 문서로 위장하여 시스템 정보를 탈취하고 GitHub를 C2 채널로 활용합니다. 캠페인 #3은 국제 군사훈련 대회(K-ICTC) 관련 문서로 위장해 국방·군사 관계자를 표적으로 삼으며, MAC 주소 기반 맞춤형 페이로드를 배포합니다. 캠페인 #4는 대학원 위탁교육 서류로 위장한 JSE 스크립트 두 종을 통해 정찰용 DLL을 로드하거나 VSCode 터널링으로 피해자 PC를 원격 제어합니다.

![mal dark img.png](mal_dark_img.png)

**캠페인 개요 비교**

| 구분 | **Campaign #1** | **Campaign #2** | **Campaign #3** | **Campaign #4** |
| --- | --- | --- | --- | --- |
| **위장 주제** | 이력서·명함·의료/보험 서류 | Pump.fun (Solana 밈코인) 기술 문서 | K-ICTC 국제과학화전투경영대회 | 국내대학원 석사야간과정 위탁교육 |
| **주요 타깃** | 채용 담당자, 거래처, 의료·보험 기관 | 암호화폐 트레이더·개발자·투자자 | 육군본부·합참·국방부, 주한 외국 무관부 | 공공기관·대기업 직원, 대학원 행정 담당자 |
| **초기 벡터** | LNK (PDF 위장) | LNK (PDF 위장) | LNK (PDF 위장) | JSE  (HWPX 위장) |
| **미끼 문서** | 1.pdf | Pumpfun-AI-Attack-Defence-Requirements.pdf | 2026 4th K-ICTC Information.pdf | 위탁교육 선발 관련 HWPX 문서 |

**기술적 특징 비교**

| 구분           | **Campaign #1**                                     | **Campaign #2**                    | **Campaign #3**         | **Campaign #4**                                            |
| ------------ | --------------------------------------------------- | ---------------------------------- | ----------------------- | ---------------------------------------------------------- |
| **주요 페이로드**  | PowerShell RAT (a.ps1)                              | PowerShell Infostealer (bpvme.ps1) | VBE → PowerShell (파일리스) | DLL 정찰 모듈 / VSCode CLI                                     |
| **C2 채널**    | 자체 서버<br>([https://nelark.icu](https://nelark.icu)) | GitHub 저장소<br>(정상 서비스 악용)          | 자체 IP (103.67.196.25)   | 정상 서버 악용([yespp.co.kr](http://yespp.co.kr)) + GitHub OAuth |
| **지속성 기법**   | Startup 폴더 LNK + 작업 스케줄러<br>(5분 주기)                 | 작업 스케줄러 (OneDrive 위장, 60분 주기)      | 작업 스케줄러<br>(15분 주기)     | VSCode 터널 (지속 원격 접속)                                       |
| **방어 우회**    | UAC 비활성화, Defender 예외 등록                            | 자가 삭제, 수집 파일 삭제                    | 다중 난독화 (동물명 변수)         | 정상 MS CDN 활용                                               |
| **타깃 식별 방식** | uid 기반 폴링                                           | IP-시간 기반 파일명                       | MAC 주소 기반 맞춤 페이로드       | (정찰 정보 일괄 수집)                                              |
## 2. 캠페인 분석

#### Campaign #1

**이력서, 명함, 의료/보험 서류로 위장 스피어피싱 캠페인**

![image.png](image.png)

**미끼 파일 타깃**

- **이력서/지원서** — 이름과 연락처 형식이 이력서 헤더와 유사하여 채용 담당자를 타깃으로 한 스피어 피싱에 자주 사용됨
- **명함 정보 문서** — 거래처나 고객 정보로 위장
- **의료/보험 서류** — "health blvd" 주소가 의료 관련 기관을 연상시켜 의료·보험 관련 서류로 위장할 가능성

#### 공격 흐름

LNK 파일(1.pdf.lnk)은 일반 PDF 문서로 위장되어 있으며, 내부에 오프셋 기반으로 두 개의 페이로드를 은닉하고 있습니다.

| 오프셋 | 내용 | 저장 경로 |
| --- | --- | --- |
| 20KB 이후 | 미끼용 PDF 파일 | %TEMP%\1.pdf |
| 10KB~20KB | 지속성용 LNK 파일 | Startup\OneDrive.lnk |

LNK 파일(1.pdf.lnk) 실행 시 미끼 PDF를 추출하여 피해자에게 정상 문서로 보여주고, 시작 프로그램 폴더에 OneDrive.lnk 파일을 생성하여 지속성을 확보합니다. 동시에 C2 서버(https://nelark.icu/xftaswx/res/bb.php)에서 추가 스크립트를 가져와서 실행합니다. 이후, 다양한 C2 통신 및 스크립트 코드를 수행하게 됩니다.

| 단계 | 행위 | 설명 |
| --- | --- | --- |
| 1단계 | LNK 파일 실행 | PDF 위장 바로가기 파일 실행 → 미끼 문서 표시 + 페이로드 드롭 |
| 2단계 | C2 초기 통신 | C2 서버(/res/bb.php)에서 초기 페이로드 다운로드 및 실행 |
| 3단계 | UAC 우회 | 1.bat 다운로드 및 실행으로 UAC 비활성화 |
| 4단계 | 지속성 확보 | Defender 예외 등록 + 스케줄러 등록 |
| 5단계 | C2 원격 제어 | 5초 간격 폴링으로 명령 수신 및 실행 |

**C2 통신 시도별 행위 요약**

| 순서 | C2 | 역할 | 실행 스크립트 |
| --- | --- | --- | --- |
| 1 | /xftaswx/res/bb.php | 초기 페이로드 | UAC 확인 + bpersist PS1 |
| 2 | /xftaswx/res/post_proc.php?fpath=bpersist.ps1 | 지속성 확보 | bpersist.ps1 |
| 3 | /xftaswx/res/bypass.b | UAC 우회 | %TEMP%\1.bat |
| 4 | /xftaswx/res/index.php | UAC 확인 결과 보고 | POST (uid, msg) |
| 5 | /xftaswx/res/post_proc.php?fpath=scheduler-once | 스케줄러 등록 | scheduler-once.bat |
| 6 | /xftaswx/res/post_proc.php?fpath=a.ps1 | 메인 RAT 루프 | a.ps1 (gCommand 포함) |
| 7 | /xftaswx/res/get-command.php?uid=<uid> | 원격 명령 수신 | 동적 명령 실행 |

#### Campaign #2

**암호 화폐 관련 공식 기술 문서로 위장 스피어피싱 캠페인**

![image.png](image%201.png)

**미끼 파일 타깃**

**1. Pump.fun 플랫폼**

- Pump.fun은 Solana 기반 밈코인 런치패드 플랫폼
- 트레이더, 개발자, 투자자들이 주요 타깃

**2. "PumpGuard" 키워드**

- 실제로 존재하지 않는 가상의 보안 도구명으로 추정
- Pump.fun 관련 AI 기반 보안 솔루션처럼 위장
- 공격/방어 요구사항 문서로 공식 기술 문서처럼 신뢰감 부여

#### 공격 흐름

| 단계 | 파일명 | 출처 | 저장 경로 | 주요 행위 | 다음 단계 |
| --- | --- | --- | --- | --- | --- |
| 1단계 | firefox.ps1 | 최초 스크립트가 직접 생성 | `%AppData%\firefox.ps1` | 암호화된 스크립트 복호화 및 실행 | view.pdf, bpvme.ps1, wale.ps1 실행 |
| 2단계 | view.pdf | GitHub `/main/view.pdf` | `%TEMP%\Pumpfun-AI-Attack-Defence-Requirements.pdf` | 미끼 PDF 문서 실행 | - |
| 2단계 | bpvme.ps1 | GitHub `/main/1.txt` | `%AppData%\bpvme.ps1` | 시스템 정보 수집 → GitHub 유출 → 자가 삭제 | - |
| 2단계 | wale.ps1 | 최초 스크립트가 직접 생성 | `%AppData%\wale.ps1` | 스케줄러 등록 (15분 후 시작, 60분 반복) | coks.ps1 다운로드 및 실행 |
| 3단계 | coks.ps1 | GitHub `/main/2.txt` | `%AppData%\coks.ps1` | 미확인 페이로드 | - |
| 지속성 | 스케줄러 | wale.ps1 등록 | Windows 작업 스케줄러 | OneDrive 프로세스로 위장, 60분마다 wale.ps1 반복 실행 | coks.ps1 반복 실행 |
| 증거인멸 | - | - | - | 최초 스크립트 삭제, 
firefox.ps1 삭제,
bpvme.ps1 삭제, 
수집 정보 파일 삭제 | - |

**최초 스크립트 생성 복호화 루틴**

- key = "AB59097(*^zxcvbn   “

```
# i -> 암호 배열 전체 길이
# j -> 키 길이(19)
pw_num = key[j] + 103

# case 1: pw_num >= encrypted[i]
plain[i] = pw_num - encrypted[i]

# case 2: pw_num < encrypted[i]
plain[i] = encrypted[i]
```

**bpvme.ps1(Infostealer) 수집 정보**

| 수집 정보 | 사용 명령 |
| --- | --- |
| IP 주소 | `Win32_NetworkAdapterConfiguration` |
| OS 정보 | `Win32_OperatingSystem` |
| 시스템 정보 | `Win32_ComputerSystem` |
| 마지막 부팅 시간 | `LastBootUpTime` |
| 기기 유형 (노트북/데스크탑) | `PCSystemType` |
| 안티바이러스 제품명 | `root\SecurityCenter2` |
| 실행 중인 프로세스 목록 | `Get-Process` |

**공격자 활용 GitHub 정보**

| 항목 | 값 |
| --- | --- |
| GitHub 계정 | `brandonleeodd93-blip` |
| Repository | `doc7` |
| GitHub PAT | `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` |
| 페이로드 경로 | `/main/1.txt`, `/main/2.txt`, `/main/view.pdf` |
| 수집 정보 경로 | `/report/{IP}-{시간}-0956_info.txt` |

#### Campaign #3

**국제과학화전투경영대회 관련 문서로 위장한 유형**

![image.png](image%202.png)

![image.png](image%203.png)

**미끼 파일 타깃**

- **육군 관련 실무자**
    - K-ICTC 행사 담당 육군본부 훈련정책 부서
    - 합참 국제협력 및 훈련 담당 장교
    - 국방부 정책 실무자
- **해외 타겟 (영문본)**
    - 주한 외국 무관부
    - 과거 K-ICTC 참가국 군 담당자
    - 미군, 호주군, 영국군 등 연합훈련 담당 연락장교

#### 공격 흐름

| 단계 | 구성 | 행위 | 비고 |
| --- | --- | --- | --- |
| 1단계 | `2026 4th K-ICTC Information.pdf.lnk` | 사용자 실행 | PDF 아이콘으로 위장된 바로가기 파일 |
| 2단계 | `curl` | `http://103.67.196.25/conf.dat` → `C:\Users\Public\Music\ant.vbe`로 저장 | C2 서버에서 VBE 다운로드 |
| 3단계 | `ant.vbe` | VBScript Encoded 파일 실행, WMI로 PowerShell 호출 | 백그라운드 실행 |
| 4단계 | PowerShell | 다중 난독화 해제 후 `(New-Object Net.WebClient).DownloadString()` 조립 | 동물명 변수(`$tiger`, `$bear`, `$puma`)로 난독화 |
| 5단계 | `getmac` | 시스템 MAC 주소 수집 | 피해자 고유 식별자 생성 |
| 6단계 | C2 요청 | `http://103.67.196.25/view1.php?type=apple&seed=<MAC>` 페이로드 요청 | MAC 기반 맞춤 페이로드 요청 |
| 7단계 | `iex` (2회) | 1차 `iex` — 원격 스크립트 요청, 
2차 `iex` — 파일리스(Fileless) 실행 | 지속성 유지 후
원격 명령어 수행 |

#### Campaign #4

**2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발 위장 스피어피싱 캠페인**

![image.png](image%204.png)

**미끼 파일 타깃**

- **공공기관 직원**
    - 중앙부처 및 지방자치단체 소속 공무원
    - 공기업 및 준정부기관 재직자
- **대기업 및 민간기업 직원**
    - 임직원 위탁교육 제도를 운영하는 대기업 재직자
- **대학원 행정 담당자**
    - 위탁교육생을 받는 대학원의 입학처·행정실 담당자

#### 공격 흐름

하나의 ZIP 압축 파일 안에 두 개의 JSE 스크립트가 포함되어 배포된 스피어피싱 캠페인입니다. 파일명은 각각 `2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발관련 서류.hwpx.jse`와 동일 파일명에 `(1)`이 붙은 변종으로, 이중 확장자(`.hwpx.jse`)를 통해 한글 문서로 위장했습니다. Windows의 기본 설정상 `.jse` 확장자가 숨겨지므로, 사용자에게는 `.hwpx` 한글 문서처럼 보입니다.

**Sample #1— 2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발관련 서류.hwpx.jse**
JSE 스크립트가 실행되면 먼저 정상 한글 문서를 드롭하고 실행해 피해자의 의심을 차단합니다. 이후 Base64로 인코딩된 1차 페이로드를 `iIdypWi.zgyY`로 저장하고, `certutil -decode`를 통해 최종 악성 DLL인 `kE2I3TP.crqn`을 생성합니다. 이를 `rundll32.exe`의 `load` 함수로 로드하며, DLL은 즉시 백신·네트워크·사용자·프로세스 등 시스템 전반에 대한 초기 정찰을 수행합니다.

**DLL 수집 정보**

| 명령어 | 수집 정보 |
| --- | --- |
| `Get-CimInstance -Namespace root/SecurityCenter2 -Classname AntivirusProduct` | 설치된 백신 제품명, 버전, 상태 |
| `dir C:\` | C 드라이브 루트 디렉토리 목록 |
| `dir C:\programdata` | ProgramData 폴더 내 파일/폴더 목록 |
| `dir C:\Users` | 사용자 계정 목록 |
| `tasklist` | 현재 실행 중인 프로세스 전체 목록 |
| `dir "C:\program files"` | 설치된 프로그램 목록 |
| `dir "%USERPROFILE%\Desktop"` | 바탕화면 파일 목록 |
| `ipconfig /all` | IP 주소, MAC 주소, DNS 서버, 게이트웨이, DHCP 정보 |
| `route print` | 라우팅 테이블 전체 |
| `net user` | 로컬 사용자 계정 목록 및 그룹 정보 |
| `netstat -nao` | 현재 활성 네트워크 연결, 포트, 연결된 PID |
| `systeminfo` | OS 버전, 패치 수준, 아키텍처, 도메인, 부팅 시간, 메모리 등 |
| `reg query HKCU\...\CurrentVersion\Run` | 현재 사용자 시작프로그램 레지스트리 항목 |

**Sample #2— 2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발관련 서류 (1).hwpx.jse**
JSE 스크립트가 실행되면 동일하게 미끼 문서로 피해자를 속인 뒤, Microsoft 공식 CDN에서 VSCode CLI ZIP을 다운로드합니다. 압축 해제 후,  `code.exe`를 `C:\ProgramData\`에 복사하고 기존에 실행 중인 `code.exe` 프로세스를 정리(중복 실행 방지)한 뒤 터널링 단계로 진입합니다.

**code.exe 터널링 과정**

| 단계 | 주체 | 동작 | 통신 대상 |
| --- | --- | --- | --- |
| 1 | 피해자 PC | `code.exe tunnel --name bizeugene` 실행 | - |
| 2 | code.exe | GitHub에 Device Code 발급 요청 | `github.com` |
| 3 | GitHub | 일회용 디바이스 코드 발급 | → 피해자 PC |
| 4 | code.exe | 디바이스 코드를 `out.txt`에 기록 | 로컬 |
| 5 | code.exe | `access_token` 엔드포인트 반복 폴링 시작 | `github.com/login/oauth/access_token` |
| 6 | JSE 스크립트 | `out.txt` 내용을 C2 서버로 POST 전송 | `yespp.co.kr/common/include/code/out.php` |
| 7 | 공격자 | C2에서 디바이스 코드 확인 | `yespp.co.kr` |
| 8 | 공격자 | 공격자의 GitHub 계정으로 코드 입력 | `github.com/login/device` |
| 9 | GitHub | 인증 완료 → access token 반환 | → 피해자 PC (code.exe) |
| 10 | code.exe | 터널 활성화 | `vscode.dev/tunnel/bizeugene` |
| 11 | 공격자 | 터널 접속 → 피해자 PC 원격 제어 | `vscode.dev/tunnel/bizeugene` |

## 3. 침해 지표

**Campaign #1**
**md5**
80088af673b0117dbd5cf528021dd970  1.pdf.lnk
c499e415f7e07f513d8319013a8b2e86  1.pdf.lnk.zip
0331a83b58231cb0cd3bfe319003ed1a  OneDrive.lnk
806fb7876b63ba89d2432cb831be01ba  a.ps1
c57a8b40d2ca402656ff3d778f42708c  bb.ps1
2689f58b803364bbfba2edb423a3b572  bpersist.ps1
552ca91696fedd387e1ea47f50f18344  scheduler-once.bat

**C2**
https://nelark.icu/xftaswx/res/post_proc.php?fpath=a.ps1
https://nelark.icu/xftaswx/res/post_proc.php?fpath=bpersist.ps1
https://nelark.icu/xftaswx/res/index.php
https://nelark.icu/xftaswx/res/post_proc.php?fpath=scheduler-once
https://nelark.icu/xftaswx/res/bypass.b

**Campaign #2
md5**
aa9d5dd632bb90addca480eaa5ff4382  PumpGuard-Pumpfun-AI-Attack-Defence-Requirements.pdf.lnk
5c2857913efc6007b3ee7028a132baa4  PumpGuard-Pumpfun-AI-Attack-Defence-Requirements.pdf.zip
6869766741b40825e31fd8bbff688bd3  bpvme.ps1
3fdce08723365d5c06e1183585164118  PumpGuard_Pumpfun_AI_Attack_Defence_Requirements_v2_1_GameEngine (2).rar
a3363e0c22c0356fdbcdc37f502bbcde  firefox.ps1
471faa43f4811a0250648d586cb3eebf  bpvme.ps1
8301fc2c740f6309864e68b6e429d0f0  whale.vbs
af7330af68a8f79b5a28fcc242e54a7e  doc_2026-03-26_08-58-03.NetAngular.pdf.zip
450774df6785e6eeb6ea906490905888  firefox.ps1
831d7c614ba32aa5d70ff9b0f259ee1d  wale.ps1

**C2
※***정상 GitHub 서비스*
****https://raw.githubusercontent.com/brandonleeodd93-blip/doc7/main/1.txt
https://raw.githubusercontent.com/brandonleeodd93-blip/doc7/main/view.pdf
https://api.github.com/repos/brandonleeodd93-blip/doc7/contents/report/{IP}-{시간}-0956_info.txt

**Campaign #3
md5**
b3c90f52e4b86a94ec637fee4354bb84  2026 4th K-ICTC Information.pdf.lnk
0dd1cf2d9a72fdbef19e77af59ba9d1f  2026 4th K-ICTC Information.pdf.zip
cbb059bd691d846e8279d617134d3129  conf.dat

**C2**
http://103.67.196.25/conf.dat
http://103.67.196.25/payload.dat
http://103.67.196.25/view1.php?type=apple&seed=<Mac>

**Campaign #4
md5**
bb5040d54135b0999cc491b41a0a45e2  2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발관련 서류 (1).hwpx.jse.zip
****9fe43e08c8f446554340f972dac8a68c  2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발관련 서류 (1).hwpx.jse
52f1ff082e981cbdfd1f045c6021c63f  2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발관련 서류.hwpx.jse
bb9e9c893b170b3774c150b1d0b93a73  iIdypWi.zgyY
08160acf08fccecde7b34090db18b321  kE2I3TP.crqn

**C2**
https://www.pyrotech.co.kr/common/include/tech/default.php
https://www.yespp.co.kr/common/include/code/out.php