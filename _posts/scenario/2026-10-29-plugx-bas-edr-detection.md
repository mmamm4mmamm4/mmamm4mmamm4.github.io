---
title: PlugX 공격 시뮬레이션 EDR 로그 분석과 SIEM 탐지 시나리오
date: 2026-10-29 00:00:00 +0900
categories:
- Detection Scenario
tags: []
author: mmamm4
---

# PlugX 공격 시뮬레이션 EDR 로그 분석과 SIEM 탐지 시나리오

BAS(Breach and Attack Simulation) 도구 Somma Cheiron으로 Windows 테스트 단말 한 대에서 PlugX(SOGU) 행위를 모사하고(BAS 시나리오가 PlugX를 표방했고, 내려받은 페이로드 이름도 `sogu_RAR_*`였습니다), 그 단말의 Genian EDR 로그를 SIEM에서 내보내 분석한 기록입니다. 로그에서 공격 흐름을 복원하고, EDR이 스스로 잡지 못한 구간을 중심으로 SIEM 탐지 룰 6개를 만들었습니다. 룰은 GPT(Codex) 독립 검토를 두 차례 받아 수정했습니다.

![2026-10-29-plugx-bas-edr-detection.png](/assets/img/posts/2026-10-29-plugx-bas-edr-detection/2026-10-29-plugx-bas-edr-detection.png)

## 환경과 대상

- 대상: 테스트용 Windows 단말 1대(Genian EDR 설치). 공격 프로세스는 대화형 사용자 계정으로 실행됐고, 무결성 수준은 HIGH(권한 상승 상태)였습니다.
- 시뮬레이터: `C:\Program Files\Somma\Cheiron\CheironManager.exe`(서비스) → `CheironAgent.exe`. 에이전트는 `c2.somma[.]kr`(`166.117.81[.]221`, `166.117.221[.]249`:443)에서 도구를 내려받아 실행합니다. Defender에는 에이전트 경로가 예외로 등록됐습니다.
- 로그: SIEM에 수집된 Genian EDR 로그(테이블 `EDR_GENIAN`)를 CSV로 내보낸 10,212건, 2026-10-29 08:45:09~09:06:33. 스키마별로 file 7,087건, process 1,218건, module 1,159건, reg 601건, network 133건, threat 14건입니다.
- 분석 방법: `CheironAgent.exe`의 `pguid`에서 시작해 `parent_pguid`로 후손 프로세스 23개를 묶고, 그 프로세스들의 파일·레지스트리·모듈·네트워크 이벤트를 시간순으로 정렬했습니다. `-E` 인자의 base64는 UTF-16LE로 디코딩했습니다.

## 공격 흐름

| 시각 | 행위 | 로그 근거 | ATT&CK |
|------|------|-----------|--------|
| 08:47 | 도구 내려받기 | `CheironAgent.exe` FileDownload → `C:\Users\Public\sogu_RAR_nNc2TXa2.RAR`, `fsguidll.exe`, `FileCreatorDllSelfKill_AEGOc.dll` 등. RAR은 08:47:43 Defender가 격리 | T1105 |
| 08:50 | DLL 사이드로딩 | PowerShell `Copy-Item ...FileCreatorDllSelfKill_AEGOc.dll C:\Users\Public\fslapi.dll` → `cmd /C C:\Users\Public\fsguidll.exe` → ModuleLoad `image_path=C:\Users\Public\fsguidll.exe`, `file_path=C:\Users\Public\fslapi.dll`. 프로세스는 118ms 뒤 종료 | T1574.002 |
| 08:51 | 프로세스 인젝션 시도 | `injector_1_x64.exe sleeping_binary_x64.exe C:\Users\Public\injectable_dll_x64.dll`. DLL은 08:51:44 Defender가 삭제 | T1055.001 |
| 08:52 | 서비스 등록 | `sc.exe create EventOEM binPath= "C:\Users\Public\service.exe" start= demand` → `Services\EventOEM\ImagePath` 기록(LocalSystem) | T1543.003 |
| 08:52 | DNS TXT 조회(통신 모사) | `powershell -ExecutionPolicy Bypass -E ...` → `Resolve-DnsName -Name google.com -Type TXT -Server <기본 DNS>` | T1071.004, T1059.001 |
| 08:53 | 키로거 실행 | `C:\Users\Public\SetWindowsHookEx_keylogger_x64.exe C:\Windows\TEMP\ai_rty5vzay.txt`, 08:54:11 `taskkill`로 종료 | T1056.001 |
| 08:55~08:58 | 정찰 | `cmd /C ipconfig /all`, `cmd /C whoami`, `cmd /C C:\Users\Public\system_information_discovery.bat`(systeminfo → `systemprofile.txt`) | T1016, T1033, T1082 |
| 09:04~09:05 | 흔적 삭제 | 인코딩 PowerShell `Remove-Item -Force`로 `systemprofile.txt`, `.bat`, `ai_*.txt`, 키로거 EXE 삭제 | T1070.004 |

`fslapi.dll`의 원본 이름(FileCreatorDllSelfKill)으로 보아 로드되면 파일 하나를 만들고 호스트 프로세스를 끝내는 검증용 DLL로 보입니다. 로드 직후 프로세스 종료는 확인했지만, 그 DLL이 만든 파일은 EDR 로그에 없었습니다. 인젝션도 대상 프로세스 안의 모듈 로드 기록이 없어 성공 여부를 로그로 판단할 수 없었습니다. 키로거도 실행과 출력 파일 생성까지만 확인했고 실제로 키 입력이 수집됐는지는 확인하지 않았습니다. DNS TXT 조회는 C2 통신을 모사한 것이며 C2 채널이 성립했다는 뜻은 아닙니다.

## EDR이 탐지한 것과 탐지하지 않은 것

EDR 위협 이벤트는 14건이었고, 내용이 비어 있는 2건을 빼면 12건이었습니다. 위협 이벤트의 `_time`은 실제 행위(`event_time`)보다 약 90초 늦게 수집됐습니다.

- 탐지: 인코딩 PowerShell(`SuspiciousPowershellCommand`) 6건, 의심 서비스 파일(`SuspiciousServiceFile`) 1건, 키로거 ML 탐지 2건(파일 생성·실행), 정찰 명령(`GetSystemInfoCommand`) 2건(whoami, systeminfo 배치 파일).
- BAS 인프라 탐지: `SuspiciousNetworkingByScript` 1건은 CheironManager가 띄운 PowerShell이 `cheiron-v2.somma[.]kr`로 접속한 것이라 공격 행위가 아닙니다.
- 대응 위협 이벤트 없음: DLL 사이드로딩, 프로세스 인젝션 시도, `ipconfig /all`, 흔적 삭제. 이 CSV 범위에서 해당 행위에 대응하는 위협 이벤트를 찾지 못했다는 뜻이며, 내용이 비어 있는 위협 이벤트 2건의 정체는 확인하지 못했습니다. 사이드로딩과 삭제는 SIEM 룰로 보완할 수 있는 구간이었습니다.

## 기준선

같은 CSV의 비공격 이벤트(Defender 플랫폼 업데이트, ngen·mscorsvw 314건, OneDrive, Edge, svchost 통신, Genian 에이전트)를 정상 기준선으로 썼습니다. 공격 이벤트를 포함한 CSV 전체에서 `C:\Windows`·`C:\Program Files` 밖 DLL을 로드한 이벤트는 공격의 `fsguidll.exe` 1건뿐이었고, 사용자 폴더 경로 서비스 등록도 공격의 `EventOEM` 1건뿐이었습니다. 즉 정상 이벤트에서는 두 패턴이 나오지 않았습니다. 정리 단계를 처음 실측했을 때는 이 로그의 PowerShell 실행마다 `%TEMP%\__PSScriptPolicyTest_*.ps1`이 만들어졌다가 지워지는 동작이 반복돼, 스크립트 호스트의 `.ps1` 삭제 9건이 잡혀 예외로 뺐습니다.

기준선이 21분·단말 1대라서 운영 환경 오탐을 대표하지는 못합니다. 룰을 활성화하기 전에 전사 EDR 로그 7일 이상을 조회 모드로 돌려 예외 목록을 채워야 합니다.

## 탐지 룰

룰은 단계별 단일 룰 5개(R1~R5)와 이를 묶는 상관 룰 1개(R6)로 구성했습니다. BAS 에이전트 이름(Cheiron)이나 이번 샘플의 파일명은 조건에 넣지 않고 기법만 기준으로 삼았습니다. 위험 위치는 `C:\Users\Public`·`C:\PerfLogs` 하위 전체와, `C:\ProgramData`·`C:\Windows\Temp`·사용자 Temp·Roaming·Downloads의 바로 아래 파일로 좁혔습니다. 설치 프로그램이 Temp 하위 폴더에 압축을 풀고 DLL을 불러오는 정상 동작을 줄이려는 설계이며, 실제 설치 작업으로 오탐 감소를 측정하지는 않았습니다. 서비스 실행 파일(R2와 R6의 서비스 단계)만 예외로 AppData 전체 하위와 경로 중간의 `temp`·`downloads` 하위까지 넓게 봅니다. 서비스 실행 파일이 그런 곳에 있을 정상적인 이유가 드물다고 판단했기 때문입니다. 같은 판정 기준을 파이썬으로 구현해 CSV에서 적중을 실측했습니다. SIEM에 등록한 뒤 와일드카드 조건이 동작하지 않는 문제를 찾아 v5에서 고쳤습니다(검증 결과 절 참고).

### 운영 방식

강한 신호인 사이드로딩 후보(R1)와 위험 경로 서비스 등록(R2)은 이벤트 한 건으로 판정되므로 실시간으로 바로 티켓을 냅니다. 같은 폴더 DLL 로드는 정상 프로그램의 명시적 DLL 로드에서도 나올 수 있어 사이드로딩 확정이 아니라 조사 대상 후보입니다. 오탐이 잦은 R3·R4는 분류를 지정하지 않아 티켓 없이 이벤트만 남기고 조사 때 참고합니다. 개수를 세야 하는 R5·R6는 실시간 시나리오에서 집계가 안 되므로 배치로 돌립니다. R6는 R4 이벤트를 받아 쓰지 않고 원본 로그에서 같은 PowerShell 조건을 다시 평가하므로, R4를 꺼도 R6 판정은 그대로입니다.

| 룰 | 내용 | 시나리오 | 티켓 | 중복 설정 |
|----|------|----------|------|-----------|
| R1 | 위험 위치에서 실행된 프로세스가 같은 폴더의 DLL 로드 | 실시간 | 발행(상) | `$hostname::$pguid`, 이벤트 제거 300초 |
| R2 | 서비스 ImagePath의 실행 파일이 위험 위치 | 실시간 | 발행(상) | `$hostname::$reg_key_path::$reg_value`, 이벤트 제거 300초 |
| R3 | Public·PerfLogs 하위 또는 ProgramData 루트에서 EXE 실행 | 실시간 | 미발행(조사용) | `$hostname::$pguid`, 이벤트 제거 300초 |
| R4 | `-EncodedCommand`(base64 20자 이상)와 `-ExecutionPolicy Bypass`를 함께 쓴 PowerShell | 실시간 | 미발행(조사용) | `$hostname::$pguid`, 이벤트 제거 300초 |
| R5 | 같은 단말(IP) 10분 안에 정찰 도구 3종 이상 | 배치(5분마다, 10분) | 발행(중) | `$hostname::$host_ip`, 티켓 축약 3600초 |
| R6 | 30분 안에 사이드로딩 또는 서비스 등록 + 의심 단계 합계 3개 이상 | 배치(10분마다, 30분) | 발행(상, 탐지 후 즉시 조사) | `$hostname::$host_ip`, 이벤트 제거 0초, 티켓 축약 3600초 |

R4는 base64가 20자 미만인 짧은 인코딩 명령과 `Bypass` 없이 쓴 인코딩 명령을 놓칩니다. 정규식은 base64 모양만 확인하며, 실제로 UTF-16LE로 디코딩되는지는 확인하지 않습니다. R2는 따옴표 경로를 먼저 뽑고, 따옴표가 없으면 처음 나오는 `.exe`까지를 실행 파일로 봅니다. 그래서 환경변수(`%ProgramData%`)나 NT 경로 표기, 중간 폴더 이름에 `.exe `가 들어간 경로는 따로 정규화해야 합니다.

R6는 다음 실행까지 경보가 최대 약 10분 늦어질 수 있고(수집 지연 별도), 30분 창 경계에 걸친 행위는 놓칠 수 있습니다. 첫 경보는 R1·R2가 실시간으로 내므로 이 지연은 감수했습니다. 실시간 시나리오에는 로그 스키마를 지정하고, 조회용 쿼리에서 `table` 줄과 첫 줄의 선행 `|`, `_schema` 조건을 뺀 `search ...`부터 넣습니다.

### 쿼리 최적화

v4에서는 스키마·이름·와일드카드 같은 값싼 조건을 앞의 `search`에 두고, 정규식과 `eval`은 뒤로 보냈습니다. 앞 단계에서 탈락한 행은 뒤로 전달되지 않습니다. 같은 식 안에서 단락 평가가 일어나는지는 문서로 확인하지 못했습니다. 가장 효과가 큰 것은 R6의 첫 `search`에서 단계 후보 이벤트만 남기는 사전 필터였습니다. 이번 CSV 기준으로 정규식·`eval`을 거치는 행이 10,065건에서 49건으로 줄었고, 탐지 결과는 v2와 같았습니다(5단계 적중). R4·R6에는 `bypass` 포함 조건을, R1·R3에는 경로 접두 조건을 사전 필터로 넣었습니다. v4에서는 이 조건들을 와일드카드(`cmd_line == "*bypass*"`, `image_path == "c:\\users\\*"`)로 썼지만 SIEM에서 0건이 나와 v5에서 `contains(lower(...))`·`indexof(lower(...))`로 바꿨습니다(검증 결과 절 참고). 이 조건들은 뒤의 최종 조건이 반드시 요구하는 것이고 `lower()`로 바꾼 뒤 비교하므로 탐지 범위를 줄이지 않습니다.

### R1 위험 위치 DLL 사이드로딩 (실시간, 중요도 상, 티켓 발행)

```
table duration=1d EDR_GENIAN
| search _schema == "genian-edr-module" and event_subtype == "ModuleLoad"
      and lower(file_path) == "*.dll"
      and (indexof(lower(image_path), "c:\\users\\") == 0 or indexof(lower(image_path), "c:\\programdata\\") == 0
           or indexof(lower(image_path), "c:\\windows\\temp\\") == 0 or indexof(lower(image_path), "c:\\perflogs\\") == 0)
| eval img_dir = lower(substr(image_path, 0, lastindexof(image_path, "\\"))),
       dll_dir = lower(substr(file_path, 0, lastindexof(file_path, "\\")))
| search img_dir == dll_dir
      and (in(img_dir, "c:\\users\\public", "c:\\perflogs", "c:\\programdata", "c:\\windows\\temp")
           or indexof(img_dir, "c:\\users\\public\\") == 0 or indexof(img_dir, "c:\\perflogs\\") == 0
           or match(img_dir, "^c:\\\\users\\\\[^\\\\]+\\\\(?:appdata\\\\local\\\\temp|appdata\\\\roaming|downloads)$"))
```

### R2 위험 위치 실행 파일로 서비스 ImagePath 설정·변경 (실시간, 중요도 상, 티켓 발행)

```
table duration=1d EDR_GENIAN
| search _schema == "genian-edr-reg" and event_subtype == "RegSetValue"
      and lower(reg_value_name) == "imagepath" and indexof(lower(reg_key_path), "\\services\\") >= 0
| search match(lower(reg_key_path), "^(?:hklm|hkey_local_machine|\\\\registry\\\\machine)\\\\system\\\\(?:currentcontrolset|controlset[0-9]{3})\\\\services\\\\[^\\\\]+$")
| eval svc_bin = lower(nvl(valueof(groups(reg_value, "^\\s*\"([^\"]+)\""), 0),
                           valueof(groups(reg_value, "(?i)^\\s*([^\"\\r\\n]+?\\.exe)(?:\\s|$)"), 0))),
       svc_sep = lastindexof(svc_bin, "\\")
| search svc_bin == "*.exe" and svc_sep >= 0
| eval svc_dir = substr(svc_bin, 0, svc_sep)
| search in(svc_dir, "c:\\users\\public", "c:\\perflogs", "c:\\programdata")
      or indexof(svc_dir, "c:\\users\\public\\") == 0 or indexof(svc_dir, "c:\\perflogs\\") == 0
      or match(svc_dir, "^c:\\\\users\\\\[^\\\\]+\\\\appdata(?:\\\\|$)")
      or match(svc_dir, "(^|\\\\)(temp|downloads)(\\\\|$)")
```

### R3 Public·PerfLogs 하위 또는 ProgramData 루트에서 EXE 실행 (실시간, 중요도 중, 티켓 미발행)

```
table duration=1d EDR_GENIAN
| search _schema == "genian-edr-process" and event_subtype == "ProcessStart"
      and lower(image_path) == "*.exe"
      and (indexof(lower(image_path), "c:\\users\\public\\") == 0 or indexof(lower(image_path), "c:\\perflogs\\") == 0 or indexof(lower(image_path), "c:\\programdata\\") == 0)
| eval img_dir = lower(substr(image_path, 0, lastindexof(image_path, "\\")))
| search in(img_dir, "c:\\users\\public", "c:\\perflogs", "c:\\programdata")
      or indexof(img_dir, "c:\\users\\public\\") == 0 or indexof(img_dir, "c:\\perflogs\\") == 0
```

### R4 인코딩 명령 + 실행정책 우회 PowerShell (실시간, 중요도 중, 티켓 미발행)

```
table duration=1d EDR_GENIAN
| search _schema == "genian-edr-process" and event_subtype == "ProcessStart"
      and in(lower(image), "powershell.exe", "pwsh.exe") and contains(lower(cmd_line), "bypass")
| eval b64 = valueof(groups(cmd_line, "(?i)(?:^|\\s)\"?-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\"?\\s+\"?([a-z0-9+/]{20,}={0,2})\"?(?:\\s|$)"), 0)
| search isnotnull(b64)
      and match(cmd_line, "(?i)(?:^|\\s)\"?-(?:ep|ex|exe|exec|execu|execut|executi|executio|execution|executionp|executionpo|executionpol|executionpoli|executionpolic|executionpolicy)\"?\\s+\"?bypass\"?(?:\\s|$)")
# b64 는 UTF-16LE base64 입니다. 분석 PC(CyberChef 등)에서 디코딩해 내용만 확인하고 절대 실행하지 않습니다.
```

### R5 10분 내 같은 단말의 정찰 도구 3종 이상 (배치: */5 * * * *, 분석기간 600초, 중요도 중)

```
# 계정이 아니라 단말(hostname·host_ip)로 묶습니다. EDR이 whoami 같은 짧은 프로세스의 계정을 비워 보내는 경우가 있어, 계정은 집계 조건이 아니라 결과의 user_key 목록으로만 남깁니다(빈 계정은 목록에서 빠짐).
table from=$("from") to=$("to") EDR_GENIAN
| search _schema == "genian-edr-process" and event_subtype == "ProcessStart"
| eval tool = lower(image)
| search in(tool, "whoami.exe", "ipconfig.exe", "systeminfo.exe", "net.exe", "nltest.exe", "tasklist.exe",
                  "quser.exe", "query.exe", "netstat.exe", "arp.exe", "route.exe", "hostname.exe")
      and len(trim(hostname)) > 0
| eval hostname = lower(hostname),
       user_key = if(len(trim(proc_user_id)) > 0, lower(trim(proc_user_id)), null),
       proc_key = if(len(trim(pguid)) > 0, concat("p:", pguid), concat("r:", _table, ":", _era, ":", _id))
| stats dc(tool) as tool_cnt, values(tool) as tools, dc(proc_key) as total_exec, values(user_key) as user_key,
        min(_time) as first_seen, max(_time) as last_seen by hostname, host_ip
| search tool_cnt >= 3
```

### R6 PlugX형 복수 의심 행위 동시 관측 (배치: */10 * * * *, 분석기간 1800초, 중요도 상)

```
# 필수 핵심 단계(sideload 또는 svc_install) + 총 3단계 이상. 정찰은 같은 사용자 3종 이상일 때만 단계로 인정합니다.
# 하나의 공격 체인을 확정하지 않으므로, 대응 전에 프로세스 계보(pguid → parent_pguid)를 확인합니다.
# 첫 search 에서 단계 후보 이벤트만 남겨(파일 생성 등 대량 이벤트 제외) 뒤의 eval·정규식 처리량을 줄입니다.
table from=$("from") to=$("to") EDR_GENIAN
| search (_schema == "genian-edr-module" and event_subtype == "ModuleLoad" and lower(file_path) == "*.dll"
          and (indexof(lower(image_path), "c:\\users\\") == 0 or indexof(lower(image_path), "c:\\programdata\\") == 0
               or indexof(lower(image_path), "c:\\windows\\temp\\") == 0 or indexof(lower(image_path), "c:\\perflogs\\") == 0))
      or (_schema == "genian-edr-reg" and event_subtype == "RegSetValue"
          and lower(reg_value_name) == "imagepath" and indexof(lower(reg_key_path), "\\services\\") >= 0)
      or (_schema == "genian-edr-process" and event_subtype == "ProcessStart"
          and ((in(lower(image), "powershell.exe", "pwsh.exe") and contains(lower(cmd_line), "bypass"))
               or in(lower(image), "whoami.exe", "ipconfig.exe", "systeminfo.exe", "net.exe", "nltest.exe", "tasklist.exe",
                                   "quser.exe", "query.exe", "netstat.exe", "arp.exe", "route.exe", "hostname.exe")))
      or (_schema == "genian-edr-file" and event_subtype == "FileDelete"
          and in(lower(image), "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"))
| search len(trim(hostname)) > 0
| eval hostname = lower(hostname), image_l = lower(image),
       user_key = if(len(trim(proc_user_id)) > 0, lower(trim(proc_user_id)), "<unknown>"),
       img_sep = lastindexof(image_path, "\\"), file_sep = lastindexof(file_path, "\\")
| eval img_dir = if(img_sep >= 0, lower(substr(image_path, 0, img_sep)), null),
       f_dir = if(file_sep >= 0, lower(substr(file_path, 0, file_sep)), null)
| eval img_risk = in(img_dir, "c:\\users\\public", "c:\\perflogs", "c:\\programdata", "c:\\windows\\temp")
          or indexof(img_dir, "c:\\users\\public\\") == 0 or indexof(img_dir, "c:\\perflogs\\") == 0
          or match(img_dir, "^c:\\\\users\\\\[^\\\\]+\\\\(?:appdata\\\\local\\\\temp|appdata\\\\roaming|downloads)$"),
       file_risk = in(f_dir, "c:\\users\\public", "c:\\perflogs", "c:\\programdata", "c:\\windows\\temp")
          or indexof(f_dir, "c:\\users\\public\\") == 0 or indexof(f_dir, "c:\\perflogs\\") == 0
          or match(f_dir, "^c:\\\\users\\\\[^\\\\]+\\\\(?:appdata\\\\local\\\\temp|appdata\\\\roaming|downloads)$")
| eval svc_bin = if(_schema == "genian-edr-reg",
                    lower(nvl(valueof(groups(reg_value, "^\\s*\"([^\"]+)\""), 0),
                              valueof(groups(reg_value, "(?i)^\\s*([^\"\\r\\n]+?\\.exe)(?:\\s|$)"), 0))), null)
| eval svc_sep = lastindexof(svc_bin, "\\")
| eval svc_dir = if(svc_sep >= 0, substr(svc_bin, 0, svc_sep), null)
| eval svc_risk = in(svc_dir, "c:\\users\\public", "c:\\perflogs", "c:\\programdata")
          or indexof(svc_dir, "c:\\users\\public\\") == 0 or indexof(svc_dir, "c:\\perflogs\\") == 0
          or match(svc_dir, "^c:\\\\users\\\\[^\\\\]+\\\\appdata(?:\\\\|$)")
          or match(svc_dir, "(^|\\\\)(temp|downloads)(\\\\|$)")
| eval stage = case(
    _schema == "genian-edr-module" and img_risk and img_dir == f_dir, "sideload",
    _schema == "genian-edr-reg"
        and match(lower(reg_key_path), "^(?:hklm|hkey_local_machine|\\\\registry\\\\machine)\\\\system\\\\(?:currentcontrolset|controlset[0-9]{3})\\\\services\\\\[^\\\\]+$")
        and svc_bin == "*.exe" and svc_risk, "svc_install",
    _schema == "genian-edr-process" and in(image_l, "powershell.exe", "pwsh.exe")
        and match(cmd_line, "(?i)(?:^|\\s)\"?-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\"?\\s+\"?[a-z0-9+/]{20,}={0,2}\"?(?:\\s|$)")
        and match(cmd_line, "(?i)(?:^|\\s)\"?-(?:ep|ex|exe|exec|execu|execut|executi|executio|execution|executionp|executionpo|executionpol|executionpoli|executionpolic|executionpolicy)\"?\\s+\"?bypass\"?(?:\\s|$)"), "enc_powershell",
    _schema == "genian-edr-process" and len(trim(proc_user_id)) > 0
        and in(image_l, "whoami.exe", "ipconfig.exe", "systeminfo.exe", "net.exe", "nltest.exe", "tasklist.exe",
                        "quser.exe", "query.exe", "netstat.exe", "arp.exe", "route.exe", "hostname.exe"), "recon",
    _schema == "genian-edr-file" and file_risk and not(match(lower(file_path), "\\\\__psscriptpolicytest_[^\\\\]+$"))
        and (match(lower(file_path), "\\.(exe|dll|bat|ps1|vbs)$")
             or (f_dir == "c:\\windows\\temp" and lower(file_path) == "*.txt")), "cleanup")
| search isnotnull(stage)
| eval stage_item = if(stage == "recon", image_l, "_")
| stats min(_time) as first_seen, max(_time) as last_seen by hostname, host_ip, user_key, stage, stage_item
| stats count as item_cnt, min(first_seen) as first_seen, max(last_seen) as last_seen by hostname, host_ip, user_key, stage
| search stage != "recon" or item_cnt >= 3
| stats min(first_seen) as first_seen, max(last_seen) as last_seen by hostname, host_ip, stage
| stats count as stage_cnt, values(stage) as stages, min(first_seen) as first_seen, max(last_seen) as last_seen by hostname, host_ip
| search stage_cnt >= 3 and (contains(stages, "sideload") or contains(stages, "svc_install"))
```

## 검증 결과

파이썬 실측기로 같은 CSV에 v4 룰의 판정 기준을 적용한 결과는 다음과 같습니다(v2와 같음). 적중은 모두 BAS 에이전트 프로세스 트리의 공격 행위였고, 그 밖의 이벤트에서는 적중이 없었습니다. R1~R4는 이벤트 단위(ProcessStart 중복 제거 후) 건수이고, R5·R6는 이동 창 여러 개에서 조건이 성립해도 단말 기준 1건으로 셌습니다.

| 룰 | 적중 | 적중 내용 |
|----|------|-----------|
| R1 | 1 | `C:\Users\Public\fsguidll.exe` → `C:\Users\Public\fslapi.dll` |
| R2 | 1 | `Services\EventOEM` → `c:\users\public\service.exe` |
| R3 | 4 | `fsguidll.exe`, `sleeping_binary_x64.exe`, `injector_1_x64.exe`, `SetWindowsHookEx_keylogger_x64.exe` |
| R4 | 6 | CheironAgent가 띄운 인코딩 PowerShell 전부(Copy-Item, DNS TXT, Remove-Item 4회) |
| R5 | 단말 1대 | `ipconfig`·`whoami`·`systeminfo` (08:55~08:58) |
| R6 | 단말 1대 | 5단계: sideload, svc_install, enc_powershell, recon, cleanup (08:50~09:05) |

GPT(Codex, gpt-6-astra, reasoning high) 독립 검토에는 룰 초안과 공격 배경, 쿼리 레퍼런스만 넘기고 작성자의 오탐 판단은 제공하지 않았습니다. 지적 7건 중 6건을 반영했습니다. 반영한 것은 `Public*` 와일드카드가 `PublicBackup`까지 잡는 경로 경계 문제, 서비스 ImagePath의 인자와 실행 파일 미분리, PowerShell 옵션 약어 누락, `ccmexec.exe` 이름 예외, R5 실행 횟수 중복, R6의 스키마 조건 누락과 단계 부풀림입니다. R6 중요도를 '중'으로 낮추자는 의견은 기각했습니다. 핵심 단계(사이드로딩·서비스 등록)를 필수로 두고 같은 단말 30분 안에 3단계를 요구하는 조합은 정상 운영에서 드물 것으로 판단했습니다. 다만 이 판단은 짧은 기준선에 근거한 것이라 운영 로그로 확인해야 하며, 대응 절차 첫 단계에서 프로세스 계보 확인을 필수로 두었습니다.

GPT 수정안을 다시 실측하자 새 오탐이 하나 생겼습니다. 정리 단계 범위가 사용자 Temp 바로 아래까지 넓어지면서, PowerShell이 기동할 때마다 만들고 지우는 `__PSScriptPolicyTest_*.ps1` 삭제 9건이 '흔적 삭제'로 잡혔습니다. 초안에서 이미 한 번 제외했던 패턴이라 R6 쿼리에 예외를 다시 넣었고, 이후 정리 단계 적중은 공격 파일 3건(키로거 EXE, `.bat`, `C:\Windows\Temp\ai_*.txt`)만 남았습니다. `C:\Users\Public\systemprofile.txt` 삭제는 `.txt`를 Windows Temp 바로 아래에서만 보도록 좁힌 조건 때문에 잡지 않습니다.

2차 교차검증에서는 v3 최적화안과 운영 방식을 같은 방식으로 독립 검토받았습니다. GPT 의견은 참고로 쓰고, 문법은 쿼리 레퍼런스 문서와 대조해 직접 판단했습니다. 반영한 것은 다음과 같습니다.

- `reg_value_name == "imagepath*"`가 `ImagePathBackup`까지 잡아 범위를 넓히는 문제를 확인하고 `lower(reg_value_name) == "imagepath"` 정확 일치로 되돌렸습니다.
- R5에서 계정이 빈 이벤트끼리 같은 그룹으로 합쳐지는 문제가 있어 계정 미상 이벤트를 제외했습니다. 그만큼 범위가 줄어듭니다.
- "R6가 R4 결과를 받아 쓴다"는 설명은 틀려서 고쳤습니다.
- 쿼리 파일의 구분 줄은 문서의 주석 형식(`# `)으로 바꿨습니다.
- R6 사전 필터에 모듈 경로·서비스 키·`bypass` 조건을 추가했습니다.
- `lower(image)`와 `lastindexof()` 결과를 재사용하도록 바꿨습니다.
- 중복 기준 키를 시나리오별로 정했습니다.

R6의 단계는 서로 독립된 증거가 아닐 수 있습니다. 이번 로그에서도 같은 인코딩 PowerShell이 `enc_powershell`과 `cleanup` 두 단계를 함께 채웠고, 최종 집계는 hostname만으로 묶으므로 다른 사용자·작업의 행위가 합쳐질 수 있습니다. 같은 판정 기준이라도 파이썬 실측기는 이벤트 시각마다 창을 여는 이동 창이고, SIEM 배치는 CRON 시점마다 과거 창을 조회합니다. 따라서 경계 동작까지 같지는 않습니다.

v4 룰을 SIEM에 등록했을 때 티켓은 R5에서만 발행됐고 R1·R2·R6에서는 발행되지 않았습니다(R3·R4는 설계상 미발행). 세 룰은 모두 소문자 와일드카드 패턴(`image_path == "c:\\users\\*"`, `reg_key_path == "*\\services\\*"`)을 원본 필드에 바로 비교했고, R5는 `lower(image)`를 `in()`으로 비교해 와일드카드를 쓰지 않습니다. 하루치 ModuleLoad 이벤트 2,695건에서 `image_path == "c:\\users\\*"`는 0건이었고, 값의 대소문자에 맞춘 `image_path == "C:\\Users\\*"`와 `lower(image_path) == "c:\\users\\*"`는 모두 3건이었습니다. 역슬래시가 없는 `cmd_line == "*bypass*"`도 실제 값이 `-ExecutionPolicy Bypass`라 0건이었고, `contains(lower(cmd_line), "bypass")`는 45건이었습니다. 즉 이 SIEM에서는 와일드카드 비교가 대소문자를 구분했습니다. 쿼리 문서에는 와일드카드가 있으면 대소문자를 무시한다고 되어 있어, 문서와 실제 동작이 달랐습니다. R6는 사전 필터에서 사이드로딩·서비스 등록 후보가 모두 빠져 필수 단계를 채우지 못했고, R4도 조사용 이벤트를 하나도 만들지 못했습니다. 파이썬 실측기는 문서대로 대소문자를 무시하게 구현했기 때문에 CSV 검증에서는 이 차이가 드러나지 않았습니다. v5에서는 와일드카드 앞에 항상 `lower()`를 두고, 경로 접두·포함은 `indexof()`, 부분 문자열은 `contains()`로 바꿨습니다. 수정한 R4 조회 쿼리는 BAS 두 차례 실행분의 인코딩 PowerShell을 모두 잡았고(43건), 실시간 룰의 티켓 발행은 BAS를 다시 실행해 확인할 예정입니다. BAS를 다시 실행하자 R1 티켓이 발행됐지만, 메시지 값 뒤에 `$`가 글자로 남았고 프로세스 하나가 DLL을 여러 개 로드할 때 DLL마다 티켓이 나왔습니다. 문서는 `$필드$` 형식도 허용한다고 설명하지만 이 인스턴스에서는 `$필드`만 치환돼, 모든 룰의 메시지와 중복 기준 필드를 `$필드` 형식으로 바꾸고 R1 중복 기준에서 `file_path`를 뺐습니다. 같은 재실행에서 R5는 정찰 3종이 모두 실행됐는데도 탐지되지 않았습니다. EDR이 `whoami.exe`의 `proc_user_id`만 비워 보내 계정별 집계에서 2종으로 나뉘었기 때문입니다. `host_ip`는 모든 이벤트에 채워져 있어, R5는 계정 대신 `hostname`·`host_ip`로 묶고 계정은 결과의 `user_key` 목록으로만 남기도록 바꾸고 R5·R6 중복 기준을 `$hostname::$host_ip`로 맞췄습니다.

이후 BAS를 다시 실행하며 수정본의 티켓 발행을 확인했습니다. R1·R2는 실시간으로 바로 발행됐습니다. R5는 SIEM 등록본이 계정 기준 이전 버전으로 남아 있어, 결과에 중복 기준 필드 `host_ip`가 없어 티켓이 나오지 않았습니다. 최신본으로 바꾼 뒤에는 whoami 계정이 빈 회차에서도 3종으로 집계돼 발행됐습니다. 그 과정에서 티켓 제목의 배열·날짜 표시를 다듬으려고 배치 쿼리 끝에 `strjoin()`·`string()` 가공을 붙였습니다. 그러자 가상 실행 결과는 정상인데 정기 실행에서는 탐지 기록이 남지 않았고, 이 줄을 빼자 R5·R6 티켓이 발행됐습니다. 원인은 확인하지 못했지만, 가상 실행 통과가 정기 실행 동작을 보장하지 않는다는 점은 확인했습니다. 배치 룰은 결과 가공 없이 두고 정기 실행 결과로 검증합니다.

## 정리

이번 로그에서 확인된 핵심은 두 가지입니다. 첫째, PlugX식 DLL 사이드로딩(`fsguidll.exe` → `fslapi.dll`)은 EDR ModuleLoad 로그에 그대로 남았지만 EDR 위협 탐지로는 올라오지 않았습니다. 같은 폴더 로드와 위험 위치 조건으로 이 이벤트를 후보로 뽑을 수 있었고, 이 방식으로 SIEM에서 보완할 수 있다고 봅니다. 둘째, 단일 행위만으로는 정상 관리 작업과 구분이 어려워, 사이드로딩·서비스 등록을 축으로 단계를 묶는 상관 룰을 두었습니다. 이것이 실제로 오탐을 줄이는지는 운영 로그로 단일 룰과 비교해 확인해야 합니다. 검증 범위는 BAS 로컬 단말 1대, 21분 로그입니다. SIEM에 등록한 뒤에는 와일드카드 비교가 문서와 달리 대소문자를 구분한다는 것을 확인해 고쳤습니다. CSV 실측기를 통과해도 SIEM에서 같은 결과가 나온다는 보장은 없으므로, 이후 룰은 등록 전에 조회 화면에서 조건별 건수를 먼저 확인합니다. 수정본은 BAS 재실행에서 R1·R2·R5·R6 티켓 발행까지 확인했고, 전사 7일 백테스트는 남아 있습니다.

다음에는 인코딩 PowerShell의 base64를 쿼리 안에서 디코딩해 `Resolve-DnsName -Type TXT` 같은 내용 기반 탐지가 가능한지, DNS 서버 로그와 연결해 TXT 조회 자체를 잡을 수 있는지 확인합니다.
