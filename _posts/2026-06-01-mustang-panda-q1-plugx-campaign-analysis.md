---
title: Chinese PlugX Attack Campaign Analysis — Q1 2026
date: 2026-06-01 00:00:00 +0900
categories:
- Malware Analysis
tags: []
author: mmamm4
---

# Chinese PlugX Attack Campaign Analysis — Q1 2026

## 1. Overview

PlugX is a well-known Remote Access Trojan (RAT) primarily associated with Chinese APT groups, deployed for long-term covert intrusion and intelligence theft operations. Recent PlugX threat actors have increasingly concentrated on targeted attacks against diplomatic entities and specific nations in Southeast Asia and the Middle East.

This report presents analytical findings derived from malware samples obtained from notable PlugX attack campaigns identified in Q1. Recent PlugX-related operations no longer follow a single standardized malware template; instead, the threat actor customizes the trigger file, loader configuration, and encryption scheme independently for each campaign objective.

The primary focus of this analysis is not to characterize the broad features of PlugX, but to examine the distinctive differences observed across variants identified in multiple attack campaigns. This report provides a detailed account of the specific technical adaptations employed by the threat actors to evade detection, as well as the evolutionary trajectory of those adaptations.

| **Campaign Name** | **Primary Target Nations** | **Lure Document Content** |
| --- | --- | --- |
| BRICS+ Security Summit Campaign | Diplomats of BRICS+ member states, international counter-terrorism organizations and experts | Impersonates the Russian Ministry of Foreign Affairs (Ministry of Foreign Affairs of the Russian Federation); disguised as a BRICS+ counter-terrorism conference report |
| Hội nghị bàn giao công tác (Work Handover Meeting) | Vietnam | Disguised as personnel transfer-related content from the Vietnamese Ministry of Public Security (police and domestic administrative affairs) |
| Turkish e-Invoice (e-Fatura) | Turkey | Disguised as a payment receipt from a Turkish travel agency (Jolly Tour) |
| OECD Energy Market Implications | OECD member states | Disguised as an OECD report on the Middle East situation and energy market implications |
| Nepal CIAA Impersonation Campaign | Nepali government agencies and public education administrators | Impersonates Nepal's Commission for the Investigation of Abuse of Authority (CIAA) |

## 2. Trigger Files and Lure Documents

### 2-1. BRICS+ Security Summit Campaign

- BRICS Report.lnk (shortcut file)
- Impersonates the Russian Ministry of Foreign Affairs (Ministry of Foreign Affairs of the Russian Federation); disguised as a BRICS+ counter-terrorism conference report

    ![BRICS decoy.png](/assets/img/posts/2026-06-01-mustang-panda-q1-plugx-campaign-analysis/BRICS_decoy.png)

### 2-2. Hội nghị bàn giao công tác (Work Handover Meeting)

- Hội nghị bàn giao công tác.docx.lnk (shortcut file)
- The lure document appears to impersonate sensitive personnel transfer notices from the Vietnamese Ministry of Public Security. Notably, the term "Bất Phong," used with a "breaking news" connotation, is not a standard Vietnamese expression — the more natural equivalent would be "Bất ngờ." This linguistic irregularity suggests the document was authored by a non-native Vietnamese speaker, likely using a machine translation tool.

    ![vietnam decoy.png](/assets/img/posts/2026-06-01-mustang-panda-q1-plugx-campaign-analysis/vietnam_decoy.png)

### 2-3. Turkish e-Invoice (e-Fatura)

- e-Fatura.chm (Windows Help file)
- Disguised as a payment receipt from a Turkish travel agency (Jolly Tour)

    ![chm decoy1 .png](/assets/img/posts/2026-06-01-mustang-panda-q1-plugx-campaign-analysis/chm_decoy1_.png)

### 2-4. OECD Energy Market Implications

- OECD_Update_on_implications_for_energy_markets_of_events_in_the_Middle_East.lnk (shortcut file)
- Disguised as an OECD report on the Middle East situation and energy market implications

    ![oecd energy decoy.png](/assets/img/posts/2026-06-01-mustang-panda-q1-plugx-campaign-analysis/oecd_energy_decoy.png)

### 2-5. Nepal CIAA Impersonation Campaign

- 6z03.msi (Windows Installer file)
- Disguised as an official notice from the Surkhet branch of Nepal's anti-corruption investigative body, the Commission for the Investigation of Abuse of Authority (CIAA)

    ![msi decoy.png](/assets/img/posts/2026-06-01-mustang-panda-q1-plugx-campaign-analysis/msi_decoy.png)

## 3. Behavioral Analysis

### 3-1. Initial Compromise and Trigger Mechanism

The threat actor employs various trigger file types tailored to the target environment to establish initial access. Upon execution, each file invokes internal scripts to proceed to subsequent stages.

- **LNK (Shortcut File):** Disguised as a document to lure users into clicking; executes embedded CMD/PowerShell commands upon opening.
- **CHM (Windows Help File):** Executes malicious scripts via the HTML Help execution engine (`hh.exe`).
- **MSI (Windows Installer File):** Distributed and executed under the guise of a legitimate software installation process.

**Comparative Trigger Script Analysis**

| **Campaign** | BRICS+ Security Summit Campaign | Hội nghị bàn giao công tác (Work Handover Meeting) |
| --- | --- | --- |
| **Target File** | `BRICS Report.zip` | `Hội nghị bàn giao công tác.docx.zip` |
| **Extraction Offset** | `714` bytes | `746` bytes |
| **Extracted Data Size** | `1,453,568` bytes (approx. 1.45 MB) | `2,906,624` bytes (approx. 2.9 MB) |
| **Temporary File Name** | `nrtzrghg.kq` | `jmgszngj.mi` |
| **Final Executable** | `steam_monitor.exe` | `Avk.exe` |

### 3-2. File Dropping and Execution Environment Setup

Once the script embedded in the trigger file executes, a set of files required for malicious operations is dropped into specific system directories (e.g., `%AppData%`, `%Public%`).

- **File Set Components:**
    1. **Legitimate Binary:** A trusted executable carrying a valid digital signature.
    2. **Malicious DLL:** A library file named to induce the legitimate binary to load it.
    3. **Encrypted Data:** Encoded/encrypted binary data (e.g., `.dat`, `.bin`) containing the final payload.

### 3-3. DLL Side-Loading

DLL Side-Loading is the core technique employed to evade security solution detection.

1. **Legitimate Process Execution:** The dropped legitimate binary is executed to bypass whitelist-based detection by security products.
2. **Malicious DLL Loading:** When the legitimate binary runs, it preferentially loads the malicious DLL placed in the same directory.
3. **In-Memory Decryption:** The loaded malicious DLL reads the encrypted data file from disk and performs the decryption routine in memory.

### 3-4. Final Payload Execution

The decrypted shellcode is executed directly in memory, ultimately launching the **PlugX malware**.

- **Behavioral Characteristics:** The payload operates in a **fileless** manner — running exclusively in memory rather than as a file on disk — to evade static detection.
- **Key Capabilities:** Establishes communication with a C2 server and performs command-and-control functions including keylogging, file exfiltration, and remote control.

## 4. Cipher and Decryption Comparison

The PlugX malware variant identified on March 1, 2026 (MD5: 20eb9f216a1177ee539a012e6301a93e) closely resembles the "Turkish e-Invoice (e-Fatura)" campaign described in this report and is therefore not analyzed separately. It is nonetheless worth noting that PlugX threat actors have been actively exploiting global geopolitical tensions — particularly those related to the Middle East — as lure content for their campaigns.

| **Campaign** | BRICS+ Security Summit Campaign | Hội nghị bàn giao công tác | Turkish e-Invoice (e-Fatura) | OECD Energy Market Implications | Nepal CIAA Impersonation Campaign |
| --- | --- | --- | --- | --- | --- |
| **Shellcode Decryption Algorithm** | XOR | XOR | RC4 | XOR | XOR |
| **Shellcode Decryption Key** | 0x82 | 0x70 | 20251219@@@ | 0x16 | 0xB |
| **PlugX Config Decryption Algorithm** | RC4 | RC4 | RC4 | RC4 | RC4 |
| **PlugX Config Decryption Key** | CgHFGzl | WqdpseP | qwedfgx202211 | XTrmae | iEYnFBPdx |
| **PlugX Config Decryption Key Length** | 7 | 7 | 13 | 6 | 9 |
| **Keylog Data Encryption Key** | - | - | 0x6F | - | - |

The comparison reveals a consistent characteristic: even after decrypting the PlugX configuration data with the RC4 key, the output is not immediately human-readable. A secondary custom decryption routine defined by the threat actor — implemented as shown in the script below — must be applied before the configuration data becomes legible.

```python
function Decrypt(encrypted_data, head, step):
    decrypted_result = empty_list()
    
    current_key = head
    
    for each byte in encrypted_data:
        // 1. Decrypt the byte using the current key (starts with 'head')
        decrypted_byte = byte XOR current_key
        decrypted_result.append(decrypted_byte)
        
        // 2. Roll the key for the next byte
        current_key = (current_key + step) % 256
        
    return decrypted_result
```

![image (3).png](/assets/img/posts/2026-06-01-mustang-panda-q1-plugx-campaign-analysis/image_(3).png)

## 5. Indicators of Compromise

**MD5**

```
90a58084ada79de2ee86862a0f1d73ba  AVKTray.dat
20aacc7193179c8312fc76861bdbf9dd  Avk.dll
e7cb954f4bbdbadbd2c0206577621683  Avk.exe
8a1a090b2c5de4a3c31b4062685aff9f  BRICS Report.lnk
7a183bd25d190662c3008c794f6cb604  BRICS Report.zip
63271ecd3936ab7081ff02ed57299a28  BaiNetdisk.zip
4bb305b7acbdaaafcf932aa032ed5afc  Hoi nghi ban giao cong tac.docx.lnk
3f76260dbe617c16f310194338491587  Hoi nghi ban giao cong tac.docx.zip
ab56563f3817e31568e487edc232a7ee  OECD_6z03.msi
80fc64b636834e85ed58220d456cd5c5  OECD_Update_on_implications_for_energy_markets_of_events_in_the_Middle_East.zip
33bbfa6d5c8a1078e4e260e15d563360  OECE_AVKTray.dat
9e77dea40479abf11fc3894bf50829f7  OECE_Avk.dll
e7cb954f4bbdbadbd2c0206577621683  OECE_Avk.exe
7d66f747a787314ea3b9408e3a019421  ShellFolder.exe
f72810d1c8dfd364820ef3d06f6568f8  ShellFolderDepend.dll
2090db51c5ecd85a553b14ee55f04d34  Shelter.ex
c647e6e683a88af07d861847a18468f8  crashhandler.dll
2fc456f26d853676255dd44d8270b9f3  crashlog.dat
7c1a801cb5ca5b3fca96901eabd52dbf  e-Fatura.chm
4e8f302b2a17c3cc64b866acb18424e1  e-Fatura2.chm
f331af4c164a40d13b24def0818e0198  steam_monitor.exe
```

**C2**

```
embwishes[.]com
winesnmore[.]net
carhirechicago[.]com
dalerocks[.]com
www[.]360printsol[.]com

185.219.220[.]73
91.193.17[.]117
```

---

<style>.kr-code-block{margin:1em 0;border-radius:6px;overflow-x:auto;background:#272822;}.kr-code-block>code{display:block;white-space:pre;padding:1em;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:0.85em;line-height:1.5;color:#f8f8f2;background:transparent;}</style>
<details class="kr-orig" markdown="0"><summary>🇰🇷 한국어 원문</summary><div class="kr-content">
<h2>Chinese PlugX 공격 2026년 1분기 분석 보고서</h2>
<h2>1. 개요</h2>
<p>PlugX는 주로 중국 APT 그룹과 연관된 원격 접근 트로이목마(RAT, Remote Access Trojan)로 알려져 있으며, 장기간 은밀한 침투와 정보 탈취를 목적으로 악성코드가 이용되며, 최근 PlugX 공격 그룹은 동남아시아 및 중동 특정 국가 및 외교와 관련된 Target 형태의 공격에 집중화된 양상을 보이고 있습니다.</p>
<p>본 보고서에서는 1분기에 발견된 주요 PlugX 공격 사례에서 확보한 악성코드 샘플들을 분석한 결과를 설명하고 있습니다. 최근 PlugX 관련 공격은 하나의 정형화된 악성코드가 아니라,  목적에 따라 트리거 파일과 로더 구성은 물론 암호화 방식까지 각기 다르게 커스텀된 양상을 보입니다.</p>
<p>본 분석의 핵심은 PlugX의 광범위한 특성을 설명하는 것이 아니라, 다양한 공격 캠페인에서 관찰된 변종들 사이의 특징적 차이점을 분석하는 데 있습니다. 이를 통해 공격자들이 탐지 회피를 위해 사용한 구체적인 기술적 변화와 그 진화 과정을 상세히 다루고자 합니다.</p>
<table>
<thead>
<tr>
<th><strong>캠페인 명칭</strong></th>
<th><strong>주요 타깃 국가</strong></th>
<th><strong>미끼 파일 내용</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>BRICS+ Security Summit Campaign</td>
<td>BRICS+ 회원국 외교관, 국제 대테러 기구 및 전문가</td>
<td>러시아 외무부(Ministry of Foreign Affairs of the Russian Federation)를 사칭하여 BRICS+ 대테러 컨퍼런스 보고서로 위장</td>
</tr>
<tr>
<td>Hội nghị bàn giao công tác(업무 인수인계 회의)</td>
<td>베트남</td>
<td>베트남 공안부(경찰 및 내무 행정)의 인사 이동 관련 내용 위장</td>
</tr>
<tr>
<td>Turkish e-Invoice (e-Fatura)</td>
<td>터키</td>
<td>터키 여행사(Jolly Tour) 결제 영수증 위장</td>
</tr>
<tr>
<td>OECD Energy Market Implications</td>
<td>OECD 회원국</td>
<td>중동 정세 및 에너지 시장 관련 OECD 보고서 위장</td>
</tr>
<tr>
<td>Nepal CIAA Impersonation Campaign</td>
<td>네팔 정부 기관 및 공공 교육 행정직</td>
<td>CIAA 네팔 수사기관(부정부패조사위원회) 위장</td>
</tr>
</tbody>
</table>
<h2>2. 트리거 파일 및 미끼 문서</h2>
<h3>2-1. BRICS+ Security Summit Campaign</h3>
<ul>
<li>BRICS Report.lnk (바로 가기 파일)</li>
<li>
<p>러시아 외무부(Ministry of Foreign Affairs of the Russian Federation)를 사칭하여 BRICS+ 대테러 컨퍼런스 보고서로 위장</p>
<p><img alt="BRICS decoy.png" src="/assets/img/posts/2026-06-01-mustang-panda-q1-plugx-campaign-analysis/BRICS_decoy.png" /></p>
</li>
</ul>
<h3>2-2. Hội nghị bàn giao công tác(업무 인수인계 회의)</h3>
<ul>
<li>Hội nghị bàn giao công tác.docx.lnk (바로 가기 파일)</li>
<li>
<p>해당 문장은 베트남 공안부의 인사 이동과 같은 민감한 내용을 위장한 것으로 보입니다. 또한 '속보' 의미로 사용된 "Bất Phong"은 일반적인 표현이 아니며, 베트남어에서는 "Bất ngờ"가 보다 자연스럽다고 판단됩니다. 따라서, 전반적으로 현지 언어 기준에서 어색한 표현으로 베트남인이 아닌 타 국가 언어 사용자가 번역기를 이용했을 것으로 추측됩니다.</p>
<p><img alt="vietnam decoy.png" src="/assets/img/posts/2026-06-01-mustang-panda-q1-plugx-campaign-analysis/vietnam_decoy.png" /></p>
</li>
</ul>
<h3>2-3. Turkish e-Invoice (e-Fatura)</h3>
<ul>
<li>e-Fatura.chm (윈도우 도움말 파일)</li>
<li>
<p>터키 여행사(Jolly Tour) 결제 영수증 위장</p>
<p><img alt="chm decoy1 .png" src="/assets/img/posts/2026-06-01-mustang-panda-q1-plugx-campaign-analysis/chm_decoy1_.png" /></p>
</li>
</ul>
<h3>2-4. OECD Energy Market Implications</h3>
<ul>
<li>OECD_Update_on_implications_for_energy_markets_of_events_in_the_Middle_East.lnk (바로 가기 파일)</li>
<li>
<p>중동 정세 및 에너지 시장 관련 OECD 보고서 위장</p>
<p><img alt="oecd energy decoy.png" src="/assets/img/posts/2026-06-01-mustang-panda-q1-plugx-campaign-analysis/oecd_energy_decoy.png" /></p>
</li>
</ul>
<h3>2-5. Nepal CIAA Impersonation Campaign</h3>
<ul>
<li>6z03.msi (윈도우 설치 파일)</li>
<li>
<p>네팔의 부패 방지 및 수사 기구인 부정부패조사위원회(CIAA, Commission for the Investigation of Abuse of Authority) 서케트(Surkhet) 지부에서 보낸 공문 위장</p>
<p><img alt="msi decoy.png" src="/assets/img/posts/2026-06-01-mustang-panda-q1-plugx-campaign-analysis/msi_decoy.png" /></p>
</li>
</ul>
<h2>3. 행위 분석</h2>
<h3>3-1. 초기 침투 및 트리거 메커니즘</h3>
<p>공격자는 대상 환경에 따라 다양한 형태의 트리거 파일을 활용하여 초기 침투를 시도합니다. 각 파일은 실행 시 내부 스크립트를 통해 후속 단계로 진행됩니다.</p>
<ul>
<li><strong>LNK (바로 가기 파일):</strong> 문서로 위장하여 사용자의 클릭을 유도, 내부 CMD/PowerShell 명령어 실행</li>
<li><strong>CHM (윈도우 도움말 파일):</strong> HTML 도움말 실행 엔진(<code>hh.exe</code>)을 통해 악성 스크립트 실행</li>
<li><strong>MSI (윈도우 설치 파일):</strong> 정상적인 소프트웨어 설치 과정으로 위장하여 배포 및 실행</li>
</ul>
<p><strong>트리거 파일 실행 시 유사 스크립트 비교</strong></p>
<table>
<thead>
<tr>
<th><strong>캠페인</strong></th>
<th>BRICS+ Security Summit Campaign</th>
<th>Hội nghị bàn giao công tác(업무 인수인계 회의)</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>탐색 대상 파일</strong></td>
<td><code>BRICS Report.zip</code></td>
<td><code>Hội nghị bàn giao công tác.docx.zip</code></td>
</tr>
<tr>
<td><strong>추출 시작 위치 (Offset)</strong></td>
<td><code>714</code> 바이트</td>
<td><code>746</code> 바이트</td>
</tr>
<tr>
<td><strong>추출 데이터 크기</strong></td>
<td><code>1,453,568</code> 바이트 (약 1.45MB)</td>
<td><code>2,906,624</code> 바이트 (약 2.9MB)</td>
</tr>
<tr>
<td><strong>임시 저장 파일명</strong></td>
<td><code>nrtzrghg.kq</code></td>
<td><code>jmgszngj.mi</code></td>
</tr>
<tr>
<td><strong>최종 실행 파일</strong></td>
<td><code>steam_monitor.exe</code></td>
<td><code>Avk.exe</code></td>
</tr>
</tbody>
</table>
<h3>3-2. 파일 드랍 및 실행 환경 구성</h3>
<p>트리거 파일 내부에 포함된 스크립트가 실행되면, 시스템의 특정 경로(<code>%AppData%</code>, <code>%Public%</code> 등)에 악성 행위에 필요한 파일 세트를 드랍합니다.</p>
<ul>
<li><strong>파일 세트 구성:</strong><ol>
<li><strong>정상 바이너리:</strong> 유효한 디지털 서명이 포함된 신뢰할 수 있는 실행 파일</li>
<li><strong>악성 DLL:</strong> 정상 바이너리가 로드하도록 유도된 이름의 라이브러리 파일</li>
<li><strong>암호화된 데이터:</strong> 최종 페이로드가 포함된 인코딩/암호화된 바이너리 데이터( <code>.dat</code>, <code>.bin</code> 등)</li>
</ol>
</li>
</ul>
<h3>3-3. DLL Side-Loading 기법</h3>
<p>보안 솔루션의 탐지를 우회하기 위해 <strong>DLL Side-Loading</strong> 기법을 핵심적으로 사용합니다.</p>
<ol>
<li><strong>정상 프로세스 실행:</strong> 드랍된 정상 바이너리를 실행하여 보안 솔루션의 화이트리스트 기반 탐지를 우회합니다.</li>
<li><strong>악성 DLL 로드:</strong> 정상 바이너리가 실행될 때, 동일 경로에 위치한 악성 DLL을 우선적으로 로드하게 됩니다.</li>
<li><strong>메모리 복호화:</strong> 로드된 악성 DLL은 디스크 상의 암호화된 데이터를 읽어 들여 메모리 상에서 복호화 과정을 수행합니다.</li>
</ol>
<h3>3-4. 최종 페이로드 실행</h3>
<p>복호화가 완료된 쉘코드는 메모리 상에서 직접 실행되며, 최종적으로 <strong>PlugX 악성코드</strong>가 실행됩니다.</p>
<ul>
<li><strong>동작 특성:</strong> 파일 형태가 아닌 메모리 상에서만 실행되는 <strong>Fileless</strong> 방식으로 동작하여 정적 탐지를 회피합니다.</li>
<li><strong>주요 기능:</strong> C2 서버와 통신을 수립하고 키로깅, 파일 탈취, 원격 제어 등의 명령 제어 기능을 수행합니다.</li>
</ul>
<h2>4. 암호 및 복호화 비교</h2>
<p>암호 및 복호화 비교에서 2026년 03월 01일 확인되는 PlugX 악성코드의 경우(md5 20eb9f216a1177ee539a012e6301a93e), 본 보고서에서 언급하고 있는  "Turkish e-Invoice (e-Fatura)"와 거의 흡사하여 본 보고서에서 언급은 하지 않았습니다. 다만 PlugX 공격 그룹은 최근 중동지역에서의 긴장 상태와 관련된 세계적인 이슈 역시 공격을 위한 미끼 파일(Decoy) 형태로 이용하고 있는 실정입니다.</p>
<table>
<thead>
<tr>
<th><strong>캠페인</strong></th>
<th>BRICS+ Security Summit Campaign</th>
<th>Hội nghị bàn giao công tác</th>
<th>Turkish e-Invoice (e-Fatura)</th>
<th>OECD Energy Market Implications</th>
<th>Nepal CIAA Impersonation Campaign</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>쉘코드 복호화 알고리즘</strong></td>
<td>XOR</td>
<td>XOR</td>
<td>RC4</td>
<td>XOR</td>
<td>XOR</td>
</tr>
<tr>
<td><strong>쉘코드 복호화 키</strong></td>
<td>0x82</td>
<td>0x70</td>
<td>20251219@@@</td>
<td>0x16</td>
<td>0xB</td>
</tr>
<tr>
<td><strong>PlugX 구성 정보 복호화 알고리즘</strong></td>
<td>RC4</td>
<td>RC4</td>
<td>RC4</td>
<td>RC4</td>
<td>RC4</td>
</tr>
<tr>
<td><strong>PlugX 구성 정보 복호화 키</strong></td>
<td>CgHFGzl</td>
<td>WqdpseP</td>
<td>qwedfgx202211</td>
<td>XTrmae</td>
<td>iEYnFBPdx</td>
</tr>
<tr>
<td><strong>PlugX 구성 정보 복호화 키 길이</strong></td>
<td>7</td>
<td>7</td>
<td>13</td>
<td>6</td>
<td>9</td>
</tr>
<tr>
<td><strong>키로깅 데이터 암호화 키</strong></td>
<td>-</td>
<td>-</td>
<td>0x6F</td>
<td>-</td>
<td>-</td>
</tr>
</tbody>
</table>
<p>비교 결과에서 PlugX 구성 정보를 RC4 키로 복호화해도 가독성 있는 설정 정보가 보이지 않는 특성이 확인되며, 추가적으로 공격자가 정의한 복호화를 아래 스크립트를 이용한 이후 가독성 있는 설정 정보가 보입니다.</p>
<div class="kr-code-block"><code><span class="n">function</span> <span class="n">Decrypt</span><span class="p">(</span><span class="n">encrypted_data</span><span class="p">,</span> <span class="n">head</span><span class="p">,</span> <span class="n">step</span><span class="p">):</span><br>    <span class="n">decrypted_result</span> <span class="o">=</span> <span class="n">empty_list</span><span class="p">()</span><br><br>    <span class="n">current_key</span> <span class="o">=</span> <span class="n">head</span><br><br>    <span class="k">for</span> <span class="n">each</span> <span class="n">byte</span> <span class="ow">in</span> <span class="n">encrypted_data</span><span class="p">:</span><br>        <span class="o">//</span> <span class="mf">1.</span> <span class="n">Decrypt</span> <span class="n">the</span> <span class="n">byte</span> <span class="n">using</span> <span class="n">the</span> <span class="n">current</span> <span class="n">key</span> <span class="p">(</span><span class="n">starts</span> <span class="k">with</span> <span class="s1">&#39;head&#39;</span><span class="p">)</span><br>        <span class="n">decrypted_byte</span> <span class="o">=</span> <span class="n">byte</span> <span class="n">XOR</span> <span class="n">current_key</span><br>        <span class="n">decrypted_result</span><span class="o">.</span><span class="n">append</span><span class="p">(</span><span class="n">decrypted_byte</span><span class="p">)</span><br><br>        <span class="o">//</span> <span class="mf">2.</span> <span class="n">Roll</span> <span class="n">the</span> <span class="n">key</span> <span class="k">for</span> <span class="n">the</span> <span class="nb">next</span> <span class="n">byte</span><br>        <span class="n">current_key</span> <span class="o">=</span> <span class="p">(</span><span class="n">current_key</span> <span class="o">+</span> <span class="n">step</span><span class="p">)</span> <span class="o">%</span> <span class="mi">256</span><br><br>    <span class="k">return</span> <span class="n">decrypted_result</span><br></code></div>

<p><img alt="image (3).png" src="/assets/img/posts/2026-06-01-mustang-panda-q1-plugx-campaign-analysis/image_(3).png" /></p>
<h2>5. 침해 지표</h2>
<p><strong>md5</strong></p>
<p>90a58084ada79de2ee86862a0f1d73ba  AVKTray.dat
20aacc7193179c8312fc76861bdbf9dd  Avk.dll
e7cb954f4bbdbadbd2c0206577621683  Avk.exe
8a1a090b2c5de4a3c31b4062685aff9f  BRICS Report.lnk
7a183bd25d190662c3008c794f6cb604  BRICS Report.zip
63271ecd3936ab7081ff02ed57299a28  BaiNetdisk.zip
4bb305b7acbdaaafcf932aa032ed5afc  Hội nghị bàn giao công tác.docx.lnk
3f76260dbe617c16f310194338491587  Hội nghị bàn giao công tác.docx.zip
ab56563f3817e31568e487edc232a7ee  OECD_6z03.msi
80fc64b636834e85ed58220d456cd5c5  OECD_Update_on_implications_for_energy_markets_of_events_in_the_Middle_East.zip
33bbfa6d5c8a1078e4e260e15d563360  OECE_AVKTray.dat
9e77dea40479abf11fc3894bf50829f7  OECE_Avk.dll
e7cb954f4bbdbadbd2c0206577621683  OECE_Avk.exe
7d66f747a787314ea3b9408e3a019421  ShellFolder.exe
f72810d1c8dfd364820ef3d06f6568f8  ShellFolderDepend.dll
2090db51c5ecd85a553b14ee55f04d34  Shelter.ex
c647e6e683a88af07d861847a18468f8  crashhandler.dll
2fc456f26d853676255dd44d8270b9f3  crashlog.dat
7c1a801cb5ca5b3fca96901eabd52dbf  e-Fatura.chm
4e8f302b2a17c3cc64b866acb18424e1  e-Fatura2.chm
f331af4c164a40d13b24def0818e0198  steam_monitor.exe</p>
<p><strong>C2</strong></p>
<p>embwishes[.]com
winesnmore[.]net
carhirechicago[.]com
dalerocks[.]com
www[.]360printsol[.]com</p>
<p>185.219.220[.]73
91.193.17[.]117</p>
</div></details>

