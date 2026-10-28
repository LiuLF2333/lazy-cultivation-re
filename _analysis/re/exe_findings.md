# 懒人修仙传.exe — Reverse-Engineering Reconnaissance

**Target:** `D:\XiuXian\懒人修仙传.exe`
**Size:** 3,088,896 bytes
**SHA-256:** `E781B4D57F714BAEEA7F68E1131A0558B6A74242431AF53D36393C54F52C4093`
**Analysis date:** read-only static analysis; the game was never executed and the EXE was never modified.
**Scratch tooling:** `D:\XiuXian\_analysis\re\*.py`, raw extracts in `D:\XiuXian\_analysis\re\out\`.

> Note: `pefile` is **not** available in the bundled Python 3.12 runtime, so all PE parsing,
> string extraction, single-byte-XOR brute force and x86 length-decoding below was implemented
> from scratch with `struct` (see `peparse.py`, `x86len.py`). Nothing was installed from the network.

---

## 0. Executive summary

| Question | Answer |
|---|---|
| Is the EXE obfuscated? | **No.** Chinese UI strings are plaintext UTF-16LE. A 256-key single-byte-XOR sweep matched **only key `0x00`**. |
| Is the EXE packed? | **No.** Five standard sections, no overlay, no packer markers, .text entropy 6.10–6.71, valid MSVC prologue at the entry point. |
| Does an attribute-selection dialog exist? | **No dedicated one.** 23 DIALOG resources, none is an attribute picker. |
| Is there a *reusable* list-selection routine? | **Yes.** Five different "选择…" prompts share an identical 3-call modal-list idiom (`0x020AB0` / `0x020B30` / `0x009A20`). |
| Scripting engine? | **None.** No Lua/Python/AngelScript/Squirrel/JS. No CLR (data directory 14 is empty). |
| Can MODs change behaviour? | **No — data/resources only.** `Mods\<name>\Data\` + `Mods\<name>\Res\` are existence-checked and the process chdirs into the mod dir. No code loading is tied to MODs. |
| Feasibility of a "player chooses attribute" dialog by binary patching? | **Feasible but multi-point.** Unpacked binary + an existing modal list chooser + a data-driven attribute-id table make it achievable; it is not a one-byte edit and cannot be delivered as a MOD. |

---

## 1. PE structure

### 1.1 Headers

| Field | Value |
|---|---|
| `e_lfanew` | `0x118` |
| Machine | `0x014C` (i386, PE32) |
| Number of sections | 5 |
| TimeDateStamp | 1598426429 → 2020-08-26 07:20:29 UTC |
| ImageBase | `0x00400000` |
| EntryPoint RVA | `0x0020318B` |
| Subsystem | 2 (Windows GUI) |
| DllCharacteristics | `0x8140` |
| SectionAlignment / FileAlignment | `0x1000` / `0x200` |
| SizeOfImage | `0x2FD000` |
| CheckSum | `0x0` |

Entry point bytes (`file 0x20258B`): `E8 11 0D 00 00 E9 7A FE FF FF 3B 0D C4 BF 6B 00 F2 75 02 F2 C3 …`
— a textbook MSVC CRT `_mainCRTStartup` shape (`call __security_init_cookie`-style, then a jump into the CRT), i.e. normal, unencrypted code.

### 1.2 Section table

| Name | VirtAddr | VirtSize | RawPtr | RawSize | Entropy | Characteristics |
|---|---|---|---|---|---|---|
| `.text` | `0x00001000` | `0x0024362A` | `0x00000400` | `0x00243800` | 6.4670 | `0x60000020` CODE \| EXECUTE \| READ |
| `.rdata` | `0x00245000` | `0x0007598C` | `0x00243C00` | `0x00075A00` | 5.2113 | `0x40000040` INITIALIZED_DATA \| READ |
| `.data` | `0x002BB000` | `0x00010568` | `0x002B9600` | `0x00009000` | 4.0110 | `0xC0000040` DATA \| READ \| WRITE |
| `.rsrc` | `0x002CC000` | `0x000068A8` | `0x002C2600` | `0x00006A00` | 4.3233 | `0x40000040` INITIALIZED_DATA \| READ |
| `.reloc` | `0x002D3000` | `0x000290B8` | `0x002C9000` | `0x00029200` | 6.5919 | `0x42000040` DISCARDABLE \| INITIALIZED_DATA \| READ |

Standard `MSVC 2019 + MFC` layout. No non-standard/randomised section names.

### 1.3 Data directories

| # | Name | RVA | Size |
|---|---|---|---|
| 1 | Import | `0x002B71CC` | 420 |
| 2 | Resource | `0x002CC000` | 26792 |
| 5 | BaseReloc | `0x002D3000` | 168120 |
| 6 | Debug | `0x00297F00` | 112 |
| 9 | TLS | `0x00298010` | 24 |
| 10 | LoadConfig | `0x00297F70` | 64 |
| 12 | IAT | `0x00245000` | 2588 |

Notable **absences**: DD[4] Certificate = (0,0); DD[11] BoundImport = (0,0); **DD[14] CLR = (0,0)** (so not .NET); DD[13] DelayImport = none.

### 1.4 Filesystem layout vs. the PE image

The PE file ends exactly where `.reloc` ends:

```
section ends: .text:0x243C00  .rdata:0x2B9600  .data:0x2C2600  .rsrc:0x2C9000  .reloc:0x2F2200
max section end = 0x2F2200 ; file size = 3088896 (0x2F2200) ; overlay bytes = 0
```

**No overlay** — every byte of the 3,088,896-byte file is accounted for by the mapped sections.

### 1.5 Imports (627 IAT slots, 22 DLLs)

`WININET` (4), `steam_api` (7), `KERNEL32` (171), `USER32` (225), `GDI32` (102), `MSIMG32` (2),
`WINSPOOL.DRV` (3), `ADVAPI32` (11), `SHELL32` (10), `COMCTL32` (2), `SHLWAPI` (8), `UxTheme` (12),
`ole32` (21), `OLEAUT32` (12), `gdiplus` (24), `WINMM` (3), `VERSION` (3), `dbghelp` (1),
`OLEACC` (3), `IMM32` (3).

Two `COMCTL32` imports only (`ImageList_AddMasked`, `_TrackMouseEvent`) — MFC uses `InitCommonControlsEx`
via `GetProcAddress`, not a static import.

---

## 2. Task 1 — Embedded strings and XOR brute force

### 2.1 Method

Naïve "XOR the whole 3 MB file 256 times and search" is ~800 MB of work and unnecessary.
Because `XOR(P, K)` equals `P XOR K`, searching for `keyword XOR K` in the **original** buffer is
mathematically identical to XORing the file by `K` and searching for the plaintext keyword.
`strings2.py` therefore computed `bytes(b ^ K for b in keyword_gbk)` for all 256 keys × 17 keywords
and scanned the raw file — ~1000× faster and exactly equivalent.

### 2.2 Result — **the EXE is not XOR-obfuscated**

```
KEY 0x00 (  0) : 27 hits
     属性   off=0x287C4A rva=0x28904A sec=.rdata
     属性   off=0x287C63 rva=0x289063 sec=.rdata
     ...
     确定   off=0x287BC4 rva=0x288FC4 sec=.rdata
     Select off=0x2B8382 rva=0x2B9782 sec=.rdata
     Attribute off=0x24A06C rva=0x24B46C sec=.rdata
```

**No key other than `0x00` produced a single hit** for any of
`选择 / 请选择 / 属性 / 根骨 / 机缘 / 悟性 / 确定 / 取消 / 随机 / 自选 / 列表 / 下拉`,
nor for the ASCII probes `Select` / `Attribute`.

### 2.3 Chinese strings are plaintext **UTF-16LE**, not GBK

A GBK byte search for `属性` in the raw file yields 0 hits; a **UTF-16LE** search yields many.
Full extraction (`utf16all.py`) produced **5,875** NUL-terminated UTF-16 strings; a wider index
(`strxref.py`) produced **15,794** string starts (ASCII + UTF-16) and 9,575 ASCII runs ≥5 chars.

Worked example, `file 0x28EDEC`:

```
E9 6830 0000 5DFF 6F00 ...   ->  U+6839 U+9AA8 U+005B = 根骨[
   ^^^^^ ^^^^^
   9AA8  6839  (little-endian UTF-16LE code units)
```

### 2.4 Contrast — the `.gjd` data tables *are* XOR `0xC6`

Confirmed directly against `D:\XiuXian\data\ItemTable.gjd`:

```
first bytes decoded with ^0xC6 (GBK):
  ID,名称,图标,分类,子分类,从分类,品质,等级,条件,判断,条件值,售价,最大叠加,type1,value1,type2,value2,说明
  20001,《江湖功法》,95,3,0,0,3,1,0,0,0,10000,99,200,40700,0,0,使用后可学会基本的江湖技能

选择  raw-occurrences: 0   xored-occurrences: 1
属性  raw-occurrences: 0   xored-occurrences: 7
根骨  raw-occurrences: 0   xored-occurrences: 1
机缘  raw-occurrences: 0   xored-occurrences: 1
```

**Conclusion:** the 0xC6 XOR obfuscation is a *data-table* measure only. The executable ships its UI
strings in the clear. Therefore string-based reverse engineering of the EXE is unobstructed, and
`.gjd` tables are trivially decodable.

---

## 3. Task 2 — Selection UI / MFC RTTI

### 3.1 MFC/ATL RTTI is present

`.rdata` contains the statically-linked MFC type-name table (256 `CMFC*` names, plus):

```
0x24766C CDialog        0x247674 CButton        0x24767C CListBox      0x247688 CComboBox
0x247694 CEdit          0x247854 CDialogEx      0x246BFC CTabCtrl      0x246C08 CTreeCtrl
0x246C14 CListCtrl      0x25CD08 CScrollView    0x24C514 CFormView     0x24A5F8 CPropertyPage
0x24A608 CPropertySheet 0x25CEB8 CMFCListCtrl   0x269E54 CMFCDropDownListBox
```

`.data` holds the `.?AV…@@` RTTI descriptors (e.g. `0x2BE698 .?AV?$CComObjectRootEx@…`,
`0x2BE8C8 .?AVAFX_MODULE_THREAD_STATE@@`).

> Caveat: these `CMFC*`/`CListBox` symbols come from the **statically linked MFC library**, not from
> game-specific classes. Their presence proves the app is an MFC app (and that `CListBox`/`CComboBox`
> machinery is linked in and available to call), but game classes were compiled with RTTI disabled —
> no game-specific class names appear.

### 3.2 The complete inventory of DIALOG resources — **no attribute picker**

Resource directory RVA `0x2CC000`, 89 entries, 23 DIALOG resources. Identifying strings
(`dialogs.py`, `itemuse.py`) extracted from each template:

| ID | Size | Identifying strings |
|---|---|---|
| 102 | 200 | 懒人修仙传 1.1.11, SysTabControl32, 老板键（ALT+X） |
| 103 | 64 | (MS Shell Dlg only) |
| 129 | 1782 | 角色创建, 创建, 角色名, 灵根评价, [这有四字] |
| 130 / 134 / 135 / 136 / 148 | 64 | (MS Shell Dlg only) |
| 137 | 1648 | 捡取设置, 白装, 绿装, 蓝装, 青装, 紫装, 橙装, 允许捡取装备品质, 头部 |
| 143 | 100 | 返回 |
| 144 | 108 | 突破境界, 确定 |
| 150 | 284 | 退出保存中，请勿中断, 取消, msctls_progress32 |
| 151 | 116 | 聊天频道-蛮荒, 发送 |
| 152 | 388 | 登录, 注册, 帐号名：, 密码：, 记住帐号 |
| 153 | 720 | 注册帐号, 确定, 取消, 同意霸王条款并签下卖身契 |
| 156 | 192 | PY交易处, 确定, 请输入PY口令： |
| 157 | 106 | 隐藏已完成 |
| 158 | 334 | 天工造物 _(:з」)_, 确定, 请输入制造口令：, -制造道具和装备：ID 数量, -学习技能:ID 等级, 快捷键Alt+M |
| 162 | 76 | 宠物游历记录 |
| 163 | 148 | 请输入新的名字, 确定 |
| 167 | 74 | 道友请三思 |
| 30721 | 226 | 新建(&N) , 确定, 取消, 帮助(&H) — MFC print dialog |
| 30734 | 52 | (empty) — MFC print dialog |

**None of these is an attribute chooser.** There is no dialog whose controls list 根骨/机缘/悟性/…

### 3.3 …but there **is** a reusable modal list-selection routine

Seven in-game prompts of the form "选择X" exist as strings, and disassembling the code that pushes
them (`chooser.py`) reveals that **five of them call the exact same three routines in the same order**:

| Prompt string | VA | RVA | File offset |
|---|---|---|---|
| `选择让[%s]遗忘以下其中一个技能：` | `0x0067F734` | `0x0027F734` | `0x27E334` |
| `选择派遣的宠物：` | `0x0068E960` | `0x0028E960` | `0x28D560` |
| `选择携带的物品：` | `0x0068E9CC` | `0x0028E9CC` | `0x28D5CC` |
| `选择需要注灵的药草` | `0x00690794` | `0x00290794` | `0x28F394` |
| `请选择要洗练的准备` | `0x0069145C` | `0x0029145C` | `0x29005C` |
| `选择使用的版本：新人建议玩原版` | `0x0068FFE4` | `0x0028FFE4` | `0x28EBE4` |
| `随机结果` | `0x006907D4` | `0x002907D4` | `0x28F3D4` |

The shared 3-call idiom, e.g. at the version chooser (`选择使用的版本：新人建议玩原版`):

```
file 0x0AD891  68 E4 FF 68 00        push 0x0068FFE4   ; "选择使用的版本：新人建议玩原版"
file 0x0AD896  8D 8D 7C FF FF FF     lea  ecx,[ebp-0x84]
file 0x0AD89C  E8 0F 32 F7 FF        call 0x020AB0     ; [1] create a wide CString from the title
file 0x0AD8A1  C7 45 FC 00 00 00 00  mov  dword [ebp-4],0
file 0x0AD8A8  6A 20                 push 0x20         ; (extra arg)
file 0x0AD8AA  8D 45 B0              lea  eax,[ebp-0x50]
file 0x0AD8AD  50                    push eax
file 0x0AD8AE  8D 8D 7C FF FF FF     lea  ecx,[ebp-0x84]
file 0x0AD8B4  51                    push ecx
file 0x0AD8B5  8B 4D 08              mov  ecx,[ebp+8]  ; this
file 0x0AD8B8  E8 73 32 F7 FF        call 0x020B30     ; [2] build list entry/string
file 0x0AD8BD  C7 45 FC FF FF FF FF  mov  dword [ebp-4],-1
file 0x0AD8C4  8D 8D 7C FF FF FF     lea  ecx,[ebp-0x84]
file 0x0AD8CA  E8 51 C1 F5 FF        call 0x009A20     ; [3] SHOW the modal selection list
file 0x0AD8CF  8B 55 8C              mov  edx,[ebp-0x74]
...
file 0x0AD8DC  E8 3F C7 FA FF        call 0x05A020     ; consumer of the result
file 0x0AD8E1  6A 14                 push 0x14
file 0x0AD8E8  E8 63 BE F5 FF        call 0x009750
```

Call-site table (offset of the third call = "show the chooser"):

| Prompt | `0x020AB0` | `0x020B30` | `0x009A20` (show) |
|---|---|---|---|
| 选择派遣的宠物： | `0x09F281` | `0x09F2A0` | `0x09F2B2` |
| 选择携带的物品： | `0x09F4DF` | `0x09F4FE` | `0x09F510` |
| 选择使用的版本： | `0x0AD89C` | `0x0AD8B8` | `0x0AD8CA` |
| 选择需要注灵的药草 | `0x0B3DE7` | `0x0B3E06` | `0x0B3E18` |
| 请选择要洗练的准备 | `0x0BBAB6` | `0x0BBAD5` | `0x0BBAE7` |

The routine at **`0x009A20`** is a tiny thunk, which makes it easy to identify and call:

```
file 0x009A20  55              push ebp
file 0x009A21  8B EC           mov  ebp,esp
file 0x009A23  51              push ecx
file 0x009A24  89 4D FC        mov  [ebp-4],ecx     ; this
file 0x009A27  8B 4D FC        mov  ecx,[ebp-4]
file 0x009A2A  E8 D1 FF FF FF  call 0x009A00       ; the real implementation
file 0x009A2F  8B E5           mov  esp,ebp
file 0x009A31  5D              pop  ebp
file 0x009A32  C3              ret
file 0x009A33  CC CC CC ...    (int3 padding)
```

`0x020AB0` is a wide-string constructor with a full SEH frame
(`55 8B EC 6A FF 68 08 10 63 00 64 A1 00 00 00 00 50 51 A1 C4 BF 6B 00 33 C5 50 8D 45 F4 64 A3 00 00 00 00 …`);
`0x020B30` takes `(this, string, count)`, calls `0x020DB0`, and is the list-population step.

**This is the artefact the task asked about: a reusable modal "choose one from a list" UI already
exists in the executable and is invoked from five independent features.** It is a better reuse target
than any generic `CListBox` because its argument convention is observable at five call sites.

---

## 4. Task 3 — Scripting engine: **none**

| Probe | ASCII | UTF-16 | Verdict |
|---|---|---|---|
| `lua`, `lua_State`, `luaL_` | 0 | 0 | absent |
| `python`, `Python` | 0 | 0 | absent |
| `angelscript`, `Angel` | 0 | 0 | absent |
| `squirrel`, `.nut` | 0 | 0 | absent |
| `javascript`, `quickjs`, `duktape`, `mruby`, `ruby` | 0 | 0 | absent |
| `V8` | 13 | 0 | **false positive** — matches inside raw x86 code bytes and data (e.g. `…8bF\x0c\x8d{(W…`), not a symbol |
| `script` | 7 | 6 | **false positive** — substrings such as `De`**`script`**`or` in RTTI text and the Unicode `Script` property names at `0x24581E` |
| `mscoree.dll` | 0 | 1 | MSVC CRT stub; paired with `CorExitProcess`. **DD[14] CLR is empty ⇒ not managed code** |
| `clr` | 1 | 0 | substring of `__`**`clr`**`call` in the MSVC type-name table |

Dynamic code loading *does* exist but is unrelated to scripting:

```
LoadLibraryA               call sites in .text = 0
LoadLibraryW               call sites in .text = 3
LoadLibraryExW             call sites in .text = 5
GetProcAddress             call sites in .text = 90
FreeLibrary                call sites in .text = 18
VirtualProtect             call sites in .text = 2
```

This is the normal footprint of MFC + delay-loaded `gdiplus`/`UxTheme`/`dbghelp`/`steam_api`
(`MiniDumpWriteDump` is imported for the crash dumper `Dump_1.%d.%d_%d.dmp`).

**Conclusion: there is no scripting engine and no way to add behaviour without touching native code.**

---

## 5. Task 4 — How MODs load, and what they can change

### 5.1 Configuration chain

`D:\XiuXian\config.ini`:

```ini
[ModConfig]
SelMod=
```

String evidence (all UTF-16LE; offsets verified by `modxref.py`):

| String | File offset | RVA | VA |
|---|---|---|---|
| `config.ini` | `0x28FEBC` | `0x0028FEBC` | `0x0068FEBC` |
| `ModConfig` | `0x28FF1C` | `0x0028FF1C` | `0x0068FF1C` |
| `SelMod` | `0x28FEE0` | `0x0028FEE0` | `0x0068FEE0` |
| `Mods\` | `0x2923D4` | `0x002923D4` | `0x006923D4` |
| `\Res\` | `0x292754` | `0x00292754` | `0x00692754` |
| `\Data\` | `0x292778` | `0x00292778` | `0x00692778` |
| `原版` | `0x292630` | `0x00292630` | `0x00692630` |
| `\*.*` | `0x292638` | `0x00292638` | `0x00692638` |
| `explorer` | `0x292674` | `0x00292674` | `0x00692674` |
| `http://www.guajigame.com/modManage.html` | `0x292688` | `0x00292688` | `0x00692688` |
| `重新扫描完成` | `0x2926D8` | `0x002926D8` | `0x006926D8` |
| `刷新MOD信息完成` | `0x292700` | `0x00292700` | `0x00692700` |
| `Mod使用说明\n1.从资料站或网盘下载mod文件\n2.解压至游戏目录中的Mods文件夹中\n3.刷新Mod信息` | `0x290018` | `0x00290018` | `0x00690018` |
| `读取资源失败，请检查Mod是否解压至正确的问题` | `0x292418` | `0x00292418` | `0x00692418` |

### 5.2 The MOD path-building routine (annotated)

Decoded and resolved against the IAT (`modapi.py`):

```
file 0x0C9505  68 04 01 00 00              push 0x104
file 0x0C9511  68 14 27 69 00              push 0x00692714        ; default value buffer
file 0x0C9516  68 44 27 69 00              push 0x00692744        ; "SelMod"
file 0x0C951B  68 30 27 69 00              push 0x00692730        ; "ModConfig"
file 0x0C9520  FF 15 B8 53 64 00           call [0x006453B8] = KERNEL32!GetPrivateProfileStringW
...
file 0x0C9583  68 60 27 69 00              push 0x00692760        ; "Mods\"
file 0x0C958F  E8 4C 7B F6 FF              call 0x0310E0          ; string concat  (Mods\ + <SelMod>)
file 0x0C95A5  E8 36 7B F6 FF              call 0x0310E0
file 0x0C95BB  E8 A0 DE F6 FF              call 0x037460
file 0x0C95C3  68 54 27 69 00              push 0x00692754        ; "\Res\"
file 0x0C95CF  E8 8C 43 F4 FF              call 0x00D960          ; append
file 0x0C95E5  E8 76 DE F6 FF              call 0x037460
file 0x0C95ED  68 78 27 69 00              push 0x00692778        ; "\Data\"
file 0x0C95F9  E8 62 43 F4 FF              call 0x00D960          ; append
file 0x0C9608  FF 15 18 55 64 00           call [0x00645518] = SHLWAPI!PathFileExistsW   ; gate \Res\
file 0x0C9619  FF 15 18 55 64 00           call [0x00645518] = SHLWAPI!PathFileExistsW   ; gate \Data\
file 0x0C962A  FF 15 E0 53 64 00           call [0x006453E0] = KERNEL32!SetCurrentDirectoryW
file 0x0C963F  E8 F3 35 14 00              call 0x20CC37
file 0x0C964D  E8 43 8F 13 00              call 0x202595
```

Imported APIs used across the whole MOD region (`file 0x0C6C00–0x0C9800`):

```
KERNEL32!lstrlenW                    x18
KERNEL32!GetModuleFileNameW          x6      (locate the game root)
KERNEL32!SetCurrentDirectoryW        x3
KERNEL32!GetPrivateProfileStringW    x1
KERNEL32!WritePrivateProfileStringW  x1
SHLWAPI!PathFileExistsW              x2
SHELL32!ShellExecuteW                x2      ("explorer", modManage.html)
USER32!MessageBoxW / MessageBoxA     x3 / x1
```

### 5.3 What a MOD can and cannot do

A MOD is a directory `Mods\<name>\` containing **`Data\` and/or `Res\`** subtrees:

- `Mods\<name>\Data\*.gjd` — overrides data tables.
- `Mods\<name>\Res\*` — overrides art/audio.
- `config.ini [ModConfig] SelMod=<name>` selects it; `原版` (vanilla) deselects.

The loader performs **only** `GetPrivateProfileStringW` → concatenate path → `PathFileExistsW` →
`SetCurrentDirectoryW`. There is:

- **no DLL loading** keyed on the MOD name,
- **no script/plugin loading**,
- **no manifest, ABI or code hook** of any kind.

**⇒ MODs can change data and resources only. They cannot change item-use behaviour.**

---

## 6. Task 5 — Packing status: **not packed**

| Check | Result |
|---|---|
| Section names | `.text .rdata .data .rsrc .reloc` — all standard; no `UPX0`/`UPX1`/`.aspack`/`.vmp`/`.enigma` |
| Packer signatures (`UPX!`, `ASPack`, `PECompact`, `FSG!`, `MEW`, `Themida`, `VMProtect`, `.petite`, `MPRESS`, `Enigma`, `Nullsoft`) | **all 0 occurrences** |
| Overlay / trailing data | **0 bytes** (max section end == file size) |
| Entry-point code | valid MSVC CRT code, not a packer stub |
| `.text` entropy, 64 KB blocks | 6.1044, 6.1411, 6.1434, 6.4109, 6.4417, 6.4428, 6.3754, 6.4094, 6.7059, 6.0576 (packed code ≈ 7.9) |
| Whole-section entropy | `.text` 6.4670, `.rdata` 5.2113, `.data` 4.0110, `.rsrc` 4.3233, `.reloc` 6.5919 |
| Plaintext density | `.text` 427 ASCII runs / 27 UTF-16 runs; `.rdata` 1,860 / 2,496; `.data` 509 / 6 |

Strings appear in plaintext throughout, `.reloc` holds 3,366 ASCII runs (typical of a large MFC
relocation table), and `.text` entropy sits in the normal 6.0–6.7 band for MFC-heavy x86 code.

**⇒ The binary is fully unpacked and directly patchable.**

---

## 7. The attribute system (supporting evidence for the question)

### 7.1 `GameAttribStringTable.gjd` — the attribute namespace

Header: `属性名（最多8字）,内ID,属性类型,计算方式,价值,包装字符串(最多30个字）,数值填充方式,备注`
117 rows, internal IDs from 0 to 5001.

| Internal ID | Attribute | | Internal ID | Attribute |
|---|---|---|---|---|
| 0 | 无 | | 21 | 暴击 |
| **1** | **根骨** | | 22 | 暴伤 |
| 2 | 真气 | | 23 | 破防 |
| 3 | 武术 | | 24 | 破魔 |
| 4 | 灵力 | | 25 | 穿透 |
| 5 | 灵巧 | | 26 | 命中 |
| **6** | **机缘** | | 27 | 闪避 |
| 10 | 体力 | | 28–32 | 金/木/水/火/土系亲和 |
| 11 | 法力 | | 33 | 嘲讽 |
| 12 | 护盾 | | 34 | 神念 |
| 13 | 物攻 | | 35 | 吸魂 |
| 14 / 15 | 低物攻 / 高物攻 | | 50–81 | 百分比与衍生类 |
| 16 | 法攻 | | 82–91 | 等级/境界/经验类 |
| 17 / 18 / 19 / 20 | 防御 / 法防 / 护甲 / 速度 | | … | (up to 5001) |

This is the definitive list a player-facing attribute chooser would present.

### 7.2 EXE-side attribute strings

| String | File offset | VA | Code xref |
|---|---|---|---|
| `无效属性 %d` | `0x27FD80` | `0x00681180` | `push` at file `0x01728A` |
| `属性异常，无领悟属性` | `0x2889BC` | `0x00689DBC` | `push` at file `0x0790C5` |
| `重构角色属性.` | `0x2899AC` | `0x0068ADAC` | `push` at file `0x085893` |
| `查看宠物%s时发现角色属性已经变化，主动刷新属性` | `0x2867A4` | `0x00687BA4` | `push` at file `0x06DCA0` |
| `当前属性` | `0x28FF8C` | `0x0069138C` | `push` at file `0x0BB71E` |
| `新属性` | `0x28FFA0` | `0x006913A0` | `push` at file `0x0BB8CE` |
| `没有可保存的属性` | `0x28F8B4` | `0x00690CB4` | `push` at file `0x0B54D8` |
| `没有可以洗练的属性` | `0x28FFB8` | `0x006913B8` | `push` at file `0x0BBA1C` |
| `无洗练属性` | `0x28FFCC` | `0x006913CC` | `push` at file `0x0BB9C7` |
| `随机结果` | `0x28F3D4` | `0x006907D4` | `push` at file `0x0B4348` |
| `根骨[` / `机缘[` | `0x28EDEC` / `0x28EE28` | `0x006901EC` / `0x00690228` | `push` at `0x0AECFA` / `0x0AEFE8` |
| `所有基础属性增加20点` | `0x284A30` | `0x00685E30` | **no direct xref** (reached via a pointer table) |

The function containing the `无效属性 %d` push (starts at file `0x017240`) is an
**attribute-id → display-string** builder: it looks the id up in a container
(`mov ecx,[0x6C8878]; call …`), rejects unknown ids with `无效属性 %d`, then special-cases
**id 13**:

```
file 0x0172C2  83 7D 08 0D   cmp dword [ebp+8],0xD      ; 13 == 物攻
file 0x0172D6  68 A4 11 68 00 push "攻击  %d～%d"
file 0x0172F7  68 B8 11 68 00 push "攻击 %d"
file 0x017312  68 C4 11 68 00 push "攻击 +%d"
```

and otherwise emits `+%d` / ` %d` suffixes. This tells us attribute records carry an id, a value and
a display wrapper — consistent with the `包装字符串` / `数值填充方式` columns of the table above.

### 7.3 `type1` and the `132` handler

`ItemTable.gjd` — 285 rows, **35 distinct `type1` values** (all either 0 or in 100–303):

```
0(83) 100(1) 105(11) 106(18) 107(4) 108(3) 110(5) 112(1) 113(1) 114(1) 115(8) 116(2) 117(1)
118(3) 119(1) 120(1) 121(1) 122(1) 123(16) 124(1) 126(1) 127(2) 128(1) 129(3) 130(2) 131(2)
132(2) 200(61) 201(6) 202(2) 203(13) 204(2) 300(20) 302(2) 303(3)
```

The `type1=132` rows — the only "attribute pill" candidates in a player-visible sense:

| ID | 名称 | 图标 | 分类 | 品质 | 等级 | 售价 | 叠加 | type1 | value1 | type2 | value2 | 说明 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 22365 | 测试-加根骨 | 192 | 1 | 7 | 3 | 20000 | 99 | **132** | 50 | 0 | 0 | **测试限制次数的定向加属性道具** |
| 22366 | 测试-加机缘 | 192 | 1 | 7 | 2 | 20000 | 99 | **132** | 50 | 0 | 0 | **测试限制次数的定向加属性道具** |

Two facts matter here:

1. **The item IDs 22365 / 22366 appear nowhere in the executable.** A raw scan for the little-endian
   dwords `0x5759` (22365) and `0x575A` (22366) yields **0 occurrences in `.text` and 0 in the whole
   file**. So the attribute injected is **not** hardcoded per item — it is read from data.
2. **The column names `type1`, `value1`, `value2` do not appear anywhere in the EXE** (ASCII 0,
   UTF-16 0, GBK 0), whereas `名称`/`说明`/`品质` *do* appear (as unrelated UI strings). The `.gjd`
   header is `ID,名称,图标,…`. Therefore the loader parses the CSV **by column position**, not by name.

The **item-use entry point** is the function at `file 0x075B40` (RVA `0x076740`), identified by its
UI strings:

```
file 0x075C19  push 0x006883F8   ; "是否批量使用%d个%s？"
file 0x075C2F  push 0x00688448   ; "提醒"
file 0x075C42  call [KERNEL32/User32] MessageBoxW
file 0x075C67  call 0x072890     ; perform the use
```

Inside it, `push imm32 132` occurs once, at `file 0x0767F5`:

```
file 0x0767DC  83 BA 90 02 00 00 1D   cmp dword [edx+0x290],0x1D    ; guard on a per-item field (29)
file 0x0767E3  0F 85 4D 03 00 00      jne 0x076B36
file 0x0767E9  C7 85 00 91 FE FF 01 00 00 00   mov dword [ebp-0x6EFF00],1   ; set limit = 1
file 0x0767F3  6A 01                  push 1
file 0x0767F5  68 84 00 00 00         push 132                      ; <-- type1 = 132
file 0x0767FA  8B 4D 08               mov ecx,[ebp+8]
file 0x0767FD  E8 7E 22 FC FF         call 0x038A80                 ; look up value1 for this type1
file 0x076802  89 85 EC 90 FE FF      mov [ebp-0x6F14],eax
...
file 0x07681A  E8 61 AD FB FF         call 0x031580
file 0x076826  E8 45 82 00 00         call 0x07EA70                 ; apply
```

So the `132` path already: (a) reads a value keyed by `type1=132` from the item record via
`0x038A80`, and (b) applies it. The attribute identity therefore travels in the **data**, and the
per-item limit lives in a runtime field at object offset `+0x290`
(the item-use function compares `[obj+0x290]` against a small counter enum 0–29 and against 100 —
that is a *use counter / limit*, **not** `type1`).

> Methodological note: an initial `cmp r/m32, imm8` byte-scan produced a misleading picture because
> `.text` also contains jump tables **and a text-command parser** (e.g. `cmp eax,73/76/84/104` =
> `'I','L','T','h'`). It also matched only `cmp` forms. A properly-decoded sweep (`x86len.py`,
> 0.009 % decode-failure across 3079 functions) plus a raw search over *all* immediate forms
> (`cmp`/`push`) gave the reliable result above: **`132` is present, as `push imm32`, 8× in `.text`.**

---

## 8. Verdict — feasibility of a player-chooses-attribute dialog by binary patching

### 8.1 Arguments in favour

1. **The binary is unpacked and unobfuscated.** No packer, no overlay, plaintext UTF-16 strings,
   normal entropy — a patched copy can be produced and reviewed.
2. **The problem is already almost solved by the game itself.** `type1 = 132` *means*
   "定向加属性道具" (targeted attribute item). The handler exists; it currently obtains the attribute
   from data rather than from the player.
3. **A modal list-selection UI already exists and is called from five independent features**
   (`0x020AB0` → `0x020B30` → `0x009A20`). A player-facing attribute chooser therefore does **not**
   require authoring a new dialog: it requires building the candidate list and calling `0x009A20`,
   exactly as `选择派遣的宠物：` / `选择携带的物品：` / `选择使用的版本：` already do.
4. **The attribute namespace is fully data-driven** — `GameAttribStringTable.gjd`, 117 rows with
   internal IDs and display wrappers, already loaded into a live container (the `无效属性 %d`
   function dereferences it through `mov ecx,[0x6C8878]`).
5. **The dispatch is generic, not per-item** — item IDs are not hardcoded, so one patch covers all
   `132` items (and could be extended to new ones purely through data).

### 8.2 Arguments against / costs

1. **There is no `type1` value that means "let the player pick".** `132` already means "targeted
   attribute from data". A patch must either redirect the `132` branch or claim one of the rarely
   used codes (`129`, `130` exist in ItemTable with 3 and 2 rows respectively, and `125`/`133`–`135`
   have rows in neither). The `132` branch sits inside a ~13 KB function that uses computed jump
   tables, so it is **not** a cleanly delimited handler — the linear disassembler misaligns in
   places there, and the exact branch span still needs recovery (e.g. via recursive-descent tracing
   from `0x0767F5`, or by re-deriving function starts while skipping in-`.text` jump tables).
2. **The chooser's exact argument convention must be pinned down.** Five consistent call sites give
   a strong template (title string + entry string + count), but the caller must also supply the
   correct `this` pointer and read back the selected index from the right stack slot
   (the version chooser reads `[ebp-0x74]` after the call). Getting the ABI wrong crashes the game.
3. **You need the live attribute-table container** to enumerate the candidate attributes, and the
   item-record layout to write the chosen id back. Both are reachable (`0x038A80`, `[0x6C8878]`)
   but need further static work, and the added code must fit in a code cave or be injected.
4. **This cannot be shipped as a MOD.** MODs are data + resources only (§5.3), so the change must be
   an EXE patch (or an injected DLL/hook). That forfeits the clean rollback the MOD mechanism gives
   you and interacts with the Steam integrity check the binary references
   (`游戏启动失败，请通过Steam右键选择游戏-属性-本地文件-检验文件的完整后重试`).

### 8.3 Bottom line

> **Verdict: feasible, and materially easier than a from-scratch UI mod, but it is a multi-point code
> patch — definitely not a one-byte edit, and not expressible as a MOD.**
>
> The two hardest generic obstacles (an unpacked/readable binary, and a pre-existing list-selection
> UI) are both already satisfied. The realistic shape of the change is:
>
> 1. Recover the exact `type1 == 132` branch and its record/store slack inside the item-use function
>    at `file 0x075B40`.
> 2. Enumerate the attribute container (via `0x038A80` / `[0x006C8878]`) and build the list of
>    eligible attribute ids with their display names from the `GameAttribStringTable` records.
> 3. Call the existing chooser chain `0x020AB0` / `0x020B30` / `0x009A20` with a new title string
>    (a string literal can be added to a code cave / unused `.rdata` padding).
> 4. Replace the data-derived attribute with the player's selection, then fall through to the
>    existing "apply" call at `0x07EA70`.
>
> **Easiest legal/lowest-risk alternative first:** since `132` takes its attribute from `value1`
> in the item record, you can already add *distinct* attribute pills (one per attribute) purely by
> extending `ItemTable.gjd` — a pure data change with no patching at all. That gives "player picks
> the pill" behaviour (via the inventory UI) without touching the executable; it is not the same as
> a modal chooser, but it delivers the gameplay outcome at zero binary risk.

---

## 9. Reproduction / artefacts

| File | Purpose |
|---|---|
| `D:\XiuXian\_analysis\re\peparse.py` | manual PE parser (headers, sections, dirs, entropy) |
| `D:\XiuXian\_analysis\re\x86len.py` | x86-32 length decoder (SSE/SSE2/x87/string ops) — 0.009 % failure over `.text` |
| `D:\XiuXian\_analysis\re\strings1.py`, `strings2.py`, `utf16all.py` | string extraction + 256-key XOR keyword sweep |
| `D:\XiuXian\_analysis\re\strxref.py`, `chooser.py`, `disas.py` | string → code cross-reference, chooser-idiom discovery |
| `D:\XiuXian\_analysis\re\dialogs.py`, `resources.py`, `itemuse.py` | resource tree + DIALOG template parsing |
| `D:\XiuXian\_analysis\re\modapi.py`, `modxref.py`, `verify2.py` | MOD loader disassembly with IAT resolution |
| `D:\XiuXian\_analysis\re\jumptables.py`, `switcher.py`, `census2.py`, `finalcheck.py` | switch/field/immediate analysis |
| `D:\XiuXian\_analysis\re\out\utf16_all_strings.txt` | 5,875 UTF-16 strings (offset, RVA, text) |
| `D:\XiuXian\_analysis\re\out\ascii_strings.txt` | 9,575 ASCII strings (offset, RVA, section, text) |
| `D:\XiuXian\_analysis\re\out\xor_keyword_hits.txt` | the 256-key XOR result (key 0x00 only) |
| `D:\XiuXian\_analysis\re\out\resources.txt` | full 89-entry resource tree |
| `D:\XiuXian\_analysis\re\out\mod_loader.txt` | annotated MOD-loader disassembly |
| `D:\XiuXian\_analysis\re\out\dispatcher.txt` | annotated item-use / parser-region disassembly |

All writes are confined to `D:\XiuXian\_analysis\re\`; the target EXE was opened read-only and its
SHA-256 still matches `E781B4D5…52C4093`.
