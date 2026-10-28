# 懒人修仙传 —— 逆向分析与战斗加速补丁

对《懒人修仙传》v1.1.1.11（Steam 版，PE32 x86 / MFC，未加壳）的静态逆向分析，
以及在其基础上做出的**战斗回合加速补丁**与**原生 GDI 句柄泄漏修复**。

> 本仓库**不包含**游戏本体、DLL、美术资源与存档（见 `.gitignore`）。
> 所有补丁产物都由仓库内的脚本从**你自己的正版 exe** 现场生成。

---

## 一、成果概览

| 项目 | 结果 |
|---|---|
| 战斗速度 | 原版 1 战斗帧/秒 → **约 600 帧/秒**（约 1000~5000 只/分），且不阻塞 UI 操作 |
| 花屏问题 | 定位并修复游戏**原生 GDI 句柄泄漏**（原 +9.6 句柄/秒，约 22 分钟撞上 10000 上限） |
| 原版改动 | 生成新文件，`懒人修仙传.exe` 全程未被修改，可随时回退 |
| 验证方式 | 静态反汇编 + Unicorn x86 仿真（28 项断言）+ 运行时插桩实测 |

### 产物

| 文件 | SHA-256 | 说明 |
|---|---|---|
| `懒人修仙传.exe`（原版） | `f7331e8282943ca2620666f530eb11046c97d0052e04664e2fc7d1d6b601ed3e` | 未改动 |
| `懒人修仙传.speed2.exe` **推荐** | `31cf48aa75f2f6594c7e2eedab787f64cfb055237e5a76cdac98cf114a6560c1` | 加速 + 修泄漏，**保留 ASLR**（代码全位置无关） |
| `懒人修仙传.speed.exe` | `74a3860c5cbe4cc4ab3581a7de307fea4cf96a1bd1e4d4a13d58bc00bcc241f0` | 同上，但关闭了 ASLR（早期版本） |

两者功能一致，仅 ASLR 处理方式不同。**新装请用 `speed2`。**

---

## 二、快速开始

```powershell
# 1. 生成需要的全部产物（各自带原始字节校验，版本不符会拒绝写入）
python _analysis\battle\patch_battle_speed.py "D:\XiuXian\懒人修仙传.speed2.exe"

# 2. 验证
python _analysis\battle\verify_battle_speed.py     # 字节差异 / PE 头 / 反汇编
python _analysis\battle\harness_battle_speed.py    # 加速代码洞 17 项
python _analysis\battle\harness_leakfix.py         # 泄漏修复代码洞 11 项

# 3. 直接双击运行 speed2.exe；或备份后覆盖原版
Copy-Item '懒人修仙传.exe' "懒人修仙传.exe.bak.$(Get-Date -Format yyyyMMdd-HHmmss)"
Copy-Item '懒人修仙传.speed2.exe' '懒人修仙传.exe' -Force
```

调参（`_analysis/battle/patch_battle_speed.py` 顶部）：

| 常量 | 默认 | 含义 |
|---|---|---|
| `CAP` | 60 | 每 100 ms 最多推进帧数 → 速度上限 = 10×CAP 帧/秒；改 24 约 2000 只/分 |
| `BUDGET` | 45_000_000 | 单次爆发 TSC 周期上限（≈15 ms @3 GHz）；卡就降到 25_000_000 |
| `WITH_HOUSE` | False | 设为 True 则每帧同时跑 `0x47EE70`（动画/特效推进），1:1 复刻原版帧语义 |

---

## 三、技术要点

### 3.1 战斗是纯帧驱动

`0x48AAB0` 是战斗状态机，`[obj+0x40]` 为阶段：0=回合间等待、1=回合执行、2=回合收尾。
`0x48A000–0x491000` 内无 `Sleep`/`timeGetTime`/QPC 依赖 ⇒ 速度只取决于"调用多少次"。

### 3.2 一秒一次的闸门（原版慢的根源）

```
0x4C5CE0  OnTimer（id-0x3E9 查 0x4C6620 跳转表）
0x4C5D6F  add edx,0x0A          ; 每 100 ms +10
0x4C5D87  cmp eax,[edx+0x24F8]  ; 阈值 100
0x4C5DD1  call 0x4C2A90         ; ★ 每秒一次
0x4C2AA0  call 0x48AAB0         ; ★ 全程序唯一调用点
```

### 3.3 三处补丁

| # | 位置 | 改动 | 作用 |
|---|---|---|---|
| 1 | `0x48AB42` | `7E 33` → `EB 33` | 删除回合间等待（等待帧每帧都在格式化一条日志，是卡顿源） |
| 2 | `0x4C5D66` | 9 字节 → `call 0x703E18` | 把钩子挪进 100 ms 定时器，每拍跑一波 ≤60 帧、≤15 ms 的爆发 |
| 3 | `0x4C5CAA` | 7 字节 → `call 0x703E6B` | 爆发期间旁路战斗日志文本插入（每个波次只放行 1 行） |

所有注入代码位置无关（`E8 rel32` / `[ebp-4]` / 由返回地址推算的常量偏移），
因此 ASLR 可保持开启。`.wash` 节仅加了 `MEM_WRITE` 标志（状态字需要可写）。

### 3.4 原生 GDI 泄漏（花屏的真正原因）

`0x4608E0`（513 条指令、单一返回点）里 `0x460937` 建了一个内存 DC 存到
`[ebp-0x1D4]`，**从不释放**。战斗中约 9 个/秒，10000 上限 ÷ 9.6 ≈ 22 分钟 → 整屏花屏。

修复：`0x46093D` 与 `0x4610FE` 各挂 6 字节钩子，转向两个代码洞——
创建后记住句柄，函数返回前 `DeleteDC` 并清空。

定位过程（两级插桩，均为外部 `ReadProcessMemory` 读计数）：

1. 306 个 GDI 调用点计数 → 唯一净漏是 DC（1271 个），位图/画笔/字体全部配平；
2. 76 个 `CreateCompatibleDC` 调用点按返回地址建哈希表 →
   锁定 `0x460937`（9.0/s，不配位图），与 GDI 总增量 8.8/s 吻合。

修复后实测：GDI 句柄 20 分钟保持 283→288 的摆动（原为 +9.6/秒直线）。

---

## 四、目录结构

```
├─ 战斗加速可行性报告.md          ★ 完整技术报告（含全部地址与验证数据）
├─ 项目分析报告.md / 数据表作用说明.md / 功能可行性报告.md
├─ gjd_editor.py / mod_editor.py   数据表与 MOD 编辑器
└─ _analysis/
   ├─ petool.py                  PE32 地址映射 + 反汇编工具（所有脚本的基础）
   ├─ battle/                    ★ 战斗加速与 GDI 泄漏修复
   │  ├─ patch_battle_speed.py      构建补丁（3 处钩子 + 2 个代码洞）
   │  ├─ verify_battle_speed.py     字节差异 / PE 头 / 反汇编校验
   │  ├─ harness_battle_speed.py    Unicorn 仿真：加速代码洞 17 项
   │  ├─ harness_leakfix.py         Unicorn 仿真：泄漏修复代码洞 11 项
   │  ├─ patch_gdi_probe{,2,3}.py   GDI 调用点插桩版构建
   │  ├─ read_gdi_probe{,2}.py      外部读取计数器
   │  ├─ hotpatch_dc_site*.py       运行中进程的在线插桩
   │  └─ dump.py / battle_*.txt     反汇编导出
   ├─ decode_gjd.py              数据表解码（GBK 文本 XOR 0xC6）
   └─ re/ · reports/ · decoded/  逆向脚本、输出与解码结果
```

---

## 五、踩过的坑（记录以免重犯）

| 现象 | 根因 | 修正 |
|---|---|---|
| 加速后卡顿 | 等待帧每帧格式化一条战斗日志 | 跳过等待 + 爆发预算限时 |
| 进游戏闪退（v4a） | 用 `edx` 存状态指针，而 `rdtsc` 会写 `edx:eax` | 改用 `edi`；仿真改为真实执行 `rdtsc` |
| 进游戏闪退（v4b） | 泄漏修复代码用绝对 IAT 地址，而镜像被 ASLR 重定位 | 改为由返回地址推算偏移（`speed2`） |
| 进程被自己弄崩 | 热补丁把 `.wash` 保护改成 `PAGE_READWRITE`，摘掉了代码洞的执行权限 | 该页必须用 `PAGE_EXECUTE_READWRITE` |

---

## 六、风险与回滚

- 改过的 exe 可能被 Steam 校验判定异常 —— 保留原版 exe 即可随时回滚；
- 首次测试前建议备份 `Save\`（补丁未触及存档格式）；
- 回滚：把 `懒人修仙传.exe.bak.<时间戳>` 改名回 `懒人修仙传.exe`。

仅供个人学习研究使用。
