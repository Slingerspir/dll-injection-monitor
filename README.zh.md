# exebuilder

**语言 / Language:** 中文 **|** [English](README.md)

[![build](https://github.com/Slingerspir/dll-injection-monitor/actions/workflows/build.yml/badge.svg)](https://github.com/Slingerspir/dll-injection-monitor/actions/workflows/build.yml)
[![release](https://img.shields.io/github/v/release/Slingerspir/dll-injection-monitor)](https://github.com/Slingerspir/dll-injection-monitor/releases/latest)

命令行工具：**生成一个能实时查看自己被注入了哪些 DLL 的程序**，
并且可以给它指定任意身份（文件名、图标、版本信息）。

生成的程序打开后是一个窗口，列出自己进程里加载的**全部 DLL**，
被注入的那些标上 `INJ`，状态栏变红，可以一键复制完整报告。

## 下载

直接从 [最新 Release](https://github.com/Slingerspir/dll-injection-monitor/releases/latest) 获取：

| 文件 | 说明 |
|---|---|
| `exebuilder.exe` | 生成器 |
| `demo-monitor.exe` | 开箱即用的监视器，无需参数 |

---

## 1. 构建

需要 MinGW-w64（`gcc` / `windres` 在 PATH 中）：

```bat
build.bat
```

产物：

| 文件 | 说明 |
|---|---|
| `build\exebuilder.exe` | 工具本体（**单文件**，监视器模板已内嵌在它里面） |
| `build\payload_template.exe` | 内嵌用的监视器模板（中间产物，可删） |

---

## 2. 用法

### 2.1 生成一个监视器

```bat
exebuilder.exe build --out javaw.exe --name javaw.exe ^
    --company "Eclipse Adoptium" --desc "OpenJDK Platform binary" ^
    --product "OpenJDK Platform 17.0.2" --version 17.0.2.0
```

运行生成的 `javaw.exe`，窗口标题会是 `javaw.exe - DLL injection monitor`，
里面列出它自己加载的所有 DLL：

```
ST   MODULE                             BASE                PATH
ok   javaw.exe                          0x00007FF7B62D0000  C:\...\javaw.exe
ok   ntdll.dll                         0x00007FF9xxxx0000  C:\WINDOWS\SYSTEM32\ntdll.dll
ok   kernel32.dll                      0x00007FF9xxxx0000  C:\WINDOWS\System32\KERNEL32.DLL
...
INJ  testdll.dll                       0x00007FF991F70000  C:\...\testdll.dll
```

被注入时顶部会变成红色的 `INJECTION DETECTED - 1 injected DLL(s)`。

### 2.2 查看任意 exe 的身份信息

```bat
exebuilder.exe info build\javaw.exe
```

### 2.3 只导出监视器模板（不盖身份）

```bat
exebuilder.exe payload monitor.exe
```

---

## 3. 全部参数

| 参数 | 说明 |
|---|---|
| `--out <path>` | 输出 exe（必填） |
| `--name <str>` | `OriginalFilename`，不给就用输出文件名 |
| `--internal <str>` | `InternalName`，不给就用文件名去掉后缀 |
| `--company <str>` | `CompanyName` |
| `--desc <str>` | `FileDescription` |
| `--product <str>` | `ProductName` |
| `--copyright <str>` | `LegalCopyright` |
| `--version <a.b.c.d>` | `FILEVERSION` / `PRODUCTVERSION` |
| `--icon <path.ico>` | 嵌入图标（支持多尺寸 ico） |
| `--manifest <path>` | 嵌入 manifest xml |
| `--src <path>` | 改用自定义宿主程序，而不是内置监视器 |

支持 `--key value` 和 `--key=value` 两种写法。

---

## 4. 实测

### 4.1 身份信息生效

```
> exebuilder.exe build --out dist\javaw.exe --name javaw.exe ^
      --internal javaw --company "Eclipse Adoptium" ^
      --desc "OpenJDK Platform binary" --product "OpenJDK Platform 17.0.2" ^
      --version 17.0.2.0

[*] extracted built-in monitor (148148 bytes) -> dist\javaw.exe
[+] version resource written (668 bytes)
[+] committed 1 resource group(s)

== dist\javaw.exe ==
  CompanyName       : Eclipse Adoptium
  FileDescription   : OpenJDK Platform binary
  FileVersion       : 17.0.2.0
  InternalName      : javaw
  OriginalFilename  : javaw.exe
  ProductName       : OpenJDK Platform 17.0.2
```

用 PowerShell 的 `(Get-Item x).VersionInfo` 独立核对一致。

### 4.2 注入检测生效

向生成的程序注入一个测试 DLL 后，读它的窗口列表：

```
ListBox has 33 rows
  [30] INJ  testdll.dll   0x7FF991F70000  C:\...\testdll.dll
  [32] [MODULE] testdll.dll  |  base=0x7FF991F70000 size=0x17000 ...
```

未注入时同一列表是 30 行、没有任何 `INJ`。

### 4.3 批量生成不同身份

```
app_svc.exe      Contoso            1.0.0.1    service.exe
app_tool.exe     My Company         3.1.4.0    mytool.exe
javaw.exe        Eclipse Adoptium   17.0.2.0   javaw.exe
```

---

## 5. 检测原理

生成的程序内嵌三层检测：

| # | 名称 | 方法 | 抓什么 |
|---|---|---|---|
| 1 | Toolhelp 模块快照 | `CreateToolhelp32Snapshot` + `Module32First/Next` | 普通 `LoadLibrary` 注入（也是 DLL 列表的来源） |
| 2 | 无文件支撑可执行内存 | `VirtualQuery` 找 `MEM_PRIVATE` + `PAGE_EXECUTE*` | 反射式加载 / 手动映射 |
| 3 | 内联 hook 检测 | 查 `ntdll` 关键 API 前 12 字节 `E9`/`EB`/`FF 25`/`48 B8..FF E0`/`68..C3`/`CC` | 被打补丁的敏感 API |

模块名与内置白名单比对，**不在白名单里的就是注入**。

> 宿主程序自己的名字不在固定白名单里（因为可以被 `--name` 改成任意名字），
> 所以它是**按路径自我识别**的 —— 否则自定义命名的程序会把自己标成 `INJ`。

---

## 6. 界面功能

| 操作 | 效果 |
|---|---|
| **Copy all (Ctrl+C)** 按钮 | 完整报告（进程信息 + 全部 DLL + 注入项 + findings）进剪贴板 |
| 窗口内按 `Ctrl+C` | 同上 |
| **Save report...** | 存成 `injection_report_<PID>.txt`（UTF-8） |
| 列表多选 | 可以手动框选若干行 |

列表刷新是**静默的**：只改动真正变化的行，并保留滚动位置和选中项，
所以不会每 1.5 秒跳回顶部。

界面支持 **DPI 缩放**（`WM_DPICHANGED` 会重新布局并重建字体）。

---

## 7. 代码结构

```
src\exebuilder.c   工具本体：参数解析 / info / build / payload / 资源拼装
src\monitor.c      监视器内核：三层检测 + 窗口 UI + 报告
src\monitor.h
src\payload.c      生成程序的入口（读自身文件名作标题，调用 monitor_run）
src\payload.rc     把监视器模板内嵌进 exebuilder 的 RCDATA
build.bat          一键构建
```

如果只想在自己的程序里用这个监视器，链接 `monitor.c` 然后调：

```c
MonitorConfig cfg = { L"my app" };
return monitor_run(hInst, &cfg);
```

---

## 8. 实现要点 / 踩过的坑

### 版本资源必须回填 wLength

`VS_VERSIONINFO` 是嵌套资源树，每个节点都要 DWORD 对齐。一开始按公式预算
长度，漏算了 key 字符串的对齐填充，`wLength` 比真实数据大 4 字节。

`UpdateResourceW` 仍然返回**成功**，但 `GetFileVersionInfoSize` 返回 0，
系统把整个版本资源判定为非法而静默丢弃。

修法是**写完再回填**：`*(WORD *)node.p = (WORD)node.len`。

### ScanResult 必须放堆上

`ScanResult` 约 830 KB（`modules[1024]` + `items[256]`），声明成局部变量会
爆掉默认 1 MB 栈。栈溢出表现为 `0xC000041D`，不是干净的崩溃。

---

## 9. FAQ

**Q: 生成的 exe 比模板小？**
A: 正常。资源目录被重写，未使用的对齐填充被丢弃，代码节不受影响。

**Q: `objdump` 说 "file format not recognized"？**
A: MinGW 的 objdump 解析不了某些资源节布局，不代表文件坏了。
用 `exebuilder.exe info` 判断。

**Q: PowerShell 读 `VersionInfo` 是空的？**
A: PowerShell 按**文件名**缓存版本信息，改名再看，或用 `exebuilder.exe info`。

**Q: 注入没被检测到？**
A: 注入器和目标位数必须一致（都是 x64）。另外如果目标以管理员权限运行，
非提权的注入器会 `OpenProcess failed (5)`。
