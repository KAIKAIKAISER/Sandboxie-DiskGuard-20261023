# DiskGuard — 基于 Sandboxie 核心的磁盘访问限制器

DiskGuard 是一款面向 Windows 10/11 x64 的轻量级磁盘访问限制器。它**复用**
[Sandboxie Plus](https://github.com/sandboxie-plus/Sandboxie) 的内核驱动（SbieDrv）、
服务（SbieSvc）与用户态 API 库（SbieDll），并以其为基础提供一套全新的 Tauri 2 UI
（Rust 后端 + 原生前端），不使用原版 Qt 界面，也不修改 Sandboxie 核心代码。

本仓库基于上游 `sandboxie-plus/Sandboxie@77ce6d3`（完整历史保留），所有新增代码位于：

```
app/                    DiskGuard 应用（Tauri 2）
  src-tauri/            Rust 后端
    src/sbie.rs         SbieDll.dll 动态加载与 API 封装
    src/rules.rs        应用配置 → Sandboxie.ini 规则映射
    src/trace.rs        实时访问日志（驱动资源监视器）
    src/store.rs        应用元数据持久化（%APPDATA%\DiskGuard\config.json）
    src/commands.rs     Tauri IPC 命令层
    src/main.rs         入口（托盘/单实例/开机自启/后台线程）
  ui/                   原生 HTML/CSS/JS 前端（无构建步骤）
.github/workflows/diskguard.yml      应用构建 + 核心构建 + 打包发布
.github/workflows/sync-upstream.yml  上游同步（每周 merge upstream/master）
```

## 功能与 Sandboxie 机制的对应关系

| DiskGuard 功能 | 复用的 Sandboxie 机制（上游代码位置） |
| --- | --- |
| 目录黑名单（拒绝读写） | `ClosedFilePath` 指令；驱动在 `core/drv/file.c:1553-1564` 返回 `ACCESS_DENIED`（或写访问时返回 `OBJECT_NAME_NOT_FOUND` 将路径“隐藏”） |
| 白名单（封闭根 + 放行目录） | 封闭根 `ClosedFilePath` + 放行 `OpenFilePath`/`ReadFilePath`；盒子启用 `UseRuleSpecificity=y`，最具体规则优先（`core/drv/process_util.c:929-1075`） |
| 只监控模式 | 不写拦截规则，全部按 Sandboxie 默认语义（真实路径只读、写入进沙箱），配合 `FileTrace=*` 记录打开 |
| 递归规则 | 单个 `*` 跨越 `\`（`common/pattern.c`），`D:\dir\*` 覆盖全部子目录；`|` 前缀禁用自动补星实现精确匹配（`core/drv/process_util.c:669-672`） |
| 自动保护（启动即入箱） | 盒子段内 `ForceProcess=<exe>`（`core/drv/process_force.c:1148-1243`，每盒独立列表），可选 `ForceFolder=<安装目录>` |
| 关联子进程不逃逸 | 驱动进程创建通知中子进程直接克隆父进程盒子（`core/drv/process.c:1230-1251`），无需额外配置 |
| 配置持久化 | 写入 Sandboxie.ini：`SbieDll_UpdateConf()` 走 SbieSvc CONFIG server，`refresh=TRUE` 自动触发 `SbieApi_ReloadConf`（`core/dll/callsvc.c:873-935`）；普通用户即可调用（非沙箱进程、未设 `EditAdminOnly`） |
| 实时访问日志 | 驱动资源监视器：`SbieApi_MonitorControl` 开启（`core/drv/session.c:666-756`），`API_MONITOR_GET2` 批量读取（`session.c:1179-1263`），格式与 QSbieAPI 解析一致（`SandboxiePlus/QSbieAPI/SbieAPI.cpp:3066-3169`） |
| 在沙箱中启动程序 | `Start.exe /box:<name> <exe>`（`apps/start/start.cpp`，`Parse_Command_Line`）；`/terminate` 终止 |
| 每软件独立配置 | 每个受控程序一个独立盒子（`DG_<名称>`），规则写在各自段内，互不影响；`[GlobalSettings]` 不被 DiskGuard 使用 |

## 访问日志语义（如实说明）

驱动 minifilter 只注册了 `IRP_MJ_CREATE`、`IRP_MJ_SET_INFORMATION`（重命名/链接）与
映像加载（`core/drv/file_flt.c:97-148`）。因此 DiskGuard 的日志事件与 Sandboxie
驱动能力严格一致：

* **每条事件 = 一次文件/目录打开调用**（NtCreateFile/NtOpenFile），附带打开时的
  DesiredAccess（日志中的 `0x…` 掩码），据此区分读打开/写打开；
* **目录枚举**（IRP_MJ_DIRECTORY_CONTROL）与**实际读写字节**不由驱动单独上报，
  因此不存在“枚举事件/读字节事件”——DiskGuard 不虚构此类记录；
* 被规则拒绝的打开带 `MONITOR_DENY` 标志（`core/drv/file.c:1739-1741`），
  日志中显示为“拒绝”；
* DiskGuard 另行保留管道/映像/注册表/磁盘设备类事件（`MONITOR_PIPE/IMAGE/KEY/DRIVE`），
  UI 默认可按类型过滤。

日志保留：内存环形缓冲 20000 条 + `%APPDATA%\DiskGuard\logs\access-YYYYMMDD.jsonl`
（保留 7 天），支持 CSV/JSONL 导出。

## 构建与驱动签名策略

* **DiskGuard 应用**：GitHub Actions（windows-2022）中 `tauri build` 产出
  NSIS 安装包与便携版，不需要驱动签名。
* **Sandboxie 核心（本仓库自行构建）**：按上游 CI 同样方式
  msbuild `SandboxDll.sln(Win32)` + `Sandbox.sln(x64)` + `SandboxDrv.sln(x64)`，
  产物为**测试签名**（TestSigned）驱动，仅用于开发验证；使用时需
  `bcdedit /set testsigning on`。**不绕过、也不试图绕过 Windows 驱动签名要求。**
* **正式使用**：推荐安装上游官方发布的 Sandboxie Plus 安装包（其驱动经微软认证
  签名），DiskGuard 检测到后即可接管。Release 附件中对两种包做了明确区分。

## 与上游的同步策略

* 本仓库为上游 `sandboxie-plus/Sandboxie@77ce6d3` 的**供应商快照**（单一导入提交，
  上游 SHA 记录于 `UPSTREAM-REF.txt`），核心代码零修改；
* `sync-upstream.yml` 每周用上游 master 的工作树整体替换本仓库中除保留清单
  （`app/`、文档、工作流）外的全部文件并提交，从而持续跟进上游更新；
* 上游 `main.yml` 的 `paths-ignore` 增加了 `app/**` 等本仓库新增目录，
  避免应用改动触发无谓的完整核心构建；
* 新增文件（`app/`、`DISKGUARD.md`、新工作流）与上游文件零重叠。

## 许可证

* Sandboxie 核心与其构建产物遵循上游 `LICENSE.Classic` / `LICENSE.Plus`（GPL-3.0）；
* DiskGuard 应用（`app/`）作为 Sandboxie API 的衍生作品，同样以 GPL-3.0 发布；
* 未移除、未变更任何上游许可声明。

## 本地开发

```cmd
cd app\src-tauri
cargo tauri dev        :: 需要 Rust stable；前端无需 Node
cargo tauri build      :: 产出 NSIS 安装包
```

运行时依赖：已安装的 Sandboxie 核心（SbieSvc 运行中）。未安装时 DiskGuard
仍可启动，仅显示引导信息并禁用控制功能。
