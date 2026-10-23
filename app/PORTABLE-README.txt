DiskGuard - 磁盘访问限制器（便携版）
====================================

本压缩包仅包含 DiskGuard 前端程序。磁盘访问控制能力完全来自 Sandboxie 核心组件
（内核驱动 SbieDrv、服务 SbieSvc、SbieDll），请先安装 Sandboxie 核心：

  方式 A（推荐）：安装 Sandboxie Plus 官方版
      https://github.com/sandboxie-plus/Sandboxie/releases
      （官方安装包的驱动/服务带有微软认证签名，无需测试模式）

  方式 B：使用本仓库 Release 中的 DiskGuard-Core-TestSigned-x64.zip
      该包内的 SbieDrv.sys 为测试签名构建，必须先开启 Windows 测试签名模式：
        bcdedit /set testsigning on     （管理员命令行，重启生效）
      这类构建仅用于开发验证，正式使用请选择方式 A。

使用：
  1. 解压本压缩包到任意目录，运行 DiskGuard.exe（需要 WebView2 运行时，
     Windows 10/11 一般已内置）。
  2. 首次启动后 DiskGuard 会自动检测 Sandboxie 核心并接管配置。

说明：
  * DiskGuard 不会修改 Sandboxie 程序本身，所有规则写入 Sandboxie.ini
    （通过 SbieSvc 配置服务），可随时用任何 Sandboxie 管理工具查看/修改。
  * 访问日志文件保存在 %APPDATA%\DiskGuard\logs\ 下（每日一个 JSONL 文件）。
