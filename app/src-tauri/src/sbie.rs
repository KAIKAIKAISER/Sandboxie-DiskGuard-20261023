// DiskGuard - Sandboxie 宿主 API 封装
//
// 通过运行时动态加载 Sandboxie 安装目录中的 SbieDll.dll，调用其导出的
// SbieApi_* / SbieDll_* 函数（64 位下按函数名导出，见 Sandboxie/core/dll/SboxDll.vcxproj
// 与 sbieapi.h 的 SBIEAPI_EXPORT 定义）。不修改 Sandboxie 核心代码。

#![cfg(windows)]

use libloading::Library;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// ini 盒子名称缓冲长度（BOXNAME_COUNT，Sandboxie/core/dll/sbieapi.h）
pub const BOXNAME_COUNT: usize = 34;
/// ini 单值缓冲长度（字符数）
pub const CONF_LINE_CHARS: usize = 1024;

// CONF_GET_* 标志（Sandboxie/core/drv/api_flags.h:37-39）
const CONF_GET_NO_EXPAND: u32 = 0x2000_0000;
const CONF_GET_NO_TEMPLS: u32 = 0x1000_0000;

// API_MONITOR_GET2（Sandboxie/core/drv/api_defs.h:372）
const API_MONITOR_GET2: u32 = 161;
// STATUS_MORE_ENTRIES（NTSTATUS 警告级，NT_SUCCESS 为真）
pub const STATUS_MORE_ENTRIES: i32 = 0x0000_0105;
pub const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_011A as i32;
pub const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;

type FnGetHomePath = unsafe extern "system" fn(*mut u16, u32, *mut u16, u32) -> i32;
type FnEnumBoxesEx = unsafe extern "system" fn(i32, *mut u16, i32) -> i32;
type FnEnumProcessEx = unsafe extern "system" fn(*const u16, i32, u32, *mut u32, *mut u32) -> i32;
type FnQueryProcess = unsafe extern "system" fn(usize, *mut u16, *mut u16, *mut u16, *mut u32) -> i32;
type FnQueryBoxPath = unsafe extern "system" fn(
    *const u16,
    *mut u16,
    *mut u16,
    *mut u16,
    *mut u32,
    *mut u32,
    *mut u32,
) -> i32;
type FnMonitorControl = unsafe extern "system" fn(*mut u32, *mut u32) -> i32;
type FnMonitorGetEx = unsafe extern "system" fn(*mut u32, *mut u32, *mut u32, *mut u16) -> i32;
type FnQueryConf = unsafe extern "system" fn(*const u16, *const u16, u32, *mut u16, u32) -> i32;
type FnUpdateConf =
    unsafe extern "system" fn(u16, *const u16, *const u16, *const u16) -> u32;
// SbieApi_Call 为变参：parms[i] = va_arg(ULONG_PTR)，指针/整型一律按 usize 传入
type FnCall = unsafe extern "C" fn(u32, i32, ...) -> i32;

#[derive(Clone, Copy)]
pub struct SbieFns {
    pub get_home_path: FnGetHomePath,
    pub enum_boxes_ex: FnEnumBoxesEx,
    pub enum_process_ex: FnEnumProcessEx,
    pub query_process: FnQueryProcess,
    pub query_box_path: FnQueryBoxPath,
    pub monitor_control: FnMonitorControl,
    pub monitor_get_ex: FnMonitorGetEx,
    pub query_conf: FnQueryConf,
    pub update_conf: FnUpdateConf,
    pub call: FnCall,
}

pub struct Sbie {
    pub fns: SbieFns,
    pub home: PathBuf,
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

/// 定位 Sandboxie 安装目录：优先读 SbieSvc / SbieDrv 服务注册表键的
/// ImagePath（Sandboxie/core/dll/support.c:54、core/drv/driver.c:584 的做法），
/// 再回退到常见安装路径。
fn locate_home() -> Option<PathBuf> {
    for svc in ["SbieSvc", "SbieDrv"] {
        if let Some(dir) = service_image_dir(svc) {
            return Some(dir);
        }
    }
    for candidate in [
        r"C:\Program Files\Sandboxie-Plus",
        r"C:\Program Files\Sandboxie",
    ] {
        let p = PathBuf::from(candidate);
        if p.join("SbieDll.dll").exists() {
            return Some(p);
        }
    }
    None
}

fn service_image_dir(service: &str) -> Option<PathBuf> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("reg")
        .args([
            "query",
            &format!("HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service}"),
            "/v",
            "ImagePath",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if !line.contains("ImagePath") {
            continue;
        }
        let pos = line.find("REG_")?;
        let rest = &line[pos..];
        let ws = rest.find(char::is_whitespace)?;
        let val = rest[ws..].trim().trim_matches('"');
        let val = val.strip_prefix("\\??\\").unwrap_or(val);
        let dir = Path::new(val).parent()?.to_path_buf();
        if dir.join("SbieDll.dll").exists() {
            return Some(dir);
        }
    }
    None
}

impl Sbie {
    pub fn load() -> Result<Sbie, String> {
        let home = locate_home()
            .ok_or_else(|| "未找到 Sandboxie 安装目录（未安装或 SbieDll.dll 缺失）".to_string())?;
        let dll = home.join("SbieDll.dll");
        let lib = unsafe { Library::new(&dll) }
            .map_err(|e| format!("加载 {} 失败: {e}", dll.display()))?;
        let fns = unsafe { resolve_fns(&lib)? };
        // 函数指针在库卸载后失效，此处有意让 Library 常驻进程生命周期
        std::mem::forget(lib);
        Ok(Sbie { fns, home })
    }

    /// 驱动 API 健康检查：API_GET_HOME_PATH 走 \Device\SandboxieDriverApi IOCTL，
    /// 成功即代表驱动与 API 通道正常。
    pub fn api_ok(&self) -> bool {
        let mut nt = [0u16; 300];
        let mut dos = [0u16; 300];
        unsafe {
            (self.fns.get_home_path)(nt.as_mut_ptr(), 300, dos.as_mut_ptr(), 300) == 0
        }
    }

    pub fn home_dos_path(&self) -> Option<String> {
        let mut nt = [0u16; 300];
        let mut dos = [0u16; 300];
        let st = unsafe {
            (self.fns.get_home_path)(nt.as_mut_ptr(), 300, dos.as_mut_ptr(), 300)
        };
        if st != 0 {
            return None;
        }
        let s = unsafe { wide_to_string(dos.as_ptr()) };
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// Sandboxie.ini 路径：驱动以伪设置 IniLocation 暴露（core/drv/conf.c:1524），
    /// "H"=安装目录，"W"=Windows 目录，其余为自定义路径。
    pub fn ini_path(&self) -> String {
        let mut buf = [0u16; CONF_LINE_CHARS];
        let st = unsafe {
            (self.fns.query_conf)(
                std::ptr::null(),
                to_wide("IniLocation").as_ptr(),
                CONF_GET_NO_EXPAND | CONF_GET_NO_TEMPLS,
                buf.as_mut_ptr(),
                (buf.len() * 2) as u32,
            )
        };
        let loc = if st == 0 {
            unsafe { wide_to_string(buf.as_ptr()) }
        } else {
            String::new()
        };
        match loc.as_str() {
            "H" => self.home.join("Sandboxie.ini").display().to_string(),
            "W" => std::env::var("SystemRoot")
                .map(|w| format!("{w}\\Sandboxie.ini"))
                .unwrap_or_else(|_| "C:\\Windows\\Sandboxie.ini".to_string()),
            p if !p.is_empty() => p.to_string(),
            _ => self.home.join("Sandboxie.ini").display().to_string(),
        }
    }

    /// 枚举全部盒子名。EnumBoxesEx 返回下一个索引，-1 表示结束
    /// （参考 Sandboxie/apps/ini/query.c:47-63）。
    pub fn enum_boxes(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut idx: i32 = 0;
        let mut name = [0u16; BOXNAME_COUNT];
        loop {
            let n = unsafe { (self.fns.enum_boxes_ex)(idx, name.as_mut_ptr(), 0) };
            if n == -1 {
                break;
            }
            out.push(unsafe { wide_to_string(name.as_ptr()) });
            if n <= idx || out.len() > 512 {
                break;
            }
            idx = n;
        }
        out
    }

    /// 枚举某盒子内的进程 PID（API_ENUM_PROCESSES，缓冲 512）。
    pub fn enum_processes(&self, box_name: &str) -> Vec<u32> {
        let bname = to_wide(box_name);
        let mut pids = [0u32; 512];
        let mut count: u32 = 512;
        let st = unsafe {
            (self.fns.enum_process_ex)(bname.as_ptr(), 0, u32::MAX, pids.as_mut_ptr(), &mut count)
        };
        if st != 0 {
            return Vec::new();
        }
        let n = (count as usize).min(512);
        pids[..n].iter().copied().filter(|p| *p != 0).collect()
    }

    /// 查询进程（须为沙箱内进程）：返回 (盒子名, 映像名)。
    pub fn query_process(&self, pid: u32) -> Option<(String, String)> {
        let mut boxn = [0u16; BOXNAME_COUNT];
        let mut img = [0u16; 96];
        let mut sid = [0u16; 96];
        let mut session = 0u32;
        let st = unsafe {
            (self.fns.query_process)(
                pid as usize,
                boxn.as_mut_ptr(),
                img.as_mut_ptr(),
                sid.as_mut_ptr(),
                &mut session,
            )
        };
        if st != 0 {
            return None;
        }
        Some((
            unsafe { wide_to_string(boxn.as_ptr()) },
            unsafe { wide_to_string(img.as_ptr()) },
        ))
    }

    /// 沙箱文件根目录（FileRootPath，默认 C:\Sandbox\<user>\<box>）。
    pub fn box_file_path(&self, box_name: &str) -> Option<String> {
        let b = to_wide(box_name);
        let mut file = [0u16; 512];
        let mut key = [0u16; 512];
        let mut ipc = [0u16; 512];
        let (mut fl, mut kl, mut il) = (512u32, 512u32, 512u32);
        let st = unsafe {
            (self.fns.query_box_path)(
                b.as_ptr(),
                file.as_mut_ptr(),
                key.as_mut_ptr(),
                ipc.as_mut_ptr(),
                &mut fl,
                &mut kl,
                &mut il,
            )
        };
        if st != 0 {
            return None;
        }
        let s = unsafe { wide_to_string(file.as_ptr()) };
        let s = s.trim_start_matches("\\??\\").to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// 启用/停用驱动资源监视器（API_MONITOR_CONTROL）。
    pub fn monitor_control(&self, enable: bool) -> Result<(), String> {
        let mut new_state: u32 = if enable { 1 } else { 0 };
        let mut old_state: u32 = 0;
        let st = unsafe {
            (self.fns.monitor_control)(&mut new_state, &mut old_state)
        };
        if st == 0 {
            Ok(())
        } else {
            Err(format!("SbieApi_MonitorControl 失败: NTSTATUS 0x{st:08X}"))
        }
    }

    /// 单条读取监视消息（API_MONITOR_GET_EX，返回 (类型,PID,TID,首字符串)）。
    pub fn monitor_get_one(&self) -> Result<(u32, u32, u32, String), i32> {
        let mut ty = 0u32;
        let mut pid = 0u32;
        let mut tid = 0u32;
        let mut name = [0u16; 256];
        let st = unsafe {
            (self.fns.monitor_get_ex)(&mut ty, &mut pid, &mut tid, name.as_mut_ptr())
        };
        if st == 0 {
            Ok((ty, pid, tid, unsafe { wide_to_string(name.as_ptr()) }))
        } else {
            Err(st)
        }
    }

    /// 批量读取监视消息（API_MONITOR_GET2，经 SbieApi_Call）。
    /// buf 为 UTF-16 缓冲；返回 (本次写入的字节数, 是否仍有积压)。
    pub fn monitor_get_batch(&self, buf: &mut [u16]) -> Result<(usize, bool), i32> {
        let mut len: u32 = (buf.len() * 2) as u32;
        let st = unsafe {
            (self.fns.call)(
                API_MONITOR_GET2,
                2,
                buf.as_mut_ptr() as usize,
                &mut len as *mut u32 as usize,
            )
        };
        if st == 0 {
            Ok((len as usize, false))
        } else if st == STATUS_MORE_ENTRIES {
            Ok((len as usize, true))
        } else {
            Err(st)
        }
    }

    // ---------- 配置读写（经 SbieSvc CONFIG server） ----------

    /// 写入/更新/追加/删除配置。op: 's'=置值 'a'=追加 'd'=删除。
    /// value=None 且 op='d' 表示删除该设置的行；SbieDll_UpdateConf 固定 refresh=TRUE，
    /// 服务端写盘后自动调用 SbieApi_ReloadConf（core/dll/callsvc.c:873-935）。
    pub fn conf_update(
        &self,
        op: char,
        section: &str,
        setting: &str,
        value: Option<&str>,
    ) -> Result<(), String> {
        let sec = to_wide(section);
        let set = to_wide(setting);
        let owned;
        let val_ptr = match value {
            Some(v) => {
                owned = to_wide(v);
                owned.as_ptr()
            }
            None => std::ptr::null(),
        };
        let st = unsafe {
            (self.fns.update_conf)(op as u16, sec.as_ptr(), set.as_ptr(), val_ptr)
        };
        if st == 0 {
            Ok(())
        } else {
            Err(format!(
                "配置更新失败（{op} {section}\\{setting}）: NTSTATUS 0x{st:08X}"
            ))
        }
    }

    pub fn conf_set(&self, section: &str, setting: &str, value: &str) -> Result<(), String> {
        self.conf_update('s', section, setting, Some(value))
    }
    pub fn conf_add(&self, section: &str, setting: &str, value: &str) -> Result<(), String> {
        self.conf_update('a', section, setting, Some(value))
    }
    pub fn conf_del_value(&self, section: &str, setting: &str, value: &str) -> Result<(), String> {
        self.conf_update('d', section, setting, Some(value))
    }
    pub fn conf_del_setting(&self, section: &str, setting: &str) -> Result<(), String> {
        self.conf_update('d', section, setting, None)
    }

    /// 枚举某设置的多个值（API_QUERY_CONF，index 低位为序号，
    /// 高位携带 NO_EXPAND|NO_TEMPLS，参考 apps/ini/query.c:98-124）。
    pub fn conf_values(&self, section: &str, setting: &str) -> Vec<String> {
        let sec = to_wide(section);
        let set = to_wide(setting);
        let mut out = Vec::new();
        for i in 0..256u32 {
            let mut buf = [0u16; CONF_LINE_CHARS];
            let st = unsafe {
                (self.fns.query_conf)(
                    sec.as_ptr(),
                    set.as_ptr(),
                    i | CONF_GET_NO_EXPAND | CONF_GET_NO_TEMPLS,
                    buf.as_mut_ptr(),
                    (buf.len() * 2) as u32,
                )
            };
            if st != 0 {
                break;
            }
            let v = unsafe { wide_to_string(buf.as_ptr()) };
            if v.is_empty() {
                break;
            }
            out.push(v);
        }
        out
    }

    /// 枚举某段内的设置名（setting 传 NULL）。
    pub fn conf_setting_names(&self, section: &str) -> Vec<String> {
        let sec = to_wide(section);
        let mut out = Vec::new();
        for i in 0..512u32 {
            let mut buf = [0u16; 66];
            let st = unsafe {
                (self.fns.query_conf)(
                    sec.as_ptr(),
                    std::ptr::null(),
                    i | CONF_GET_NO_TEMPLS,
                    buf.as_mut_ptr(),
                    (buf.len() * 2) as u32,
                )
            };
            if st != 0 {
                break;
            }
            let v = unsafe { wide_to_string(buf.as_ptr()) };
            if v.is_empty() {
                break;
            }
            out.push(v);
        }
        out
    }
}

unsafe fn resolve_fns(lib: &Library) -> Result<SbieFns, String> {
    unsafe fn sym<T: Copy>(lib: &Library, name: &str) -> Result<T, String> {
        lib.get::<T>(name.as_bytes())
            .map(|s| *s)
            .map_err(|e| format!("SbieDll 缺少导出 {name}: {e}"))
    }
    Ok(SbieFns {
        get_home_path: unsafe { sym(&lib, "SbieApi_GetHomePath")? },
        enum_boxes_ex: unsafe { sym(&lib, "SbieApi_EnumBoxesEx")? },
        enum_process_ex: unsafe { sym(&lib, "SbieApi_EnumProcessEx")? },
        query_process: unsafe { sym(&lib, "SbieApi_QueryProcess")? },
        query_box_path: unsafe { sym(&lib, "SbieApi_QueryBoxPath")? },
        monitor_control: unsafe { sym(&lib, "SbieApi_MonitorControl")? },
        monitor_get_ex: unsafe { sym(&lib, "SbieApi_MonitorGetEx")? },
        query_conf: unsafe { sym(&lib, "SbieApi_QueryConf")? },
        update_conf: unsafe { sym(&lib, "SbieDll_UpdateConf")? },
        call: unsafe { sym(&lib, "SbieApi_Call")? },
    })
}

/// 惰性加载的 Sandboxie 宿主。未安装/加载失败时给出可读原因。
pub struct SbieHost {
    inner: OnceLock<std::sync::Arc<Sbie>>,
    err: Mutex<Option<String>>,
}

impl SbieHost {
    pub fn new() -> Self {
        SbieHost {
            inner: OnceLock::new(),
            err: Mutex::new(None),
        }
    }

    pub fn get(&self) -> Result<std::sync::Arc<Sbie>, String> {
        if let Some(s) = self.inner.get() {
            return Ok(s.clone());
        }
        match Sbie::load() {
            Ok(s) => {
                let arc = std::sync::Arc::new(s);
                let _ = self.inner.set(arc.clone());
                *self.lock_err() = None;
                Ok(arc)
            }
            Err(e) => {
                *self.lock_err() = Some(e.clone());
                Err(e)
            }
        }
    }

    pub fn last_error(&self) -> Option<String> {
        self.lock_err().clone()
    }

    fn lock_err(&self) -> std::sync::MutexGuard<'_, Option<String>> {
        self.err.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for SbieHost {
    fn default() -> Self {
        Self::new()
    }
}

/// 把一组目标值同步到某个 ini 设置（先删多余值，再补缺失值）。
pub fn sync_conf_list(
    sbie: &Sbie,
    section: &str,
    setting: &str,
    desired: &[String],
) -> Result<(), String> {
    let current = sbie.conf_values(section, setting);
    let wanted: HashSet<&String> = desired.iter().collect();
    for v in &current {
        if !wanted.contains(v) {
            sbie.conf_del_value(section, setting, v)?;
        }
    }
    let existing: HashSet<&String> = current.iter().collect();
    for v in desired {
        if !existing.contains(v) {
            sbie.conf_add(section, setting, v)?;
        }
    }
    Ok(())
}
