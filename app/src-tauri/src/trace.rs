// DiskGuard - 实时访问日志（驱动资源监视器）
//
// 数据来源为 Sandboxie 内核驱动的监视环形缓冲：
//   启用/停用：SbieApi_MonitorControl（core/drv/session.c:666-756）
//   批量读取：API_MONITOR_GET2（core/drv/session.c:1179-1263）
//   记录格式：[SIZE4][Time8][Type4][Pid4][Tid4][NUL 分隔字符串...][0xFFFF][tag...]，
//             与 QSbieAPI 的解析一致（SandboxiePlus/QSbieAPI/SbieAPI.cpp:3066-3169）
//
// 日志语义（如实说明，不做臆造）：
//   * 每条记录对应一次 NtCreateFile/NtOpenFile 打开调用。驱动 minifilter 仅注册
//     IRP_MJ_CREATE / SET_INFORMATION / SECTION 同步（core/drv/file_flt.c:97-148），
//     目录枚举（IRP_MJ_DIRECTORY_CONTROL）与实际读写字节不单独产生事件。
//   * 文件打开的详细记录带 "(FA)/(FD) DesiredAccess.Disposition.CreateOptions" 消息
//     （core/drv/file.c:1694-1741），可据此区分读访问/写访问。
//   * 被 ClosedFilePath 拒绝的打开带 MONITOR_DENY 标志（file.c:1739-1741）。

#![cfg(windows)]

use crate::sbie::{Sbie, SbieHost, STATUS_DEVICE_NOT_READY};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::Manager;

// MONITOR_* 常量（core/drv/api_flags.h:51-86）
const MONITOR_TYPE_MASK: u32 = 0x0000_00FF;
const MONITOR_OPEN: u32 = 0x0001_0000;
const MONITOR_DENY: u32 = 0x0002_0000;

const MONITOR_PIPE: u32 = 0x02;
const MONITOR_DRIVE: u32 = 0x05;
const MONITOR_IGNORE: u32 = 0x08;
const MONITOR_FILE: u32 = 0x0A;
const MONITOR_KEY: u32 = 0x0B;
const MONITOR_OTHER: u32 = 0x0C;
const MONITOR_IMAGE: u32 = 0x09;

#[derive(Debug, Clone, Serialize)]
pub struct TraceEvent {
    pub seq: u64,
    /// 毫秒级 Unix 时间戳
    pub ts: i64,
    pub pid: u32,
    pub tid: u32,
    pub process: String,
    pub box_name: String,
    pub path: String,
    pub msg: String,
    /// file | pipe | image | registry | drive | other
    pub kind: String,
    /// open-read | open-write | open | info
    pub op: String,
    /// allow | deny
    pub result: String,
    /// 打开调用的 DesiredAccess 十六进制（可用时）
    pub access: String,
}

pub struct Ring {
    buf: VecDeque<TraceEvent>,
    cap: usize,
    next_seq: u64,
}

impl Ring {
    pub fn new(cap: usize) -> Self {
        Ring {
            buf: VecDeque::with_capacity(cap.min(1024)),
            cap,
            next_seq: 1,
        }
    }

    pub fn push(&mut self, mut e: TraceEvent) {
        e.seq = self.next_seq;
        self.next_seq += 1;
        if self.buf.len() >= self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(e);
    }

    pub fn since(&self, since: u64, limit: usize) -> (Vec<TraceEvent>, u64) {
        let out: Vec<TraceEvent> = self
            .buf
            .iter()
            .filter(|e| e.seq > since)
            .take(limit)
            .cloned()
            .collect();
        let last = self.next_seq - 1;
        (out, last)
    }

    pub fn clear(&mut self) {
        self.buf.clear();
    }

    pub fn all(&self) -> Vec<TraceEvent> {
        self.buf.iter().cloned().collect()
    }
}

struct RawEvent {
    ts: i64,
    ty: u32,
    pid: u32,
    tid: u32,
    strings: Vec<String>,
}

pub struct ProcInfoCache {
    map: HashMap<u32, (String, String)>,
}

impl ProcInfoCache {
    pub fn new() -> Self {
        ProcInfoCache {
            map: HashMap::new(),
        }
    }

    fn lookup(&mut self, sbie: &Sbie, pid: u32) -> (String, String) {
        if let Some(v) = self.map.get(&pid) {
            return v.clone();
        }
        let v = sbie.query_process(pid).unwrap_or_default();
        if !(v.0.is_empty() && v.1.is_empty()) {
            self.map.insert(pid, v.clone());
        }
        v
    }
}

fn filetime_to_ms(ft: i64) -> i64 {
    // FILETIME(100ns since 1601-01-01) -> Unix 毫秒
    if ft <= 0 {
        return now_ms();
    }
    const EPOCH_DIFF: i64 = 116_444_736_000_000_000;
    (ft - EPOCH_DIFF) / 10_000
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 解析一批 GET2 数据（字节切片）。
fn parse_batch(bytes: &[u8]) -> Vec<RawEvent> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= bytes.len() {
        let size = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if size == 0 {
            break;
        }
        if off + size > bytes.len() || size < 20 {
            break;
        }
        let e = &bytes[off..off + size];
        off += size;

        let ts = i64::from_le_bytes(e[0..8].try_into().unwrap());
        let ty = u32::from_le_bytes(e[8..12].try_into().unwrap());
        let pid = u32::from_le_bytes(e[12..16].try_into().unwrap());
        let tid = u32::from_le_bytes(e[16..20].try_into().unwrap());

        let mut strings = Vec::new();
        let mut pos = 20usize;
        while pos + 2 <= e.len() {
            let w = u16::from_le_bytes([e[pos], e[pos + 1]]);
            if w == 0xFFFF {
                break; // 栈回溯 tag 区开始，本工具不使用
            }
            let start = pos;
            while pos + 2 <= e.len() && u16::from_le_bytes([e[pos], e[pos + 1]]) != 0 {
                pos += 2;
            }
            let units: Vec<u16> = e[start..pos]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            strings.push(String::from_utf16_lossy(&units));
            pos += 2; // 跳过 NUL
        }
        out.push(RawEvent {
            ts,
            ty,
            pid,
            tid,
            strings,
        });
    }
    out
}

/// "(FA) 120089.01.00000020" -> DesiredAccess 十六进制串
fn parse_access(msg: &str) -> Option<String> {
    let rest = msg.strip_prefix("(F")?;
    let rest = rest.split_once(')')?.1.trim();
    let hex = rest.split('.').next()?.trim().to_string();
    if hex.is_empty() {
        None
    } else {
        Some(hex)
    }
}

fn access_has_write(hex: &str) -> bool {
    u32::from_str_radix(hex, 16)
        .map(|a| (a & 0x0006) != 0 || (a & 0x0001_0000) != 0)
        .unwrap_or(false)
}

fn convert(
    raw: &RawEvent,
    cache: &mut ProcInfoCache,
    sbie: &Sbie,
) -> Option<TraceEvent> {
    let base = raw.ty & MONITOR_TYPE_MASK;
    let kind = match base {
        MONITOR_FILE => "file",
        MONITOR_PIPE => "pipe",
        MONITOR_IMAGE => "image",
        MONITOR_KEY => "registry",
        MONITOR_DRIVE => "drive",
        MONITOR_IGNORE | MONITOR_OTHER => "other",
        _ => return None,
    };
    let deny = raw.ty & MONITOR_DENY != 0;
    let open_write_flag = raw.ty & MONITOR_OPEN != 0;
    let path = raw.strings.first().cloned().unwrap_or_default();
    if path.is_empty() {
        return None;
    }
    let msg = raw.strings.get(1).cloned().unwrap_or_default();

    let (op, access) = if base == MONITOR_FILE {
        match parse_access(&msg) {
            Some(acc) => {
                let op = if access_has_write(&acc) {
                    "open-write"
                } else {
                    "open-read"
                };
                (op.to_string(), acc)
            }
            None if open_write_flag => ("open-write".to_string(), String::new()),
            None => ("open".to_string(), String::new()),
        }
    } else {
        ("open".to_string(), String::new())
    };

    let (box_name, process) = cache.lookup(sbie, raw.pid);

    Some(TraceEvent {
        seq: 0,
        ts: filetime_to_ms(raw.ts),
        pid: raw.pid,
        tid: raw.tid,
        process,
        box_name,
        path,
        msg,
        kind: kind.to_string(),
        op,
        result: if deny { "deny" } else { "allow" }.to_string(),
        access,
    })
}

struct LogFile {
    day: String,
    file: Option<std::fs::File>,
}

impl LogFile {
    fn new() -> Self {
        LogFile {
            day: String::new(),
            file: None,
        }
    }

    fn append(&mut self, logs_dir: &PathBuf, events: &[TraceEvent]) {
        if events.is_empty() {
            return;
        }
        let day = chrono::Local::now().format("%Y%m%d").to_string();
        if self.file.is_none() || self.day != day {
            let _ = std::fs::create_dir_all(logs_dir);
            let path = logs_dir.join(format!("access-{day}.jsonl"));
            self.file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .ok();
            self.day = day;
        }
        if let Some(f) = self.file.as_mut() {
            for e in events {
                if let Ok(line) = serde_json::to_string(e) {
                    let _ = writeln!(f, "{line}");
                }
            }
            let _ = f.flush();
        }
    }
}

fn cleanup_old_logs(logs_dir: &PathBuf, keep_days: u32) {
    let cutoff = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_sub(keep_days as u64 * 86_400);
    if let Ok(rd) = std::fs::read_dir(logs_dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("access-") || !name.ends_with(".jsonl") {
                continue;
            }
            if let Ok(md) = entry.metadata() {
                if let Ok(modified) = md.modified() {
                    if let Ok(secs) = modified.duration_since(UNIX_EPOCH) {
                        if secs.as_secs() < cutoff {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }
}

/// 后台监视线程：确保监视器开启 → 循环批量拉取 → 解析 → 入环形缓冲 + 落盘。
pub fn monitor_loop(
    logs_dir: PathBuf,
    sbie_host: Arc<SbieHost>,
    ring: Arc<Mutex<Ring>>,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
) {
    let _ = std::fs::create_dir_all(&logs_dir);
    cleanup_old_logs(&logs_dir, 7);

    let mut cache = ProcInfoCache::new();
    let mut log = LogFile::new();
    let mut enabled = false;
    // GET2 缓冲：256 页，与 QSbieAPI 相同（SbieAPI.cpp:3069）
    let mut buffer = vec![0u16; 262_144];

    while !stop.load(Ordering::Relaxed) {
        let sbie = match sbie_host.get() {
            Ok(s) => s,
            Err(_) => {
                if active.swap(false, Ordering::Relaxed) {
                    enabled = false;
                }
                std::thread::sleep(Duration::from_secs(3));
                continue;
            }
        };

        if !enabled {
            match sbie.monitor_control(true) {
                Ok(()) => {
                    enabled = true;
                    active.store(true, Ordering::Relaxed);
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_secs(3));
                    continue;
                }
            }
        }

        let mut got_any = false;
        for _round in 0..64 {
            match sbie.monitor_get_batch(&mut buffer) {
                Ok((len, _more)) => {
                    got_any = true;
                    if len == 0 {
                        break;
                    }
                    let bytes =
                        unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u8, len) };
                    let raws = parse_batch(bytes);
                    if raws.is_empty() {
                        break;
                    }
                    let mut events = Vec::with_capacity(raws.len());
                    for r in &raws {
                        if let Some(ev) = convert(r, &mut cache, &sbie) {
                            events.push(ev);
                        }
                    }
                    if !events.is_empty() {
                        log.append(&logs_dir, &events);
                        ring.lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .drain_for(events);
                    }
                }
                Err(st) => {
                    if st == STATUS_DEVICE_NOT_READY {
                        // 驱动可能重启，重新启用监视
                        enabled = false;
                    }
                    break;
                }
            }
        }

        let pace = if got_any {
            Duration::from_millis(80)
        } else {
            Duration::from_millis(200)
        };
        std::thread::sleep(pace);
    }

    if enabled {
        let _ = sbie_host.get().map(|s| s.monitor_control(false));
    }
    active.store(false, Ordering::Relaxed);
}

impl Ring {
    fn drain_for(&mut self, events: Vec<TraceEvent>) {
        for e in events {
            self.push(e);
        }
    }
}
