// DiskGuard - 应用侧配置持久化
//
// 应用自身的元数据（受控软件列表、UI 偏好）保存在 %APPDATA%\DiskGuard\config.json。
// 与 Sandboxie 相关的生效配置（盒子段落、路径规则）保存在 Sandboxie.ini 中，
// 通过 SbieDll_UpdateConf 写入 —— Sandboxie.ini 是唯一生效源，本文件只是 UI 元数据。

#![cfg(windows)]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// 只监控：不拦截，仅记录
    Monitor,
    /// 黑名单：列出的目录（及子目录）读写全部拒绝
    Blacklist,
    /// 白名单：仅放行列出的目录（只读或读写），封闭根内的其余路径拒绝
    Whitelist,
}

impl Mode {
    pub fn label(&self) -> &'static str {
        match self {
            Mode::Monitor => "只监控",
            Mode::Blacklist => "黑名单",
            Mode::Whitelist => "白名单",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    /// 读写放行（OpenFilePath）
    #[default]
    Rw,
    /// 只读放行（ReadFilePath）
    ReadOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub path: String,
    /// true = 递归子目录（写成 <path>\*），false = 仅该确切路径（写成 |<path>）
    #[serde(default = "default_true")]
    pub recursive: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 白名单模式下的放行类型；黑名单模式忽略
    #[serde(default)]
    pub kind: RuleKind,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppEntry {
    pub id: String,
    pub name: String,
    pub exe: String,
    #[serde(default)]
    pub exe_name: String,
    pub box_name: String,
    pub mode: Mode,
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// 白名单模式的默认封闭根（这些根内除白名单外全部拒绝）
    #[serde(default)]
    pub closed_roots: Vec<Rule>,
    /// 启动时强制进入沙箱（ForceProcess）
    #[serde(default = "default_true")]
    pub force: bool,
    /// 按安装目录强制（ForceFolder，覆盖该目录下全部程序与子进程）
    #[serde(default)]
    pub force_folder: bool,
    /// 该软件的保护总开关
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub created: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prefs {
    /// auto | dark | light
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default = "default_true")]
    pub close_to_tray: bool,
}

fn default_theme() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Store {
    #[serde(default)]
    pub apps: Vec<AppEntry>,
    #[serde(default)]
    pub prefs: Prefs,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            theme: default_theme(),
            autostart: false,
            close_to_tray: true,
        }
    }
}

pub fn appdata_dir() -> PathBuf {
    std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("DiskGuard")
}

fn config_path() -> PathBuf {
    appdata_dir().join("config.json")
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn short_hash(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:08x}")
}

pub fn sanitize_box_stem(name: &str) -> String {
    let filtered: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else if c.is_ascii() {
                '_'
            } else {
                '\u{0}'
            }
        })
        .filter(|c| *c != '\u{0}')
        .collect();
    let trimmed = filtered.trim_matches('_').to_string();
    let stem = if trimmed.is_empty() {
        "App".to_string()
    } else {
        trimmed
    };
    stem.chars().take(20).collect()
}

fn expand_env(p: &str) -> String {
    let mut out = p.to_string();
    for (var, key) in [
        ("%ProgramFiles%", "ProgramFiles"),
        ("%ProgramFiles(x86)%", "ProgramFiles(x86)"),
        ("%SystemDrive%", "SystemDrive"),
    ] {
        if out.contains(var) {
            if let Ok(v) = std::env::var(key) {
                out = out.replace(var, &v);
            }
        }
    }
    out
}

fn preset(
    id: &str,
    name: &str,
    candidates: &[&str],
    box_stem: &str,
) -> AppEntry {
    let found = candidates
        .iter()
        .map(|c| expand_env(c))
        .find(|p| PathBuf::from(p).exists())
        .unwrap_or_else(|| expand_env(candidates[0]));
    let exe_name = PathBuf::from(&found)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    AppEntry {
        id: id.to_string(),
        name: name.to_string(),
        exe: found,
        exe_name,
        box_name: format!("DG_{box_stem}"),
        mode: Mode::Monitor,
        rules: Vec::new(),
        closed_roots: Vec::new(),
        force: true,
        force_folder: false,
        enabled: true,
        created: now_ms(),
    }
}

fn default_store() -> Store {
    Store {
        apps: vec![
            preset(
                "preset-qq",
                "QQ",
                &[
                    r"%ProgramFiles%\Tencent\QQNT\QQ.exe",
                    r"%ProgramFiles%\Tencent\QQ\Bin\QQ.exe",
                    r"%ProgramFiles(x86)%\Tencent\QQ\Bin\QQ.exe",
                ],
                "QQ",
            ),
            preset(
                "preset-wechat",
                "微信",
                &[
                    r"%ProgramFiles%\Tencent\Weixin\Weixin.exe",
                    r"%ProgramFiles%\Tencent\WeChat\WeChat.exe",
                    r"%ProgramFiles(x86)%\Tencent\WeChat\WeChat.exe",
                ],
                "WeChat",
            ),
        ],
        prefs: Prefs::default(),
    }
}

impl Store {
    pub fn load() -> Store {
        let path = config_path();
        if let Ok(text) = std::fs::read_to_string(&path) {
            match serde_json::from_str::<Store>(&text) {
                Ok(mut s) => {
                    // 预置项缺失时补齐（老配置升级）
                    for p in default_store().apps {
                        if !s.apps.iter().any(|a| a.id == p.id) {
                            s.apps.push(p);
                        }
                    }
                    return s;
                }
                Err(_) => {}
            }
        }
        let s = default_store();
        let _ = s.save();
        s
    }

    pub fn save(&self) -> Result<(), String> {
        let dir = appdata_dir();
        std::fs::create_dir_all(&dir).map_err(|e| format!("创建配置目录失败: {e}"))?;
        let path = config_path();
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, text).map_err(|e| format!("写入配置失败: {e}"))?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("保存配置失败: {e}"))?;
        Ok(())
    }

    pub fn find(&self, id: &str) -> Option<&AppEntry> {
        self.apps.iter().find(|a| a.id == id)
    }

    pub fn find_mut(&mut self, id: &str) -> Option<&mut AppEntry> {
        self.apps.iter_mut().find(|a| a.id == id)
    }

    /// 生成不冲突的盒子名：DG_<规范化名>[_<hash>]
    pub fn unique_box_name(&self, name: &str, exe: &str) -> String {
        let stem = sanitize_box_stem(name);
        let mut candidate = format!("DG_{stem}");
        if !self.apps.iter().any(|a| a.box_name == candidate) {
            return candidate;
        }
        candidate = format!("DG_{stem}_{}", short_hash(exe));
        let mut n = 2;
        while self.apps.iter().any(|a| a.box_name == candidate) {
            candidate = format!("DG_{stem}_{}_{n}", short_hash(exe));
            n += 1;
        }
        candidate
    }

    pub fn new_id(&self) -> String {
        format!("app-{}-{}", now_ms(), short_hash(&format!("{}-{}", now_ms(), self.apps.len())))
    }
}
