// DiskGuard - Tauri 命令层（前端 IPC 接口）

#![cfg(windows)]

use crate::{rules, AppState};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use tauri::State;

#[derive(Serialize, Clone)]
pub struct StatusInfo {
    pub sbie_found: bool,
    pub home: String,
    pub service_installed: bool,
    pub service_running: bool,
    pub driver_installed: bool,
    pub driver_running: bool,
    pub api_ok: bool,
    pub ini_path: String,
    pub monitor_active: bool,
    pub message: String,
}

fn service_state(name: &str) -> (bool, bool) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("sc")
        .args(["query", name])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            let installed = o.status.success() || text.contains("STATE");
            let running = text.contains("RUNNING");
            (installed, running)
        }
        Err(_) => (false, false),
    }
}

#[tauri::command]
pub fn get_status(state: State<'_, AppState>) -> StatusInfo {
    let (service_installed, service_running) = service_state("SbieSvc");
    let (driver_installed, driver_running) = service_state("SbieDrv");
    let mut sbie_found = false;
    let mut home = String::new();
    let mut api_ok = false;
    let mut ini_path = String::new();
    let mut message = String::new();

    match state.sbie.get() {
        Ok(s) => {
            sbie_found = true;
            home = s.home.display().to_string();
            ini_path = s.ini_path();
            api_ok = s.api_ok();
            if !api_ok {
                message = "已找到 Sandboxie，但驱动 API 不可用（SbieDrv 未运行或版本不匹配）".into();
            }
        }
        Err(e) => {
            message = e;
        }
    }

    StatusInfo {
        sbie_found,
        home,
        service_installed,
        service_running,
        driver_installed,
        driver_running,
        api_ok,
        ini_path,
        monitor_active: state.monitor_active.load(Ordering::Relaxed),
        message,
    }
}

#[derive(Serialize, Clone)]
pub struct AppView {
    pub id: String,
    pub name: String,
    pub exe: String,
    pub exe_name: String,
    pub box_name: String,
    pub mode: crate::store::Mode,
    pub rules: Vec<crate::store::Rule>,
    pub closed_roots: Vec<crate::store::Rule>,
    pub force: bool,
    pub force_folder: bool,
    pub enabled: bool,
    pub running_pids: Vec<u32>,
    pub applied: bool,
    pub exe_exists: bool,
}

fn to_view(
    a: &crate::store::AppEntry,
    sbie: Option<&std::sync::Arc<crate::sbie::Sbie>>,
) -> AppView {
    let running_pids = sbie
        .map(|s| s.enum_processes(&a.box_name))
        .unwrap_or_default();
    let applied = sbie
        .map(|s| s.enum_boxes().iter().any(|b| b == &a.box_name))
        .unwrap_or(false);
    let exe_exists = !a.exe.is_empty() && std::path::Path::new(&a.exe).exists();
    AppView {
        id: a.id.clone(),
        name: a.name.clone(),
        exe: a.exe.clone(),
        exe_name: a.exe_name.clone(),
        box_name: a.box_name.clone(),
        mode: a.mode,
        rules: a.rules.clone(),
        closed_roots: a.closed_roots.clone(),
        force: a.force,
        force_folder: a.force_folder,
        enabled: a.enabled,
        running_pids,
        applied,
        exe_exists,
    }
}

#[tauri::command]
pub fn list_apps(state: State<'_, AppState>) -> Result<Vec<AppView>, String> {
    let store = state.store.lock().unwrap_or_else(|e| e.into_inner());
    let sbie = state.sbie.get().ok();
    Ok(store
        .apps
        .iter()
        .map(|a| to_view(a, sbie.as_ref()))
        .collect())
}

#[derive(Deserialize)]
pub struct AddAppInput {
    pub name: String,
    pub exe: String,
}

#[tauri::command]
pub fn add_app(state: State<'_, AppState>, input: AddAppInput) -> Result<AppView, String> {
    let exe = input.exe.trim().trim_matches('"').to_string();
    if exe.is_empty() || !std::path::Path::new(&exe).exists() {
        return Err("程序路径无效或文件不存在".into());
    }
    let exe_name = std::path::Path::new(&exe)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    if exe_name.is_empty() || !exe_name.to_lowercase().ends_with(".exe") {
        return Err("请选择一个 .exe 可执行文件".into());
    }
    let name = if input.name.trim().is_empty() {
        exe_name.trim_end_matches(".exe").to_string()
    } else {
        input.name.trim().to_string()
    };

    let mut store = state.store.lock().unwrap_or_else(|e| e.into_inner());
    let box_name = store.unique_box_name(&name, &exe);
    let entry = crate::store::AppEntry {
        id: store.new_id(),
        name,
        exe: exe.clone(),
        exe_name,
        box_name,
        mode: crate::store::Mode::Monitor,
        rules: Vec::new(),
        closed_roots: Vec::new(),
        force: true,
        force_folder: false,
        enabled: true,
        created: chrono::Utc::now().timestamp_millis(),
    };
    store.apps.push(entry.clone());
    store.save()?;

    let view = {
        let applied = state
            .sbie
            .get()
            .map(|s| rules::apply_app(&s, &entry).is_ok())
            .unwrap_or(false);
        let mut v = to_view(&entry, None);
        v.applied = applied;
        v
    };
    Ok(view)
}

#[derive(Deserialize)]
pub struct AppEntryInput {
    pub id: String,
    pub name: String,
    pub exe: String,
    pub mode: crate::store::Mode,
    #[serde(default)]
    pub rules: Vec<crate::store::Rule>,
    #[serde(default)]
    pub closed_roots: Vec<crate::store::Rule>,
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub force_folder: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
pub struct UpdateOutcome {
    pub applied: bool,
    pub warning: Option<String>,
}

#[tauri::command]
pub fn update_app(
    state: State<'_, AppState>,
    app: AppEntryInput,
) -> Result<UpdateOutcome, String> {
    let exe = app.exe.trim().trim_matches('"').to_string();
    let exe_name = std::path::Path::new(&exe)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut store = state.store.lock().unwrap_or_else(|e| e.into_inner());
    let entry = store
        .find_mut(&app.id)
        .ok_or_else(|| "找不到该软件条目".to_string())?;
    entry.name = app.name.trim().to_string();
    entry.exe = exe;
    entry.exe_name = exe_name;
    entry.mode = app.mode;
    entry.rules = app.rules;
    entry.closed_roots = app.closed_roots;
    entry.force = app.force;
    entry.force_folder = app.force_folder;
    entry.enabled = app.enabled;
    let snapshot = entry.clone();
    store.save()?;
    drop(store);

    let (applied, warning) = match state.sbie.get() {
        Ok(s) => match rules::apply_app(&s, &snapshot) {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e)),
        },
        Err(e) => (false, Some(e)),
    };
    Ok(UpdateOutcome { applied, warning })
}

#[tauri::command]
pub fn remove_app(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let entry = {
        let store = state.store.lock().unwrap_or_else(|e| e.into_inner());
        store.find(&id).cloned()
    }
    .ok_or_else(|| "找不到该软件条目".to_string())?;

    // 尽力终止沙箱内进程，再拆除规则
    if let Ok(s) = state.sbie.get() {
        let start = s.home.join("Start.exe");
        if start.exists() {
            let _ = std::process::Command::new(&start)
                .args([format!("/box:{}", entry.box_name), "/terminate".to_string()])
                .status();
        }
        let _ = rules::remove_box(&s, &entry.box_name);
    }
    let mut store = state.store.lock().unwrap_or_else(|e| e.into_inner());
    store.apps.retain(|a| a.id != id);
    store.save()?;
    Ok(())
}

#[tauri::command]
pub fn launch_app(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let entry = {
        let store = state.store.lock().unwrap_or_else(|e| e.into_inner());
        store.find(&id).cloned()
    }
    .ok_or_else(|| "找不到该软件条目".to_string())?;
    let s = state.sbie.get()?;
    if !entry.exe.is_empty() {
        rules::apply_app(&s, &entry)?;
    }
    let start = s.home.join("Start.exe");
    if !start.exists() {
        return Err(format!("未找到 {}", start.display()));
    }
    std::process::Command::new(&start)
        .args([format!("/box:{}", entry.box_name), entry.exe.clone()])
        .spawn()
        .map_err(|e| format!("启动失败: {e}"))?;
    Ok(())
}

#[tauri::command]
pub fn terminate_app(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let entry = {
        let store = state.store.lock().unwrap_or_else(|e| e.into_inner());
        store.find(&id).cloned()
    }
    .ok_or_else(|| "找不到该软件条目".to_string())?;
    let s = state.sbie.get()?;
    let start = s.home.join("Start.exe");
    std::process::Command::new(&start)
        .args([format!("/box:{}", entry.box_name), "/terminate".to_string()])
        .status()
        .map_err(|e| format!("终止失败: {e}"))?;
    Ok(())
}

#[derive(Serialize, Clone)]
pub struct ProcView {
    pub pid: u32,
    pub image: String,
}

#[tauri::command]
pub fn list_box_processes(
    state: State<'_, AppState>,
    id: String,
) -> Result<Vec<ProcView>, String> {
    let entry = {
        let store = state.store.lock().unwrap_or_else(|e| e.into_inner());
        store.find(&id).cloned()
    }
    .ok_or_else(|| "找不到该软件条目".to_string())?;
    let s = state.sbie.get()?;
    let mut out = Vec::new();
    for pid in s.enum_processes(&entry.box_name) {
        let image = s
            .query_process(pid)
            .map(|(_, img)| img)
            .unwrap_or_else(|| "?".into());
        out.push(ProcView { pid, image });
    }
    Ok(out)
}

#[tauri::command]
pub fn get_events(
    state: State<'_, AppState>,
    since: u64,
    limit: Option<usize>,
) -> Result<(Vec<crate::trace::TraceEvent>, u64), String> {
    let ring = state.ring.lock().unwrap_or_else(|e| e.into_inner());
    Ok(ring.since(since, limit.unwrap_or(500)))
}

#[tauri::command]
pub fn clear_events(state: State<'_, AppState>) -> Result<u64, String> {
    let mut ring = state.ring.lock().unwrap_or_else(|e| e.into_inner());
    ring.clear();
    Ok(0)
}

fn csv_escape(s: &str) -> String {
    if s.contains('"') || s.contains(',') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[tauri::command]
pub fn export_events(
    state: State<'_, AppState>,
    path: String,
    format: String,
) -> Result<usize, String> {
    let events = {
        let ring = state.ring.lock().unwrap_or_else(|e| e.into_inner());
        ring.all()
    };
    let mut text = String::new();
    match format.as_str() {
        "csv" => {
            use chrono::TimeZone;
            text.push('\u{FEFF}');
            text.push_str("时间,进程,PID,TID,沙箱,路径,操作,结果,访问掩码,消息\r\n");
            for e in &events {
                let ts = chrono::Local
                    .timestamp_millis_opt(e.ts)
                    .single()
                    .map(|d| d.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
                    .unwrap_or_default();
                text.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{}\r\n",
                    ts,
                    csv_escape(&e.process),
                    e.pid,
                    e.tid,
                    csv_escape(&e.box_name),
                    csv_escape(&e.path),
                    csv_escape(&e.op),
                    csv_escape(&e.result),
                    e.access,
                    csv_escape(&e.msg)
                ));
            }
        }
        _ => {
            for e in &events {
                if let Ok(line) = serde_json::to_string(e) {
                    text.push_str(&line);
                    text.push('\n');
                }
            }
        }
    }
    std::fs::write(&path, text).map_err(|e| format!("写入导出文件失败: {e}"))?;
    Ok(events.len())
}

#[tauri::command]
pub fn get_prefs(state: State<'_, AppState>) -> Result<crate::store::Prefs, String> {
    let store = state.store.lock().unwrap_or_else(|e| e.into_inner());
    Ok(store.prefs.clone())
}

#[tauri::command]
pub fn set_pref(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    key: String,
    value: serde_json::Value,
) -> Result<(), String> {
    if key == "autostart" {
        let on = value.as_bool().unwrap_or(false);
        {
            let mut store = state.store.lock().unwrap_or_else(|e| e.into_inner());
            store.prefs.autostart = on;
            store.save()?;
        }
        use tauri_plugin_autostart::ManagerExt;
        let r = if on {
            app.autolaunch().enable()
        } else {
            app.autolaunch().disable()
        };
        r.map_err(|e| format!("设置开机自启失败: {e}"))?;
        return Ok(());
    }
    let mut store = state.store.lock().unwrap_or_else(|e| e.into_inner());
    match key.as_str() {
        "theme" => {
            let v = value.as_str().unwrap_or("auto").to_string();
            if !["auto", "dark", "light"].contains(&v.as_str()) {
                return Err("无效的主题值".into());
            }
            store.prefs.theme = v;
        }
        "close_to_tray" => {
            store.prefs.close_to_tray = value.as_bool().unwrap_or(true);
        }
        _ => return Err("未知偏好项".into()),
    }
    store.save()?;
    Ok(())
}

#[tauri::command]
pub async fn pick_file(
    title: String,
    exe_only: bool,
) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut d = rfd::FileDialog::new().set_title(&title);
        if exe_only {
            d = d.add_filter("可执行文件", &["exe"]);
        }
        Ok(d.pick_file().map(|p| p.to_string_lossy().to_string()))
    })
    .await
    .map_err(|e| format!("文件对话框失败: {e}"))?
}

#[tauri::command]
pub async fn pick_folder(title: String) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let d = rfd::FileDialog::new().set_title(&title);
        Ok(d.pick_folder().map(|p| p.to_string_lossy().to_string()))
    })
    .await
    .map_err(|e| format!("目录对话框失败: {e}"))?
}

#[tauri::command]
pub fn open_in_explorer(path: String) -> Result<(), String> {
    std::process::Command::new("explorer")
        .arg(&path)
        .spawn()
        .map_err(|e| format!("打开目录失败: {e}"))?;
    Ok(())
}

#[tauri::command]
pub fn get_sandbox_path(state: State<'_, AppState>, id: String) -> Result<String, String> {
    let entry = {
        let store = state.store.lock().unwrap_or_else(|e| e.into_inner());
        store.find(&id).cloned()
    }
    .ok_or_else(|| "找不到该软件条目".to_string())?;
    let s = state.sbie.get()?;
    s.box_file_path(&entry.box_name)
        .ok_or_else(|| "无法查询沙箱目录（盒子尚未创建？）".to_string())
}

/// 后台循环：Sandboxie 服务恢复可用后，自动把全部受控软件的配置补应用到 Sandboxie.ini。
pub fn apply_pending_loop(app: tauri::AppHandle) {
    use tauri::Manager;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(20));
        let state = app.state::<AppState>();
        let sbie = match state.sbie.get() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let apps: Vec<crate::store::AppEntry> = {
            let store = state.store.lock().unwrap_or_else(|e| e.into_inner());
            store.apps.clone()
        };
        for entry in apps {
            if entry.enabled {
                let _ = rules::apply_app(&sbie, &entry);
            }
        }
    }
}
