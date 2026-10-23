// DiskGuard - 基于 Sandboxie 核心的磁盘访问限制器
//
// 复用 Sandboxie 内核驱动（SbieDrv）、服务（SbieSvc）与 SbieDll 提供的全部
// 底层能力；本应用只提供现代化 UI 与策略编排，不重复实现内核组件。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod rules;
mod sbie;
mod store;
mod trace;

use sbie::SbieHost;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::menu::{MenuBuilder, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;
use trace::Ring;

pub struct AppState {
    pub sbie: Arc<SbieHost>,
    pub store: Mutex<store::Store>,
    pub ring: Arc<Mutex<Ring>>,
    pub monitor_stop: Arc<AtomicBool>,
    pub monitor_active: Arc<AtomicBool>,
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn toggle_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let visible = w.is_visible().unwrap_or(false);
        if visible && w.is_focused().unwrap_or(false) {
            let _ = w.hide();
        } else {
            let _ = w.show();
            let _ = w.unminimize();
            let _ = w.set_focus();
        }
    }
}

fn main() {
    let sbie = Arc::new(SbieHost::new());
    let ring = Arc::new(Mutex::new(Ring::new(20000)));
    let monitor_stop = Arc::new(AtomicBool::new(false));
    let monitor_active = Arc::new(AtomicBool::new(false));

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main(app);
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(AppState {
            sbie: sbie.clone(),
            store: Mutex::new(store::Store::load()),
            ring: ring.clone(),
            monitor_stop: monitor_stop.clone(),
            monitor_active: monitor_active.clone(),
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::list_apps,
            commands::add_app,
            commands::update_app,
            commands::remove_app,
            commands::launch_app,
            commands::terminate_app,
            commands::list_box_processes,
            commands::get_events,
            commands::clear_events,
            commands::export_events,
            commands::get_prefs,
            commands::set_pref,
            commands::pick_file,
            commands::pick_folder,
            commands::open_in_explorer,
            commands::get_sandbox_path,
        ])
        .setup(move |app| {
            let handle = app.handle().clone();

            let show_item = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
            let quit_item =
                MenuItem::with_id(app, "quit", "退出 DiskGuard", true, None::<&str>)?;
            let menu = MenuBuilder::new(app)
                .items(&[&show_item, &quit_item])
                .build()?;

            let tray = TrayIconBuilder::with_id("diskguard-tray")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("DiskGuard · 磁盘访问控制")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => show_main(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        toggle_main(tray.app_handle());
                    }
                })
                .build(app)?;
            // 托盘图标必须与应用同生命周期；此处有意保留
            std::mem::forget(tray);

            // 实时日志监视线程
            {
                let logs_dir = app
                    .path()
                    .app_data_dir()
                    .unwrap_or_else(|_| std::env::temp_dir().join("DiskGuard"))
                    .join("logs");
                let sbie = sbie.clone();
                let ring = ring.clone();
                let stop = monitor_stop.clone();
                let active = monitor_active.clone();
                std::thread::spawn(move || {
                    trace::monitor_loop(logs_dir, sbie, ring, stop, active);
                });
            }

            // 配置补应用线程（服务恢复后自动同步 Sandboxie.ini）
            {
                let handle = handle.clone();
                std::thread::spawn(move || commands::apply_pending_loop(handle));
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // 关闭窗口即最小化到托盘，退出请使用托盘菜单
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("DiskGuard 运行失败");
}
