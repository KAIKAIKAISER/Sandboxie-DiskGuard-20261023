// DiskGuard - 应用配置 → Sandboxie.ini 规则映射
//
// 对应上游驱动指令（Sandboxie/core/drv/file.c:557-571 与 process_util.c 的装载/匹配）：
//   ClosedFilePath  -> 真实路径读/写全部拒绝（file.c:1553-1564 返回 ACCESS_DENIED 或隐藏）
//   ReadFilePath    -> 只读放行，写入拒绝
//   OpenFilePath    -> 读写直通放行（不受沙箱重定向）
//   UseRuleSpecificity=y -> 最具体规则优先（process_util.c:929-1075），
//                           使白名单的具体放行规则能压过封闭根的宽规则
//   ForceProcess / ForceFolder -> 强制沙箱（core/drv/process_force.c:1148-1243，每盒生效）
//   FileTrace=*     -> 文件打开产生详细 trace 记录（core/drv/process.c:927-948）
// 通配符语义：单个 * 跨目录分隔符，故 <dir>\* 递归覆盖子目录；值以 | 开头则不自动补 *（精确匹配）。

#![cfg(windows)]

use crate::sbie::{sync_conf_list, Sbie};
use crate::store::{AppEntry, Mode, Rule, RuleKind};
use std::path::Path;

pub struct Desired {
    pub force_process: Vec<String>,
    pub force_folder: Vec<String>,
    pub closed: Vec<String>,
    pub open: Vec<String>,
    pub read: Vec<String>,
}

/// 规则 → ini 值。递归规则写成 <path>\*；非递归写成 |<path>（禁用自动补星，精确匹配）。
pub fn rule_to_value(r: &Rule) -> String {
    let p: String = r
        .path
        .trim()
        .trim_end_matches(['\\', '/'])
        .to_string();
    if p.is_empty() {
        return String::new();
    }
    if r.recursive {
        format!("{p}\\*")
    } else {
        format!("|{p}")
    }
}

pub fn desired_for(app: &AppEntry) -> Desired {
    let mut closed = Vec::new();
    let mut open = Vec::new();
    let mut read = Vec::new();

    match app.mode {
        Mode::Monitor => {}
        Mode::Blacklist => {
            for r in &app.rules {
                if r.enabled {
                    let v = rule_to_value(r);
                    if !v.is_empty() {
                        closed.push(v);
                    }
                }
            }
        }
        Mode::Whitelist => {
            for r in &app.closed_roots {
                if r.enabled {
                    let v = rule_to_value(r);
                    if !v.is_empty() {
                        closed.push(v);
                    }
                }
            }
            for r in &app.rules {
                if !r.enabled {
                    continue;
                }
                let v = rule_to_value(r);
                if v.is_empty() {
                    continue;
                }
                match r.kind {
                    RuleKind::Rw => open.push(v),
                    RuleKind::ReadOnly => read.push(v),
                }
            }
        }
    }

    let force_process = if app.force && !app.exe_name.is_empty() {
        vec![app.exe_name.clone()]
    } else {
        Vec::new()
    };
    let force_folder = if app.force_folder {
        Path::new(&app.exe)
            .parent()
            .map(|p| p.to_string_lossy().trim_end_matches('\\').to_string())
            .filter(|s| !s.is_empty())
            .into_iter()
            .collect()
    } else {
        Vec::new()
    };

    Desired {
        force_process,
        force_folder,
        closed,
        open,
        read,
    }
}

/// 把一个受控软件的配置同步到 Sandboxie.ini（差异同步，未变化的行不动）。
pub fn apply_app(sbie: &Sbie, app: &AppEntry) -> Result<(), String> {
    let box_name = &app.box_name;
    sbie.conf_set(box_name, "Enabled", if app.enabled { "y" } else { "n" })?;
    sbie.conf_set(box_name, "BoxNameTitle", "y")?;
    sbie.conf_set(box_name, "UseRuleSpecificity", "y")?;
    sbie.conf_set(box_name, "FileTrace", "*")?;

    let d = desired_for(app);
    sync_conf_list(sbie, box_name, "ForceProcess", &d.force_process)?;
    sync_conf_list(sbie, box_name, "ForceFolder", &d.force_folder)?;
    sync_conf_list(sbie, box_name, "ClosedFilePath", &d.closed)?;
    sync_conf_list(sbie, box_name, "OpenFilePath", &d.open)?;
    sync_conf_list(sbie, box_name, "ReadFilePath", &d.read)?;
    Ok(())
}

/// 撤销一个盒子的全部 DiskGuard 配置（逐设置删除；空段不影响 Sandboxie 其他功能）。
pub fn remove_box(sbie: &Sbie, box_name: &str) -> Result<(), String> {
    let settings = sbie.conf_setting_names(box_name);
    for setting in settings {
        let vals = sbie.conf_values(box_name, &setting);
        if vals.is_empty() {
            sbie.conf_del_setting(box_name, &setting)?;
        } else {
            for v in vals {
                let _ = sbie.conf_del_value(box_name, &setting, &v);
            }
        }
    }
    Ok(())
}
