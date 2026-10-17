//! База вендоров (файл manuf из Wireshark) зашивается в exe, если при сборке задан WBS_MANUF=<путь>.
//! Без него программа работает, только колонка «Вендор» берётся из установленного Wireshark (если он есть).

use std::path::{Path, PathBuf};

fn main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("manuf");
    println!("cargo:rerun-if-env-changed=WBS_MANUF");
    match std::env::var("WBS_MANUF") {
        Ok(p) if Path::new(&p).is_file() => {
            println!("cargo:rerun-if-changed={p}");
            std::fs::copy(&p, &out).expect("копирование manuf");
        }
        _ => std::fs::write(&out, b"").expect("запись пустого manuf"),
    }
    tauri_build::build();
}
