//! Zip без сжатия (метод STORED) - контейнер для .xlsx. Без внешних крейтов: заголовки по спецификации
//! PKWARE APPNOTE, контрольная сумма CRC-32 (IEEE 802.3, полином 0xEDB88320).

fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *slot = c;
        }
        t
    });
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = t[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// Архив из файлов (имя, содержимое) без сжатия. Время файлов - 1980-01-01 00:00 (минимальное в формате).
pub fn store(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    let mut central: Vec<u8> = vec![];
    let (time, date) = (0u16, (1u16 << 5) | 1); // 1980-01-01
    for (name, data) in files {
        let offset = out.len() as u32;
        let crc = crc32(data);
        let n = name.as_bytes();
        let size = data.len() as u32;
        // локальный заголовок
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // версия для распаковки
        out.extend_from_slice(&0x0800u16.to_le_bytes()); // имена в UTF-8
        out.extend_from_slice(&0u16.to_le_bytes()); // STORED
        out.extend_from_slice(&time.to_le_bytes());
        out.extend_from_slice(&date.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(n.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(n);
        out.extend_from_slice(data);
        // запись центрального каталога
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0x0800u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&time.to_le_bytes());
        central.extend_from_slice(&date.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(n.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0u8; 12]); // extra, комментарий, диск, внутренние и внешние атрибуты
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(n);
    }
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]); // номера дисков
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }
}
