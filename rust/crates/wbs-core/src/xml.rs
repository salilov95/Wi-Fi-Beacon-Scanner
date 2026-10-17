//! Минимальный разбор XML без внешних крейтов - для событий журнала Windows (`EvtRender` → XML).
//!
//! Понимает элементы, атрибуты, текст, `<![CDATA[...]]>`, комментарии, `<?...?>` и сущности
//! (`&lt; &gt; &amp; &quot; &apos; &#NN; &#xHH;`). Имя - без префикса, пространство имён - в `ns`
//! (как `{ns}name` в ElementTree): событие Windows без своего пространства имён 1.x не разбирает.
//! Как `xml.etree.ElementTree` в 1.x, у элемента `text` - текст до первого дочернего элемента.

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Element {
    pub name: String,
    /// URI пространства имён ("" - без него).
    pub ns: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<Element>,
}

impl Element {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    /// Первый дочерний элемент с таким пространством имён и именем (`find("e:Name", NS)` в ElementTree).
    pub fn child(&self, ns: &str, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name && c.ns == ns)
    }
    pub fn children_named<'a>(&'a self, ns: &'a str, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name && c.ns == ns)
    }
}

fn local(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_string()
}

fn decode(s: &str) -> Result<String, String> {
    // концы строк в XML нормализуются до \n (как делает expat)
    let norm;
    let s = if s.contains('\r') {
        norm = s.replace("\r\n", "\n").replace('\r', "\n");
        norm.as_str()
    } else {
        s
    };
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        let end = tail.find(';').ok_or("сущность без ';'")?;
        let ent = &tail[..end];
        let ch = match ent {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ if ent.starts_with("#x") || ent.starts_with("#X") => u32::from_str_radix(&ent[2..], 16)
                .ok()
                .and_then(char::from_u32)
                .ok_or(format!("сущность &{ent};"))?,
            _ if ent.starts_with('#') => ent[1..]
                .parse::<u32>()
                .ok()
                .and_then(char::from_u32)
                .ok_or(format!("сущность &{ent};"))?,
            _ => return Err(format!("неизвестная сущность &{ent};")),
        };
        out.push(ch);
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

struct P<'a> {
    s: &'a str,
    pos: usize,
    /// Объявления пространств имён по вложенности: (префикс, URI); префикс "" - по умолчанию.
    scopes: Vec<(String, String)>,
}

impl<'a> P<'a> {
    fn rest(&self) -> &'a str {
        &self.s[self.pos..]
    }
    fn skip_ws(&mut self) {
        let r = self.rest();
        self.pos += r.len() - r.trim_start().len();
    }
    fn expect(&mut self, t: &str) -> Result<(), String> {
        if self.rest().starts_with(t) {
            self.pos += t.len();
            Ok(())
        } else {
            Err(format!("ожидалось {t:?} на {}", self.pos))
        }
    }
    fn until(&mut self, t: &str) -> Result<&'a str, String> {
        let r = self.rest();
        let i = r.find(t).ok_or(format!("нет {t:?}"))?;
        self.pos += i + t.len();
        Ok(&r[..i])
    }
    /// Пропуск пролога, комментариев и инструкций между элементами.
    fn skip_misc(&mut self) -> Result<(), String> {
        loop {
            self.skip_ws();
            if self.rest().starts_with("<?") {
                self.until("?>")?;
            } else if self.rest().starts_with("<!--") {
                self.until("-->")?;
            } else if self.rest().starts_with("<!DOCTYPE") {
                self.until(">")?;
            } else {
                return Ok(());
            }
        }
    }
    fn name(&mut self) -> Result<&'a str, String> {
        let r = self.rest();
        let n = r
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/' || c == '=')
            .unwrap_or(r.len());
        if n == 0 {
            return Err(format!("нет имени на {}", self.pos));
        }
        self.pos += n;
        Ok(&r[..n])
    }
    fn element(&mut self) -> Result<Element, String> {
        self.expect("<")?;
        let raw_name = self.name()?;
        let mut el = Element {
            name: local(raw_name),
            ..Element::default()
        };
        let scope_len = self.scopes.len();
        let empty;
        loop {
            self.skip_ws();
            if self.rest().starts_with("/>") {
                self.pos += 2;
                empty = true;
                break;
            }
            if self.rest().starts_with('>') {
                self.pos += 1;
                empty = false;
                break;
            }
            let k = self.name()?;
            self.skip_ws();
            self.expect("=")?;
            self.skip_ws();
            let q = self.rest().chars().next().ok_or("конец в атрибуте")?;
            if q != '"' && q != '\'' {
                return Err(format!("атрибут без кавычек на {}", self.pos));
            }
            self.pos += 1;
            let v = decode(self.until(&q.to_string())?)?;
            if k == "xmlns" {
                self.scopes.push((String::new(), v.clone()));
            } else if let Some(prefix) = k.strip_prefix("xmlns:") {
                self.scopes.push((prefix.to_string(), v.clone()));
            }
            let name = if k.starts_with("xmlns") {
                k.to_string()
            } else {
                local(k)
            };
            el.attrs.push((name, v));
        }
        let prefix = raw_name.rsplit_once(':').map_or("", |(p, _)| p);
        el.ns = self
            .scopes
            .iter()
            .rev()
            .find(|(p, _)| p == prefix)
            .map(|(_, u)| u.clone())
            .unwrap_or_default();
        if empty {
            self.scopes.truncate(scope_len);
            return Ok(el);
        }
        let mut text_done = false;
        loop {
            let r = self.rest();
            if r.is_empty() {
                return Err(format!("элемент {raw_name} не закрыт"));
            }
            if r.starts_with("</") {
                self.pos += 2;
                let close = self.name()?;
                if close != raw_name {
                    return Err(format!("закрыт {close}, ожидался {raw_name}"));
                }
                self.skip_ws();
                self.expect(">")?;
                self.scopes.truncate(scope_len);
                return Ok(el);
            }
            if r.starts_with("<!--") {
                self.until("-->")?;
            } else if r.starts_with("<![CDATA[") {
                self.pos += 9;
                let t = self.until("]]>")?;
                if !text_done {
                    el.text.push_str(t);
                }
            } else if r.starts_with("<?") {
                self.until("?>")?;
            } else if r.starts_with('<') {
                el.children.push(self.element()?);
                text_done = true;
            } else {
                let n = r.find('<').unwrap_or(r.len());
                if !text_done {
                    el.text.push_str(&decode(&r[..n])?);
                }
                self.pos += n;
            }
        }
    }
}

/// Корневой элемент документа.
pub fn parse(s: &str) -> Result<Element, String> {
    let mut p = P {
        s: s.trim_start_matches('\u{feff}'),
        pos: 0,
        scopes: vec![],
    };
    p.skip_misc()?;
    let root = p.element()?;
    p.skip_misc()?;
    if !p.rest().trim().is_empty() {
        return Err("лишнее после корневого элемента".into());
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let x = parse(
            "<?xml version='1.0'?><!-- c --><e:Ev xmlns:e='u' a=\"1&amp;2\"> hi &lt;<b/>tail<c n='x'>t<![CDATA[<z>]]></c></e:Ev>",
        )
        .unwrap();
        assert_eq!((x.name.as_str(), x.ns.as_str()), ("Ev", "u"));
        assert_eq!(x.attr("a"), Some("1&2"));
        assert_eq!(x.text, " hi <");
        assert_eq!(x.children.len(), 2);
        assert_eq!(x.child("", "c").unwrap().text, "t<z>");
        let y = parse("<a xmlns='d'><b/><p:c xmlns:p='q'/></a>").unwrap();
        assert!(y.child("d", "b").is_some() && y.child("q", "c").is_some() && y.child("", "b").is_none());
        assert!(parse("<a><b></a>").is_err());
        assert!(parse("<a>&bogus;</a>").is_err());
        assert_eq!(parse("<a>&#1055;&#x440;</a>").unwrap().text, "Пр");
    }
}
