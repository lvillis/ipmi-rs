pub(crate) fn enabled() -> bool {
    std::env::var("IPMI_DEBUG")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

pub(crate) fn dump_hex(label: &str, bytes: &[u8]) {
    if !enabled() {
        return;
    }
    let mut out = String::with_capacity(label.len() + bytes.len() * 3 + 4);
    out.push_str(label);
    out.push_str(" (");
    out.push_str(&bytes.len().to_string());
    out.push_str("):");
    for b in bytes {
        out.push(' ');
        out.push_str(&format!("{b:02x}"));
    }

    #[cfg(feature = "tracing")]
    tracing::trace!("{out}");

    #[cfg(not(feature = "tracing"))]
    eprintln!("{out}");
}
