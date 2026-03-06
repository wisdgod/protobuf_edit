use crate::messages;

pub(crate) fn format_frame_name_template(
    template: &str,
    source: &str,
    idx: usize,
    payload_len: usize,
) -> String {
    use core::fmt::Write as _;

    let template = template.trim();
    let template =
        if template.is_empty() { messages::DEFAULT_FRAME_NAME_TEMPLATE } else { template };

    let mut out = String::with_capacity(template.len().saturating_add(source.len()));
    let mut last: usize = 0;
    while let Some(open_rel) = template[last..].find('{') {
        let open = last.saturating_add(open_rel);
        let Some(close_rel) = template[open.saturating_add(1)..].find('}') else {
            break;
        };
        let close = open.saturating_add(1).saturating_add(close_rel);

        out.push_str(&template[last..open]);
        match &template[open.saturating_add(1)..close] {
            "source" => out.push_str(source),
            "idx" => {
                let _ = write!(out, "{idx}");
            }
            "idx1" => {
                let _ = write!(out, "{}", idx.saturating_add(1));
            }
            "len" => {
                let _ = write!(out, "{payload_len}");
            }
            other => {
                out.push('{');
                out.push_str(other);
                out.push('}');
            }
        }
        last = close.saturating_add(1);
    }
    out.push_str(&template[last..]);
    out
}
