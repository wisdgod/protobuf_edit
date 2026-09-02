//! Minimal static localization: two locales, one struct of UI strings.
//! Dynamic messages (toasts, errors) stay English for now.

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Locale {
    En,
    Zh,
}

impl Locale {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Zh => "zh",
        }
    }

    pub(crate) fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "en" => Some(Self::En),
            "zh" => Some(Self::Zh),
            _ => None,
        }
    }

    pub(crate) const fn toggle(self) -> Self {
        match self {
            Self::En => Self::Zh,
            Self::Zh => Self::En,
        }
    }

    /// Short label shown on the locale switcher button.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::En => "EN",
            Self::Zh => "中",
        }
    }

    pub(crate) const fn t(self) -> &'static Texts {
        match self {
            Self::En => &EN,
            Self::Zh => &ZH,
        }
    }
}

/// All static UI strings. Technical protobuf terms (Varint, Len, Hex, ...)
/// intentionally stay identical across locales.
pub(crate) struct Texts {
    // Shell / tabs
    pub library: &'static str,
    pub close_tab: &'static str,
    pub frames_tab_suffix: &'static str,
    pub read_only: &'static str,
    pub read_only_title: &'static str,
    pub locale_title: &'static str,

    // Start page
    pub drop_title: &'static str,
    pub drop_hint: &'static str,
    pub paste_placeholder: &'static str,
    pub import_name_placeholder: &'static str,
    pub import: &'static str,
    pub upload: &'static str,
    pub options: &'static str,
    pub frame_template_placeholder: &'static str,
    pub search_placeholder: &'static str,
    pub new_message: &'static str,
    pub select_all: &'static str,
    pub select_none: &'static str,
    pub delete: &'static str,
    pub no_messages: &'static str,
    pub rename: &'static str,
    pub message_fallback: &'static str,

    // Document / tree
    pub no_protobuf_structure: &'static str,
    pub no_data_loaded: &'static str,
    pub no_frame_selected: &'static str,
    pub inspector: &'static str,
    pub inspector_open_title: &'static str,

    // Status bar
    pub no_data: &'static str,
    pub bytes_unit: &'static str,
    pub rows_unit: &'static str,
    pub root_fields_unit: &'static str,
    pub highlights_unit: &'static str,
    pub no_selection: &'static str,
    pub field: &'static str,
    pub span: &'static str,
    pub payload: &'static str,
    pub zero_edits: &'static str,
    pub edits_pending: &'static str,
    pub frames: &'static str,
    pub export: &'static str,
    pub copy_as: &'static str,
    pub copy_share_url: &'static str,
    pub download_bin: &'static str,
    pub save_expand_defaults: &'static str,
    pub save_reparse: &'static str,
    pub bump_reorder: &'static str,

    // Inspector
    pub insert_field: &'static str,
    pub insert: &'static str,
    pub apply: &'static str,
    pub clear: &'static str,
    pub delete_field: &'static str,
    pub close_deselect_title: &'static str,
    pub field_number: &'static str,
    pub wire_type: &'static str,
    pub value: &'static str,
    pub bits: &'static str,
    pub target: &'static str,
    pub insert_span_note: &'static str,

    // Envelope tab
    pub frame_preview: &'static str,
    pub envelope_frames: &'static str,
    pub show_list: &'static str,
    pub hide_list: &'static str,
    pub extract_all: &'static str,
    pub auto_decompress: &'static str,
    pub close: &'static str,
    pub extract: &'static str,

    // Hex context menu
    pub text_column: &'static str,
    pub text_off: &'static str,
}

pub(crate) static EN: Texts = Texts {
    library: "Library",
    close_tab: "Close tab",
    frames_tab_suffix: "frames",
    read_only: "Read-only",
    read_only_title: "Toggle read-only mode (hides editing UI)",
    locale_title: "Switch language",

    drop_title: "Drop a file or paste data",
    drop_hint: "Base64 · Hex · binary file",
    paste_placeholder: "Paste hex/base64…",
    import_name_placeholder: "New message name (optional)",
    import: "Import",
    upload: "Upload",
    options: "Options",
    frame_template_placeholder: "Frame name template ({source} {idx} {idx1} {len})",
    search_placeholder: "Search…",
    new_message: "New",
    select_all: "All",
    select_none: "None",
    delete: "Delete",
    no_messages: "No messages yet.",
    rename: "Rename",
    message_fallback: "Message",

    no_protobuf_structure: "No protobuf structure.",
    no_data_loaded: "No data loaded.",
    no_frame_selected: "No frame selected.",
    inspector: "Inspector",
    inspector_open_title: "Open the inspector",

    no_data: "no data",
    bytes_unit: "bytes",
    rows_unit: "rows",
    root_fields_unit: "root fields",
    highlights_unit: "highlights",
    no_selection: "No selection",
    field: "Field",
    span: "span",
    payload: "payload",
    zero_edits: "0 edits",
    edits_pending: "edit(s) pending",
    frames: "Frames",
    export: "Export",
    copy_as: "Copy as",
    copy_share_url: "Copy share URL",
    download_bin: "Download .bin",
    save_expand_defaults: "Save expand defaults",
    save_reparse: "Save & Reparse",
    bump_reorder: "Bump (reorder)",

    insert_field: "Insert Field",
    insert: "Insert",
    apply: "Apply",
    clear: "Clear",
    delete_field: "Delete",
    close_deselect_title: "Close (deselect)",
    field_number: "Field number",
    wire_type: "Wire type",
    value: "Value",
    bits: "Bits",
    target: "Target",
    insert_span_note: "Inserted fields have no spans until Save & Reparse.",

    frame_preview: "Frame Preview (read-only)",
    envelope_frames: "Envelope frames",
    show_list: "Show list",
    hide_list: "Hide list",
    extract_all: "Extract all",
    auto_decompress: "Auto-decompress \u{2192} Message",
    close: "Close",
    extract: "Extract",

    text_column: "Text column",
    text_off: "Off",
};

pub(crate) static ZH: Texts = Texts {
    library: "库",
    close_tab: "关闭标签",
    frames_tab_suffix: "帧",
    read_only: "只读",
    read_only_title: "切换只读模式（隐藏编辑界面）",
    locale_title: "切换语言",

    drop_title: "拖放文件或粘贴数据",
    drop_hint: "Base64 · Hex · 二进制文件",
    paste_placeholder: "粘贴 hex/base64…",
    import_name_placeholder: "新消息名称（可选）",
    import: "导入",
    upload: "上传",
    options: "选项",
    frame_template_placeholder: "帧名称模板（{source} {idx} {idx1} {len}）",
    search_placeholder: "搜索…",
    new_message: "新建",
    select_all: "全选",
    select_none: "清空",
    delete: "删除",
    no_messages: "还没有消息。",
    rename: "重命名",
    message_fallback: "消息",

    no_protobuf_structure: "无 protobuf 结构。",
    no_data_loaded: "未加载数据。",
    no_frame_selected: "未选择帧。",
    inspector: "检查器",
    inspector_open_title: "打开检查器",

    no_data: "无数据",
    bytes_unit: "字节",
    rows_unit: "行",
    root_fields_unit: "根字段",
    highlights_unit: "高亮",
    no_selection: "未选中",
    field: "字段",
    span: "范围",
    payload: "负载",
    zero_edits: "无编辑",
    edits_pending: "项编辑待保存",
    frames: "帧",
    export: "导出",
    copy_as: "复制为",
    copy_share_url: "复制分享链接",
    download_bin: "下载 .bin",
    save_expand_defaults: "保存展开偏好",
    save_reparse: "保存并重解析",
    bump_reorder: "置顶（重排）",

    insert_field: "插入字段",
    insert: "插入",
    apply: "应用",
    clear: "清除",
    delete_field: "删除",
    close_deselect_title: "关闭（取消选中）",
    field_number: "字段号",
    wire_type: "线类型",
    value: "值",
    bits: "位值",
    target: "目标",
    insert_span_note: "插入的字段在保存并重解析前没有字节范围。",

    frame_preview: "帧预览（只读）",
    envelope_frames: "Envelope 帧",
    show_list: "显示列表",
    hide_list: "隐藏列表",
    extract_all: "全部提取",
    auto_decompress: "自动解压 \u{2192} 消息",
    close: "关闭",
    extract: "提取",

    text_column: "文本列",
    text_off: "关闭",
};
