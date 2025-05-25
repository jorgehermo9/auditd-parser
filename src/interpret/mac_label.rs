pub enum MacLabel {
    SELinux(SELinuxContext),
}

pub struct SELinuxContext {
    pub user: String,
    pub role: String,
    pub r#type: String,
    pub level: Option<SELinuxLevel>,
}

pub struct SELinuxLevel {
    pub sensitivity: String,
    pub category: Option<String>,
}

impl MacLabel {
    pub fn module(&self) -> &str {
        match self {
            MacLabel::SELinux(_) => "SELinux",
        }
    }
}

// We will assume that the MAC is always SELinux.
// Some distributions use other MAC such as AppArmor, but for now we will only interpret
// SELinux ones.
// Auparse does not interpret the MAC field and just outputs it as a string https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/interpret.c#L3484
// Ref: https://en.wikipedia.org/wiki/Mandatory_access_control
pub fn resolve_mac_label(mac: &str) -> Option<MacLabel> {
    parse_selinux_context(mac).map(MacLabel::SELinux)
}

pub fn parse_selinux_context(context: &str) -> Option<SELinuxContext> {
    // Ref: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/chap-security-enhanced_linux-selinux_contexts
    let parts: Vec<&str> = context.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    let user = parts[0].to_string();
    let role = parts[1].to_string();
    let r#type = parts[2].to_string();

    // Level is optional, sensitiviy may not be present.
    // Level is composed of sensitivity and category, being the category optional.
    let sensitivity = parts.get(3).map(ToString::to_string);
    let category = parts.get(4).map(ToString::to_string);
    let level = sensitivity.map(|sensitivity| SELinuxLevel {
        sensitivity,
        category,
    });

    Some(SELinuxContext {
        user,
        role,
        r#type,
        level,
    })
}
