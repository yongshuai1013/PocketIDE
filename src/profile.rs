/// Guest profile kept independent from any prior project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestProfile {
    pub name: &'static str,
    pub android_release: &'static str,
    pub api_level: u16,
    pub guest_abi: &'static str,
    pub init_program: &'static str,
    pub boot_class_path_era: &'static str,
}

pub const GINGERBREAD_2_3_7: GuestProfile = GuestProfile {
    name: "gingerbread-2.3.7",
    android_release: "2.3.7 Gingerbread",
    api_level: 10,
    guest_abi: "armeabi-v7a (32-bit ARM)",
    init_program: "/init",
    boot_class_path_era: "Dalvik / API 10",
};

impl GuestProfile {
    pub fn summary(self) -> String {
        format!(
            "{} | Android {} | API {} | {} | init {}",
            self.name, self.android_release, self.api_level, self.guest_abi, self.init_program
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_is_the_requested_gingerbread_target() {
        assert_eq!(GINGERBREAD_2_3_7.api_level, 10);
        assert_eq!(GINGERBREAD_2_3_7.guest_abi, "armeabi-v7a (32-bit ARM)");
        assert_eq!(GINGERBREAD_2_3_7.init_program, "/init");
    }
}
