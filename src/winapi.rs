//! Windows API wrappers for querying domain user information.

use anyhow::{Context, Result};
use std::ptr::null_mut;
use widestring::{U16CStr, U16CString};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetGetDCName, NetUserGetGroups, NetUserGetInfo, GROUP_USERS_INFO_0,
    UF_ACCOUNTDISABLE, UF_DONT_EXPIRE_PASSWD, UF_DONT_REQUIRE_PREAUTH,
    UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED, UF_HOMEDIR_REQUIRED, UF_INTERDOMAIN_TRUST_ACCOUNT,
    UF_LOCKOUT, UF_NORMAL_ACCOUNT, UF_NOT_DELEGATED, UF_PARTIAL_SECRETS_ACCOUNT,
    UF_PASSWD_CANT_CHANGE, UF_PASSWD_NOTREQD, UF_SCRIPT, UF_SERVER_TRUST_ACCOUNT,
    UF_SMARTCARD_REQUIRED, UF_TEMP_DUPLICATE_ACCOUNT, UF_TRUSTED_FOR_DELEGATION,
    UF_USE_DES_KEY_ONLY, UF_WORKSTATION_TRUST_ACCOUNT, USER_INFO_10, USER_INFO_2,
};

/// Convert a PWSTR from the Windows API to a String.
pub fn pwstr_to_string(p: PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let raw = p.0;
    if raw.is_null() {
        return None;
    }
    unsafe { U16CStr::from_ptr_str(raw).to_string().ok() }
}

/// Free a buffer allocated by the windows API.
unsafe fn free_api_buffer(ptr: *mut core::ffi::c_void) {
    if !ptr.is_null() {
        let _ = NetApiBufferFree(Some(ptr));
    }
}

/// Try to find a domain controller name for the local context.
pub fn get_domain_controller_name() -> Option<String> {
    unsafe {
        let mut dc_ptr_raw: *mut u8 = std::ptr::null_mut();
        let status = NetGetDCName(
            PCWSTR::null(),
            PCWSTR::null(),
            &mut dc_ptr_raw as *mut *mut u8,
        );
        if status != ERROR_SUCCESS.0 {
            return None;
        }
        let dc_pw = PWSTR(dc_ptr_raw as *mut _);
        let dc_name = pwstr_to_string(dc_pw);
        free_api_buffer(dc_ptr_raw as *mut _);
        dc_name
    }
}

/// Query USER_INFO_10 for basic user information.
pub fn get_user_details(servername: Option<&str>, username: &str) -> Result<USER_INFO_10> {
    unsafe {
        let mut buf: *mut core::ffi::c_void = null_mut();
        let server_pw = servername.map(|s| U16CString::from_str(s).unwrap());
        let server_p: PCWSTR = server_pw
            .as_ref()
            .map(|u| PCWSTR(u.as_ptr()))
            .unwrap_or(PCWSTR::null());

        let name_u = U16CString::from_str(username)
            .with_context(|| "failed to encode username as UTF-16")?;
        let name_p: PCWSTR = PCWSTR(name_u.as_ptr());

        let status = NetUserGetInfo(
            server_p,
            name_p,
            10,
            &mut buf as *mut *mut core::ffi::c_void as _,
        );
        if status != ERROR_SUCCESS.0 {
            anyhow::bail!("NetUserGetInfo(level=10) failed with code {status}");
        }
        if buf.is_null() {
            anyhow::bail!("NetUserGetInfo(level=10) returned null buffer");
        }
        let ui10 = (buf as *mut USER_INFO_10).read();
        free_api_buffer(buf);
        Ok(ui10)
    }
}

/// Query USER_INFO_2 for extended user information.
pub fn get_user_extended_details(servername: Option<&str>, username: &str) -> Result<USER_INFO_2> {
    unsafe {
        let mut buf: *mut core::ffi::c_void = null_mut();
        let server_pw = servername.map(|s| U16CString::from_str(s).unwrap());
        let server_p: PCWSTR = server_pw
            .as_ref()
            .map(|u| PCWSTR(u.as_ptr()))
            .unwrap_or(PCWSTR::null());

        let name_u = U16CString::from_str(username)
            .with_context(|| "failed to encode username as UTF-16")?;
        let name_p: PCWSTR = PCWSTR(name_u.as_ptr());

        let status = NetUserGetInfo(
            server_p,
            name_p,
            2,
            &mut buf as *mut *mut core::ffi::c_void as _,
        );
        if status != ERROR_SUCCESS.0 {
            anyhow::bail!("NetUserGetInfo failed with code {status}");
        }
        if buf.is_null() {
            anyhow::bail!("NetUserGetInfo returned null buffer");
        }
        let ui2 = (buf as *mut USER_INFO_2).read();
        free_api_buffer(buf);
        Ok(ui2)
    }
}

/// Query groups for a user.
pub fn get_user_groups(servername: Option<&str>, username: &str) -> Result<Vec<String>> {
    unsafe {
        let mut buf: *mut core::ffi::c_void = null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        let server_pw = servername.map(|s| U16CString::from_str(s).unwrap());
        let server_p: PCWSTR = server_pw
            .as_ref()
            .map(|u| PCWSTR(u.as_ptr()))
            .unwrap_or(PCWSTR::null());

        let name_u = U16CString::from_str(username)
            .with_context(|| "failed to encode username as UTF-16")?;
        let name_p: PCWSTR = PCWSTR(name_u.as_ptr());

        let status = NetUserGetGroups(
            server_p,
            name_p,
            0,
            &mut buf as *mut *mut core::ffi::c_void as _,
            u32::MAX,
            &mut entries_read,
            &mut total_entries,
        );
        if status != ERROR_SUCCESS.0 {
            anyhow::bail!("NetUserGetGroups failed with code {status}");
        }
        let mut groups = Vec::new();
        if !buf.is_null() && entries_read > 0 {
            let arr_ptr = buf as *const GROUP_USERS_INFO_0;
            for i in 0..entries_read {
                let item = arr_ptr.add(i as usize).read();
                if let Some(n) = pwstr_to_string(item.grui0_name) {
                    groups.push(n);
                }
            }
        }
        free_api_buffer(buf);
        Ok(groups)
    }
}

/// Decode user account flags into human-readable strings.
pub fn decode_user_flags(flags: u32) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();

    if (flags & UF_SCRIPT.0) != 0 {
        out.push("Script".to_string());
    }
    if (flags & UF_ACCOUNTDISABLE.0) != 0 {
        out.push("Account disabled".to_string());
    }
    if (flags & UF_HOMEDIR_REQUIRED.0) != 0 {
        out.push("Home directory required".to_string());
    }
    if (flags & UF_LOCKOUT.0) != 0 {
        out.push("Locked out".to_string());
    }
    if (flags & UF_PASSWD_NOTREQD.0) != 0 {
        out.push("Password not required".to_string());
    }
    if (flags & UF_PASSWD_CANT_CHANGE.0) != 0 {
        out.push("Cannot change password".to_string());
    }
    if (flags & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED.0) != 0 {
        out.push("Encrypted text password allowed".to_string());
    }
    if (flags & UF_TEMP_DUPLICATE_ACCOUNT) != 0 {
        out.push("Temporary duplicate account".to_string());
    }
    if (flags & UF_NORMAL_ACCOUNT) != 0 {
        out.push("Normal account".to_string());
    }
    if (flags & UF_INTERDOMAIN_TRUST_ACCOUNT) != 0 {
        out.push("Interdomain trust account".to_string());
    }
    if (flags & UF_WORKSTATION_TRUST_ACCOUNT) != 0 {
        out.push("Workstation trust account".to_string());
    }
    if (flags & UF_SERVER_TRUST_ACCOUNT) != 0 {
        out.push("Server trust account".to_string());
    }
    if (flags & UF_DONT_EXPIRE_PASSWD.0) != 0 {
        out.push("Password does not expire".to_string());
    }
    if (flags & UF_SMARTCARD_REQUIRED.0) != 0 {
        out.push("Smartcard required".to_string());
    }
    if (flags & UF_TRUSTED_FOR_DELEGATION.0) != 0 {
        out.push("Trusted for delegation".to_string());
    }
    if (flags & UF_NOT_DELEGATED.0) != 0 {
        out.push("Not delegated".to_string());
    }
    if (flags & UF_USE_DES_KEY_ONLY.0) != 0 {
        out.push("Use DES key only".to_string());
    }
    if (flags & UF_DONT_REQUIRE_PREAUTH.0) != 0 {
        out.push("Does not require preauth".to_string());
    }
    if (flags & UF_PARTIAL_SECRETS_ACCOUNT) != 0 {
        out.push("Partial secrets account".to_string());
    }
    if !out.is_empty() {
        Some(out)
    } else {
        None
    }
}

pub fn decode_privileges(
    priv_val: windows::Win32::NetworkManagement::NetManagement::USER_PRIV,
) -> &'static str {
    match priv_val.0 {
        0 => "Guest",
        1 => "User",
        2 => "Administrator",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::NetworkManagement::NetManagement::{
        UF_ACCOUNTDISABLE, UF_DONT_EXPIRE_PASSWD, UF_DONT_REQUIRE_PREAUTH, UF_HOMEDIR_REQUIRED,
        UF_LOCKOUT, UF_NORMAL_ACCOUNT, UF_NOT_DELEGATED, UF_PASSWD_CANT_CHANGE, UF_PASSWD_NOTREQD,
        UF_SCRIPT, UF_SMARTCARD_REQUIRED, UF_TRUSTED_FOR_DELEGATION, UF_USE_DES_KEY_ONLY,
        USER_PRIV,
    };

    #[test]
    fn decode_user_flags_empty() {
        let labels = decode_user_flags(0);
        assert!(labels.is_none());
    }

    #[test]
    fn decode_user_flags_single_known() {
        use windows::Win32::NetworkManagement::NetManagement::UF_TEMP_DUPLICATE_ACCOUNT;
        let labels = decode_user_flags(UF_TEMP_DUPLICATE_ACCOUNT);
        assert!(labels
            .unwrap()
            .iter()
            .any(|s| s.contains("Temporary duplicate account")));
    }

    #[test]
    fn decode_user_flags_script() {
        let labels = decode_user_flags(UF_SCRIPT.0).unwrap();
        assert!(labels.iter().any(|s| s == "Script"));
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn decode_user_flags_account_disabled() {
        let labels = decode_user_flags(UF_ACCOUNTDISABLE.0).unwrap();
        assert!(labels.iter().any(|s| s == "Account disabled"));
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn decode_user_flags_home_dir_required() {
        let labels = decode_user_flags(UF_HOMEDIR_REQUIRED.0).unwrap();
        assert!(labels.iter().any(|s| s == "Home directory required"));
    }

    #[test]
    fn decode_user_flags_lockout() {
        let labels = decode_user_flags(UF_LOCKOUT.0).unwrap();
        assert!(labels.iter().any(|s| s == "Locked out"));
    }

    #[test]
    fn decode_user_flags_password_not_required() {
        let labels = decode_user_flags(UF_PASSWD_NOTREQD.0).unwrap();
        assert!(labels.iter().any(|s| s == "Password not required"));
    }

    #[test]
    fn decode_user_flags_password_cant_change() {
        let labels = decode_user_flags(UF_PASSWD_CANT_CHANGE.0).unwrap();
        assert!(labels.iter().any(|s| s == "Cannot change password"));
    }

    #[test]
    fn decode_user_flags_smartcard_required() {
        let labels = decode_user_flags(UF_SMARTCARD_REQUIRED.0).unwrap();
        assert!(labels.iter().any(|s| s == "Smartcard required"));
    }

    #[test]
    fn decode_user_flags_trusted_for_delegation() {
        let labels = decode_user_flags(UF_TRUSTED_FOR_DELEGATION.0).unwrap();
        assert!(labels.iter().any(|s| s == "Trusted for delegation"));
    }

    #[test]
    fn decode_user_flags_not_delegated() {
        let labels = decode_user_flags(UF_NOT_DELEGATED.0).unwrap();
        assert!(labels.iter().any(|s| s == "Not delegated"));
    }

    #[test]
    fn decode_user_flags_use_des_key_only() {
        let labels = decode_user_flags(UF_USE_DES_KEY_ONLY.0).unwrap();
        assert!(labels.iter().any(|s| s == "Use DES key only"));
    }

    #[test]
    fn decode_user_flags_dont_require_preauth() {
        let labels = decode_user_flags(UF_DONT_REQUIRE_PREAUTH.0).unwrap();
        assert!(labels.iter().any(|s| s == "Does not require preauth"));
    }

    #[test]
    fn decode_user_flags_multiple() {
        let combined = UF_SCRIPT.0 | UF_ACCOUNTDISABLE.0 | UF_NORMAL_ACCOUNT;
        let labels = decode_user_flags(combined).unwrap();
        assert!(labels.iter().any(|s| s == "Script"));
        assert!(labels.iter().any(|s| s == "Account disabled"));
        assert!(labels.iter().any(|s| s == "Normal account"));
        assert_eq!(labels.len(), 3);
    }

    #[test]
    fn decode_user_flags_lockout_and_password_expiry() {
        let combined = UF_LOCKOUT.0 | UF_DONT_EXPIRE_PASSWD.0;
        let labels = decode_user_flags(combined).unwrap();
        assert!(labels.iter().any(|s| s == "Locked out"));
        assert!(labels.iter().any(|s| s == "Password does not expire"));
        assert_eq!(labels.len(), 2);
    }

    #[test]
    fn decode_user_flags_all_password_flags() {
        let combined = UF_PASSWD_NOTREQD.0 | UF_PASSWD_CANT_CHANGE.0 | UF_DONT_EXPIRE_PASSWD.0;
        let labels = decode_user_flags(combined).unwrap();
        assert!(labels.iter().any(|s| s == "Password not required"));
        assert!(labels.iter().any(|s| s == "Cannot change password"));
        assert!(labels.iter().any(|s| s == "Password does not expire"));
        assert_eq!(labels.len(), 3);
    }

    #[test]
    fn decode_user_flags_trust_accounts() {
        let combined =
            UF_INTERDOMAIN_TRUST_ACCOUNT | UF_WORKSTATION_TRUST_ACCOUNT | UF_SERVER_TRUST_ACCOUNT;
        let labels = decode_user_flags(combined).unwrap();
        assert!(labels.iter().any(|s| s == "Interdomain trust account"));
        assert!(labels.iter().any(|s| s == "Workstation trust account"));
        assert!(labels.iter().any(|s| s == "Server trust account"));
    }

    #[test]
    fn decode_privileges_guest() {
        assert_eq!(decode_privileges(USER_PRIV(0)), "Guest");
    }

    #[test]
    fn decode_privileges_user() {
        assert_eq!(decode_privileges(USER_PRIV(1)), "User");
    }

    #[test]
    fn decode_privileges_administrator() {
        assert_eq!(decode_privileges(USER_PRIV(2)), "Administrator");
    }

    #[test]
    fn decode_privileges_unknown() {
        assert_eq!(decode_privileges(USER_PRIV(99)), "Unknown");
    }

    #[test]
    fn decode_privileges_negative_unknown() {
        assert_eq!(decode_privileges(USER_PRIV(u32::MAX)), "Unknown");
    }
}
