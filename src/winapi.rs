//! Windows API wrappers for querying domain user information.

use anyhow::{Context, Result};
use std::ptr::null_mut;
use widestring::{U16CStr, U16CString};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetGetDCName, NetUserEnum, NetUserGetGroups, NetUserGetInfo,
    FILTER_NORMAL_ACCOUNT, GROUP_USERS_INFO_0, USER_INFO_10, USER_INFO_11,
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
            anyhow::bail!("NetUserGetInfo failed with code {status}");
        }
        if buf.is_null() {
            anyhow::bail!("NetUserGetInfo returned null buffer");
        }
        let ui10 = (buf as *mut USER_INFO_10).read();
        free_api_buffer(buf);
        Ok(ui10)
    }
}

/// Query USER_INFO_11 for extended user information.
pub fn get_user_extended_details(servername: Option<&str>, username: &str) -> Result<USER_INFO_11> {
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
            11,
            &mut buf as *mut *mut core::ffi::c_void as _,
        );
        if status != ERROR_SUCCESS.0 {
            anyhow::bail!("NetUserGetInfo failed with code {status}");
        }
        if buf.is_null() {
            anyhow::bail!("NetUserGetInfo returned null buffer");
        }
        let ui11 = (buf as *mut USER_INFO_11).read();
        free_api_buffer(buf);
        Ok(ui11)
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

/// A user record from enumeration with displayable information.
#[derive(Clone, Debug)]
pub struct EnumeratedUser {
    pub username: String,
    pub full_name: String,
    pub comment: String,
}

impl EnumeratedUser {
    /// Check if this user matches the search string (case-insensitive substring match).
    pub fn matches(&self, search: &str) -> bool {
        let search_lower = search.to_lowercase();
        self.username.to_lowercase().contains(&search_lower)
            || self.full_name.to_lowercase().contains(&search_lower)
            || self.comment.to_lowercase().contains(&search_lower)
    }
}

/// Enumerate all users on the server and return those matching the search string.
pub fn enumerate_users(servername: Option<&str>, filter: &str) -> Result<Vec<EnumeratedUser>> {
    unsafe {
        let mut buf: *mut core::ffi::c_void = null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        let mut resume_handle: u32 = 0;

        let server_pw = servername.map(|s| U16CString::from_str(s).unwrap());
        let server_p: PCWSTR = server_pw
            .as_ref()
            .map(|u| PCWSTR(u.as_ptr()))
            .unwrap_or(PCWSTR::null());

        let status = NetUserEnum(
            server_p,
            10, // USER_INFO_10 level
            FILTER_NORMAL_ACCOUNT,
            &mut buf as *mut *mut core::ffi::c_void as _,
            u32::MAX,
            &mut entries_read,
            &mut total_entries,
            Some(&mut resume_handle),
        );

        if status != ERROR_SUCCESS.0 {
            anyhow::bail!("NetUserEnum failed with code {status}");
        }

        let mut users = Vec::new();
        if !buf.is_null() && entries_read > 0 {
            let arr_ptr = buf as *const USER_INFO_10;
            for i in 0..entries_read {
                let item = arr_ptr.add(i as usize).read();
                let username = pwstr_to_string(item.usri10_name).unwrap_or_default();
                let full_name = pwstr_to_string(item.usri10_full_name).unwrap_or_default();
                let comment = pwstr_to_string(item.usri10_comment).unwrap_or_default();

                let user = EnumeratedUser {
                    username,
                    full_name,
                    comment,
                };

                // Filter by search string
                if user.matches(filter) {
                    users.push(user);
                }
            }
        }
        free_api_buffer(buf);

        Ok(users)
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
    use windows::Win32::NetworkManagement::NetManagement::USER_PRIV;

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
