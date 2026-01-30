//! netuser - A better `net user <name> /domain` for looking up users on my windows domain
//!
//! Features:
//! - CLI via `clap`
//! - Uses `windows` crate to call `NetGetDCName`, `NetUserGetInfo`, `NetUserGetGroups`
//! - Default output is the user's full name (or username if missing)
//! - `-d/--detail` prints all user info fields
//! - `-g/--groups` prints group membership
//! - `-j/--json` outputs requested details in JSON (respects other flags)

#![allow(non_snake_case)]

mod options;

use std::ptr::null_mut;

use anyhow::{Context, Result};
use clap::Parser;
use options::CmdLineOptions;
use serde::Serialize;
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

#[derive(Serialize)]
struct UserJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_name: Option<String>,
    // Only populated when --detail is provided
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_flags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_age: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priv_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    home_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,

    // Only populated when --groups is provided
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<Vec<String>>,
}

fn pwstr_to_string(p: PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // PWSTR is *mut u16 internally; convert using U16CStr from widestring
    let raw = p.0;
    if raw.is_null() {
        return None;
    }
    // Safety: Net API returns a null-terminated UTF-16 string
    unsafe { U16CStr::from_ptr_str(raw).to_string().ok() }
}

unsafe fn local_free_api_buffer(ptr: *mut core::ffi::c_void) {
    if !ptr.is_null() {
        // Ignore errors from NetApiBufferFree - nothing we can do about them here
        let _ = NetApiBufferFree(Some(ptr));
    }
}

/// Try to find a domain controller name for the local context.
/// On success, returns Some(String) containing the DC server name (eg: "\\\\DCNAME"),
/// which can be passed as the `servername` parameter to other Net* calls.
/// If it fails, returns None and callers should fall back to using a null servername.
fn get_domain_controller_name() -> Option<String> {
    unsafe {
        // The generated signature for NetGetDCName expects a pointer to a raw buffer pointer
        // (effectively an LPBYTE* / *mut *mut u8). Prepare a raw pointer and pass its address.
        let mut dc_ptr_raw: *mut u8 = std::ptr::null_mut();
        // Pass servername = NULL (local machine), domainname = NULL (default)
        // NetGetDCName expects a pointer to a raw buffer pointer, so pass &mut dc_ptr_raw.
        let status = NetGetDCName(
            PCWSTR::null(),
            PCWSTR::null(),
            &mut dc_ptr_raw as *mut *mut u8,
        );
        if status != ERROR_SUCCESS.0 {
            // couldn't get DC name
            return None;
        }
        // Wrap the raw pointer as PWSTR for our helper conversion
        let dc_pw = PWSTR(dc_ptr_raw as *mut _);
        let dc_name = pwstr_to_string(dc_pw);
        // Free allocated buffer
        local_free_api_buffer(dc_ptr_raw as *mut _);
        dc_name
    }
}

/// Normalizes user-supplied server names for use with Windows Net* APIs.
///
/// Rules:
/// - `None` => `None` (no server)
/// - empty or whitespace-only => `None`
/// - if the value already starts with `\\` (two backslashes) it is returned as-is
/// - if the value does not start with `\\`, a leading `\\` is added
fn normalize_server_input(s: Option<&str>) -> Option<String> {
    s.and_then(|v| {
        let t = v.trim();
        if t.is_empty() {
            return None;
        }
        // If already starts with double backslash, keep as-is.
        if t.starts_with("\\\\") {
            Some(t.to_string())
        } else if t.starts_with('\\') {
            // If starts with a single backslash, ensure it becomes two
            Some(format!("\\\\{}", t.trim_start_matches('\\')))
        } else {
            // Add leading double-backslash
            Some(format!("\\\\{}", t))
        }
    })
}

/// Query basic USER_INFO_2 for `username` on `servername` (which may be None for local).
fn query_user_info(servername: Option<&str>, username: &str) -> Result<USER_INFO_2> {
    unsafe {
        let mut buf: *mut core::ffi::c_void = null_mut();
        // Prepare PCWSTR for server and username
        let server_pw = servername.map(|s| U16CString::from_str(s).unwrap());
        let server_p: PCWSTR = server_pw
            .as_ref()
            .map(|u| PCWSTR(u.as_ptr()))
            .unwrap_or(PCWSTR::null());

        let name_u = U16CString::from_str(username)
            .with_context(|| "failed to encode username as UTF-16")?;
        let name_p: PCWSTR = PCWSTR(name_u.as_ptr());

        let level: u32 = 2; // USER_INFO_2
        let status = NetUserGetInfo(
            server_p,
            name_p,
            level,
            &mut buf as *mut *mut core::ffi::c_void as _,
        );
        if status != ERROR_SUCCESS.0 {
            anyhow::bail!("NetUserGetInfo failed with code {}", status);
        }
        if buf.is_null() {
            anyhow::bail!("NetUserGetInfo returned null buffer");
        }
        // Cast to USER_INFO_2 pointer
        let ui2_ptr = buf as *mut USER_INFO_2;
        let user_info = ui2_ptr.read();
        // Free buffer allocated by NetUserGetInfo
        local_free_api_buffer(buf);
        Ok(user_info)
    }
}

/// Query groups for `username` on `servername` (may be None).
fn query_user_groups(servername: Option<&str>, username: &str) -> Result<Vec<String>> {
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

        // level 0 -> GROUP_USERS_INFO_0 array
        let level: u32 = 0;
        // PrefMaxLen uses -1 in WinAPI to mean "preferred maximum length" => represented as u32::MAX
        let prefmaxlen: u32 = u32::MAX;
        let status = NetUserGetGroups(
            server_p,
            name_p,
            level,
            &mut buf as *mut *mut core::ffi::c_void as _,
            prefmaxlen,
            &mut entries_read,
            &mut total_entries,
        );
        if status != ERROR_SUCCESS.0 {
            anyhow::bail!("NetUserGetGroups failed with code {}", status);
        }
        let mut groups = Vec::new();
        if !buf.is_null() && entries_read > 0 {
            // buf points to an array of GROUP_USERS_INFO_0
            let arr_ptr = buf as *const GROUP_USERS_INFO_0;
            for i in 0..entries_read {
                let item_ptr = arr_ptr.add(i as usize);
                let item = item_ptr.read();
                let name = pwstr_to_string(item.grui0_name);
                if let Some(n) = name {
                    groups.push(n);
                }
            }
        }
        local_free_api_buffer(buf);
        Ok(groups)
    }
}

/// Lightweight representation of USER_INFO_10 results (only what we need).
struct UserInfo10 {
    username: Option<String>,
    full_name: Option<String>,
    /// admin/description comment (usri10_comment)
    comment: Option<String>,
    /// user comment (usri10_usr_comment)
    usr_comment: Option<String>,
}

/// Query level 10 (USER_INFO_10) and return a lightweight struct with the fields we need.
fn query_user_info_level10(servername: Option<&str>, username: &str) -> Result<UserInfo10> {
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

        let level: u32 = 10; // USER_INFO_10
        let status = NetUserGetInfo(
            server_p,
            name_p,
            level,
            &mut buf as *mut *mut core::ffi::c_void as _,
        );
        if status != ERROR_SUCCESS.0 {
            anyhow::bail!("NetUserGetInfo(level=10) failed with code {}", status);
        }
        if buf.is_null() {
            anyhow::bail!("NetUserGetInfo(level=10) returned null buffer");
        }
        // Cast to USER_INFO_10 pointer
        let ui10_ptr = buf as *mut USER_INFO_10;
        let ui10 = ui10_ptr.read();
        // free buffer
        local_free_api_buffer(buf);
        Ok(UserInfo10 {
            username: pwstr_to_string(ui10.usri10_name),
            full_name: pwstr_to_string(ui10.usri10_full_name),
            comment: pwstr_to_string(ui10.usri10_comment),
            usr_comment: pwstr_to_string(ui10.usri10_usr_comment),
        })
    }
}

fn print_default_fullname(user_info: &USER_INFO_2, username: &str) {
    let full_name = pwstr_to_string(user_info.usri2_full_name);
    if let Some(name) = full_name {
        println!("{}", name);
    } else {
        println!("{}", username);
    }
}

/// Print summary for level 10 detailed results.
fn print_detail(info: &UserInfo10) {
    println!("Name: {}", info.username.as_deref().unwrap_or_default());
    println!(
        "Full name: {}",
        info.full_name.as_deref().unwrap_or_default()
    );

    // Print both admin/description comment and the user comment when present.
    if let Some(c) = &info.comment {
        println!("Comment: {}", c);
    }
    if let Some(uc) = &info.usr_comment {
        println!("User comment: {}", uc);
    }
}

/// Print only the full name (or username/fallback) from a level10 result.
fn print_fullname_from_info10(info: &UserInfo10, fallback_username: &str) {
    if let Some(full) = &info.full_name {
        println!("{}", full);
    } else if let Some(name) = &info.username {
        println!("{}", name);
    } else {
        println!("{}", fallback_username);
    }
}

/// Print summary for level 2 extended detailed results.
fn print_extended_detail(user_info: &USER_INFO_2) {
    println!(
        "Name: {}",
        pwstr_to_string(user_info.usri2_name).unwrap_or_default()
    );
    println!(
        "Full name: {}",
        pwstr_to_string(user_info.usri2_full_name).unwrap_or_default()
    );
    println!(
        "Comment: {}",
        pwstr_to_string(user_info.usri2_comment).unwrap_or_default()
    );
    // Also show the user-entered comment (usri2_usr_comment) if present.
    println!(
        "User comment: {}",
        pwstr_to_string(user_info.usri2_usr_comment).unwrap_or_default()
    );
    // Decode and print user flags as human-readable labels.
    let flags_vec = decode_user_flags(user_info.usri2_flags.0 as u32);
    if flags_vec.is_empty() {
        println!("User flags: (none)");
    } else {
        println!("User flags:");
        for f in &flags_vec {
            println!(" - {}", f);
        }
    }
    let pwd_age_days = seconds_to_days(user_info.usri2_password_age);
    let day_suffix = if pwd_age_days == 1 { "" } else { "s" };
    println!("Password age: {} day{}", pwd_age_days, day_suffix);
    // Show human-readable privilege label instead of numeric value.
    println!("Privilege level: {}", priv_to_label(user_info.usri2_priv));
    println!(
        "Home directory: {}",
        pwstr_to_string(user_info.usri2_home_dir).unwrap_or_default()
    );
    println!(
        "Script path: {}",
        pwstr_to_string(user_info.usri2_script_path).unwrap_or_default()
    );
    // Some generated USER_INFO_2 bindings do not expose a `usri2_profile` field.
    // Use `usri2_parms` (typical alternative) when present.
    println!(
        "Profile: {}",
        pwstr_to_string(user_info.usri2_parms).unwrap_or_default()
    );
    // Note: do NOT print password fields or other sensitive data
}

fn build_user_json_extended_detail(
    user_info: &USER_INFO_2,
    groups: Option<&Vec<String>>,
    include_detail: bool,
    include_groups: bool,
) -> UserJson {
    UserJson {
        username: pwstr_to_string(user_info.usri2_name),
        full_name: pwstr_to_string(user_info.usri2_full_name),

        // Admin/description comment
        comment: if include_detail {
            pwstr_to_string(user_info.usri2_comment)
        } else {
            None
        },
        // User-entered comment (not always present for USER_INFO_2)
        user_comment: if include_detail {
            pwstr_to_string(user_info.usri2_usr_comment)
        } else {
            None
        },
        user_flags: if include_detail {
            Some(decode_user_flags(user_info.usri2_flags.0 as u32))
        } else {
            None
        },
        password_age: if include_detail {
            Some(seconds_to_days(user_info.usri2_password_age) as u32)
        } else {
            None
        },
        priv_level: if include_detail {
            Some(priv_to_label(user_info.usri2_priv).to_string())
        } else {
            None
        },
        home_dir: if include_detail {
            pwstr_to_string(user_info.usri2_home_dir)
        } else {
            None
        },
        script_path: if include_detail {
            pwstr_to_string(user_info.usri2_script_path)
        } else {
            None
        },
        profile: if include_detail {
            pwstr_to_string(user_info.usri2_parms)
        } else {
            None
        },

        groups: if include_groups {
            groups.cloned()
        } else {
            None
        },
    }
}

/// Build a `UserJson` from a level-10 result (USER_INFO_10-like).
/// Level 10 only includes basic name/comment/full_name fields; everything
/// else remains omitted.
fn build_user_json_detail(
    info10: &UserInfo10,
    groups: Option<&Vec<String>>,
    include_groups: bool,
) -> UserJson {
    UserJson {
        username: info10.username.clone(),
        full_name: info10.full_name.clone(),

        // include both admin comment and user comment when present
        comment: info10.comment.clone(),
        user_comment: info10.usr_comment.clone(),
        user_flags: None,
        password_age: None,
        priv_level: None,
        home_dir: None,
        script_path: None,
        profile: None,

        groups: if include_groups {
            groups.cloned()
        } else {
            None
        },
    }
}

fn priv_to_label(
    priv_val: windows::Win32::NetworkManagement::NetManagement::USER_PRIV,
) -> &'static str {
    match priv_val.0 as u32 {
        0 => "Guest",
        1 => "User",
        2 => "Administrator",
        _ => "Unknown",
    }
}

/// Convert a duration in seconds to whole days (truncating).
fn seconds_to_days(seconds: u32) -> u64 {
    (seconds as u64) / 86_400
}

fn decode_user_flags(flags: u32) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    if (flags & (UF_SCRIPT.0 as u32)) != 0 {
        out.push("Script".to_string());
    }
    if (flags & (UF_ACCOUNTDISABLE.0 as u32)) != 0 {
        out.push("Account disabled".to_string());
    }
    if (flags & (UF_HOMEDIR_REQUIRED.0 as u32)) != 0 {
        out.push("Home directory required".to_string());
    }
    if (flags & (UF_LOCKOUT.0 as u32)) != 0 {
        out.push("Locked out".to_string());
    }
    if (flags & (UF_PASSWD_NOTREQD.0 as u32)) != 0 {
        out.push("Password not required".to_string());
    }
    if (flags & (UF_PASSWD_CANT_CHANGE.0 as u32)) != 0 {
        out.push("Cannot change password".to_string());
    }
    if (flags & (UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED.0 as u32)) != 0 {
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
    if (flags & (UF_DONT_EXPIRE_PASSWD.0 as u32)) != 0 {
        out.push("Password does not expire".to_string());
    }
    if (flags & (UF_SMARTCARD_REQUIRED.0 as u32)) != 0 {
        out.push("Smartcard required".to_string());
    }
    if (flags & (UF_TRUSTED_FOR_DELEGATION.0 as u32)) != 0 {
        out.push("Trusted for delegation".to_string());
    }
    if (flags & (UF_NOT_DELEGATED.0 as u32)) != 0 {
        out.push("Not delegated".to_string());
    }
    if (flags & (UF_USE_DES_KEY_ONLY.0 as u32)) != 0 {
        out.push("Use DES key only".to_string());
    }
    if (flags & (UF_DONT_REQUIRE_PREAUTH.0 as u32)) != 0 {
        out.push("Does not require preauth".to_string());
    }
    if (flags & UF_PARTIAL_SECRETS_ACCOUNT) != 0 {
        out.push("Partial secrets account".to_string());
    }

    out
}

#[derive(Debug, PartialEq, Eq)]
enum ReqLevel {
    Level2,
    Level10,
}

fn decide_req_level(details: bool, extended_details: bool, json: bool) -> ReqLevel {
    // Extended details explicitly requested -> level2
    if extended_details {
        ReqLevel::Level2
    // If brief details or JSON requested, prefer level10 for minimal exposure
    } else if details || json {
        ReqLevel::Level10
    // Default to level10 when nothing is explicitly requested (keeps behavior conservative)
    } else {
        ReqLevel::Level10
    }
}

fn main() -> Result<()> {
    let cli = CmdLineOptions::parse();

    // Determine server option:
    // - If --no-discover is set: use --server (if provided and non-empty) after normalization; otherwise use local (None).
    // - If --no-discover is not set: if --server provided use it (normalized), otherwise attempt to discover a DC and normalize its name.
    let server_opt: Option<String> = if cli.no_discover {
        // If user explicitly disabled discovery, only use an explicit --server value (normalized).
        normalize_server_input(cli.server.as_deref())
    } else {
        // Discovery allowed
        if let Some(s) = cli.server.as_deref() {
            // explicit --server provided
            normalize_server_input(Some(s))
        } else {
            // try discovery then normalize the name if we got one
            get_domain_controller_name().and_then(|s| normalize_server_input(Some(&s)))
        }
    };
    // Pass an Option<&str> to existing query functions
    let servername = server_opt.as_deref();

    // Decide which information level to request:
    // - If the user asked for extended details -> level 2 (USER_INFO_2)
    // - Else if the user asked for details -> level 10 (USER_INFO_10)
    // - Else if JSON was requested but no detail flags -> use level 10 for minimal JSON
    let req_level = decide_req_level(cli.details, cli.extended_details, cli.json);

    // Fetch data according to requested level, with the same fallback behavior (try DC, then local)
    let mut info2_opt: Option<USER_INFO_2> = None;
    let mut info10_opt: Option<UserInfo10> = None;

    match req_level {
        ReqLevel::Level2 => match query_user_info(servername, &cli.username) {
            Ok(u) => info2_opt = Some(u),
            Err(e) => {
                if servername.is_some() {
                    eprintln!(
                            "warning: failed to query user info using DC ({}). Falling back to local queries.",
                            e
                        );
                    info2_opt = Some(query_user_info(None, &cli.username).with_context(|| {
                        "failed to query user info (fallback) - ensure you have privileges"
                    })?);
                } else {
                    return Err(e).context("failed to query user info");
                }
            }
        },
        ReqLevel::Level10 => match query_user_info_level10(servername, &cli.username) {
            Ok(u10) => info10_opt = Some(u10),
            Err(e) => {
                if servername.is_some() {
                    eprintln!(
                            "warning: failed to query user info using DC ({}). Falling back to local queries.",
                            e
                        );
                    info10_opt = Some(query_user_info_level10(None, &cli.username).with_context(
                        || "failed to query user info (fallback) - ensure you have privileges",
                    )?);
                } else {
                    return Err(e).context("failed to query user info");
                }
            }
        },
    }

    // Only query groups when the user explicitly requested --groups.
    // Previously groups were queried when --json was set; now we restrict to -g/--groups only.
    let groups_result = if cli.groups {
        match query_user_groups(servername, &cli.username) {
            Ok(g) => Some(g),
            Err(e) => {
                if servername.is_some() {
                    eprintln!(
                        "warning: failed to query groups using DC ({}). Falling back to local queries.",
                        e
                    );
                    match query_user_groups(None, &cli.username) {
                        Ok(g2) => Some(g2),
                        Err(e2) => {
                            eprintln!("failed to query groups (fallback): {}", e2);
                            None
                        }
                    }
                } else {
                    eprintln!("failed to query groups: {}", e);
                    None
                }
            }
        }
    } else {
        None
    };

    // Output handling
    if cli.json {
        // Build JSON according to the information we have:
        // - If we fetched level2, use the existing USER_INFO_2 builder (detailed).
        // - If we fetched level10 (or minimal), use the level10 builder.
        let json = if let Some(ui2) = info2_opt.as_ref() {
            // include_detail true because level2 is the extended details
            build_user_json_extended_detail(ui2, groups_result.as_ref(), true, cli.groups)
        } else if let Some(ui10) = info10_opt.as_ref() {
            // level10 builder: only username, full_name and comment are populated
            build_user_json_detail(ui10, groups_result.as_ref(), cli.groups)
        } else {
            // As a last resort, emit minimal JSON with username only
            serde_json::to_value(&UserJson {
                username: Some(cli.username.clone()),
                full_name: None,
                comment: None,
                user_comment: None,
                user_flags: None,
                password_age: None,
                priv_level: None,
                home_dir: None,
                script_path: None,
                profile: None,
                groups: None,
            })?;
            // print the minimal object
            let minimal = UserJson {
                username: Some(cli.username.clone()),
                full_name: None,
                comment: None,
                user_comment: None,
                user_flags: None,
                password_age: None,
                priv_level: None,
                home_dir: None,
                script_path: None,
                profile: None,
                groups: None,
            };
            let j = serde_json::to_string_pretty(&minimal)?;
            println!("{}", j);
            return Ok(());
        };
        let j = serde_json::to_string_pretty(&json)?;
        println!("{}", j);
        return Ok(());
    }

    // Default behavior: if no detail/groups flags, print only the full name (use level 10)
    if !cli.details && !cli.extended_details && !cli.groups {
        // No detail flags requested and no groups: show only full name using level10 when available.
        if let Some(ui10) = info10_opt.as_ref() {
            print_fullname_from_info10(ui10, &cli.username);
        } else if let Some(ui2) = info2_opt.as_ref() {
            // Fallback to USER_INFO_2 based fullname
            print_default_fullname(ui2, &cli.username);
        } else {
            // As a very conservative fallback
            println!("{}", &cli.username);
        }
        return Ok(());
    }

    // If detailed, print all fields
    if cli.details {
        if let Some(ui10) = info10_opt.as_ref() {
            print_detail(ui10);
        }
    } else if cli.extended_details {
        if let Some(ui2) = info2_opt.as_ref() {
            print_extended_detail(ui2);
        }
    }

    // If groups requested, print them
    if cli.groups {
        if let Some(gs) = groups_result {
            println!("Groups:");
            for g in gs {
                println!(" - {}", g);
            }
        } else {
            println!("Groups: (none or failed to enumerate)");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::UF_TEMP_DUPLICATE_ACCOUNT;
    use super::{decode_user_flags, normalize_server_input, priv_to_label, seconds_to_days};
    use std::mem;
    use windows::Win32::NetworkManagement::NetManagement::{USER_ACCOUNT_FLAGS, USER_PRIV};

    // Helper: create a USER_INFO_2-backed TestUser structure that keeps UTF-16 buffers alive.
    struct TestUserInfo {
        _name: widestring::U16CString,
        _full: widestring::U16CString,
        _comment: widestring::U16CString,
        _home: widestring::U16CString,
        _script: widestring::U16CString,
        _parms: widestring::U16CString,
        ui: super::USER_INFO_2,
    }

    fn make_test_userinfo(
        name: &str,
        full: &str,
        comment: &str,
        home: &str,
        script: &str,
        parms: &str,
        flags: u32,
        pwd_age_secs: u32,
        priv_val: USER_PRIV,
    ) -> TestUserInfo {
        use widestring::U16CString;
        use windows::core::PWSTR;

        let name_u = U16CString::from_str(name).unwrap();
        let full_u = U16CString::from_str(full).unwrap();
        let comment_u = U16CString::from_str(comment).unwrap();
        let home_u = U16CString::from_str(home).unwrap();
        let script_u = U16CString::from_str(script).unwrap();
        let parms_u = U16CString::from_str(parms).unwrap();

        unsafe {
            let mut ui: super::USER_INFO_2 = mem::zeroed();
            ui.usri2_name = PWSTR(name_u.as_ptr() as *mut _);
            ui.usri2_full_name = PWSTR(full_u.as_ptr() as *mut _);
            ui.usri2_comment = PWSTR(comment_u.as_ptr() as *mut _);
            ui.usri2_home_dir = PWSTR(home_u.as_ptr() as *mut _);
            ui.usri2_script_path = PWSTR(script_u.as_ptr() as *mut _);
            ui.usri2_parms = PWSTR(parms_u.as_ptr() as *mut _);

            ui.usri2_flags = USER_ACCOUNT_FLAGS(flags);
            ui.usri2_password_age = pwd_age_secs;
            ui.usri2_priv = priv_val;

            TestUserInfo {
                _name: name_u,
                _full: full_u,
                _comment: comment_u,
                _home: home_u,
                _script: script_u,
                _parms: parms_u,
                ui,
            }
        }
    }

    #[test]
    fn normalize_various_inputs() {
        // Already has double backslash -> keep as-is
        assert_eq!(
            normalize_server_input(Some("\\\\DC01")),
            Some(String::from("\\\\DC01"))
        );
        // Single backslash -> normalized to double
        assert_eq!(
            normalize_server_input(Some("\\DC01")),
            Some(String::from("\\\\DC01"))
        );
        // Triple backslashes should be preserved as-is (starts_with("\\\\") is true)
        assert_eq!(
            normalize_server_input(Some("\\\\\\DC01")),
            Some(String::from("\\\\\\DC01"))
        );
        // Plain name -> prefixed with double backslash
        assert_eq!(
            normalize_server_input(Some("DC01")),
            Some(String::from("\\\\DC01"))
        );
        // Whitespace trimmed
        assert_eq!(
            normalize_server_input(Some("  DC01  ")),
            Some(String::from("\\\\DC01"))
        );
        // Empty -> None
        assert_eq!(normalize_server_input(Some("")), None);
        // None -> None
        assert_eq!(normalize_server_input(None), None);
    }

    #[test]
    fn priv_to_label_values() {
        assert_eq!(priv_to_label(USER_PRIV(0)), "Guest");
        assert_eq!(priv_to_label(USER_PRIV(1)), "User");
        assert_eq!(priv_to_label(USER_PRIV(2)), "Administrator");
        // unknown -> Unknown
        assert_eq!(priv_to_label(USER_PRIV(99)), "Unknown");
    }

    #[test]
    fn decode_user_flags_empty() {
        let labels = decode_user_flags(0);
        assert!(labels.is_empty());
    }

    #[test]
    fn decode_user_flags_single_known() {
        // Use a UF_* constant that is available in the bindings and known to be checked
        // by decode_user_flags; this asserts the mapping exists.
        let labels = decode_user_flags(UF_TEMP_DUPLICATE_ACCOUNT);
        assert!(labels
            .iter()
            .any(|s| s.contains("Temporary duplicate account")));
    }

    #[test]
    fn seconds_to_days_tests() {
        assert_eq!(seconds_to_days(0), 0);
        assert_eq!(seconds_to_days(86_400), 1);
        assert_eq!(seconds_to_days(172_800), 2);
        // partial day truncates
        assert_eq!(seconds_to_days(86_400 + 3_600), 1);
    }

    #[test]
    fn build_user_json_from_fake_user_info() {
        let t = make_test_userinfo(
            "alice",
            "Alice Example",
            "Test comment",
            r"C:\Users\alice",
            "login.bat",
            "profile_path",
            super::UF_ACCOUNTDISABLE.0 as u32,
            86_400,
            USER_PRIV(2),
        );

        let uj = super::build_user_json_extended_detail(&t.ui, None, true, false);

        assert_eq!(uj.username.as_deref(), Some("alice"));
        assert_eq!(uj.full_name.as_deref(), Some("Alice Example"));
        assert_eq!(uj.comment.as_deref(), Some("Test comment"));

        let flags = uj.user_flags.expect("expected user_flags");
        assert!(flags.iter().any(|s| s.contains("Account disabled")));

        assert_eq!(uj.password_age, Some(1));
        assert_eq!(uj.priv_level.as_deref(), Some("Administrator"));
        assert_eq!(uj.home_dir.as_deref(), Some(r"C:\Users\alice"));
        assert_eq!(uj.script_path.as_deref(), Some("login.bat"));
        assert_eq!(uj.profile.as_deref(), Some("profile_path"));
    }

    #[test]
    fn cli_short_flags_parse() {
        // Verify short flag parsing for brief and extended details.
        let c: super::CmdLineOptions =
            clap::Parser::try_parse_from(&["netuser", "-d", "alice"]).unwrap();
        assert!(c.details);
        assert!(!c.extended_details);

        let c2: super::CmdLineOptions =
            clap::Parser::try_parse_from(&["netuser", "-e", "alice"]).unwrap();
        assert!(c2.extended_details);
        assert!(!c2.details);
    }

    #[test]
    fn decide_req_level_tests() {
        use super::ReqLevel;
        // default/no flags => level10 (conservative)
        assert_eq!(
            super::decide_req_level(false, false, false),
            ReqLevel::Level10
        );
        // explicit brief details => level10
        assert_eq!(
            super::decide_req_level(true, false, false),
            ReqLevel::Level10
        );
        // explicit extended details => level2
        assert_eq!(
            super::decide_req_level(false, true, false),
            ReqLevel::Level2
        );
        // JSON requested without detail flags => level10
        assert_eq!(
            super::decide_req_level(false, false, true),
            ReqLevel::Level10
        );
    }

    #[test]
    fn json_output_detail_contains_expected_fields_and_no_nulls() {
        // Create a simple UserInfo10 and ensure JSON output contains expected keys and no nulls.
        let info10 = super::UserInfo10 {
            username: Some("bob".into()),
            full_name: Some("Bob Example".into()),
            comment: Some("A comment".into()),
            usr_comment: Some("A user comment".into()),
        };
        let uj = super::build_user_json_detail(&info10, None, false);
        let s = serde_json::to_string(&uj).unwrap();
        // must contain username and full_name and comments, must not contain the string "null"
        assert!(s.contains("\"username\""));
        assert!(s.contains("\"full_name\""));
        // both comment keys when present
        assert!(s.contains("\"comment\""));
        assert!(s.contains("\"user_comment\""));
        assert!(!s.contains("null"));
    }

    #[test]
    fn json_output_extended_detail_contains_expected_fields_and_no_nulls() {
        // Build a USER_INFO_2 and ensure JSON output (detailed) contains fields like password_age and user_flags
        let t = make_test_userinfo(
            "carol",
            "Carol Example",
            "Another comment",
            r"C:\Users\carol",
            "start.bat",
            "parms",
            super::UF_TEMP_DUPLICATE_ACCOUNT,
            86_400 * 2,
            USER_PRIV(1),
        );
        let uj = super::build_user_json_extended_detail(&t.ui, None, true, false);
        let s = serde_json::to_string(&uj).unwrap();
        assert!(s.contains("\"password_age\""));
        assert!(s.contains("\"user_flags\""));
        // No nulls should be present thanks to serde skip_serializing_if
        assert!(!s.contains("null"));
    }
}
