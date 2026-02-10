//! netuser - A better `net user <name> /domain` for looking up users on my windows domain
//!
//! Features:
//! - CLI via `clap`
//! - Uses `windows` crate to call `NetGetDCName`, `NetUserGetInfo`, `NetUserGetGroups`
//! - Default output is the user's full name (or username if missing)
//! - `-d/--detail` prints basic user info fields
//! - `-e/--extended-details` prints all user info fields
//! - `-g/--groups` prints group membership
//! - `-j/--json` outputs requested details in JSON (respects other flags)

#![allow(non_snake_case)]

mod options;
mod winapi;

use anyhow::{Context, Result};
use clap::Parser;
use options::CmdLineOptions;
use serde::Serialize;
use winapi::{
    decode_user_flags, get_domain_controller_name, get_user_details, get_user_extended_details,
    get_user_groups, pwstr_to_string,
};

/// Lightweight representation of user info results.
struct UserInfo {
    /// username
    username: Option<String>,
    /// full name
    full_name: Option<String>,
    /// admin/description comment
    comment: Option<String>,
    /// user comment
    usr_comment: Option<String>,
    /// user flags
    flags: Option<Vec<String>>,
    /// password age
    password_age: Option<u32>,
    /// user privileges
    privileges: Option<String>,
    /// user home directory
    home_dir: Option<String>,
    /// user script path
    script_path: Option<String>,
    /// user last logon time
    last_logon: Option<u32>,
    /// user last logoff time
    last_logoff: Option<u32>,
    /// user account expiration time
    acct_expires: Option<u32>,
    /// workstations
    workstations: Option<String>,
    /// max storage
    max_storage: Option<u32>,
    /// num_logons
    num_logons: Option<u32>,
    /// user logon server
    logon_server: Option<String>,
    /// country code
    country_code: Option<u32>,
}

#[derive(Serialize)]
struct UserJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_age: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    privileges: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    home_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_logon: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_logoff: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acct_expires: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workstations: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_storage: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_logons: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logon_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country_code: Option<u32>,

    // Only populated when --groups is provided
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<Vec<String>>,
}

// Functions to interpret the data received about users

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
            Some(format!("\\\\{t}"))
        }
    })
}

// Functions querying the Windows API for user information.

/// Query basic USER_INFO_2 for `username` on `servername` (which may be None for local).
fn query_user_extended_details(servername: Option<&str>, username: &str) -> Result<UserInfo> {
    let ui2 = get_user_extended_details(servername, username)?;
    Ok(UserInfo {
        username: pwstr_to_string(ui2.usri2_name),
        full_name: pwstr_to_string(ui2.usri2_full_name),
        comment: pwstr_to_string(ui2.usri2_comment),
        usr_comment: pwstr_to_string(ui2.usri2_usr_comment),
        password_age: Some(seconds_to_days(ui2.usri2_password_age)),
        flags: decode_user_flags(ui2.usri2_flags.0),
        privileges: Some(priv_to_label(ui2.usri2_priv).to_string()),
        home_dir: pwstr_to_string(ui2.usri2_home_dir),
        script_path: pwstr_to_string(ui2.usri2_script_path),
        last_logon: Some(seconds_to_days(ui2.usri2_last_logon)),
        last_logoff: Some(seconds_to_days(ui2.usri2_last_logoff)),
        acct_expires: Some(seconds_to_days(ui2.usri2_acct_expires)),
        workstations: pwstr_to_string(ui2.usri2_workstations),
        max_storage: Some(ui2.usri2_max_storage),
        num_logons: Some(ui2.usri2_num_logons),
        logon_server: pwstr_to_string(ui2.usri2_logon_server),
        country_code: Some(ui2.usri2_country_code),
    })
}

/// Query level 10 (USER_INFO_10) and return a lightweight struct with the fields we need.
fn query_user_details(servername: Option<&str>, username: &str) -> Result<UserInfo> {
    let ui10 = get_user_details(servername, username)?;
    Ok(UserInfo {
        username: pwstr_to_string(ui10.usri10_name),
        full_name: pwstr_to_string(ui10.usri10_full_name),
        comment: pwstr_to_string(ui10.usri10_comment),
        usr_comment: pwstr_to_string(ui10.usri10_usr_comment),
        flags: None,
        password_age: None,
        privileges: None,
        home_dir: None,
        script_path: None,
        last_logon: None,
        last_logoff: None,
        acct_expires: None,
        workstations: None,
        max_storage: None,
        num_logons: None,
        logon_server: None,
        country_code: None,
    })
}

/// Query groups for `username` on `servername` (may be None).
fn query_user_groups(servername: Option<&str>, username: &str) -> Result<Vec<String>> {
    get_user_groups(servername, username)
}

/// Print summary detail.
fn print_detail(user_info: &UserInfo) {
    println!(
        "Name: {}",
        user_info.username.as_deref().unwrap_or_default()
    );
    println!(
        "Full name: {}",
        user_info.full_name.as_deref().unwrap_or_default()
    );
    if let Some(comment) = &user_info.comment {
        println!("Comment: {comment}");
    }
    if let Some(usr_comment) = &user_info.usr_comment {
        println!("User comment: {usr_comment}");
    }
    if let Some(password_age) = &user_info.password_age {
        println!("Password age: {password_age} days");
    }
    if let Some(flags) = &user_info.flags {
        println!("Flags: {}", flags.join(", "));
    }
    if let Some(privileges) = &user_info.privileges {
        println!("Privilege level: {privileges}");
    }
    if let Some(home_dir) = &user_info.home_dir {
        println!("Home directory: {home_dir}");
    }
    if let Some(script_path) = &user_info.script_path {
        println!("Script path: {script_path}");
    }
    if let Some(last_logon) = &user_info.last_logon {
        println!("Last logon: {last_logon}");
    }
    if let Some(last_logoff) = &user_info.last_logoff {
        println!("Last logoff: {last_logoff}");
    }
    if let Some(acct_expires) = &user_info.acct_expires {
        println!("Account expires: {acct_expires}");
    }
    if let Some(workstations) = &user_info.workstations {
        println!("Workstations: {workstations}");
    }
    if let Some(max_storage) = &user_info.max_storage {
        println!("Max storage: {max_storage}");
    }
    if let Some(num_logons) = &user_info.num_logons {
        println!("Number of logons: {num_logons}");
    }
    if let Some(logon_server) = &user_info.logon_server {
        println!("Logon server: {logon_server}");
    }
    if let Some(country_code) = &user_info.country_code {
        println!("Country code: {country_code}");
    }
}

/// Build a `UserJson` from a UserInfo result .
fn build_user_json(
    user_info: &UserInfo,
    groups: Option<&Vec<String>>,
    include_groups: bool,
) -> UserJson {
    UserJson {
        username: user_info.username.clone(),
        full_name: user_info.full_name.clone(),
        comment: user_info.comment.clone(),
        user_comment: user_info.usr_comment.clone(),
        flags: user_info.flags.clone(),
        password_age: user_info.password_age.clone(),
        privileges: user_info.privileges.clone(),
        home_dir: user_info.home_dir.clone(),
        script_path: user_info.script_path.clone(),
        last_logon: user_info.last_logon,
        last_logoff: user_info.last_logoff,
        acct_expires: user_info.acct_expires,
        workstations: user_info.workstations.clone(),
        max_storage: user_info.max_storage,
        num_logons: user_info.num_logons,
        logon_server: user_info.logon_server.clone(),
        country_code: user_info.country_code,
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
    match priv_val.0 {
        0 => "Guest",
        1 => "User",
        2 => "Administrator",
        _ => "Unknown",
    }
}

/// Convert a duration in seconds to whole days (truncating).
fn seconds_to_days(seconds: u32) -> u32 {
    (seconds) / 86_400
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

    // Fetch data according to requested level, with the same fallback behavior (try DC, then local)
    let mut user_info_opt: Option<UserInfo> = None;

    if cli.extended_details {
        match query_user_details(servername, &cli.username) {
            Ok(u10) => user_info_opt = Some(u10),
            Err(e) => {
                if servername.is_some() {
                    eprintln!("warning: failed to query user info using DC ({e}). Falling back to local queries.");
                    user_info_opt =
                        Some(query_user_details(None, &cli.username).with_context(|| {
                            "failed to query user info (fallback) - ensure you have privileges"
                        })?);
                } else {
                    return Err(e).context("failed to query user info");
                }
            }
        }
    } else if cli.details {
        match query_user_details(servername, &cli.username) {
            Ok(u10) => user_info_opt = Some(u10),
            Err(e) => {
                if servername.is_some() {
                    eprintln!("warning: failed to query user info using DC ({e}). Falling back to local queries.");
                    user_info_opt =
                        Some(query_user_details(None, &cli.username).with_context(|| {
                            "failed to query user info (fallback) - ensure you have privileges"
                        })?);
                } else {
                    return Err(e).context("failed to query user info");
                }
            }
        }
    } else {
        user_info_opt = Some(UserInfo {
            username: Some((&cli.username).to_owned()),
            full_name: None,
            comment: None,
            usr_comment: None,
            flags: None,
            password_age: None,
            privileges: None,
            home_dir: None,
            script_path: None,
            last_logon: None,
            last_logoff: None,
            acct_expires: None,
            workstations: None,
            max_storage: None,
            num_logons: None,
            logon_server: None,
            country_code: None,
        })
    };

    // Only query groups when the user explicitly requested --groups.
    // Previously groups were queried when --json was set; now we restrict to -g/--groups only.
    let groups_result = if cli.groups {
        match query_user_groups(servername, &cli.username) {
            Ok(g) => Some(g),
            Err(e) => {
                if servername.is_some() {
                    eprintln!("warning: failed to query groups using DC ({e}). Falling back to local queries.");
                    match query_user_groups(None, &cli.username) {
                        Ok(g2) => Some(g2),
                        Err(e2) => {
                            eprintln!("failed to query groups (fallback): {e2}");
                            None
                        }
                    }
                } else {
                    eprintln!("failed to query groups: {e}");
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
        let json = if let Some(user_info) = user_info_opt.as_ref() {
            // include_detail true because level2 is the extended details
            build_user_json(user_info, groups_result.as_ref(), cli.groups)
        } else {
            // print the minimal object
            UserJson {
                username: Some(cli.username.clone()),
                full_name: None,
                comment: None,
                user_comment: None,
                flags: None,
                password_age: None,
                privileges: None,
                home_dir: None,
                script_path: None,
                last_logon: None,
                last_logoff: None,
                acct_expires: None,
                workstations: None,
                max_storage: None,
                num_logons: None,
                logon_server: None,
                country_code: None,
                groups: None,
            }
        };
        let j = serde_json::to_string_pretty(&json)?;
        println!("{j}");
        return Ok(());
    }

    // Default behavior: if no detail/groups flags, print only the full name (use level 10)
    if !cli.details && !cli.extended_details && !cli.groups {
        // No detail flags requested and no groups: show only full name using level10 when available.
        if let Some(user_info) = user_info_opt.as_ref() {
            if let Some(full_name) = &user_info.full_name {
                println!("{full_name}");
            } else if let Some(name) = &user_info.username {
                println!("{name}");
            } else {
                println!("{}", cli.username.to_owned());
            }
        } else {
            // As a very conservative fallback
            println!("{}", &cli.username);
        }
        return Ok(());
    } else {
        // If detailed, print all fields
        if cli.details || cli.extended_details {
            if let Some(user_info) = user_info_opt.as_ref() {
                print_detail(user_info);
            }
        }
        // If groups requested, print them
        if cli.groups {
            if let Some(gs) = groups_result {
                println!("Groups:");
                for g in gs {
                    println!(" - {g}");
                }
            } else {
                println!("Groups: (none or failed to enumerate)");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{normalize_server_input, priv_to_label, seconds_to_days};
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

        let flags = uj.flags.expect("expected user_flags");
        assert!(flags.iter().any(|s| s.contains("Account disabled")));

        assert_eq!(uj.password_age, Some(1));
        assert_eq!(uj.privileges.as_deref(), Some("Administrator"));
        assert_eq!(uj.home_dir.as_deref(), Some(r"C:\Users\alice"));
        assert_eq!(uj.script_path.as_deref(), Some("login.bat"));
        assert_eq!(uj.profile_path.as_deref(), Some("profile_path"));
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
    fn json_output_detail_contains_expected_fields_and_no_nulls() {
        // Create a simple UserInfo10 and ensure JSON output contains expected keys and no nulls.
        let info10 = super::UserInfo {
            username: Some("bob".into()),
            full_name: Some("Bob Example".into()),
            comment: Some("A comment".into()),
            usr_comment: Some("A user comment".into()),
            password_age: None,
            flags: None,
            privileges: None,
            home_dir: None,
            script_path: None,
            last_logon: None,
            last_logoff: None,
            acct_expires: None,
            workstations: None,
            max_storage: None,
            num_logons: None,
            logon_server: None,
            country_code: None,
        };
        let uj = super::build_user_json(&info10, None, false);
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
