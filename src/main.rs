//! netuser - A better `net user <name> /domain` for looking up users on my windows domain
//!
//! Features:
//! - Default output is the user's full name (or username if missing)
//! - `-d/--detail` prints basic user info fields
//! - `-e/--extended-details` prints all user info fields
//! - `-g/--groups` prints group membership
//! - `-r/--reverse` performs a reverse lookup to find users by full name, username, or comment
//! - `-j/--json` outputs requested details in JSON (respects other flags)

#![allow(non_snake_case)]

mod options;
mod winapi;

use anyhow::{Context, Result};
use clap::Parser;
use comfy_table::Table;
use options::CmdLineOptions;
use serde::Serialize;
use winapi::{
    decode_privileges, enumerate_users, get_domain_controller_name, get_user_details,
    get_user_extended_details, get_user_groups, pwstr_to_string,
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
    /// password age
    password_age: Option<u32>,
    /// user privileges
    privileges: Option<String>,
    /// user home directory
    home_dir: Option<String>,
    /// user last logon time
    last_logon: Option<u32>,
    /// user last logoff time
    last_logoff: Option<u32>,
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
    password_age: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    privileges: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    home_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_logon: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_logoff: Option<u32>,
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

#[derive(Serialize)]
struct ReverseSearchResult {
    username: String,
    full_name: String,
    comment: String,
}

#[derive(Serialize)]
struct ReverseSearchResults {
    results: Vec<ReverseSearchResult>,
    total: usize,
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

/// Query basic USER_INFO_11 for `username` on `servername` (which may be None for local).
fn query_user_extended_details(servername: Option<&str>, username: &str) -> Result<UserInfo> {
    let ui11 = get_user_extended_details(servername, username)?;
    Ok(UserInfo {
        username: pwstr_to_string(ui11.usri11_name),
        full_name: pwstr_to_string(ui11.usri11_full_name),
        comment: pwstr_to_string(ui11.usri11_comment),
        usr_comment: pwstr_to_string(ui11.usri11_usr_comment),
        password_age: Some(seconds_to_days(ui11.usri11_password_age)),
        privileges: Some(decode_privileges(ui11.usri11_priv).to_string()),
        home_dir: pwstr_to_string(ui11.usri11_home_dir),
        last_logon: Some(seconds_to_days(ui11.usri11_last_logon)),
        last_logoff: Some(seconds_to_days(ui11.usri11_last_logoff)),
        workstations: pwstr_to_string(ui11.usri11_workstations),
        max_storage: Some(ui11.usri11_max_storage),
        num_logons: Some(ui11.usri11_num_logons),
        logon_server: pwstr_to_string(ui11.usri11_logon_server),
        country_code: Some(ui11.usri11_country_code),
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
        password_age: None,
        privileges: None,
        home_dir: None,
        last_logon: None,
        last_logoff: None,
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
    if let Some(privileges) = &user_info.privileges {
        println!("Privilege level: {privileges}");
    }
    if let Some(home_dir) = &user_info.home_dir {
        println!("Home directory: {home_dir}");
    }
    if let Some(last_logon) = &user_info.last_logon {
        println!("Last logon: {last_logon}");
    }
    if let Some(last_logoff) = &user_info.last_logoff {
        println!("Last logoff: {last_logoff}");
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
        password_age: user_info.password_age,
        privileges: user_info.privileges.clone(),
        home_dir: user_info.home_dir.clone(),
        last_logon: user_info.last_logon,
        last_logoff: user_info.last_logoff,
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

/// Convert a duration in seconds to whole days (truncating).
fn seconds_to_days(seconds: u32) -> u32 {
    (seconds) / 86_400
}

/// Display enumerated users in a formatted table.
fn display_users_table(users: &[winapi::EnumeratedUser]) {
    if users.is_empty() {
        println!("No users found matching the search criteria.");
        return;
    }

    let mut table = Table::new();
    table.set_header(vec!["Username", "Full Name", "Comment"]);

    for user in users {
        table.add_row(vec![&user.username, &user.full_name, &user.comment]);
    }

    println!("{table}");
    println!("\nTotal: {} user(s) found", users.len());
}

/// Display enumerated users as JSON.
fn display_users_json(users: &[winapi::EnumeratedUser]) -> Result<()> {
    let results = ReverseSearchResults {
        results: users
            .iter()
            .map(|u| ReverseSearchResult {
                username: u.username.clone(),
                full_name: u.full_name.clone(),
                comment: u.comment.clone(),
            })
            .collect(),
        total: users.len(),
    };

    let json = serde_json::to_string_pretty(&results)?;
    println!("{json}");
    Ok(())
}

fn main() -> Result<()> {
    let cli = CmdLineOptions::parse();

    // Handle reverse lookup mode
    if cli.reverse {
        // Determine server option for reverse lookup
        let server_opt: Option<String> = if cli.no_discover {
            normalize_server_input(cli.server.as_deref())
        } else {
            if let Some(s) = cli.server.as_deref() {
                normalize_server_input(Some(s))
            } else {
                get_domain_controller_name().and_then(|s| normalize_server_input(Some(&s)))
            }
        };
        let servername = server_opt.as_deref();

        // Enumerate all users matching the search string
        let users = enumerate_users(servername, &cli.username)
            .or_else(|e| {
                if servername.is_some() {
                    eprintln!("warning: failed to enumerate users on DC ({e}). Falling back to local queries.");
                    enumerate_users(None, &cli.username)
                } else {
                    Err(e)
                }
            })
            .context("failed to enumerate users - ensure you have privileges")?;

        // Display results based on output format
        if cli.json {
            display_users_json(&users)?;
        } else {
            display_users_table(&users);
        }
        return Ok(());
    }

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
    let user_info_opt: Option<UserInfo>;

    if cli.extended_details {
        match query_user_extended_details(servername, &cli.username) {
            Ok(u10) => user_info_opt = Some(u10),
            Err(e) => {
                if servername.is_some() {
                    eprintln!("warning: failed to query user info using DC ({e}). Falling back to local queries.");
                    user_info_opt = Some(
                        query_user_extended_details(None, &cli.username).with_context(|| {
                            "failed to query user info (fallback) - ensure you have privileges"
                        })?,
                    );
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
            username: Some(cli.username.to_owned()),
            full_name: None,
            comment: None,
            usr_comment: None,
            password_age: None,
            privileges: None,
            home_dir: None,
            last_logon: None,
            last_logoff: None,
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
        let json = if let Some(user_info) = user_info_opt.as_ref() {
            build_user_json(user_info, groups_result.as_ref(), cli.groups)
        } else {
            // print the minimal object
            UserJson {
                username: Some(cli.username.clone()),
                full_name: None,
                comment: None,
                user_comment: None,
                password_age: None,
                privileges: None,
                home_dir: None,
                last_logon: None,
                last_logoff: None,
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
    use super::{build_user_json, normalize_server_input, print_detail, seconds_to_days, UserInfo};

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
    fn normalize_preserves_case() {
        assert_eq!(
            normalize_server_input(Some("DC01")),
            Some(String::from("\\\\DC01"))
        );
        assert_eq!(
            normalize_server_input(Some("\\\\\\DC01")),
            Some(String::from("\\\\\\DC01"))
        );
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
    fn seconds_to_days_zero() {
        assert_eq!(seconds_to_days(0), 0);
    }

    #[test]
    fn seconds_to_days_one_day() {
        assert_eq!(seconds_to_days(86400), 1);
    }

    #[test]
    fn seconds_to_days_just_under_one_day() {
        assert_eq!(seconds_to_days(86399), 0);
    }

    #[test]
    fn seconds_to_days_two_days() {
        assert_eq!(seconds_to_days(172800), 2);
    }

    #[test]
    fn seconds_to_days_max_value() {
        assert_eq!(seconds_to_days(u32::MAX), u32::MAX / 86400);
    }

    #[test]
    fn seconds_to_days_just_over_one_day() {
        assert_eq!(seconds_to_days(86401), 1);
    }

    #[test]
    fn seconds_to_days_one_second() {
        assert_eq!(seconds_to_days(1), 0);
    }

    #[test]
    fn seconds_to_days_large_value() {
        // 365 days worth of seconds
        assert_eq!(seconds_to_days(365 * 86400), 365);
    }

    #[test]
    fn cli_short_flags_parse() {
        // Verify short flag parsing for brief and extended details.
        let c: super::CmdLineOptions =
            clap::Parser::try_parse_from(&["netuser", "-d", "alice"]).unwrap();
        assert!(c.details);
        assert!(!c.extended_details);
        assert_eq!(c.username, "alice".to_string());

        let c2: super::CmdLineOptions =
            clap::Parser::try_parse_from(&["netuser", "-e", "alice"]).unwrap();
        assert!(c2.extended_details);
        assert!(!c2.details);
        assert_eq!(c2.username, "alice".to_string());

        let c3: super::CmdLineOptions =
            clap::Parser::try_parse_from(&["netuser", "alice", "-s", "domain_controller", "-j"])
                .unwrap();
        assert!(c3.json);
        assert_eq!(c3.server, Some("domain_controller".to_string()));
        assert_eq!(c3.username, "alice".to_string());
    }

    #[test]
    fn cli_long_flags_parse() {
        let args = vec![
            "netuser".to_string(),
            "alice".to_string(),
            "--server".to_string(),
            "domain_controller".to_string(),
            "--json".to_string(),
            "--extended-details".to_string(),
        ];
        let c: super::CmdLineOptions = clap::Parser::try_parse_from(args).unwrap();
        assert!(c.json);
        assert!(c.extended_details);
        assert_eq!(c.server, Some("domain_controller".to_string()));
        assert_eq!(c.username, "alice".to_string());
    }

    #[test]
    fn json_output_detail_contains_expected_fields_with_nones() {
        // Create a simple UserInfo10 and ensure JSON output contains expected keys and no nulls.
        let info10 = super::UserInfo {
            username: Some("bob".into()),
            full_name: Some("Bob Example".into()),
            comment: Some("A comment".into()),
            usr_comment: Some("A user comment".into()),
            password_age: None,
            privileges: None,
            home_dir: None,
            last_logon: None,
            last_logoff: None,
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
    fn json_output_detail_contains_expected_fields_and_no_nulls() {
        let user_info = super::UserInfo {
            username: Some("admin".into()),
            full_name: Some("Administrator".into()),
            comment: Some("Built-in account".into()),
            usr_comment: Some("System admin".into()),
            password_age: Some(0),
            privileges: Some("Administrator".into()),
            home_dir: Some("C:\\Users\\admin".into()),
            last_logon: Some(3),
            last_logoff: Some(2),
            workstations: Some("All".into()),
            max_storage: Some(0),
            num_logons: Some(42),
            logon_server: Some("\\\\DC01".into()),
            country_code: Some(44),
        };

        let groups = vec![
            "Administrators".to_string(),
            "Users".to_string(),
            "Remote Desktop Users".to_string(),
        ];

        let json = build_user_json(&user_info, Some(&groups), true);

        assert_eq!(json.username, Some("admin".to_string()));
        assert_eq!(json.full_name, Some("Administrator".to_string()));
        assert_eq!(json.comment, Some("Built-in account".to_string()));
        assert_eq!(json.user_comment, Some("System admin".to_string()));
        assert_eq!(json.privileges, Some("Administrator".to_string()));
        assert_eq!(json.home_dir, Some("C:\\Users\\admin".to_string()));
        assert_eq!(json.last_logon, Some(3));
        assert_eq!(json.last_logoff, Some(2));
        assert_eq!(json.workstations, Some("All".to_string()));
        assert_eq!(json.max_storage, Some(0));
        assert_eq!(json.num_logons, Some(42));
        assert_eq!(json.logon_server, Some("\\\\DC01".to_string()));
        assert_eq!(json.country_code, Some(44));
        assert_eq!(json.groups, Some(groups));
    }

    #[test]
    fn build_user_json_maps_all_fields() {
        let user_info = UserInfo {
            username: Some("testuser".to_string()),
            full_name: Some("Test User".to_string()),
            comment: Some("A comment".to_string()),
            usr_comment: Some("User comment".to_string()),
            password_age: Some(30),
            privileges: Some("User".to_string()),
            home_dir: Some("C:\\home".to_string()),
            last_logon: Some(0),
            last_logoff: Some(0),
            workstations: Some("WS1".to_string()),
            max_storage: Some(0),
            num_logons: Some(5),
            logon_server: Some("DC1".to_string()),
            country_code: Some(0),
        };

        let groups = vec!["Admins".to_string(), "Users".to_string()];
        let json = build_user_json(&user_info, Some(&groups), true);

        assert_eq!(json.username, Some("testuser".to_string()));
        assert_eq!(json.full_name, Some("Test User".to_string()));
        assert_eq!(json.comment, Some("A comment".to_string()));
        assert_eq!(json.user_comment, Some("User comment".to_string()));
        assert_eq!(json.privileges, Some("User".to_string()));
        assert_eq!(json.home_dir, Some("C:\\home".to_string()));
        assert_eq!(json.last_logon, Some(0));
        assert_eq!(json.last_logoff, Some(0));
        assert_eq!(json.workstations, Some("WS1".to_string()));
        assert_eq!(json.max_storage, Some(0));
        assert_eq!(json.num_logons, Some(5));
        assert_eq!(json.logon_server, Some("DC1".to_string()));
        assert_eq!(json.country_code, Some(0));
        assert_eq!(json.groups, Some(groups));
    }

    #[test]
    fn build_user_json_empty_optional_fields_become_none() {
        let user_info = UserInfo {
            username: Some("testuser".to_string()),
            full_name: Some("".to_string()),
            comment: Some("".to_string()),
            usr_comment: Some("".to_string()),
            password_age: Some(0),
            privileges: Some("User".to_string()),
            home_dir: Some("".to_string()),
            last_logon: Some(0),
            last_logoff: Some(0),
            workstations: Some("".to_string()),
            max_storage: Some(0),
            num_logons: Some(0),
            logon_server: Some("".to_string()),
            country_code: Some(0),
        };

        let json = build_user_json(&user_info, None, false);

        assert_eq!(json.username, Some("testuser".to_string()));
        assert_eq!(json.full_name, Some("".to_string()));
        assert_eq!(json.comment, Some("".to_string()));
        assert_eq!(json.user_comment, Some("".to_string()));
        assert_eq!(json.home_dir, Some("".to_string()));
        assert_eq!(json.last_logon, Some(0));
        assert_eq!(json.last_logoff, Some(0));
        assert_eq!(json.workstations, Some("".to_string()));
        assert_eq!(json.max_storage, Some(0));
        assert_eq!(json.logon_server, Some("".to_string()));
        assert_eq!(json.country_code, Some(0));
        assert_eq!(json.groups, None);
    }

    #[test]
    fn build_user_json_preserves_whitespace_in_fields() {
        let user_info = UserInfo {
            username: Some("user1".to_string()),
            full_name: Some("  Name With Spaces  ".to_string()),
            comment: Some("  comment  ".to_string()),
            usr_comment: Some("  ".to_string()),
            password_age: Some(0),
            privileges: Some("User".to_string()),
            home_dir: Some("  C:\\path  ".to_string()),
            last_logon: Some(0),
            last_logoff: Some(0),
            workstations: Some("".to_string()),
            max_storage: Some(0),
            num_logons: Some(0),
            logon_server: Some("".to_string()),
            country_code: Some(0),
        };

        let json = build_user_json(&user_info, None, false);

        // Whitespace-only strings are preserved as-is by build_user_json
        assert_eq!(json.user_comment, Some("  ".to_string()));
        // Strings with content plus whitespace are preserved
        assert_eq!(json.full_name, Some("  Name With Spaces  ".to_string()));
        assert_eq!(json.comment, Some("  comment  ".to_string()));
    }

    #[test]
    fn build_user_json_empty_groups_returns_none() {
        let user_info = UserInfo {
            username: Some("user1".to_string()),
            full_name: Some("Test".to_string()),
            comment: Some("".to_string()),
            usr_comment: Some("".to_string()),
            password_age: Some(0),
            privileges: Some("User".to_string()),
            home_dir: Some("".to_string()),
            last_logon: Some(0),
            last_logoff: Some(0),
            workstations: Some("".to_string()),
            max_storage: Some(0),
            num_logons: Some(0),
            logon_server: Some("".to_string()),
            country_code: Some(0),
        };

        let json = build_user_json(&user_info, None, false);
        assert_eq!(json.groups, None);
    }

    #[test]
    fn build_user_json_single_group() {
        let user_info = UserInfo {
            username: Some("user1".to_string()),
            full_name: Some("Test".to_string()),
            comment: Some("".to_string()),
            usr_comment: Some("".to_string()),
            password_age: Some(0),
            privileges: Some("User".to_string()),
            home_dir: Some("".to_string()),
            last_logon: Some(0),
            last_logoff: Some(0),
            workstations: Some("".to_string()),
            max_storage: Some(0),
            num_logons: Some(0),
            logon_server: Some("".to_string()),
            country_code: Some(0),
        };

        let groups = vec!["Developers".to_string()];
        let json = build_user_json(&user_info, Some(&groups), true);
        assert_eq!(json.groups, Some(groups));
    }

    #[test]
    fn print_detail_does_not_panic() {
        // Smoke test: ensure print_detail handles typical user info without panicking
        let user_info = UserInfo {
            username: Some("test".to_string()),
            full_name: Some("Test User".to_string()),
            comment: Some("Test comment".to_string()),
            usr_comment: Some("User comment".to_string()),
            password_age: Some(10),
            privileges: Some("User".to_string()),
            home_dir: Some("C:\\home\\test".to_string()),
            last_logon: Some(10),
            last_logoff: Some(10),
            workstations: Some("WS1,WS2".to_string()),
            max_storage: Some(0),
            num_logons: Some(42),
            logon_server: Some("\\\\DC01".to_string()),
            country_code: Some(0),
        };
        print_detail(&user_info);
    }

    #[test]
    fn print_detail_empty_optional_fields() {
        // Smoke test with minimal fields
        let user_info = UserInfo {
            username: Some("minimal".to_string()),
            full_name: Some("".to_string()),
            comment: Some("".to_string()),
            usr_comment: Some("".to_string()),
            password_age: Some(0),
            privileges: Some("User".to_string()),
            home_dir: Some("".to_string()),
            last_logon: Some(0),
            last_logoff: Some(0),
            workstations: Some("".to_string()),
            max_storage: Some(0),
            num_logons: Some(0),
            logon_server: Some("".to_string()),
            country_code: Some(0),
        };
        print_detail(&user_info);
    }

    #[test]
    fn print_detail_special_characters() {
        // Smoke test with special characters in fields
        let user_info = UserInfo {
            username: Some("user@domain".to_string()),
            full_name: Some("User, First M. Last (ID: 123)".to_string()),
            comment: Some("Comment with \"quotes\" and 'apostrophes'".to_string()),
            usr_comment: Some("Unicode: café, 日本語".to_string()),
            password_age: Some(0),
            privileges: Some("User".to_string()),
            home_dir: Some("\\\\server\\share\\user@domain".to_string()),
            last_logon: Some(0),
            last_logoff: Some(0),
            workstations: Some("".to_string()),
            max_storage: Some(0),
            num_logons: Some(0),
            logon_server: Some("".to_string()),
            country_code: Some(0),
        };
        print_detail(&user_info);
    }
}
