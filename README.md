# netuser

A better `net user <name> /domain` for looking up users on my Windows domain.

## Usage

Run the `netuser` command with a single username argument. It queries the Windows networking APIs to fetch domain user information from the Windows APIs rather than invoking the `net user` command-line tool.

Basic syntax:

```
netuser <username>
```

Examples:

- `netuser alice` — look up user `alice` on the domain.
- In PowerShell (from the project/build directory): `.\netuser alice`
- In Command Prompt: `netuser alice`

Behavior and notes:

- The tool queries the Windows Net* APIs to obtain user and group information. It does not shell out to or parse the text output of the `net user` command.
- Because it uses the Windows networking APIs, the tool requires network access to a domain controller or a machine joined to the domain (depending on flags). If a Domain Controller is not explicitly provided, the tool attempts automatic domain controller discovery unless `--no-discover` is used.
- Ensure the user executing the tool has the appropriate permissions to query account information on the domain.
- The set of fields returned by the Net* APIs (and therefore the fields the tool includes) can vary between Windows versions and locale settings. If you see missing or unexpected fields, check the environment (Windows version, locale) and server-side settings.
- This tool was written on Windows 11, I don't know how it will behave on earlier versions.

## Flags

The CLI supports several short and long flags to control the amount and format of information returned. Short forms are shown first where available.

- `-d`, `--details`
  - Show brief details about the user (e.g. comment).
  - Mutually exclusive with `--extended-details`.
  - Example: `netuser -d alice`

- `-e`, `--extended-details`
  - Show extended details (password age, privilege level, account flags, profile/home/script, etc.).
  - Mutually exclusive with `--details`.
  - Example: `netuser -e alice`

- `-g`, `--groups`
  - Include the groups the user is a member of in the output.
  - Example: `netuser -g alice`

- `-s <SERVER>`, `--server <SERVER>`
  - Query a specific server / domain controller. Accepted formats are normalized to the Net* API form (leading `\\`).
  - Example: `netuser --server DC01 alice`

- `--no-discover`
  - Skip automatic domain controller discovery and use the local machine unless `--server` is provided.
  - Example: `netuser --no-discover alice`

- `-j`, `--json`
  - Output requested details in JSON.
  - JSON includes only the fields requested by other flags:
    - `-j` alone: minimal JSON (USER_INFO_10-level fields when available).
    - `-j -d`: brief detail fields in JSON.
    - `-j -e`: extended fields in JSON.
  - Example: `netuser -e -j alice`

How flags interact / defaults:

- `--details` and `--extended-details` are mutually exclusive. If neither is provided, the default behavior is to print the user's full name only.
- `--json` does not in itself request more detail; combine with `-d` or `-e` to include the corresponding fields.
- `--groups` can be combined with either details mode or used alone.

Notes and caveats:

- The set of available fields and their formatting depends on the Windows version and locale. If returned data looks off, use a domain-connected host to inspect the server-side data or verify API call behavior.
- The tool translates numeric user account flags into human-readable labels derived from the USER_ACCOUNT_FLAGS values returned by the Net* APIs.
- `password_age` is represented in days in JSON output (integer truncation).

## Sample JSON output

Below are representative sample JSON outputs for common flag combinations. These are example formats and field names the tool populates. Actual values and present fields depend on what the domain returns and which detail level is requested.

- `netuser -j alice` (JSON, no detail flags — minimal / level10 when available)

```
{
  "username": "alice",
  "full_name": "Alice Doe"
}
```

- `netuser -d -j alice` (brief details / USER_INFO_10 fields included)

```
{
  "username": "alice",
  "full_name": "Alice Doe",
  "comment": "Corporate account for Alice Doe",
  "user_comment": "Preferred display name: Alice D."
}
```

- `netuser -e -j alice` (extended details / USER_INFO_2-level fields)

```
{
  "username": "alice",
  "full_name": "Alice Doe",
  "comment": "Corporate account for Alice Doe",
  "user_comment": "Preferred display name: Alice D.",
  "user_flags": [
    "Normal account",
    "Password does not expire"
  ],
  "password_age": 42,
  "priv_level": "User",
  "home_dir": "\\\\fileserver\\home\\alice",
  "script_path": "\\\\profiles\\scripts\\login.bat",
  "profile": "\\\\profiles\\alice"
}
```

- `netuser -g -j alice` (groups only, minimal fields plus `groups`)

```
{
  "username": "alice",
  "full_name": "Alice Doe",
  "groups": [
    "DOMAIN\\Employees",
    "DOMAIN\\Engineering",
    "DOMAIN\\AllStaff"
  ]
}
```

- `netuser -d -g -j alice` (brief details + groups)

```
{
  "username": "alice",
  "full_name": "Alice Doe",
  "comment": "Corporate account for Alice Doe",
  "user_comment": "Preferred display name: Alice D.",
  "groups": [
    "DOMAIN\\Employees",
    "DOMAIN\\Engineering"
  ]
}
```

- `netuser -e -g -j alice` (extended details + groups)

```
{
  "username": "alice",
  "full_name": "Alice Doe",
  "comment": "Corporate account for Alice Doe",
  "user_comment": "Preferred display name: Alice D.",
  "user_flags": [
    "Normal account",
    "Password does not expire"
  ],
  "password_age": 42,
  "priv_level": "User",
  "home_dir": "\\\\fileserver\\home\\alice",
  "script_path": "\\\\profiles\\scripts\\login.bat",
  "profile": "\\\\profiles\\alice",
  "groups": [
    "DOMAIN\\Employees",
    "DOMAIN\\Engineering",
    "DOMAIN\\AllStaff"
  ]
}
```

Notes about the sample JSONs:

- Fields with omitted values are not present in the JSON output.
- `password_age` is shown in days (rounded to integer days).
- `priv_level` maps numeric privilege to a label such as `"User"`, `"Administrator"`, or similar.

## Contributing

Feel free to contribute I would be happy to take a look at any PRs raised.
