use std::os::unix::fs::FileTypeExt;
use std::{env, net, io, fs, path};
use std::process::Command;
use std::str::FromStr;
use std::fs::FileType;

use serde::Deserialize;
use litemap::LiteMap;

use nix::unistd::{geteuid, getuid, setuid, User, Group};


/* CONSTANTS */

const CONFIG_FILE: &str = "/etc/lord.toml";
const NO_SPEC_OPT: &str = "missing spec option";
const INV_SPEC_OPT: &str = "invalid spec option";
const DEFAULT_SHELL_PATH: &str = "/bin/sh";


/* CONFIG STRUCT */

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct AppletConfig {
    commands: Vec<String>,

    #[serde(default)]
    src_users: Vec<String>,

    #[serde(default)]
    src_groups: Vec<String>,

    // allow all users to run this
    #[serde(default)]
    open_bar: bool,

    #[serde(default)]
    var: LiteMap<String, String>,

    #[serde(default)]
    env: LiteMap<String, String>,

    #[serde(default)]
    env_keep: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct GlobalConfig {
    include: Option<String>,
    shell: Option<String>,

    #[serde(default)]
    base_env: LiteMap<String, String>,

    #[serde(flatten)]
    applets: LiteMap<String, AppletConfig>,
}


/* ---- GENERIC UTILITIES ---- */

fn read_config_dir(dir_path: &str, config_str: &mut String) -> io::Result<()> {
    for entry in fs::read_dir(dir_path)? {
        config_str.push('\n');
        let path = entry?.path();
        let content = fs::read_to_string(path)?;
        *config_str += content.as_str();
    }

    Ok(())
}

fn toml_parse(config_str: &str, base_err: &'static str) -> Result<GlobalConfig, &'static str> {
    match toml::from_str(config_str) {
        Ok(config) => Ok(config),
        Err(error) => {
            println!("config: {error:?}");
            Err(base_err)
        }
    }
}

fn read_config() -> Result<GlobalConfig, &'static str> {
    let Ok(mut config_str) = fs::read_to_string(CONFIG_FILE) else {
        return Err("failed to read global config file");
    };

    let global = toml_parse(&config_str, "failed to parse base config file")?;

    if let Some(dir_path) = &global.include {
        let Ok(()) = read_config_dir(&dir_path, &mut config_str) else {
            return Err("failed to read config subdir files");
        };
    }

    toml_parse(&config_str, "failed to parse joined config file")
}

fn check_src_user(config: &AppletConfig) -> Result<bool, &'static str> {
    if config.open_bar {
        return Ok(true);
    }

    let Ok(Some(user)) = User::from_uid(getuid()) else {
        return Err("failed to identify source user");
    };

    if config.src_users.contains(&user.name) {
        return Ok(true);
    }

    for group in &config.src_groups {
        if let Some(true) = is_user_member_of_group(group, &user.name) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn main() -> Result<(), &'static str> {
    let mut argv = env::args();

    let _svc = argv.next().ok_or("invalid invocation")?;
    let applet = argv.next().ok_or("missing mode argument")?;

    if ["-h", "--help", "help"].contains(&applet.as_str()) {
        println!("{}", include_str!("usage.txt"));
        return Ok(());
    }

    let current_euid = geteuid();
    if !current_euid.is_root() {
        return Err("not root! is the set-uid bit set?");
    }

    let config = read_config()?;

    let Some(applet_cfg) = config.applets.get(&applet) else {
        return Err("unknown applet");
    };

    if !check_src_user(applet_cfg)? {
        return Err("unauthorized");
    }

    if setuid(current_euid).is_err() {
        return Err("failed to setuid");
    }

    let mut variables: LiteMap<String, String> = LiteMap::new();
    let mut missing = false;

    while let Some(argument) = argv.next() {
        let Some((key, value)) = argument.split_once('=') else {
            return Err("malformated argument (should be key=value)");
        };

        let Some(spec) = applet_cfg.var.get(key) else {
            return Err("unknown argument");
        };

        parse_opt(spec, value)?;

        variables.insert(key.into(), value.into());
    }

    for (key, _value) in &applet_cfg.var {
        if !variables.contains_key(key.as_str()) {
            println!("missing: {key}");
            missing = true;
        }
    }

    if missing {
        return Err("missing argument");
    }

    let mut env: LiteMap<String, String> = config.base_env.clone();
    let mut commands = Vec::new();

    for template in &applet_cfg.commands {
        commands.push(resolve_vars(&variables, &template)?);
    }

    for (key, template) in &applet_cfg.env {
        let value = resolve_vars(&variables, &template)?;
        env.insert(key.into(), value);
    }

    for key in &applet_cfg.env_keep {
        match env::var(key) {
            Ok(value) => _ = env.insert(key.into(), value),
            Err(env::VarError::NotPresent) => (),
            Err(error) => {
                println!("env error: {error:?}");
                return Err("failed to import env value");
            },
        }
    }

    if !env.contains_key("PATH") {
        return Err("no PATH in env");
    };

    let shell_path = match &config.shell {
        Some(path) => path.as_str(),
        None => DEFAULT_SHELL_PATH,
    };

    if !shell_path.starts_with('/') {
        return Err("please provide an absolute shell path");
    }

    for command in commands {
        let mut shell = Command::new(&shell_path);
        shell.env_clear().envs(&env);
        shell.args(["-c", &command]);

        match shell.spawn() {
            Ok(mut exit) => _ = exit.wait(),
            Err(error) => {
                println!("runner => {error:?}");
                return Err("failed to spawn runner command");
            }
        }
    }

    Ok(())
}

fn resolve_vars(variables: &LiteMap<String, String>, mut template: &str) -> Result<String, &'static str> {
    let mut command = String::new();

    while let Some((prefix, name_and_rest)) = template.split_once('{') {
        command += prefix;

        if prefix.ends_with('\\') {
            command.push('{');
            template = name_and_rest;
        } else if let Some((var_name, rest)) = name_and_rest.split_once('}') {
            let Some(value) = variables.get(var_name) else {
                println!("no def: {var_name}");
                return Err("missing variable definition");
            };

            command += value;
            template = rest;
        }
    }

    command += template;
    Ok(command)
}

// canonicalizes a unix path without it needing to exist
fn blind_canon(value: &str) -> Result<String, &'static str> {
    let mut path = String::from(value);

    let Ok(cwd) = env::current_dir() else {
        return Err("failed to read current directory");
    };
    
    let Some(cwd) = cwd.to_str() else {
        return Err("non-utf8 chracters in current directory");
    };

    if !path.starts_with('/') {
        path = format!("{cwd}/{path}");
    }

    for token in ["//", "/./"] {
        while let Some((before, after)) = path.split_once(token) {
            path = format!("{before}/{after}");
        }
    }

    while let Some((before, after)) = path.split_once("/../") {
        let Some((parent, _dir)) = before.rsplit_once('/') else {
            return Err("invalid path");
        };

        path = format!("{parent}/{after}");
    }
    
    Ok(path)
}

fn fs_check(
    file_type_check: Option<fn(&fs::FileType) -> bool>,
    existence_check: Option<bool>,
    ancestor: &str,
    direct_only: bool,
    value: &str,
) -> Result<bool, &'static str> {
    let str_path = blind_canon(value)?;
    let path = path::Path::new(&str_path);

    if let Some(existence) = existence_check {
        if path.exists() != existence {
            return Ok(false);
        }
    }

    let parent_ok = match direct_only {
        true => match path.parent() {
            Some(parent) => parent.to_str() == Some(ancestor),
            None => return Err("failed to identify path parent"),
        }
        false => str_path.starts_with(&ancestor),
    };

    if !parent_ok {
        return Ok(false);
    }

    let Some(file_type_check) = file_type_check else {
        return Ok(true);
    };

    match fs::metadata(path) {
        Ok(md) => Ok(file_type_check(&md.file_type())),
        Err(_) => Ok(false),
    }
}

fn find_entry(dir_path: &str, entry_name: &str) -> io::Result<bool> {
    for entry in fs::read_dir(dir_path)? {
        let name = entry?.file_name();

        if Some(entry_name) == name.to_str() {
            return Ok(true);
        }
    }

    Ok(false)
}

fn entry_check(
    file_type_check: Option<fn(&fs::FileType) -> bool>,
    dir_path: &str,
    entry: &str,
) -> Result<bool, &'static str> {
    match find_entry(dir_path, entry) {
        Ok(true) => (),
        Ok(false) => return Ok(false),
        Err(error) => {
            println!("path: {dir_path:?}");
            println!("read_dir: {error:?}");
            return Err("failed to read directory");
        },
    }

    let Some(file_type_check) = file_type_check else {
        return Ok(true);
    };

    let path = format!("{dir_path}/{entry}");
    match fs::metadata(path) {
        Ok(md) => Ok(file_type_check(&md.file_type())),
        Err(_) => Ok(false),
    }
}

fn valid_domain_name(value: &str) -> bool {
    for part in value.split('.') {
        if part.starts_with('-') | part.ends_with('-') | part.is_empty() {
            return false;
        }

        for c in part.chars() {
            let letter = matches!(c, 'a'..='z' | 'A'..='Z');
            let others = matches!(c, '0'..='1' | '-');
            if !(letter | others) {
                return false;
            }
        }
    }

    true
}

fn valid_email_addr(value: &str, allow_unicode: bool) -> bool {
    const LOCAL_SPECIAL: &str = "!#$%&'*+/=?^_`{|}~-";

    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };

    if !valid_domain_name(domain) {
        return false;
    }

    if let Some(rest) = local.strip_prefix('"') {
        let Some(local) = rest.strip_suffix('"') else {
            return false;
        };

        let mut local = local.bytes();

        while let Some(b) = local.next() {
            match b {
                0x01..=0x08 => (/* valid */),
                0x0b | 0x0c => (/* valid */),
                0x0e..=0x1f => (/* valid */),
                0x21        => (/* valid */),
                0x23..=0x5b => (/* valid */),
                0x5d..=0x7f => (/* valid */),

                // escaped character
                b'\\' => match local.next() {
                    Some(0x01..=0x09) => (/* valid */),
                    Some(0x0b | 0x0c) => (/* valid */),
                    Some(0x0e..=0x7f) => (/* valid */),
                    _other => return false,
                },

                // this is the right exit
                b'"' => return local.next().is_none(),

                _other => break,
            }
        }

        // not the right exit
        false
    } else {
        let consec_dots = local.split_once("..").is_some();
        let xtreme_dots = local.starts_with('.') | local.ends_with('.');

        if consec_dots | xtreme_dots | local.is_empty() {
            return false;
        }

        for c in local.chars() {
            let letter = match allow_unicode {
                false => c.is_ascii_alphabetic(),
                true => c.is_alphabetic(),
            };

            let number = c.is_digit(10);
            let others = LOCAL_SPECIAL.contains(c);

            if !(letter | number | others) {
                return false;
            }
        }

        true
    }
}

fn valid_ip(mut value: &str, ipv6: Option<bool>, with_cidr: bool) -> bool {
    if with_cidr {
        let Some((before, after)) = value.rsplit_once('/') else {
            return false;
        };

        let mask = after.parse::<u8>();

        if !matches!(mask, Ok(0..=32)) {
            return false;
        }

        value = before;
    }

    match ipv6 {
        Some(false) => net::Ipv4Addr::from_str(value).is_ok(),
        Some(true) => net::Ipv6Addr::from_str(value).is_ok(),
        None => net::IpAddr::from_str(value).is_ok(),
    }
}

fn range_check(spec: Option<&str>, num: i64) -> Result<bool, &'static str> {
    let Some(spec) = spec else {
        return Ok(true);
    };

    let (min_str, max_str) = spec.split_once('-').unwrap_or((spec, spec));
    let (Ok(min), Ok(max)) = (min_str.parse(), max_str.parse()) else {
        return Err(INV_SPEC_OPT);
    };

    Ok((num >= min) & (num <= max))
}

fn charset_check(value: &str, alpha: bool, digits: bool, radix: u32, len_spec: Option<&str>) -> Result<bool, &'static str> {
    let Ok(len_i64) = value.len().try_into() else {
        return Ok(false);
    };

    if range_check(len_spec, len_i64)? {
        return Ok(false);
    }

    for c in value.chars() {
        let letter = c.is_alphabetic() & alpha;
        let number = c.is_digit(radix) & digits;
        if !(letter | number) {
            return Ok(false);
        }
    }

    Ok(true)
}

fn mac_addr_check(value: &str, typical: bool) -> bool {
    let is_min_mac = || value.eq_ignore_ascii_case("00:00:00:00:00:00");
    let is_max_mac = || value.eq_ignore_ascii_case("ff:ff:ff:ff:ff:ff");
    let not_typical = || is_min_mac() || is_max_mac();
    let is_hex = |c: char| c.is_ascii_hexdigit();

    if (typical && not_typical()) || (value.len() != 17) {
        return false;
    }

    for part in value.split('.') {
        if part.len() != 2 || !part.chars().all(is_hex) {
            return false;
        }
    }

    true
}

fn is_user_member_of_group(group: &str, user: &str) -> Option<bool> {
    match Group::from_name(group) {
        Ok(Some(group)) => Some(group.mem.iter().any(|u| u == user)),
        _other => None,
    }
}

fn parse_opt(mut spec: &str, value: &str) -> Result<(), &'static str> {
    let mut spec_opt = None;

    if let Some((before, after)) = spec.split_once(':') {
        spec_opt = Some(after);
        spec = before;
    }

    let valid = match spec {
        "user" => matches!(User::from_name(value), Ok(Some(_))),
        "group" => matches!(Group::from_name(value), Ok(Some(_))),
        "member-of" => {
            let group = spec_opt.ok_or(NO_SPEC_OPT)?;
            is_user_member_of_group(group, value).ok_or(INV_SPEC_OPT)?
        }
        "interface" => entry_check(None, "/sys/class/net/", value)?,
        "hex-number" => {
            let value = value.strip_prefix("0x").unwrap_or(value);
            match i64::from_str_radix(value, 16) {
                Ok(num) => range_check(spec_opt, num)?,
                Err(_) => false,
            }
        },
        "number" => match i64::from_str_radix(value, 10) {
            Ok(num) => range_check(spec_opt, num)?,
            Err(_) => false,
        },

        "arbitrary" => true,
        "eq" => spec_opt.ok_or(NO_SPEC_OPT)? == value,

        "email" => valid_email_addr(value, true),
        "ascii-email" => valid_email_addr(value, false),
        "domain-name" => valid_domain_name(value),

        "digits" => charset_check(value, false, true, 10, spec_opt)?,
        "hex-digits" => charset_check(value, false, true, 16, spec_opt)?,
        "alphanumeric" => charset_check(value, true, true, 10, spec_opt)?,
        "letters" => charset_check(value, true, false, 10, spec_opt)?,

        "any-mac-addr" => mac_addr_check(value, false),
        "typical-mac-addr" => mac_addr_check(value, true),

        "ipv4-cidr" => valid_ip(value, Some(false), true),
        "ipv4-addr" => valid_ip(value, Some(false), false),
        "ipv6-cidr" => valid_ip(value, Some(true), true),
        "ipv6-addr" => valid_ip(value, Some(true), false),
        "ip-cidr" => valid_ip(value, None, true),
        "ip-addr" => valid_ip(value, None, false),

        "node-of" => entry_check(None, spec_opt.ok_or(NO_SPEC_OPT)?, value)?,
        "file-of" => entry_check(Some(FileType::is_file), spec_opt.ok_or(NO_SPEC_OPT)?, value)?,
        "link-of" => entry_check(Some(FileType::is_symlink), spec_opt.ok_or(NO_SPEC_OPT)?, value)?,
        "dir-of" => entry_check(Some(FileType::is_dir), spec_opt.ok_or(NO_SPEC_OPT)?, value)?,
        "socket-of" => entry_check(Some(FileType::is_socket), spec_opt.ok_or(NO_SPEC_OPT)?, value)?,
        "chardev-of" => entry_check(Some(FileType::is_char_device), spec_opt.ok_or(NO_SPEC_OPT)?, value)?,
        "blockdev-of" => entry_check(Some(FileType::is_block_device), spec_opt.ok_or(NO_SPEC_OPT)?, value)?,

        "node-in" => fs_check(None, Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, true, value)?,
        "file-in" => fs_check(Some(FileType::is_file), Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, true, value)?,
        "link-in" => fs_check(Some(FileType::is_symlink), Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, true, value)?,
        "dir-in" => fs_check(Some(FileType::is_dir), Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, true, value)?,
        "socket-in" => fs_check(Some(FileType::is_socket), Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, true, value)?,
        "chardev-in" => fs_check(Some(FileType::is_char_device), Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, true, value)?,
        "blockdev-in" => fs_check(Some(FileType::is_block_device), Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, true, value)?,

        "node-below" => fs_check(None, Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, false, value)?,
        "file-below" => fs_check(Some(FileType::is_file), Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, false, value)?,
        "link-below" => fs_check(Some(FileType::is_symlink), Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, false, value)?,
        "dir-below" => fs_check(Some(FileType::is_dir), Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, false, value)?,
        "socket-below" => fs_check(Some(FileType::is_socket), Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, false, value)?,
        "chardev-below" => fs_check(Some(FileType::is_char_device), Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, false, value)?,
        "blockdev-below" => fs_check(Some(FileType::is_block_device), Some(true), spec_opt.ok_or(NO_SPEC_OPT)?, false, value)?,

        "new-node-in" => fs_check(None, Some(false), spec_opt.ok_or(NO_SPEC_OPT)?, true, value)?,
        "new-node-below" => fs_check(None, Some(false), spec_opt.ok_or(NO_SPEC_OPT)?, false, value)?,

        "maybe-node-in" => fs_check(None, None, spec_opt.ok_or(NO_SPEC_OPT)?, true, value)?,
        "maybe-node-below" => fs_check(None, None, spec_opt.ok_or(NO_SPEC_OPT)?, false, value)?,

        _other => return Err("failed to parse variable spec"),
    };

    match valid {
        true => Ok(()),
        false => Err("invalid variable value"),
    }
}
