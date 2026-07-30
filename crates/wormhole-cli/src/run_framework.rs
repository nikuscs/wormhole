//! Framework-aware port and host argument injection for `wormhole run`.

#[derive(Clone, Copy)]
struct FrameworkFlags {
    strict_port: bool,
    host: HostFlag,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HostFlag {
    None,
    Loopback,
    Expo,
}

#[derive(Clone, Copy)]
struct FrameworkDetection {
    framework: FrameworkFlags,
    invocation: Invocation,
    script: ScriptFlags,
}

#[derive(Clone, Copy, Default)]
struct ScriptFlags {
    port: bool,
    host: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Invocation {
    Direct,
    Package,
    TurboPackage,
}

pub(super) fn inject_framework_flags(
    arguments: &mut Vec<String>,
    port: u16,
    cwd: &std::path::Path,
) {
    let Some(detection) = detect_framework(arguments, cwd) else {
        return;
    };
    let has_port = has_flag(arguments, "--port")
        || (detection.invocation == Invocation::Direct && detection.script.port);
    let has_host =
        detection.script.host || has_flag(arguments, "--host") || has_flag(arguments, "--hostname");
    if has_port && (has_host || detection.framework.host == HostFlag::None) {
        return;
    }
    let separators = match detection.invocation {
        Invocation::Direct => 0,
        Invocation::Package => 1,
        Invocation::TurboPackage => 2,
    };
    while arguments.iter().filter(|value| value.as_str() == "--").count() < separators {
        arguments.push("--".to_owned());
    }
    if !has_port {
        arguments.extend(["--port".to_owned(), port.to_string()]);
        if detection.framework.strict_port {
            arguments.push("--strictPort".to_owned());
        }
    }
    if !has_host {
        match detection.framework.host {
            HostFlag::None => {}
            HostFlag::Loopback => {
                arguments.extend(["--host".to_owned(), "127.0.0.1".to_owned()]);
            }
            HostFlag::Expo => {
                arguments.extend(["--host".to_owned(), "localhost".to_owned()]);
            }
        }
    }
}

fn detect_framework(arguments: &[String], cwd: &std::path::Path) -> Option<FrameworkDetection> {
    direct_framework(arguments)
        .map(|framework| FrameworkDetection {
            framework,
            invocation: Invocation::Direct,
            script: ScriptFlags::default(),
        })
        .or_else(|| package_script_framework(arguments, cwd))
}

fn direct_framework(arguments: &[String]) -> Option<FrameworkFlags> {
    let first = basename(arguments.first()?);
    if let Some(framework) = framework(first) {
        return Some(framework);
    }
    let mut index = match first {
        "npx" | "bunx" | "pnpx" => 1,
        "yarn" | "pnpm" => {
            let mut index = skip_flags(arguments, 1);
            if arguments.get(index).is_some_and(|value| matches!(value.as_str(), "dlx" | "exec")) {
                index += 1;
            }
            index
        }
        _ => return None,
    };
    index = skip_flags(arguments, index);
    framework(basename(arguments.get(index)?))
}

fn package_script_framework(
    arguments: &[String],
    cwd: &std::path::Path,
) -> Option<FrameworkDetection> {
    let runner = basename(arguments.first()?);
    if !matches!(runner, "npm" | "pnpm" | "yarn" | "bun") {
        return None;
    }
    let mut index = 1;
    if arguments.get(index).is_some_and(|value| value == "run") {
        index += 1;
    } else if runner == "npm" {
        return None;
    }
    let script_name = arguments.get(index)?;
    let document = read_package(cwd)?;
    let script = document.get("scripts")?.get(script_name)?.as_str()?;
    let tokens = script_tokens(script);
    script_detection(&tokens, Invocation::Package)
        .or_else(|| turbo_script_detection(&tokens, cwd, &document))
}

fn script_detection(tokens: &[&str], invocation: Invocation) -> Option<FrameworkDetection> {
    let framework = tokens.iter().find_map(|token| framework(basename(token)))?;
    Some(FrameworkDetection {
        framework,
        invocation,
        script: ScriptFlags {
            port: tokens.iter().any(|token| *token == "--port" || token.starts_with("--port=")),
            host: tokens.iter().any(|token| *token == "--host" || token.starts_with("--host=")),
        },
    })
}

fn turbo_script_detection(
    tokens: &[&str],
    cwd: &std::path::Path,
    root: &serde_json::Value,
) -> Option<FrameworkDetection> {
    let turbo = tokens.iter().position(|token| basename(token) == "turbo")?;
    let mut task = turbo + 1;
    if tokens.get(task).is_some_and(|token| *token == "run") {
        task += 1;
    }
    let task = *tokens.get(task)?;
    let filter = turbo_filter(tokens)?;
    let package = workspace_package(cwd, root, filter)?;
    let script = package.get("scripts")?.get(task)?.as_str()?;
    script_detection(&script_tokens(script), Invocation::TurboPackage)
}

fn turbo_filter<'a>(tokens: &'a [&str]) -> Option<&'a str> {
    tokens.iter().enumerate().find_map(|(index, token)| {
        token
            .strip_prefix("--filter=")
            .or_else(|| (*token == "--filter").then(|| tokens.get(index + 1).copied()).flatten())
    })
}

fn workspace_package(
    cwd: &std::path::Path,
    root: &serde_json::Value,
    package_name: &str,
) -> Option<serde_json::Value> {
    let patterns = root.get("workspaces")?.as_array()?;
    patterns.iter().filter_map(serde_json::Value::as_str).find_map(|pattern| {
        workspace_paths(cwd, pattern).find_map(|path| {
            let package = read_package(&path)?;
            (package.get("name")?.as_str()? == package_name).then_some(package)
        })
    })
}

fn workspace_paths(
    cwd: &std::path::Path,
    pattern: &str,
) -> Box<dyn Iterator<Item = std::path::PathBuf>> {
    if let Some(parent) = pattern.strip_suffix("/*") {
        let paths = std::fs::read_dir(cwd.join(parent))
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path());
        Box::new(paths)
    } else {
        Box::new(std::iter::once(cwd.join(pattern)))
    }
}

fn read_package(directory: &std::path::Path) -> Option<serde_json::Value> {
    serde_json::from_slice(&std::fs::read(directory.join("package.json")).ok()?).ok()
}

fn script_tokens(script: &str) -> Vec<&str> {
    script.split_whitespace().map(|token| token.trim_matches(['\'', '"'])).collect()
}

fn framework(command: &str) -> Option<FrameworkFlags> {
    match command {
        "vite" | "vp" | "react-router" => {
            Some(FrameworkFlags { strict_port: true, host: HostFlag::Loopback })
        }
        "rsbuild" | "astro" | "ng" | "react-native" => {
            Some(FrameworkFlags { strict_port: false, host: HostFlag::Loopback })
        }
        "next" => Some(FrameworkFlags { strict_port: false, host: HostFlag::None }),
        "expo" => Some(FrameworkFlags { strict_port: false, host: HostFlag::Expo }),
        _ => None,
    }
}

fn basename(value: &str) -> &str {
    std::path::Path::new(value).file_name().and_then(|name| name.to_str()).unwrap_or(value)
}

fn skip_flags(arguments: &[String], mut index: usize) -> usize {
    while arguments.get(index).is_some_and(|value| value.starts_with('-')) {
        index += 1;
    }
    index
}

fn has_flag(arguments: &[String], flag: &str) -> bool {
    arguments.iter().any(|value| value == flag || value.starts_with(&format!("{flag}=")))
}
