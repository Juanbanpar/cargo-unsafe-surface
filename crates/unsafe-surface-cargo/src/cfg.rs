//! Querying the compilation target configuration from the installed
//! toolchain.
//!
//! `rustc --print cfg` is a read-only compiler query: it prints the `cfg`
//! values of the *installed* compiler for a target and never touches the
//! analysed repository, so running it is safe on untrusted code.

use std::collections::BTreeMap;
use std::process::Command;

use crate::error::CargoError;

/// `cfg` key/value pairs for a compilation target.
///
/// Values are `None` for flag-style cfgs (`unix`) and `Some(v)` for
/// key/value cfgs (`target_arch = "x86_64"`). Multiple values per key are
/// represented by multiple entries in the map's value list.
pub type CfgValues = BTreeMap<String, Vec<Option<String>>>;

/// Returns the `cfg` values for `target` (or the host target when `None`).
///
/// # Errors
///
/// Returns [`CargoError::RustcCfg`] when `rustc` cannot be executed or its
/// output cannot be parsed.
pub fn query_rustc_cfg(target: Option<&str>) -> Result<CfgValues, CargoError> {
    let mut command = Command::new("rustc");
    command.arg("--print").arg("cfg");
    if let Some(target) = target {
        command.arg("--target").arg(target);
    }
    let output = command
        .output()
        .map_err(|e| CargoError::RustcCfg(format!("failed to spawn rustc: {e}")))?;
    if !output.status.success() {
        return Err(CargoError::RustcCfg(format!(
            "rustc exited with status {}",
            output.status
        )));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| CargoError::RustcCfg(format!("rustc output was not UTF-8: {e}")))?;
    Ok(parse_cfg_output(&stdout))
}

/// Parses `rustc --print cfg` output. Exposed for unit testing.
pub(crate) fn parse_cfg_output(output: &str) -> CfgValues {
    let mut values: CfgValues = BTreeMap::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim().trim_matches('"').to_owned();
            values
                .entry(key.trim().to_owned())
                .or_default()
                .push(Some(value));
        } else {
            values.entry(line.to_owned()).or_default().push(None);
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flag_and_key_value_cfgs() {
        let output =
            "unix\ntarget_arch=\"x86_64\"\ntarget_feature=\"sse\"\ntarget_feature=\"sse2\"\n";
        let values = parse_cfg_output(output);
        assert_eq!(values["unix"], vec![None]);
        assert_eq!(values["target_arch"], vec![Some("x86_64".to_owned())]);
        assert_eq!(
            values["target_feature"],
            vec![Some("sse".to_owned()), Some("sse2".to_owned())]
        );
    }

    #[test]
    fn host_cfg_is_available() {
        // The host toolchain must answer; this also exercises Command setup.
        let values = query_rustc_cfg(None).expect("rustc --print cfg should work");
        assert!(values.contains_key("target_arch"));
    }
}
