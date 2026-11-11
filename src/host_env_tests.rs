// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! `deploy/prepare-runtime-env.sh` is what infra runs on the host before the
//! container starts. These tests run that very script and feed what it writes
//! to the service's own configuration parser.

use std::{collections::HashMap, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

use crate::config::Config;

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/prepare-runtime-env.sh");

fn run(directory: &Path) -> std::process::Output {
    let provider = directory.join("provider.env");
    std::fs::write(&provider, "").unwrap();
    Command::new("sh")
        .arg(SCRIPT)
        .arg(directory.join("secrets").join("runtime.env"))
        .arg(provider)
        .output()
        .expect("sh runs")
}

fn read(directory: &Path) -> HashMap<String, String> {
    std::fs::read_to_string(directory.join("secrets").join("runtime.env"))
        .unwrap()
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('=').expect("KEY=value");
            (key.to_owned(), value.to_owned())
        })
        .collect()
}

#[test]
fn the_host_script_writes_an_environment_the_service_accepts() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(directory.path());
    assert!(output.status.success(), "{output:?}");
    let values = read(directory.path());
    let config = Config::from_lookup(|key| values.get(key).cloned()).expect("the service starts");
    assert_eq!(config.issuer_id(), "https://auth.aiaiaiai.org");

    // 0x1 is registered as a public client on its own callback.
    let client = &config.clients["nilx-one"];
    assert_eq!(client.secret_sha256, None);
    assert!(client.pub_dress_scope);
    assert_eq!(
        client.redirect_uris,
        ["https://nilx.one/api/v1/auth/aiaiaiai/callback"]
    );

    // The secrets are the host's alone: private files, independent values.
    let secrets = directory.path().join("secrets");
    assert_eq!(
        std::fs::metadata(&secrets).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(secrets.join("runtime.env"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_ne!(values["AIS_SECRET"], values["AIS_PASSWORD_PEPPER"]);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&values["AIS_SECRET"]));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&values["AIS_SECRET"]));
}

#[test]
fn the_secrets_are_generated_once_and_kept() {
    let directory = tempfile::tempdir().unwrap();
    assert!(run(directory.path()).status.success());
    let first = read(directory.path());
    assert!(run(directory.path()).status.success());
    // A rerun, as on every deploy, changes none of the three: a new one would
    // change every `sub`, every password check or every token in flight.
    assert_eq!(read(directory.path()), first);
}

#[test]
fn a_present_but_unusable_secret_stops_the_deploy_and_is_not_replaced() {
    for bad in [
        "AIS_SIGNING_KEY=short",
        "AIS_SIGNING_KEY=not+base64url+not+base64url+not+base64+",
        "AIS_SECRET=too-short",
        "AIS_PASSWORD_PEPPER=too-short",
    ] {
        let directory = tempfile::tempdir().unwrap();
        assert!(run(directory.path()).status.success());
        let mut values = read(directory.path());
        let (name, value) = bad.split_once('=').unwrap();
        values.insert(name.to_owned(), value.to_owned());
        let broken: String = values.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
        let path = directory.path().join("secrets").join("runtime.env");
        std::fs::write(&path, &broken).unwrap();
        let output = run(directory.path());
        assert!(!output.status.success(), "{bad} was accepted");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            broken,
            "{bad} was replaced"
        );
    }

    // The same value twice is refused too.
    let directory = tempfile::tempdir().unwrap();
    assert!(run(directory.path()).status.success());
    let mut values = read(directory.path());
    values.insert(
        "AIS_PASSWORD_PEPPER".to_owned(),
        values["AIS_SECRET"].clone(),
    );
    let path = directory.path().join("secrets").join("runtime.env");
    let broken: String = values.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
    std::fs::write(&path, &broken).unwrap();
    assert!(!run(directory.path()).status.success());
}
