// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! `deploy/prepare-runtime-env.sh` is what infra runs on the host before the
//! container starts. These tests run that very script and feed what it writes
//! to the service's own configuration parser. Docker is a stub on `PATH` that
//! says whether the data volume exists.

use std::{collections::HashMap, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

use crate::config::Config;

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/prepare-runtime-env.sh");

#[derive(Clone, Copy, PartialEq)]
enum Volume {
    Absent,
    Exists,
}

fn runtime_env(directory: &Path) -> std::path::PathBuf {
    directory.join("secrets").join("runtime.env")
}

fn run(directory: &Path, volume: Volume) -> std::process::Output {
    let provider = directory.join("provider.env");
    std::fs::write(&provider, "").unwrap();
    let bin = directory.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let docker = bin.join("docker");
    std::fs::write(
        &docker,
        "#!/bin/sh\n\
         if [ \"$1 $2\" = \"volume inspect\" ]; then\n\
           if [ \"$FAKE_VOLUME\" = exists ]; then echo '[{\"Name\":\"4x-ais-data\"}]'; exit 0; fi\n\
           echo \"Error response from daemon: get $3: no such volume\" >&2; exit 1\n\
         fi\n\
         exit 2\n",
    )
    .unwrap();
    std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Command::new("sh")
        .arg(SCRIPT)
        .arg(runtime_env(directory))
        .arg(provider)
        .env("PATH", path)
        .env(
            "FAKE_VOLUME",
            if volume == Volume::Exists {
                "exists"
            } else {
                "absent"
            },
        )
        .output()
        .expect("sh runs")
}

fn read(directory: &Path) -> HashMap<String, String> {
    std::fs::read_to_string(runtime_env(directory))
        .unwrap()
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('=').expect("KEY=value");
            (key.to_owned(), value.to_owned())
        })
        .collect()
}

fn write(directory: &Path, values: &HashMap<String, String>) -> String {
    let text: String = values.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
    std::fs::write(runtime_env(directory), &text).unwrap();
    text
}

#[test]
fn the_host_script_writes_an_environment_the_service_accepts() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(directory.path(), Volume::Absent);
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
        std::fs::metadata(runtime_env(directory.path()))
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
fn the_secrets_are_generated_once_and_kept_across_redeploys() {
    let directory = tempfile::tempdir().unwrap();
    assert!(run(directory.path(), Volume::Absent).status.success());
    let first = read(directory.path());
    // A redeploy: the file and the volume both exist. None of the three changes:
    // a new one would change every `sub`, every password check or every token.
    assert!(run(directory.path(), Volume::Exists).status.success());
    assert_eq!(read(directory.path()), first);
}

#[test]
fn a_lost_secrets_file_next_to_a_surviving_volume_fails_loudly() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(directory.path(), Volume::Exists);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("data volume"));
    assert!(
        !runtime_env(directory.path()).exists(),
        "no secrets were minted"
    );
}

#[test]
fn an_existing_file_is_never_completed_or_repaired_by_minting() {
    // Each is a partial write, a hand edit or a restore from an old copy.
    for missing in ["AIS_SIGNING_KEY", "AIS_SECRET", "AIS_PASSWORD_PEPPER"] {
        for empty_value in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            assert!(run(directory.path(), Volume::Absent).status.success());
            let mut values = read(directory.path());
            if empty_value {
                values.insert(missing.to_owned(), String::new());
            } else {
                values.remove(missing);
            }
            let broken = write(directory.path(), &values);
            let output = run(directory.path(), Volume::Exists);
            assert!(
                !output.status.success(),
                "{missing} (empty: {empty_value}) was accepted"
            );
            assert_eq!(
                std::fs::read_to_string(runtime_env(directory.path())).unwrap(),
                broken,
                "{missing} was replaced"
            );
        }
    }

    // An empty file is not a first creation either, even with no volume.
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(directory.path().join("secrets")).unwrap();
    std::fs::write(runtime_env(directory.path()), "").unwrap();
    assert!(!run(directory.path(), Volume::Absent).status.success());
    assert_eq!(
        std::fs::read_to_string(runtime_env(directory.path())).unwrap(),
        ""
    );
}

#[test]
fn a_present_but_unusable_secret_stops_the_deploy_and_is_not_replaced() {
    for bad in [
        "AIS_SIGNING_KEY=short",
        "AIS_SIGNING_KEY=not+base64url+not+base64url+not+base64+",
        // 43 base64url characters, but the last one carries nonzero spare bits:
        // the service's strict decode refuses it, so the container would crash-loop.
        "AIS_SIGNING_KEY=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "AIS_SECRET=too-short",
        "AIS_PASSWORD_PEPPER=too-short",
    ] {
        let directory = tempfile::tempdir().unwrap();
        assert!(run(directory.path(), Volume::Absent).status.success());
        let mut values = read(directory.path());
        let (name, value) = bad.split_once('=').unwrap();
        values.insert(name.to_owned(), value.to_owned());
        let broken = write(directory.path(), &values);
        let output = run(directory.path(), Volume::Exists);
        assert!(!output.status.success(), "{bad} was accepted");
        assert_eq!(
            std::fs::read_to_string(runtime_env(directory.path())).unwrap(),
            broken,
            "{bad} was replaced"
        );
    }

    // The same value twice is refused too.
    let directory = tempfile::tempdir().unwrap();
    assert!(run(directory.path(), Volume::Absent).status.success());
    let mut values = read(directory.path());
    values.insert(
        "AIS_PASSWORD_PEPPER".to_owned(),
        values["AIS_SECRET"].clone(),
    );
    write(directory.path(), &values);
    assert!(!run(directory.path(), Volume::Exists).status.success());
}

#[test]
fn every_generated_signing_key_is_one_the_service_decodes() {
    // The generated seed always ends in a canonical character, so the strict
    // decode the service applies accepts it, whatever the random bytes were.
    for _ in 0..20 {
        let directory = tempfile::tempdir().unwrap();
        assert!(run(directory.path(), Volume::Absent).status.success());
        let values = read(directory.path());
        Config::from_lookup(|key| values.get(key).cloned()).expect("the service starts");
    }
}
