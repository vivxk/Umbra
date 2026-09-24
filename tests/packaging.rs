use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

#[test]
fn test_systemd_boot_service_template_invariants() {
    let service_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("systemd/umbra-boot.service");
    assert!(
        service_path.exists(),
        "systemd/umbra-boot.service template must exist"
    );

    let content = fs::read_to_string(&service_path).expect("read systemd service file");

    // Section 43 & Section 88 Invariants:
    // 1. Must be oneshot with RemainAfterExit=yes (no resident daemon bloat)
    assert!(
        content.contains("Type=oneshot"),
        "Must be Type=oneshot to avoid persistent daemon bloat"
    );
    assert!(
        content.contains("RemainAfterExit=yes"),
        "Must have RemainAfterExit=yes"
    );

    // 2. Lifecycle commands
    assert!(
        content.contains("ExecStart=/usr/bin/umbra start"),
        "ExecStart must invoke /usr/bin/umbra start"
    );
    assert!(
        content.contains("ExecStop=/usr/bin/umbra stop"),
        "ExecStop must invoke /usr/bin/umbra stop"
    );

    // 3. Boot ordering before network-online.target
    assert!(
        content.contains("Before=network-online.target"),
        "Must be ordered Before=network-online.target to enforce boot-time network boundary"
    );
    assert!(
        content.contains("After=network.target tor.service"),
        "Must be ordered After=network.target tor.service"
    );
    assert!(
        content.contains("Wants=tor.service"),
        "Must declare Wants=tor.service"
    );

    // 4. Standard install target
    assert!(
        content.contains("WantedBy=multi-user.target"),
        "Must be WantedBy=multi-user.target"
    );
}

#[test]
fn test_install_script_lifecycle_and_security_checks() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let install_sh = repo_root.join("scripts/install.sh");
    assert!(install_sh.exists(), "scripts/install.sh must exist");

    let tmp = tempfile::tempdir().expect("tempdir");
    let destdir = tmp.path();

    // 1. First installation into isolated DESTDIR
    let status = Command::new("bash")
        .arg(&install_sh)
        .env("DESTDIR", destdir)
        .env("PREFIX", "/usr")
        .status()
        .expect("run install.sh");
    assert!(status.success(), "install.sh should succeed into DESTDIR");

    let installed_bin = destdir.join("usr/bin/umbra");
    assert!(installed_bin.exists(), "Installed binary must exist");
    let bin_perms = fs::metadata(&installed_bin).unwrap().permissions();
    assert_eq!(
        bin_perms.mode() & 0o111,
        0o111,
        "Installed binary must have executable permissions"
    );

    let installed_symlink = destdir.join("usr/local/bin/umbra");
    assert!(
        installed_symlink.is_symlink() || installed_symlink.exists(),
        "Installed symlink at /usr/local/bin/umbra must exist"
    );

    let installed_fragment = destdir.join("etc/tor/torrc.d/umbra.conf");
    assert!(
        installed_fragment.exists(),
        "Tor fragment must be installed"
    );
    let fragment_content = fs::read_to_string(&installed_fragment).unwrap();
    assert!(
        fragment_content.contains("# umbra-managed"),
        "Tor fragment must have '# umbra-managed' marker"
    );
    assert!(fragment_content.contains("TransPort 127.0.0.1:9040"));
    assert!(fragment_content.contains("DNSPort 127.0.0.1:5353"));
    assert!(fragment_content.contains("ControlPort 127.0.0.1:9051"));
    assert!(fragment_content.contains("CookieAuthentication 1"));

    let installed_service = destdir.join("etc/systemd/system/umbra-boot.service");
    assert!(
        installed_service.exists(),
        "Systemd unit template must be installed"
    );

    // 2. Unmanaged file protection: refuse to overwrite unmanaged file
    fs::write(&installed_fragment, "# user custom tor config\n").unwrap();
    let unmanaged_status = Command::new("bash")
        .arg(&install_sh)
        .env("DESTDIR", destdir)
        .status()
        .expect("run install.sh on unmanaged fragment");
    assert!(
        !unmanaged_status.success(),
        "install.sh must refuse to overwrite unmanaged Tor fragment"
    );

    // 3. Symlink attack protection: refuse to overwrite symlink
    fs::remove_file(&installed_fragment).unwrap();
    let decoy = destdir.join("decoy.txt");
    fs::write(&decoy, "secret").unwrap();
    std::os::unix::fs::symlink(&decoy, &installed_fragment).unwrap();

    let symlink_status = Command::new("bash")
        .arg(&install_sh)
        .env("DESTDIR", destdir)
        .status()
        .expect("run install.sh on symlink fragment");
    assert!(
        !symlink_status.success(),
        "install.sh must refuse to overwrite symlink fragment"
    );
    assert_eq!(
        fs::read_to_string(&decoy).unwrap(),
        "secret",
        "Target of symlink must not be corrupted"
    );
}

#[test]
fn test_uninstall_script_inactive_enforcement_and_safe_cleanup() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let install_sh = repo_root.join("scripts/install.sh");
    let uninstall_sh = repo_root.join("scripts/uninstall.sh");

    let tmp = tempfile::tempdir().expect("tempdir");
    let destdir = tmp.path();

    // 1. Install into DESTDIR
    let inst_status = Command::new("bash")
        .arg(&install_sh)
        .env("DESTDIR", destdir)
        .status()
        .expect("run install.sh");
    assert!(inst_status.success());

    // 2. Section 89 inactive check: simulate active state file in /run/umbra/active.json
    let run_dir = destdir.join("run/umbra");
    fs::create_dir_all(&run_dir).unwrap();
    let active_state_file = run_dir.join("active.json");
    fs::write(&active_state_file, r#"{"activation_id":"test"}"#).unwrap();

    // Verify uninstaller strictly REFUSES removal when active
    let active_uninstall_status = Command::new("bash")
        .arg(&uninstall_sh)
        .env("DESTDIR", destdir)
        .status()
        .expect("run uninstall.sh while active");
    assert!(
        !active_uninstall_status.success(),
        "uninstall.sh must strictly REFUSE uninstallation when Umbra is ACTIVE"
    );

    // Binaries and configs must remain intact after refusal
    assert!(destdir.join("usr/bin/umbra").exists());
    assert!(destdir.join("etc/tor/torrc.d/umbra.conf").exists());

    // 3. Clear active state file -> uninstallation now permitted
    fs::remove_file(&active_state_file).unwrap();

    // Verify unmanaged file preservation during uninstall
    let tor_fragment = destdir.join("etc/tor/torrc.d/umbra.conf");
    fs::write(&tor_fragment, "# custom user configuration\n").unwrap();

    let uninstall_unmanaged_status = Command::new("bash")
        .arg(&uninstall_sh)
        .env("DESTDIR", destdir)
        .status()
        .expect("run uninstall.sh with unmanaged fragment");
    assert!(
        uninstall_unmanaged_status.success(),
        "uninstall.sh should succeed"
    );
    assert!(
        tor_fragment.exists(),
        "Unmanaged config must NOT be deleted by uninstall.sh"
    );

    // Now test managed file cleanup
    fs::write(
        &tor_fragment,
        "# umbra-managed: Umbra Tor Configuration Fragment\n",
    )
    .unwrap();
    let final_uninstall_status = Command::new("bash")
        .arg(&uninstall_sh)
        .env("DESTDIR", destdir)
        .status()
        .expect("run final uninstall.sh");
    assert!(final_uninstall_status.success());

    // Everything managed should be removed
    assert!(!destdir.join("usr/bin/umbra").exists());
    assert!(!destdir.join("usr/local/bin/umbra").exists());
    assert!(!tor_fragment.exists());
    assert!(!destdir
        .join("etc/systemd/system/umbra-boot.service")
        .exists());
    assert!(!destdir.join("run/umbra").exists());
}
