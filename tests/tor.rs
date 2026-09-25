use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use tempfile::tempdir;
use umbra::error::UmbraError;
use umbra::tor::{
    find_socket_inode_owner, hex_encode, parse_proc_net_line, parse_proc_net_sockets,
    verify_executable_security, verify_executable_security_with_config, verify_socket_ownership,
    TorController, TorIdentity,
};

#[test]
fn test_tor_identity_creation() {
    let ident = TorIdentity {
        pid: 1234,
        uid: 122,
        exe_path: "/usr/bin/tor".to_string(),
    };

    assert_eq!(ident.pid, 1234);
    assert_eq!(ident.uid, 122);
    assert_ne!(ident.uid, 0, "Tor must never run as root UID 0");
    assert_eq!(ident.exe_path, "/usr/bin/tor");
}

// ============================================================================
// 1. Executable Security & Trusted Path Verification Tests
// ============================================================================

#[test]
fn test_executable_outside_trusted_prefixes_rejected() {
    let dir = tempdir().unwrap();
    let exe_path = dir.path().join("tor");
    fs::write(&exe_path, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o755)).unwrap();

    let my_uid = nix::unistd::getuid().as_raw();
    let res = verify_executable_security_with_config(
        &exe_path,
        Some(my_uid),
        &["/usr/bin", "/usr/sbin", "/bin", "/sbin"],
    );

    match res {
        Err(UmbraError::TorExecutableUntrusted(msg)) => {
            assert!(
                msg.contains("does not reside in trusted root-owned paths"),
                "unexpected error: {msg}"
            );
        }
        other => panic!("expected TorExecutableUntrusted, got {other:?}"),
    }
}

#[test]
fn test_executable_group_writable_rejected() {
    let dir = tempdir().unwrap();
    let trusted_prefix = dir.path().to_str().unwrap();
    let exe_path = dir.path().join("tor");
    fs::write(&exe_path, b"mock").unwrap();
    // 0o775 has group write permission
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o775)).unwrap();

    let my_uid = nix::unistd::getuid().as_raw();
    let res = verify_executable_security_with_config(&exe_path, Some(my_uid), &[trusted_prefix]);

    match res {
        Err(UmbraError::TorExecutableUntrusted(msg)) => {
            assert!(
                msg.contains("group- or world-writable"),
                "unexpected error: {msg}"
            );
        }
        other => panic!("expected TorExecutableUntrusted for group-writable, got {other:?}"),
    }
}

#[test]
fn test_executable_world_writable_rejected() {
    let dir = tempdir().unwrap();
    let trusted_prefix = dir.path().to_str().unwrap();
    let exe_path = dir.path().join("tor");
    fs::write(&exe_path, b"mock").unwrap();
    // 0o777 has world write permission
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o777)).unwrap();

    let my_uid = nix::unistd::getuid().as_raw();
    let res = verify_executable_security_with_config(&exe_path, Some(my_uid), &[trusted_prefix]);

    match res {
        Err(UmbraError::TorExecutableUntrusted(msg)) => {
            assert!(
                msg.contains("group- or world-writable"),
                "unexpected error: {msg}"
            );
        }
        other => panic!("expected TorExecutableUntrusted for world-writable, got {other:?}"),
    }
}

#[test]
fn test_executable_not_executable_rejected() {
    let dir = tempdir().unwrap();
    let trusted_prefix = dir.path().to_str().unwrap();
    let exe_path = dir.path().join("tor");
    fs::write(&exe_path, b"mock").unwrap();
    // 0o644 is not executable
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o644)).unwrap();

    let my_uid = nix::unistd::getuid().as_raw();
    let res = verify_executable_security_with_config(&exe_path, Some(my_uid), &[trusted_prefix]);

    match res {
        Err(UmbraError::TorExecutableUntrusted(msg)) => {
            assert!(msg.contains("not executable"), "unexpected error: {msg}");
        }
        other => panic!("expected TorExecutableUntrusted for non-executable, got {other:?}"),
    }
}

#[test]
fn test_executable_directory_rejected() {
    let dir = tempdir().unwrap();
    let trusted_prefix = dir.path().to_str().unwrap();
    let sub_dir = dir.path().join("tor_dir");
    fs::create_dir(&sub_dir).unwrap();

    let my_uid = nix::unistd::getuid().as_raw();
    let res = verify_executable_security_with_config(&sub_dir, Some(my_uid), &[trusted_prefix]);

    match res {
        Err(UmbraError::TorExecutableUntrusted(msg)) => {
            assert!(
                msg.contains("not a regular file"),
                "unexpected error: {msg}"
            );
        }
        other => panic!("expected TorExecutableUntrusted for directory, got {other:?}"),
    }
}

#[test]
fn test_executable_owner_mismatch_rejected() {
    let dir = tempdir().unwrap();
    let trusted_prefix = dir.path().to_str().unwrap();
    let exe_path = dir.path().join("tor");
    fs::write(&exe_path, b"mock").unwrap();
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o755)).unwrap();

    let my_uid = nix::unistd::getuid().as_raw();
    // Require UID 9999 (which differs from my_uid)
    let res =
        verify_executable_security_with_config(&exe_path, Some(my_uid + 9999), &[trusted_prefix]);

    match res {
        Err(UmbraError::TorExecutableUntrusted(msg)) => {
            assert!(msg.contains("owned by UID"), "unexpected error: {msg}");
        }
        other => panic!("expected TorExecutableUntrusted for UID mismatch, got {other:?}"),
    }
}

#[test]
fn test_executable_valid_mock_succeeds() {
    let dir = tempdir().unwrap();
    let trusted_prefix = dir.path().to_str().unwrap();
    let exe_path = dir.path().join("tor");
    fs::write(&exe_path, b"mock_tor_binary").unwrap();
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o755)).unwrap();

    let my_uid = nix::unistd::getuid().as_raw();
    let res = verify_executable_security_with_config(&exe_path, Some(my_uid), &[trusted_prefix]);

    assert!(
        res.is_ok(),
        "expected valid executable to pass verification"
    );
}

#[test]
fn test_executable_real_system_tor_if_installed() {
    let tor_path = Path::new("/usr/bin/tor");
    if tor_path.exists() {
        let res = verify_executable_security(tor_path);
        assert!(
            res.is_ok(),
            "system /usr/bin/tor should pass security check: {res:?}"
        );
    }
}

#[test]
fn test_executable_symlink_pointing_to_untrusted_target_rejected() {
    let trusted_dir = tempdir().unwrap();
    let untrusted_dir = tempdir().unwrap();

    let real_exe = untrusted_dir.path().join("evil_tor");
    fs::write(&real_exe, b"mock_evil_binary").unwrap();
    fs::set_permissions(&real_exe, fs::Permissions::from_mode(0o755)).unwrap();

    let symlink_in_trusted = trusted_dir.path().join("tor");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_exe, &symlink_in_trusted).unwrap();

    let my_uid = nix::unistd::getuid().as_raw();
    let res = verify_executable_security_with_config(
        &symlink_in_trusted,
        Some(my_uid),
        &[trusted_dir.path().to_str().unwrap()],
    );

    match res {
        Err(UmbraError::TorExecutableUntrusted(msg)) => {
            assert!(msg.contains("does not reside in trusted root-owned paths"));
        }
        other => {
            panic!("expected TorExecutableUntrusted for symlink to untrusted target, got {other:?}")
        }
    }
}

#[test]
fn test_executable_untrusted_symlink_pointing_to_trusted_binary_rejected() {
    let trusted_dir = tempdir().unwrap();
    let untrusted_dir = tempdir().unwrap();

    let real_exe = trusted_dir.path().join("tor");
    fs::write(&real_exe, b"mock_tor_binary").unwrap();
    fs::set_permissions(&real_exe, fs::Permissions::from_mode(0o755)).unwrap();

    let symlink_in_untrusted = untrusted_dir.path().join("tor_link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_exe, &symlink_in_untrusted).unwrap();

    let my_uid = nix::unistd::getuid().as_raw();
    let res = verify_executable_security_with_config(
        &symlink_in_untrusted,
        Some(my_uid),
        &[trusted_dir.path().to_str().unwrap()],
    );

    match res {
        Err(UmbraError::TorExecutableUntrusted(msg)) => {
            assert!(msg.contains("does not reside in trusted root-owned paths"));
        }
        other => {
            panic!("expected TorExecutableUntrusted for untrusted symlink path, got {other:?}")
        }
    }
}

#[test]
fn test_executable_suid_rejected() {
    let dir = tempdir().unwrap();
    let trusted_prefix = dir.path().to_str().unwrap();
    let exe_path = dir.path().join("tor_suid");
    fs::write(&exe_path, b"mock").unwrap();
    // 0o4755 has SUID bit set
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o4755)).unwrap();

    let my_uid = nix::unistd::getuid().as_raw();
    let res = verify_executable_security_with_config(&exe_path, Some(my_uid), &[trusted_prefix]);

    match res {
        Err(UmbraError::TorExecutableUntrusted(msg)) => {
            assert!(msg.contains("SUID/SGID bit set"));
        }
        other => panic!("expected TorExecutableUntrusted for SUID binary, got {other:?}"),
    }
}

// ============================================================================
// 2. Process Inspection & UID Hardening Tests
// ============================================================================

fn setup_mock_proc_entry(
    proc_dir: &Path,
    pid: u32,
    comm: &str,
    uid: u32,
    exe_target: &Path,
) -> PathBuf {
    let pid_dir = proc_dir.join(pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();

    fs::write(pid_dir.join("comm"), format!("{comm}\n")).unwrap();
    fs::write(
        pid_dir.join("status"),
        format!("Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
    )
    .unwrap();

    #[cfg(unix)]
    let _ = std::os::unix::fs::symlink(exe_target, pid_dir.join("exe"));

    pid_dir
}

#[test]
fn test_process_missing_pid() {
    let proc_dir = tempdir().unwrap();
    let res = TorController::verify_tor_process_at(proc_dir.path(), 9999, None, &["/usr/bin"]);
    match res {
        Err(UmbraError::TorProcessNotFound(pid)) => assert_eq!(pid, 9999),
        other => panic!("expected TorProcessNotFound, got {other:?}"),
    }
}

#[test]
fn test_process_comm_mismatch() {
    let proc_dir = tempdir().unwrap();
    let exe_dir = tempdir().unwrap();
    let exe_path = exe_dir.path().join("nginx");
    fs::write(&exe_path, b"binary").unwrap();
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o755)).unwrap();

    setup_mock_proc_entry(proc_dir.path(), 100, "nginx", 1000, &exe_path);

    let res = TorController::verify_tor_process_at(
        proc_dir.path(),
        100,
        None,
        &[exe_dir.path().to_str().unwrap()],
    );
    match res {
        Err(UmbraError::TorProcessMismatch { pid, comm }) => {
            assert_eq!(pid, 100);
            assert_eq!(comm, "nginx");
        }
        other => panic!("expected TorProcessMismatch, got {other:?}"),
    }
}

#[test]
fn test_process_running_as_root_rejected() {
    let proc_dir = tempdir().unwrap();
    let exe_dir = tempdir().unwrap();
    let exe_path = exe_dir.path().join("tor");
    fs::write(&exe_path, b"binary").unwrap();
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o755)).unwrap();

    // UID 0 = root
    setup_mock_proc_entry(proc_dir.path(), 101, "tor", 0, &exe_path);

    let res = TorController::verify_tor_process_at(
        proc_dir.path(),
        101,
        None,
        &[exe_dir.path().to_str().unwrap()],
    );
    match res {
        Err(UmbraError::TorRunningAsRoot) => {}
        other => panic!("expected TorRunningAsRoot, got {other:?}"),
    }
}

#[test]
fn test_process_effective_uid_root_rejected() {
    let proc_dir = tempdir().unwrap();
    let exe_dir = tempdir().unwrap();
    let exe_path = exe_dir.path().join("tor");
    fs::write(&exe_path, b"binary").unwrap();
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o755)).unwrap();

    let pid_dir = proc_dir.path().join("103");
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(pid_dir.join("comm"), "tor\n").unwrap();
    // Real UID = 122, Effective UID = 0 (root)
    fs::write(
        pid_dir.join("status"),
        "Name:\ttor\nUid:\t122\t0\t122\t122\n",
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&exe_path, pid_dir.join("exe")).unwrap();

    let res = TorController::verify_tor_process_at(
        proc_dir.path(),
        103,
        None,
        &[exe_dir.path().to_str().unwrap()],
    );
    match res {
        Err(UmbraError::TorRunningAsRoot) => {}
        other => panic!("expected TorRunningAsRoot for effective UID 0, got {other:?}"),
    }
}

#[test]
fn test_process_valid_unprivileged() {
    let proc_dir = tempdir().unwrap();
    let exe_dir = tempdir().unwrap();
    let exe_path = exe_dir.path().join("tor");
    fs::write(&exe_path, b"binary").unwrap();
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o755)).unwrap();

    let my_uid = nix::unistd::getuid().as_raw();
    setup_mock_proc_entry(proc_dir.path(), 102, "tor", 122, &exe_path);

    let res = TorController::verify_tor_process_at(
        proc_dir.path(),
        102,
        Some(my_uid),
        &[exe_dir.path().to_str().unwrap()],
    );
    assert!(res.is_ok(), "expected valid process verification: {res:?}");
    let ident = res.unwrap();
    assert_eq!(ident.pid, 102);
    assert_eq!(ident.uid, 122);
}

#[test]
fn test_find_tor_process_scan_finds_valid() {
    let proc_dir = tempdir().unwrap();
    let exe_dir = tempdir().unwrap();
    let exe_path = exe_dir.path().join("tor.real");
    fs::write(&exe_path, b"binary").unwrap();
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o755)).unwrap();

    let my_uid = nix::unistd::getuid().as_raw();
    // Non-tor process
    setup_mock_proc_entry(proc_dir.path(), 200, "bash", 1000, &exe_path);
    // Tor process
    setup_mock_proc_entry(proc_dir.path(), 201, "tor.real", 122, &exe_path);

    let res = TorController::find_tor_process_at(
        proc_dir.path(),
        Some(my_uid),
        &[exe_dir.path().to_str().unwrap()],
    );
    assert!(res.is_ok());
    let ident = res.unwrap().expect("should find tor.real");
    assert_eq!(ident.pid, 201);
    assert_eq!(ident.uid, 122);
}

#[test]
fn test_find_tor_process_scan_fails_on_root_tor() {
    let proc_dir = tempdir().unwrap();
    let exe_dir = tempdir().unwrap();
    let exe_path = exe_dir.path().join("tor");
    fs::write(&exe_path, b"binary").unwrap();
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o755)).unwrap();

    setup_mock_proc_entry(proc_dir.path(), 300, "tor", 0, &exe_path);

    let res = TorController::find_tor_process_at(
        proc_dir.path(),
        None,
        &[exe_dir.path().to_str().unwrap()],
    );
    match res {
        Err(UmbraError::TorRunningAsRoot) => {}
        other => panic!("expected TorRunningAsRoot from find_tor_process, got {other:?}"),
    }
}

// ============================================================================
// 4. Socket Parsing & Listener State Tests
// ============================================================================

#[test]
fn test_parse_proc_net_tcp_entry() {
    // 0100007F is 127.0.0.1 in little endian
    // 2350 hex is 9040 decimal
    // 0A is TCP_LISTEN
    // uid is 122, inode is 29052
    let line = "   0: 0100007F:2350 00000000:0000 0A 00000000:00000000 00:00000000 00000000   122        0 29052 1 00000000b761d09b 100 0 0 10 0";
    let entry = parse_proc_net_line(line).expect("should parse valid line");

    assert_eq!(entry.local_ip, [127, 0, 0, 1]);
    assert_eq!(entry.local_port, 9040);
    assert_eq!(entry.state, 0x0A);
    assert_eq!(entry.uid, 122);
    assert_eq!(entry.inode, 29052);
}

#[test]
fn test_parse_proc_net_line_non_loopback() {
    // 00000000 is 0.0.0.0 (all interfaces)
    // 235B hex is 9051 decimal
    let line = "   1: 00000000:235B 00000000:0000 0A 00000000:00000000 00:00000000 00000000   122        0 30000 1 00000000b761d09b 100 0 0 10 0";
    let entry = parse_proc_net_line(line).expect("should parse line");

    assert_eq!(entry.local_ip, [0, 0, 0, 0]);
    assert_eq!(entry.local_port, 9051);
}

#[test]
fn test_parse_proc_net_sockets_filters_headers() {
    let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2350 00000000:0000 0A 00000000:00000000 00:00000000 00000000   122        0 29052 1 00000000b761d09b 100 0 0 10 0
   1: 0100007F:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   122        0 29053 1 00000000b761d09b 100 0 0 10 0
";
    let entries = parse_proc_net_sockets(content);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].local_port, 9040);
    assert_eq!(entries[1].local_port, 5353);
}

#[test]
fn test_find_socket_inode_owner_mock() {
    let proc_dir = tempdir().unwrap();
    let pid_dir = proc_dir.path().join("500");
    let fd_dir = pid_dir.join("fd");
    fs::create_dir_all(&fd_dir).unwrap();

    fs::write(pid_dir.join("comm"), "tor\n").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink("socket:[44444]", fd_dir.join("3")).unwrap();
        symlink("/dev/null", fd_dir.join("4")).unwrap();
    }

    let owner = find_socket_inode_owner(proc_dir.path(), 44444).unwrap();
    assert_eq!(owner, Some((500, "tor".to_string())));

    let not_found = find_socket_inode_owner(proc_dir.path(), 99999).unwrap();
    assert_eq!(not_found, None);
}

#[test]
fn test_verify_socket_ownership_wrong_uid() {
    let dir = tempdir().unwrap();
    let tcp_file = dir.path().join("tcp");
    let content = "   0: 0100007F:2350 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 29052 1 00000000b761d09b 100 0 0 10 0\n";
    fs::write(&tcp_file, content).unwrap();

    // Expect UID 122, but socket is UID 1000
    let res = verify_socket_ownership(&tcp_file, dir.path(), 9040, Some(122), None);
    match res {
        Err(UmbraError::TorListenerWrongProcess {
            port,
            expected,
            actual,
        }) => {
            assert_eq!(port, 9040);
            assert!(expected.contains("122"));
            assert!(actual.contains("1000"));
        }
        other => panic!("expected TorListenerWrongProcess for UID, got {other:?}"),
    }
}

#[test]
fn test_verify_socket_ownership_wrong_pid() {
    let dir = tempdir().unwrap();
    let tcp_file = dir.path().join("tcp");
    let content = "   0: 0100007F:235B 00000000:0000 0A 00000000:00000000 00:00000000 00000000   122        0 33333 1 00000000b761d09b 100 0 0 10 0\n";
    fs::write(&tcp_file, content).unwrap();

    // Mock proc where socket 33333 is owned by PID 600 ("evil_process")
    let pid_dir = dir.path().join("600");
    let fd_dir = pid_dir.join("fd");
    fs::create_dir_all(&fd_dir).unwrap();
    fs::write(pid_dir.join("comm"), "evil_process\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("socket:[33333]", fd_dir.join("3")).unwrap();

    // Expect Tor PID 500, but actual is 600
    let res = verify_socket_ownership(&tcp_file, dir.path(), 9051, Some(122), Some(500));
    match res {
        Err(UmbraError::TorListenerWrongProcess {
            port,
            expected,
            actual,
        }) => {
            assert_eq!(port, 9051);
            assert!(expected.contains("500"));
            assert!(actual.contains("evil_process (PID 600)"));
        }
        other => panic!("expected TorListenerWrongProcess for PID, got {other:?}"),
    }
}

#[test]
fn test_verify_socket_ownership_remote_bind_rejected() {
    let dir = tempdir().unwrap();
    let tcp_file = dir.path().join("tcp");
    // 00000000:235B -> bound to 0.0.0.0
    let content = "   0: 00000000:235B 00000000:0000 0A 00000000:00000000 00:00000000 00000000   122        0 33333 1 00000000b761d09b 100 0 0 10 0\n";
    fs::write(&tcp_file, content).unwrap();

    let res = verify_socket_ownership(&tcp_file, dir.path(), 9051, None, None);
    match res {
        Err(UmbraError::TorListenerWrongProcess { actual, .. }) => {
            assert!(actual.contains("0.0.0.0"));
        }
        Err(UmbraError::TorControlError(msg)) => {
            assert!(msg.contains("not bound to local-only 127.0.0.1"));
        }
        other => panic!(
            "expected TorListenerWrongProcess or TorControlError for remote bind, got {other:?}"
        ),
    }
}

#[test]
fn test_verify_socket_ownership_root_uid_rejected() {
    let dir = tempdir().unwrap();
    let tcp_file = dir.path().join("tcp");
    // UID 0 (root) on port 9040
    let content = "   0: 0100007F:2350 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 29052 1 00000000b761d09b 100 0 0 10 0\n";
    fs::write(&tcp_file, content).unwrap();

    let res = verify_socket_ownership(&tcp_file, dir.path(), 9040, None, None);
    match res {
        Err(UmbraError::TorRunningAsRoot) => {}
        other => panic!("expected TorRunningAsRoot for UID 0 socket, got {other:?}"),
    }
}

#[test]
fn test_tcp_socket_in_closed_state_not_matched_as_listener() {
    let dir = tempdir().unwrap();
    let tcp_file = dir.path().join("tcp");
    // State 07 (TCP_CLOSE) on port 9040
    let content = "   0: 0100007F:2350 00000000:0000 07 00000000:00000000 00:00000000 00000000   122        0 29052 1 00000000b761d09b 100 0 0 10 0\n";
    fs::write(&tcp_file, content).unwrap();

    let res = verify_socket_ownership(&tcp_file, dir.path(), 9040, None, None);
    match res {
        Err(UmbraError::TorListenerPortClosed { port, details }) => {
            assert_eq!(port, 9040);
            assert!(details.contains("port closed") || details.contains("no listener"));
        }
        other => panic!("expected TorListenerPortClosed for TCP_CLOSE state socket, got {other:?}"),
    }
}

#[test]
fn test_verify_socket_ownership_pid_does_not_own_inode_rejected() {
    let dir = tempdir().unwrap();
    let tcp_file = dir.path().join("tcp");
    // Inode 77777 on port 9040
    let content = "   0: 0100007F:2350 00000000:0000 0A 00000000:00000000 00:00000000 00000000   122        0 77777 1 00000000b761d09b 100 0 0 10 0\n";
    fs::write(&tcp_file, content).unwrap();

    // Tor PID 500 has fd/3 -> socket:[11111], NOT socket:[77777]
    let pid_dir = dir.path().join("500");
    let fd_dir = pid_dir.join("fd");
    fs::create_dir_all(&fd_dir).unwrap();
    fs::write(pid_dir.join("comm"), "tor\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("socket:[11111]", fd_dir.join("3")).unwrap();

    // Verification must fail because Tor (PID 500) does not own socket 77777
    let res = verify_socket_ownership(&tcp_file, dir.path(), 9040, Some(122), Some(500));
    match res {
        Err(UmbraError::TorListenerWrongProcess {
            port,
            expected,
            actual,
        }) => {
            assert_eq!(port, 9040);
            assert!(expected.contains("500"));
            assert!(actual.contains("unknown") || actual.contains("different"));
        }
        other => panic!(
            "expected TorListenerWrongProcess when expected PID doesn't own socket, got {other:?}"
        ),
    }
}

// ============================================================================
// 5. Mock Tor ControlPort Listener & NEWNYM Protocol Tests
// ============================================================================

#[test]
fn test_mock_controlport_newnym_success_cookie_auth() {
    let cookie_dir = tempdir().unwrap();
    let cookie_file = cookie_dir.path().join("control_auth_cookie");
    let test_cookie = [0x42u8; 32];
    fs::write(&cookie_file, test_cookie).unwrap();
    let hex_expected = hex_encode(&test_cookie);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let cookie_file_clone = cookie_file.clone();
    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());

        // 1. Client sends PROTOCOLINFO 1
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "PROTOCOLINFO 1");

        // Respond with PROTOCOLINFO and COOKIEFILE
        let resp = format!(
            "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE COOKIEFILE=\"{}\"\r\n250-VERSION Tor=\"0.4.9.12\"\r\n250 OK\r\n",
            cookie_file_clone.display()
        );
        stream.write_all(resp.as_bytes()).unwrap();

        // 2. Client sends AUTHENTICATE <hex>
        line.clear();
        reader.read_line(&mut line).unwrap();
        let expected_cmd = format!("AUTHENTICATE {hex_expected}");
        assert_eq!(line.trim(), expected_cmd);
        stream.write_all(b"250 OK\r\n").unwrap();

        // 3. Client sends SIGNAL NEWNYM
        line.clear();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "SIGNAL NEWNYM");
        stream.write_all(b"250 OK\r\n").unwrap();

        // 4. Client sends QUIT
        line.clear();
        let _ = reader.read_line(&mut line);
        let _ = stream.write_all(b"250 closing connection\r\n");
    });

    let res = TorController::request_newnym_with_options(port, None, Some(&cookie_file));
    assert!(res.is_ok(), "NEWNYM handshake should succeed: {res:?}");

    server_handle.join().unwrap();
}

#[test]
fn test_mock_controlport_newnym_success_no_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());

        // 1. Client sends PROTOCOLINFO 1
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "PROTOCOLINFO 1");

        stream
            .write_all(b"250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n250 OK\r\n")
            .unwrap();

        // 2. Client sends AUTHENTICATE
        line.clear();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "AUTHENTICATE");
        stream.write_all(b"250 OK\r\n").unwrap();

        // 3. Client sends SIGNAL NEWNYM
        line.clear();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "SIGNAL NEWNYM");
        stream.write_all(b"250 OK\r\n").unwrap();

        // 4. Client sends QUIT
        line.clear();
        let _ = reader.read_line(&mut line);
    });

    let res = TorController::request_newnym_with_options(port, None, None);
    assert!(res.is_ok(), "NEWNYM with no-auth should succeed: {res:?}");

    server_handle.join().unwrap();
}

#[test]
fn test_mock_controlport_auth_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());

        let mut line = String::new();
        reader.read_line(&mut line).unwrap(); // PROTOCOLINFO 1
        stream
            .write_all(b"250-PROTOCOLINFO 1\r\n250-AUTH METHODS=HASHEDPASSWORD\r\n250 OK\r\n")
            .unwrap();

        line.clear();
        reader.read_line(&mut line).unwrap(); // AUTHENTICATE
        stream
            .write_all(b"515 Authentication failed: Password did not match\r\n")
            .unwrap();
    });

    let res = TorController::request_newnym_with_options(port, None, None);
    match res {
        Err(UmbraError::TorControlAuthFailed(msg)) => {
            assert!(msg.contains("515 Authentication failed"));
        }
        other => panic!("expected TorControlAuthFailed, got {other:?}"),
    }

    server_handle.join().unwrap();
}

#[test]
fn test_mock_controlport_protocol_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());

        let mut line = String::new();
        reader.read_line(&mut line).unwrap(); // PROTOCOLINFO 1
        stream
            .write_all(b"510 Unrecognized command \"PROTOCOLINFO 1\"\r\n")
            .unwrap();
    });

    let res = TorController::request_newnym_with_options(port, None, None);
    match res {
        Err(UmbraError::TorListenerWrongProcess { actual, .. }) => {
            assert!(actual.contains("510"));
        }
        Err(UmbraError::TorControlProtocolError(msg)) => {
            assert!(msg.contains("510"));
        }
        other => panic!("expected protocol error or wrong process, got {other:?}"),
    }

    server_handle.join().unwrap();
}

#[test]
fn test_mock_controlport_wrong_protocol_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());

        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        // Respond with HTTP header instead of RFC 250
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });

    let res = TorController::verify_controlport_with_identity(port, None);
    match res {
        Err(UmbraError::TorListenerWrongProcess {
            port: p,
            expected,
            actual,
        }) => {
            assert_eq!(p, port);
            assert!(expected.contains("Tor ControlPort"));
            assert!(actual.contains("protocol error"));
        }
        other => panic!("expected TorListenerWrongProcess for non-Tor listener, got {other:?}"),
    }

    server_handle.join().unwrap();
}

#[test]
fn test_controlport_closed_port_detected() {
    // Bind and drop immediately to obtain an unused closed port
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = listener.local_addr().unwrap().port();
    drop(listener);

    let res = TorController::verify_controlport_with_identity(closed_port, None);
    match res {
        Err(UmbraError::TorListenerPortClosed { port, details }) => {
            assert_eq!(port, closed_port);
            assert!(
                details.contains("refused")
                    || details.contains("failed")
                    || details.contains("port closed")
                    || details.contains("no listener")
            );
        }
        other => panic!("expected TorListenerPortClosed, got {other:?}"),
    }
}

#[test]
fn test_controlport_timeout_detected() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        // Sleep to induce read timeout on client
        thread::sleep(Duration::from_millis(1500));
    });

    let res = TorController::verify_controlport_with_identity(port, None);
    match res {
        Err(UmbraError::TorListenerTimeout { port: p, details }) => {
            assert_eq!(p, port);
            assert!(details.contains("timed out"));
        }
        other => panic!("expected TorListenerTimeout, got {other:?}"),
    }

    server_handle.join().unwrap();
}

#[test]
fn test_transport_closed_port_detected() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = listener.local_addr().unwrap().port();
    drop(listener);

    let res = TorController::verify_transport_with_identity(closed_port, None);
    match res {
        Err(UmbraError::TorListenerPortClosed { port, .. }) => {
            assert_eq!(port, closed_port);
        }
        other => panic!("expected TorListenerPortClosed, got {other:?}"),
    }
}

#[test]
fn test_custom_cookie_path_missing_fails() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());

        let mut line = String::new();
        reader.read_line(&mut line).unwrap(); // PROTOCOLINFO 1
        stream
            .write_all(b"250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE\r\n250 OK\r\n")
            .unwrap();
    });

    let non_existent_cookie = Path::new("/non/existent/cookie/path");
    let res = TorController::request_newnym_with_options(port, None, Some(non_existent_cookie));

    match res {
        Err(UmbraError::TorControlAuthFailed(msg)) => {
            assert!(msg.contains("failed to open custom cookie file"));
        }
        other => {
            panic!("expected TorControlAuthFailed for non-existent cookie file, got {other:?}")
        }
    }

    server_handle.join().unwrap();
}

#[test]
fn test_request_newnym_fails_when_tor_not_running() {
    // If Tor process is not running on the host, request_newnym must fail-closed with TorNotRunning
    // or fail to find process
    let ident = TorController::find_tor_process();
    if ident.is_ok() && ident.unwrap().is_none() {
        let res = TorController::request_newnym(9051);
        match res {
            Err(UmbraError::TorNotRunning) => {}
            other => panic!("expected TorNotRunning when Tor is not running, got {other:?}"),
        }
    }
}

// ============================================================================
// 6. DNSPort Verification Tests
// ============================================================================

#[test]
fn test_dnsport_closed_port_detected() {
    // Bind and immediately drop UDP socket to find an unused port
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let closed_port = socket.local_addr().unwrap().port();
    drop(socket);

    let res = TorController::verify_dnsport_with_identity(closed_port, None);
    match res {
        Err(UmbraError::TorListenerPortClosed { port, details }) => {
            assert_eq!(port, closed_port);
            assert!(
                details.contains("refused")
                    || details.contains("failed")
                    || details.contains("closed")
            );
        }
        Err(UmbraError::TorListenerTimeout { port, .. }) => {
            // Some environments drop ICMP unreachable and time out
            assert_eq!(port, closed_port);
        }
        other => {
            panic!("expected TorListenerPortClosed or Timeout for closed DNSPort, got {other:?}")
        }
    }
}

#[test]
fn test_mock_dnsport_success() {
    let server_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = server_socket.local_addr().unwrap().port();

    // Verify that the listener is detected on 127.0.0.1 and owned by a non-root process
    let res = TorController::verify_dnsport_with_identity(port, None);
    assert!(
        res.is_ok(),
        "mock DNSPort listener verification should succeed: {res:?}"
    );
}
