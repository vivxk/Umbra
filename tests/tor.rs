use umbra::tor::TorIdentity;

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
