use std::fs;
use tempfile::tempdir;
use umbra::error::UmbraError;
use umbra::interface::{InterfaceBaseline, InterfaceController, RouteCandidate};
use umbra::mac::MacAddress;

#[test]
fn test_route_table_parser_single_default_route() {
    let route_table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t011ED80A\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t001ED80A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    let candidates = InterfaceController::parse_default_routes(route_table);
    assert_eq!(
        candidates,
        vec![RouteCandidate {
            interface: "eth0".to_string(),
            metric: 100,
        }]
    );

    let ifaces = InterfaceController::parse_default_route_interfaces(route_table);
    assert_eq!(ifaces, vec!["eth0"]);
}

#[test]
fn test_route_table_parser_multiple_default_routes_metric_sorting() {
    // 3 default routes with metrics: wlan0 (600), eth0 (100), eth1 (200)
    let route_table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlan0\t00000000\t011ED80A\t0003\t0\t0\t600\t00000000\t0\t0\t0
eth1\t00000000\t011ED80A\t0003\t0\t0\t200\t00000000\t0\t0\t0
eth0\t00000000\t011ED80A\t0003\t0\t0\t100\t00000000\t0\t0\t0
";

    let defaults = InterfaceController::parse_default_route_interfaces(route_table);
    assert_eq!(
        defaults,
        vec!["eth0", "eth1", "wlan0"],
        "Default routes must be ordered by metric ascending (lowest metric first)"
    );

    let candidates = InterfaceController::parse_default_routes(route_table);
    let authoritative = InterfaceController::resolve_authoritative_candidate(&candidates)
        .expect("should resolve eth0 as lowest metric");
    assert_eq!(authoritative, "eth0");
}

#[test]
fn test_route_ambiguity_detection_fails_safely() {
    // Ambiguous: two distinct interfaces (eth0 and wlan0) share identical lowest metric (100)
    let ambiguous_candidates = vec![
        RouteCandidate {
            interface: "eth0".to_string(),
            metric: 100,
        },
        RouteCandidate {
            interface: "wlan0".to_string(),
            metric: 100,
        },
        RouteCandidate {
            interface: "eth1".to_string(),
            metric: 200,
        },
    ];

    let res = InterfaceController::resolve_authoritative_candidate(&ambiguous_candidates);
    assert!(
        matches!(res, Err(UmbraError::EgressResolutionFailed(_))),
        "Must fail safely when multiple distinct interfaces share lowest metric"
    );

    // Duplicate entries for the same interface (e.g. multi-gateway on same dev) is NOT ambiguous
    let duplicate_candidates = vec![
        RouteCandidate {
            interface: "eth0".to_string(),
            metric: 100,
        },
        RouteCandidate {
            interface: "eth0".to_string(),
            metric: 100,
        },
        RouteCandidate {
            interface: "eth1".to_string(),
            metric: 200,
        },
    ];

    let auth = InterfaceController::resolve_authoritative_candidate(&duplicate_candidates)
        .expect("duplicate routes on the same interface must resolve to that interface");
    assert_eq!(auth, "eth0");
}

#[test]
fn test_parse_ip_route_default_output() {
    let output = "\
default via 192.168.1.1 dev eth0 proto dhcp metric 100
default via 10.0.0.1 dev wlan0 proto dhcp metric 200
";
    let candidates = InterfaceController::parse_ip_route_default_output(output);
    assert_eq!(
        candidates,
        vec![
            RouteCandidate {
                interface: "eth0".to_string(),
                metric: 100,
            },
            RouteCandidate {
                interface: "wlan0".to_string(),
                metric: 200,
            },
        ]
    );

    // Test output without explicit metric (defaults to 0)
    let no_metric_output = "default via 192.168.1.1 dev eth0\n";
    let candidates_no_m = InterfaceController::parse_ip_route_default_output(no_metric_output);
    assert_eq!(
        candidates_no_m,
        vec![RouteCandidate {
            interface: "eth0".to_string(),
            metric: 0,
        }]
    );
}

#[test]
fn test_route_table_parser_filters_loopback() {
    let route_table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
lo\t00000000\t00000000\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t00000000\t011ED80A\t0003\t0\t0\t100\t00000000\t0\t0\t0
";

    let defaults = InterfaceController::parse_default_route_interfaces(route_table);
    assert_eq!(defaults, vec!["eth0"], "Loopback must be filtered out");
}

#[test]
fn test_route_table_parser_requires_rtf_up() {
    // Route 1 has flags 0002 (RTF_GATEWAY without RTF_UP)
    // Route 2 has flags 0003 (RTF_GATEWAY | RTF_UP)
    let route_table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth_down\t00000000\t011ED80A\t0002\t0\t0\t50\t00000000\t0\t0\t0
eth_up\t00000000\t011ED80A\t0003\t0\t0\t100\t00000000\t0\t0\t0
";

    let defaults = InterfaceController::parse_default_route_interfaces(route_table);
    assert_eq!(
        defaults,
        vec!["eth_up"],
        "Routes lacking RTF_UP must be excluded"
    );
}

#[test]
fn test_route_table_parser_empty_and_corrupt() {
    assert!(InterfaceController::parse_default_routes("").is_empty());
    assert!(InterfaceController::parse_default_routes("Header line only\n").is_empty());
    assert!(InterfaceController::parse_default_routes("gibberish not enough columns").is_empty());

    assert!(InterfaceController::resolve_authoritative_candidate(&[]).is_err());
}

#[test]
fn test_sysfs_baseline_capture_mock_up() {
    let temp = tempdir().expect("create temp dir");
    let iface_dir = temp.path().join("eth0");
    fs::create_dir_all(&iface_dir).expect("create iface dir");

    fs::write(iface_dir.join("address"), "00:15:5d:d8:1e:d5\n").expect("write address");
    fs::write(iface_dir.join("flags"), "0x1003\n").expect("write flags");

    let baseline = InterfaceController::capture_baseline_from_sysfs(temp.path(), "eth0")
        .expect("capture baseline");

    assert_eq!(
        baseline,
        InterfaceBaseline {
            name: "eth0".to_string(),
            original_mac: MacAddress::parse("00:15:5d:d8:1e:d5").unwrap(),
            was_up: true,
        }
    );
}

#[test]
fn test_sysfs_baseline_capture_mock_down() {
    let temp = tempdir().expect("create temp dir");
    let iface_dir = temp.path().join("wlan0");
    fs::create_dir_all(&iface_dir).expect("create iface dir");

    fs::write(iface_dir.join("address"), "02:42:ac:11:00:02\n").expect("write address");
    // 0x1002 has bit 0 (IFF_UP) cleared
    fs::write(iface_dir.join("flags"), "0x1002\n").expect("write flags");

    let baseline = InterfaceController::capture_baseline_from_sysfs(temp.path(), "wlan0")
        .expect("capture baseline");

    assert_eq!(
        baseline,
        InterfaceBaseline {
            name: "wlan0".to_string(),
            original_mac: MacAddress::parse("02:42:ac:11:00:02").unwrap(),
            was_up: false,
        }
    );
}

#[test]
fn test_sysfs_baseline_capture_rejects_loopback() {
    let temp = tempdir().expect("create temp dir");
    let iface_dir = temp.path().join("lo");
    fs::create_dir_all(&iface_dir).expect("create iface dir");
    fs::write(iface_dir.join("address"), "00:00:00:00:00:00\n").unwrap();
    fs::write(iface_dir.join("flags"), "0x1003\n").unwrap();

    let res = InterfaceController::capture_baseline_from_sysfs(temp.path(), "lo");
    assert!(
        matches!(res, Err(UmbraError::InterfaceNotFound(_))),
        "Loopback must be rejected as an egress interface"
    );
}

#[test]
fn test_sysfs_baseline_capture_rejects_all_zeros_and_multicast_mac() {
    let temp = tempdir().expect("create temp dir");
    let iface_dir = temp.path().join("tun0");
    fs::create_dir_all(&iface_dir).expect("create iface dir");
    fs::write(iface_dir.join("address"), "00:00:00:00:00:00\n").unwrap();
    fs::write(iface_dir.join("flags"), "0x1003\n").unwrap();

    let res = InterfaceController::capture_baseline_from_sysfs(temp.path(), "tun0");
    assert!(
        matches!(res, Err(UmbraError::InvalidMacAddress(_))),
        "All-zero MAC must be rejected"
    );

    // Multicast MAC
    fs::write(iface_dir.join("address"), "01:00:5e:00:00:01\n").unwrap();
    let res = InterfaceController::capture_baseline_from_sysfs(temp.path(), "tun0");
    assert!(
        matches!(res, Err(UmbraError::InvalidMacAddress(_))),
        "Multicast MAC must be rejected"
    );
}

#[test]
fn test_apply_and_restore_reject_loopback() {
    let valid_mac = MacAddress::generate_random().unwrap();
    let res = InterfaceController::apply_mac("lo", valid_mac);
    assert!(matches!(res, Err(UmbraError::MacChangeFailed { .. })));

    let baseline_lo = InterfaceBaseline {
        name: "lo".to_string(),
        original_mac: valid_mac,
        was_up: true,
    };
    let res = InterfaceController::restore_baseline(&baseline_lo);
    assert!(matches!(res, Err(UmbraError::MacRestoreFailed { .. })));
}

#[test]
fn test_apply_mac_rejects_non_randomized_mac() {
    let invalid_mac = MacAddress::new([0, 0, 0, 0, 0, 0]);
    let res = InterfaceController::apply_mac("eth0", invalid_mac);
    assert!(matches!(res, Err(UmbraError::InvalidMacAddress(_))));
}

#[test]
fn test_sysfs_baseline_capture_nonexistent_interface() {
    let temp = tempdir().expect("create temp dir");
    let res = InterfaceController::capture_baseline_from_sysfs(temp.path(), "eth99");
    assert!(matches!(res, Err(UmbraError::InterfaceNotFound(_))));
}

#[test]
fn test_sysfs_read_mac_malformed() {
    let temp = tempdir().expect("create temp dir");
    let iface_dir = temp.path().join("eth0");
    fs::create_dir_all(&iface_dir).expect("create iface dir");

    fs::write(iface_dir.join("address"), "invalid-mac\n").expect("write bad address");
    fs::write(iface_dir.join("flags"), "0x1003\n").expect("write flags");

    let res = InterfaceController::read_mac_from_sysfs(temp.path(), "eth0");
    assert!(matches!(res, Err(UmbraError::InvalidMacAddress(_))));
}

#[test]
fn test_sysfs_flags_invalid_hex() {
    let temp = tempdir().expect("create temp dir");
    let iface_dir = temp.path().join("eth0");
    fs::create_dir_all(&iface_dir).expect("create iface dir");

    fs::write(iface_dir.join("address"), "00:15:5d:d8:1e:d5\n").expect("write address");
    fs::write(iface_dir.join("flags"), "not_hex_flag\n").expect("write bad flags");

    let res = InterfaceController::is_administratively_up_from_sysfs(temp.path(), "eth0");
    assert!(matches!(
        res,
        Err(UmbraError::InterfaceStateChangeFailed { .. })
    ));
}

#[test]
fn test_sysfs_missing_files() {
    let temp = tempdir().expect("create temp dir");
    let iface_dir = temp.path().join("eth0");
    fs::create_dir_all(&iface_dir).expect("create iface dir");

    // Missing address
    assert!(matches!(
        InterfaceController::read_mac_from_sysfs(temp.path(), "eth0"),
        Err(UmbraError::InterfaceNotFound(_))
    ));

    // Write address only, missing flags
    fs::write(iface_dir.join("address"), "00:15:5d:d8:1e:d5\n").unwrap();
    assert!(matches!(
        InterfaceController::is_administratively_up_from_sysfs(temp.path(), "eth0"),
        Err(UmbraError::InterfaceNotFound(_))
    ));
}
