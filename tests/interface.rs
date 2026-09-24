use std::fs;
use tempfile::tempdir;
use umbra::error::UmbraError;
use umbra::interface::{InterfaceBaseline, InterfaceController};
use umbra::mac::MacAddress;

#[test]
fn test_route_table_parser_single_default_route() {
    let route_table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t011ED80A\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t001ED80A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    let defaults = InterfaceController::parse_default_routes(route_table);
    assert_eq!(defaults, vec!["eth0"]);
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

    let defaults = InterfaceController::parse_default_routes(route_table);
    assert_eq!(
        defaults,
        vec!["eth0", "eth1", "wlan0"],
        "Default routes must be ordered by metric ascending (lowest metric first)"
    );
}

#[test]
fn test_route_table_parser_filters_loopback() {
    let route_table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
lo\t00000000\t00000000\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t00000000\t011ED80A\t0003\t0\t0\t100\t00000000\t0\t0\t0
";

    let defaults = InterfaceController::parse_default_routes(route_table);
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

    let defaults = InterfaceController::parse_default_routes(route_table);
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
    assert!(matches!(res, Err(UmbraError::InterfaceNotFound(_))));
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
