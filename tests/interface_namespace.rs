mod common;

use std::process::Command;
use umbra::error::UmbraError;
use umbra::interface::InterfaceController;
use umbra::mac::MacAddress;

#[test]
fn test_interface_baseline_and_mac_randomization_in_netns() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_if_rand").expect("netns isolation required");
        netns.run_test("test_interface_baseline_and_mac_randomization_in_netns");
        return;
    }

    let iface = "test_dummy0";
    let init_mac_str = "02:11:22:33:44:55";

    // 1. Create a dummy interface inside this isolated network namespace
    let st = Command::new("ip")
        .args(["link", "add", "dev", iface, "type", "dummy"])
        .status()
        .expect("create dummy interface");
    assert!(st.success());

    let st = Command::new("ip")
        .args(["link", "set", "dev", iface, "address", init_mac_str])
        .status()
        .expect("set initial dummy MAC");
    assert!(st.success());

    let st = Command::new("ip")
        .args(["link", "set", "dev", iface, "up"])
        .status()
        .expect("bring dummy UP");
    assert!(st.success());

    // 2. Capture baseline
    let baseline = InterfaceController::capture_baseline(iface).expect("baseline capture");
    assert_eq!(baseline.name, iface);
    assert_eq!(baseline.original_mac.to_string(), init_mac_str);
    assert!(baseline.was_up, "Interface should be administratively UP");

    // 3. Generate randomized MAC and apply
    let new_mac = MacAddress::generate_random().expect("generate random MAC");
    assert!(new_mac.is_valid_randomized());
    assert_ne!(new_mac, baseline.original_mac);

    InterfaceController::apply_mac(iface, new_mac).expect("apply MAC");

    // 4. Live verify MAC changed and interface remains UP
    let live_mac = InterfaceController::read_mac(iface).expect("read live MAC");
    assert_eq!(live_mac, new_mac);
    assert!(
        InterfaceController::is_administratively_up(iface).expect("check admin UP"),
        "Interface must remain UP after MAC change"
    );

    // 5. Restore baseline
    InterfaceController::restore_baseline(&baseline).expect("restore baseline");

    // 6. Live verify MAC restored and interface remains UP
    let restored_mac = InterfaceController::read_mac(iface).expect("read restored MAC");
    assert_eq!(restored_mac, baseline.original_mac);
    assert!(
        InterfaceController::is_administratively_up(iface).expect("check admin UP"),
        "Interface must remain UP after restoration"
    );

    // Clean up interface
    let _ = Command::new("ip")
        .args(["link", "del", "dev", iface])
        .status();
}

#[test]
fn test_interface_state_transition_down_preserved_in_netns() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_if_down").expect("netns isolation required");
        netns.run_test("test_interface_state_transition_down_preserved_in_netns");
        return;
    }

    let iface = "test_dummy1";
    let init_mac_str = "02:22:33:44:55:66";

    // 1. Create a dummy interface kept administratively DOWN
    let st = Command::new("ip")
        .args(["link", "add", "dev", iface, "type", "dummy"])
        .status()
        .expect("create dummy interface");
    assert!(st.success());

    let st = Command::new("ip")
        .args(["link", "set", "dev", iface, "address", init_mac_str])
        .status()
        .expect("set initial dummy MAC");
    assert!(st.success());

    let st = Command::new("ip")
        .args(["link", "set", "dev", iface, "down"])
        .status()
        .expect("ensure dummy DOWN");
    assert!(st.success());

    // 2. Capture baseline
    let baseline = InterfaceController::capture_baseline(iface).expect("baseline capture");
    assert_eq!(baseline.name, iface);
    assert_eq!(baseline.original_mac.to_string(), init_mac_str);
    assert!(
        !baseline.was_up,
        "Interface should be administratively DOWN"
    );

    // 3. Apply randomized MAC
    let new_mac = MacAddress::generate_random().expect("generate random MAC");
    InterfaceController::apply_mac(iface, new_mac).expect("apply MAC");

    // 4. Verify live MAC updated and interface remains DOWN
    let live_mac = InterfaceController::read_mac(iface).expect("read live MAC");
    assert_eq!(live_mac, new_mac);
    assert!(
        !InterfaceController::is_administratively_up(iface).expect("check admin DOWN"),
        "Interface must remain DOWN after MAC change"
    );

    // 5. Restore baseline
    InterfaceController::restore_baseline(&baseline).expect("restore baseline");

    // 6. Verify original MAC restored and interface remains DOWN
    let restored_mac = InterfaceController::read_mac(iface).expect("read restored MAC");
    assert_eq!(restored_mac, baseline.original_mac);
    assert!(
        !InterfaceController::is_administratively_up(iface).expect("check admin DOWN"),
        "Interface must remain DOWN after restoration"
    );

    // Clean up
    let _ = Command::new("ip")
        .args(["link", "del", "dev", iface])
        .status();
}

#[test]
fn test_interface_admin_state_toggle_in_netns() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_if_togg").expect("netns isolation required");
        netns.run_test("test_interface_admin_state_toggle_in_netns");
        return;
    }

    let iface = "test_dummy2";

    let st = Command::new("ip")
        .args(["link", "add", "dev", iface, "type", "dummy"])
        .status()
        .expect("create dummy");
    assert!(st.success());

    // Toggle UP
    InterfaceController::set_admin_state(iface, true).expect("set UP");
    assert!(InterfaceController::is_administratively_up(iface).unwrap());

    // Toggle DOWN
    InterfaceController::set_admin_state(iface, false).expect("set DOWN");
    assert!(!InterfaceController::is_administratively_up(iface).unwrap());

    // Toggle UP again
    InterfaceController::set_admin_state(iface, true).expect("set UP again");
    assert!(InterfaceController::is_administratively_up(iface).unwrap());

    // Clean up
    let _ = Command::new("ip")
        .args(["link", "del", "dev", iface])
        .status();
}

#[test]
fn test_interface_nonexistent_device_handling() {
    let bad_iface = "nonexistent_dev_99";

    // capture_baseline fails
    let res = InterfaceController::capture_baseline(bad_iface);
    assert!(matches!(res, Err(UmbraError::InterfaceNotFound(_))));

    // read_mac fails
    let res = InterfaceController::read_mac(bad_iface);
    assert!(matches!(res, Err(UmbraError::InterfaceNotFound(_))));

    // is_administratively_up fails
    let res = InterfaceController::is_administratively_up(bad_iface);
    assert!(matches!(res, Err(UmbraError::InterfaceNotFound(_))));

    // set_admin_state fails
    let res = InterfaceController::set_admin_state(bad_iface, true);
    assert!(matches!(
        res,
        Err(UmbraError::InterfaceStateChangeFailed { .. })
    ));
}

#[test]
fn test_interface_loopback_rejected_in_netns() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_if_lo").expect("netns isolation required");
        netns.run_test("test_interface_loopback_rejected_in_netns");
        return;
    }

    // capture_baseline on lo must fail
    let res = InterfaceController::capture_baseline("lo");
    assert!(
        matches!(res, Err(UmbraError::InterfaceNotFound(_))),
        "Capturing baseline on loopback must be rejected"
    );

    // apply_mac on lo must fail
    let rand_mac = MacAddress::generate_random().unwrap();
    let res = InterfaceController::apply_mac("lo", rand_mac);
    assert!(
        matches!(res, Err(UmbraError::MacChangeFailed { .. })),
        "Applying MAC on loopback must be rejected"
    );

    // restore_baseline on lo must fail
    let lo_baseline = umbra::interface::InterfaceBaseline {
        name: "lo".to_string(),
        original_mac: rand_mac,
        was_up: true,
    };
    let res = InterfaceController::restore_baseline(&lo_baseline);
    assert!(
        matches!(res, Err(UmbraError::MacRestoreFailed { .. })),
        "Restoring baseline on loopback must be rejected"
    );
}
