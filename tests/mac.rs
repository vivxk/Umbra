use std::collections::HashSet;
use umbra::mac::MacAddress;

#[test]
fn test_mac_unicast_and_locally_administered() {
    for _ in 0..100 {
        let mac = MacAddress::generate_random().expect("should generate random MAC");
        let bytes = mac.bytes();

        // Must be unicast (bit 0 == 0)
        assert_eq!(bytes[0] & 0x01, 0, "MAC {mac} must be unicast");

        // Must be locally administered (bit 1 == 1)
        assert_eq!(
            bytes[0] & 0x02,
            0x02,
            "MAC {mac} must be locally administered"
        );

        assert!(mac.is_valid_randomized());
        assert!(mac.is_unicast());
        assert!(mac.is_locally_administered());
    }
}

#[test]
fn test_mac_parsing_colon_format() {
    let mac = MacAddress::parse("02:42:ac:11:00:02").expect("valid MAC format");
    assert_eq!(mac.bytes(), [0x02, 0x42, 0xac, 0x11, 0x00, 0x02]);
    assert_eq!(mac.to_string(), "02:42:ac:11:00:02");
}

#[test]
fn test_mac_parsing_hyphen_format() {
    let mac = MacAddress::parse("02-42-ac-11-00-02").expect("valid MAC format");
    assert_eq!(mac.bytes(), [0x02, 0x42, 0xac, 0x11, 0x00, 0x02]);
}

#[test]
fn test_mac_parsing_case_insensitive() {
    let mac = MacAddress::parse("02:42:AC:11:00:02").expect("valid uppercase hex");
    assert_eq!(mac.to_string(), "02:42:ac:11:00:02");
}

#[test]
fn test_mac_parsing_invalid_length() {
    assert!(MacAddress::parse("02:42:ac:11:00").is_err());
    assert!(MacAddress::parse("02:42:ac:11:00:02:ff").is_err());
    assert!(MacAddress::parse("").is_err());
}

#[test]
fn test_mac_parsing_invalid_hex() {
    assert!(MacAddress::parse("02:42:zz:11:00:02").is_err());
    assert!(MacAddress::parse("02:42:  :11:00:02").is_err());
}

#[test]
fn test_mac_parsing_invalid_octet_format() {
    // Single digit octet
    assert!(MacAddress::parse("2:42:ac:11:00:02").is_err());
    // Triple digit octet
    assert!(MacAddress::parse("002:42:ac:11:00:02").is_err());
    // Mixed or unknown delimiters
    assert!(MacAddress::parse("02.42.ac.11.00.02").is_err());
}

#[test]
fn test_mac_properties_and_predicates() {
    // All zeroes
    let zero_mac = MacAddress::new([0, 0, 0, 0, 0, 0]);
    assert!(!zero_mac.is_locally_administered());
    assert!(zero_mac.is_unicast());
    assert!(!zero_mac.is_valid_randomized());

    // Multicast (bit 0 = 1)
    let multicast_mac = MacAddress::new([0x03, 0x00, 0x5e, 0x00, 0x00, 0x01]);
    assert!(!multicast_mac.is_unicast());
    assert!(multicast_mac.is_locally_administered());
    assert!(!multicast_mac.is_valid_randomized());

    // Globally administered (bit 1 = 0)
    let global_mac = MacAddress::new([0x00, 0x15, 0x5d, 0xd8, 0x1e, 0xd5]);
    assert!(global_mac.is_unicast());
    assert!(!global_mac.is_locally_administered());
    assert!(!global_mac.is_valid_randomized());

    // Valid locally administered unicast
    let valid_mac = MacAddress::new([0x02, 0x15, 0x5d, 0xd8, 0x1e, 0xd5]);
    assert!(valid_mac.is_unicast());
    assert!(valid_mac.is_locally_administered());
    assert!(valid_mac.is_valid_randomized());
}

#[test]
fn test_mac_hash_and_equality() {
    let mac1 = MacAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    let mac2 = MacAddress::parse("02:aa:bb:cc:dd:ee").unwrap();
    let mac3 = MacAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xef]);

    assert_eq!(mac1, mac2);
    assert_ne!(mac1, mac3);

    let mut set = HashSet::new();
    set.insert(mac1);
    assert!(set.contains(&mac2));
    assert!(!set.contains(&mac3));
}

#[test]
fn test_mac_debug_and_display() {
    let mac = MacAddress::new([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(mac.to_string(), "02:11:22:33:44:55");
    assert_eq!(format!("{mac:?}"), "MacAddress(02:11:22:33:44:55)");
}
