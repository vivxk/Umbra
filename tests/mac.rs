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
}

#[test]
fn test_mac_parsing_invalid_hex() {
    assert!(MacAddress::parse("02:42:zz:11:00:02").is_err());
}
