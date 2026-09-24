use umbra::constants::{NFT_TABLE_FAMILY, NFT_TABLE_NAME, OWNERSHIP_MARKER};
use umbra::error::UmbraError;
use umbra::firewall::{FirewallConfig, FirewallController};

#[test]
fn test_firewall_rule_generation() {
    let config = FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: 122,
        tor_transport_port: 9040,
        tor_dns_port: 5353,
        tor_control_port: 9051,
        egress_interface: "eth0".to_string(),
        activation_id: "test_act".to_string(),
    };

    let ruleset = FirewallController::generate_ruleset(&config);

    // Verify key security requirements in generated ruleset
    assert!(ruleset.contains("table inet umbra"));
    assert!(ruleset.contains("chain output_nat"));
    assert!(ruleset.contains("chain output_filter"));
    assert!(ruleset.contains(OWNERSHIP_MARKER));

    // Tor UID bypass
    assert!(ruleset.contains("skuid 122 return"));
    assert!(ruleset.contains("skuid 122 accept"));

    // IPv6 external leak protection
    assert!(ruleset.contains("meta nfproto ipv6 return"));
    assert!(ruleset.contains("ip6 daddr != ::1 drop"));

    // Redirections
    assert!(ruleset.contains("udp dport 53 redirect to :5353"));
    assert!(ruleset.contains("tcp dport != 9040 redirect to :9040"));

    // DNS leak prevention (TCP reset, never sent to TransPort)
    assert!(ruleset.contains("tcp dport 53 return"));
    assert!(ruleset.contains("tcp dport 53 reject with tcp reset"));

    // QUIC and DoT drops
    assert!(ruleset.contains("tcp dport 853 return"));
    assert!(ruleset.contains("udp dport 443 drop"));
    assert!(ruleset.contains("tcp dport 853 drop"));
    assert!(ruleset.contains("udp dport 853 drop"));

    // IPv6 DNS drops
    assert!(ruleset.contains("meta nfproto ipv6 udp dport 53 drop"));
    assert!(ruleset.contains("meta nfproto ipv6 tcp dport 53 drop"));

    // Fail-closed drops
    assert!(ruleset.contains("meta l4proto udp drop"));
}

#[test]
fn test_firewall_syntax_check_valid() {
    let config = FirewallConfig {
        tor_uid: 122,
        ..Default::default()
    };
    let ruleset = FirewallController::generate_ruleset(&config);

    // nft -c -f - validates syntax without kernel modification
    FirewallController::check_syntax(&ruleset).expect("generated ruleset syntax must be valid");
}

#[test]
fn test_firewall_syntax_check_invalid_fails() {
    let bad_ruleset = "table inet umbra { invalid syntax here }}}";
    let res = FirewallController::check_syntax(bad_ruleset);
    assert!(
        matches!(res, Err(UmbraError::FirewallInstallFailed(_))),
        "Malformed ruleset must fail syntax validation"
    );
}

#[test]
fn test_firewall_authenticate_ruleset_text() {
    // Valid text containing ownership marker
    let valid_text = format!("table inet umbra {{ comment \"{}\"; }}", OWNERSHIP_MARKER);
    assert!(FirewallController::authenticate_ruleset_text(&valid_text).is_ok());

    // Missing marker
    let missing_marker = "table inet umbra { comment \"other-tool\"; }";
    let res = FirewallController::authenticate_ruleset_text(missing_marker);
    assert!(matches!(res, Err(UmbraError::FirewallOwnershipUnknown(_))));

    // Empty text
    let empty_text = "   \n\t  ";
    let res = FirewallController::authenticate_ruleset_text(empty_text);
    assert!(matches!(res, Err(UmbraError::FirewallOwnershipUnknown(_))));
}

#[test]
fn test_firewall_rule_generation_custom_parameters() {
    let config = FirewallConfig {
        table_name: "custom_umbra".to_string(),
        table_family: "inet".to_string(),
        tor_uid: 999,
        tor_transport_port: 9099,
        tor_dns_port: 5399,
        tor_control_port: 9098,
        egress_interface: "wlan0".to_string(),
        activation_id: "act_custom".to_string(),
    };

    let ruleset = FirewallController::generate_ruleset(&config);
    assert!(ruleset.contains("table inet custom_umbra"));
    assert!(ruleset.contains("skuid 999 return"));
    assert!(ruleset.contains("redirect to :5399"));
    assert!(ruleset.contains("redirect to :9099"));
    assert!(ruleset.contains("tcp dport 9098 accept"));

    // Syntax validation of custom ruleset
    FirewallController::check_syntax(&ruleset).expect("custom ruleset syntax must be valid");
}
