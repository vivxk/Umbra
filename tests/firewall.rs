use umbra::constants::{NFT_TABLE_FAMILY, NFT_TABLE_NAME, OWNERSHIP_MARKER};
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

    // Redirections
    assert!(ruleset.contains("udp dport 53 redirect to :5353"));
    assert!(ruleset.contains("tcp dport != 9040 redirect to :9040"));

    // DNS leak prevention (TCP reset)
    assert!(ruleset.contains("tcp dport 53 reject with tcp reset"));

    // Fail-closed drops
    assert!(ruleset.contains("meta l4proto udp drop"));
    assert!(ruleset.contains("ip6 daddr != ::1 drop"));
}
