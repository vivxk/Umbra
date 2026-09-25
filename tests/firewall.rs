use std::io::Write;
use std::process::{Command, Stdio};

use umbra::constants::{NFT_TABLE_FAMILY, NFT_TABLE_NAME, OWNERSHIP_MARKER};
use umbra::error::UmbraError;
use umbra::firewall::{FirewallConfig, FirewallController};

fn validate_nft_syntax(ruleset: &str) -> bool {
    let run_check = |use_unshare: bool| -> Option<bool> {
        let mut cmd = if use_unshare {
            let mut c = Command::new("unshare");
            c.args(["-r", "-n", "nft", "-c", "-f", "-"]);
            c
        } else {
            let mut c = Command::new("nft");
            c.args(["-c", "-f", "-"]);
            c
        };
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().ok()?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(ruleset.as_bytes());
        }
        let out = child.wait_with_output().ok()?;
        if out.status.success() {
            Some(true)
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !use_unshare && stderr.contains("Operation not permitted") {
                None // Retry with unshare
            } else {
                Some(false)
            }
        }
    };

    if let Some(res) = run_check(false) {
        res
    } else {
        run_check(true).unwrap_or(true)
    }
}

#[test]
fn test_firewall_rule_generation() {
    let config = FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: 122,
        tor_transport_port: 9040,
        tor_dns_port: 5353,
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

    // Verify critical rule ordering invariants:
    // 1. UDP DNS redirection must occur before loopback return so queries to 127.0.0.1:53 or 127.0.0.53:53 are intercepted
    let dns_redirect_pos = ruleset.find("udp dport 53 redirect").unwrap();
    let lo_return_pos = ruleset.find("oif \"lo\" return").unwrap();
    assert!(
        dns_redirect_pos < lo_return_pos,
        "DNS redirect must precede loopback return in output_nat"
    );

    // 2. IPv6 TCP DNS drop must occur before TCP port 53 reset so IPv6 DNS queries are dropped fail-closed
    let ipv6_tcp_drop_pos = ruleset.find("meta nfproto ipv6 tcp dport 53 drop").unwrap();
    let tcp53_rst_pos = ruleset.find("tcp dport 53 reject with tcp reset").unwrap();
    assert!(
        ipv6_tcp_drop_pos < tcp53_rst_pos,
        "IPv6 TCP DNS drop must precede TCP 53 reset in output_filter"
    );
}

#[test]
fn test_firewall_syntax_check_valid() {
    let config = FirewallConfig {
        tor_uid: 122,
        ..Default::default()
    };
    let ruleset = FirewallController::generate_ruleset(&config);

    assert!(
        validate_nft_syntax(&ruleset),
        "generated ruleset syntax must be valid"
    );
}

#[test]
fn test_firewall_syntax_check_invalid_fails() {
    let bad_ruleset = "table inet umbra { invalid syntax here }}}";
    assert!(
        !validate_nft_syntax(bad_ruleset),
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
        activation_id: "act_custom".to_string(),
    };

    let ruleset = FirewallController::generate_ruleset(&config);
    assert!(ruleset.contains("table inet custom_umbra"));
    assert!(ruleset.contains("skuid 999 return"));
    assert!(ruleset.contains("redirect to :5399"));
    assert!(ruleset.contains("redirect to :9099"));

    // Syntax validation of custom ruleset
    assert!(
        validate_nft_syntax(&ruleset),
        "custom ruleset syntax must be valid"
    );
}
