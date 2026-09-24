use umbra::dns::DnsController;

#[test]
fn test_read_configured_nameservers() {
    let servers = DnsController::read_configured_nameservers();
    // In Linux environments with /etc/resolv.conf, this should not panic
    println!("Discovered nameservers: {servers:?}");
}
