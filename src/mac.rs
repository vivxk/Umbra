//! MAC address generation, validation, and manipulation utilities.

use std::fmt;
use std::fs::File;
use std::io::Read;

use crate::error::{Result, UmbraError};

/// 6-byte IEEE 802 MAC address
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub fn bytes(&self) -> [u8; 6] {
        self.0
    }

    /// Checks if the MAC address is unicast (multicast bit, LSB of octet 0, is 0)
    pub fn is_unicast(&self) -> bool {
        (self.0[0] & 0x01) == 0
    }

    /// Checks if the MAC address is locally administered (U/L bit, bit 1 of octet 0, is 1)
    pub fn is_locally_administered(&self) -> bool {
        (self.0[0] & 0x02) == 0x02
    }

    /// Checks if the MAC address is valid for randomization (unicast, locally administered, not all zero)
    pub fn is_valid_randomized(&self) -> bool {
        self.is_unicast() && self.is_locally_administered() && self.0 != [0; 6]
    }

    /// Generates a cryptographically random, unicast, locally administered MAC address.
    /// Reads entropy directly from Linux /dev/urandom.
    pub fn generate_random() -> Result<Self> {
        let mut file = File::open("/dev/urandom").map_err(|e| {
            UmbraError::MacGenerationFailed(format!("failed to open /dev/urandom: {e}"))
        })?;

        let mut bytes = [0u8; 6];
        file.read_exact(&mut bytes).map_err(|e| {
            UmbraError::MacGenerationFailed(format!("failed to read /dev/urandom: {e}"))
        })?;

        // Enforce locally administered (bit 1 = 1) and unicast (bit 0 = 0)
        bytes[0] = (bytes[0] | 0x02) & 0xFE;

        let mac = Self(bytes);
        if !mac.is_valid_randomized() {
            return Err(UmbraError::MacGenerationFailed(
                "generated MAC failed invariant checks".to_string(),
            ));
        }

        Ok(mac)
    }

    /// Parses a MAC address from string formats: "aa:bb:cc:dd:ee:ff" or "aa-bb-cc-dd-ee-ff"
    pub fn parse(s: &str) -> Result<Self> {
        let clean = s.trim();
        let parts: Vec<&str> = if clean.contains(':') {
            clean.split(':').collect()
        } else if clean.contains('-') {
            clean.split('-').collect()
        } else {
            return Err(UmbraError::InvalidMacAddress(format!(
                "invalid MAC delimiter in '{clean}'"
            )));
        };

        if parts.len() != 6 {
            return Err(UmbraError::InvalidMacAddress(format!(
                "expected 6 octets, got {} in '{clean}'",
                parts.len()
            )));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            if part.len() != 2 {
                return Err(UmbraError::InvalidMacAddress(format!(
                    "invalid octet length '{part}' in '{clean}'"
                )));
            }
            bytes[i] = u8::from_str_radix(part, 16).map_err(|_| {
                UmbraError::InvalidMacAddress(format!("invalid hex in octet '{part}' in '{clean}'"))
            })?;
        }

        Ok(Self(bytes))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddress({})", self)
    }
}
