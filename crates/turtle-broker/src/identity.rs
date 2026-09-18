//! Per-instance transport binding. Caller-supplied Turtle IDs are not authority.

use getrandom::fill;
use hex::encode;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceBinding {
    pub instance_id: String,
    pub secret: [u8; 32],
}

pub fn mint_instance_binding() -> InstanceBinding {
    let mut id = [0u8; 16];
    let mut secret = [0u8; 32];
    fill(&mut id).expect("getrandom");
    fill(&mut secret).expect("getrandom");
    InstanceBinding {
        instance_id: encode(id),
        secret,
    }
}

pub fn presented_secret_matches(binding: &InstanceBinding, presented: &[u8]) -> bool {
    presented.len() == binding.secret.len() && presented == binding.secret.as_slice()
}
