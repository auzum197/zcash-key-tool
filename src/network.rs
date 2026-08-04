//! Which Zcash network a derivation targets. Ours rather than
//! `zcash_protocol`'s, whose `Network` carries no regtest variant.

use zcash_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Main,
    Test,
    Regtest,
}

impl Network {
    pub const ALL: [Self; 3] = [Self::Main, Self::Test, Self::Regtest];

    pub fn label(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Test => "test",
            Self::Regtest => "regtest",
        }
    }
}

impl Parameters for Network {
    fn network_type(&self) -> NetworkType {
        match self {
            Self::Main => NetworkType::Main,
            Self::Test => NetworkType::Test,
            Self::Regtest => NetworkType::Regtest,
        }
    }

    // offline tool: no chain, no heights
    fn activation_height(&self, _: NetworkUpgrade) -> Option<BlockHeight> {
        None
    }
}
