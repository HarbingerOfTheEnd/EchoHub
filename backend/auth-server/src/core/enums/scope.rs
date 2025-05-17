use std::{collections::HashMap, sync::Once};

use once_cell::sync::Lazy;

pub struct Scope;

impl Scope {
    pub const USER: i64 = 1;
    pub const BOT: i64 = 1 << 1;
    pub const IDENTITY_READ: i64 = 1 << 2;
    pub const GUILDS_READ: i64 = 1 << 3;
    pub const GUILDS_JOIN: i64 = 1 << 4;
    pub const GUILDS_MEMBER_READ: i64 = 1 << 5;

    pub fn bitfield_from_scopes(scopes: &[&str]) -> i64 {
        scopes
            .iter()
            .filter_map(|s| Self::scope_value_map().get(*s))
            .sum()
    }

    pub fn scopes_from_bitfield(bitfield: i64) -> Vec<&'static str> {
        Self::scope_value_map()
            .iter()
            .filter_map(|(name, val)| {
                if (bitfield & val) == *val {
                    Some(*name)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn grants_all(bitfield: i64, scopes: &[i64]) -> bool {
        scopes.iter().all(|s| (bitfield & *s) == *s)
    }

    pub fn grants_any(bitfield: i64, scopes: &[i64]) -> bool {
        scopes.iter().any(|s| (bitfield & *s) == *s)
    }

    fn scope_value_map() -> &'static HashMap<&'static str, i64> {
        static MAP: Lazy<HashMap<&'static str, i64>> = Lazy::new(|| {
            let mut m = HashMap::new();
            m.insert("user", Scope::USER);
            m.insert("bot", Scope::BOT);
            m.insert("identity.read", Scope::IDENTITY_READ);
            m.insert("guilds.read", Scope::GUILDS_READ);
            m.insert("guilds.join", Scope::GUILDS_JOIN);
            m.insert("guilds.member.read", Scope::GUILDS_MEMBER_READ);
            m
        });
        &MAP
    }
}
