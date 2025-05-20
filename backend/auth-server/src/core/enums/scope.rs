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
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitfield_from_scopes_single() {
        assert_eq!(Scope::bitfield_from_scopes(&["user"]), Scope::USER);
        assert_eq!(Scope::bitfield_from_scopes(&["bot"]), Scope::BOT);
        assert_eq!(
            Scope::bitfield_from_scopes(&["identity.read"]),
            Scope::IDENTITY_READ
        );
        assert_eq!(
            Scope::bitfield_from_scopes(&["guilds.read"]),
            Scope::GUILDS_READ
        );
        assert_eq!(
            Scope::bitfield_from_scopes(&["guilds.join"]),
            Scope::GUILDS_JOIN
        );
        assert_eq!(
            Scope::bitfield_from_scopes(&["guilds.member.read"]),
            Scope::GUILDS_MEMBER_READ
        );
    }

    #[test]
    fn test_bitfield_from_scopes_multiple() {
        let scopes = ["user", "bot", "guilds.read"];
        let expected = Scope::USER | Scope::BOT | Scope::GUILDS_READ;
        assert_eq!(Scope::bitfield_from_scopes(&scopes), expected);
    }

    #[test]
    fn test_bitfield_from_scopes_invalid() {
        let scopes = ["invalid", "user"];
        assert_eq!(Scope::bitfield_from_scopes(&scopes), Scope::USER);
    }

    #[test]
    fn test_scopes_from_bitfield_single() {
        let bitfield = Scope::BOT;
        let scopes = Scope::scopes_from_bitfield(bitfield);
        assert_eq!(scopes, vec!["bot"]);
    }

    #[test]
    fn test_scopes_from_bitfield_multiple() {
        let bitfield = Scope::USER | Scope::IDENTITY_READ | Scope::GUILDS_JOIN;
        let mut scopes = Scope::scopes_from_bitfield(bitfield);
        scopes.sort();
        let mut expected = vec!["user", "identity.read", "guilds.join"];
        expected.sort();
        assert_eq!(scopes, expected);
    }

    #[test]
    fn test_scopes_from_bitfield_none() {
        let bitfield = 0;
        let scopes = Scope::scopes_from_bitfield(bitfield);
        assert!(scopes.is_empty());
    }

    #[test]
    fn test_grants_all_true() {
        let bitfield = Scope::USER | Scope::BOT | Scope::GUILDS_READ;
        let scopes = [Scope::USER, Scope::BOT];
        assert!(Scope::grants_all(bitfield, &scopes));
    }

    #[test]
    fn test_grants_all_false() {
        let bitfield = Scope::USER | Scope::BOT;
        let scopes = [Scope::USER, Scope::GUILDS_READ];
        assert!(!Scope::grants_all(bitfield, &scopes));
    }

    #[test]
    fn test_grants_any_true() {
        let bitfield = Scope::USER | Scope::BOT;
        let scopes = [Scope::GUILDS_READ, Scope::BOT];
        assert!(Scope::grants_any(bitfield, &scopes));
    }

    #[test]
    fn test_grants_any_false() {
        let bitfield = Scope::USER;
        let scopes = [Scope::BOT, Scope::GUILDS_READ];
        assert!(!Scope::grants_any(bitfield, &scopes));
    }

    #[test]
    fn test_scope_value_map_contents() {
        let map = Scope::scope_value_map();
        assert_eq!(map.get("user"), Some(&Scope::USER));
        assert_eq!(map.get("bot"), Some(&Scope::BOT));
        assert_eq!(map.get("identity.read"), Some(&Scope::IDENTITY_READ));
        assert_eq!(map.get("guilds.read"), Some(&Scope::GUILDS_READ));
        assert_eq!(map.get("guilds.join"), Some(&Scope::GUILDS_JOIN));
        assert_eq!(
            map.get("guilds.member.read"),
            Some(&Scope::GUILDS_MEMBER_READ)
        );
        assert!(map.get("invalid").is_none());
    }
}
