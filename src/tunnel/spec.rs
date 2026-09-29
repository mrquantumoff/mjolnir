//! Command-line forms: `[BIND:]PORT:HOST:HOSTPORT` forward specs, `HOST:PORT`
//! endpoints, and the permit patterns that limit what a key may open or
//! listen on.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail, ensure};

use crate::keys::{AuthorizedKey, PublicKey};

/// A host name or address and a port. IPv6 addresses print in brackets.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl FromStr for HostPort {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let parts = split_fields(s)?;
        let [host, port] =
            <[String; 2]>::try_from(parts).map_err(|_| anyhow!("{s:?} is not HOST:PORT"))?;
        ensure!(!host.is_empty(), "{s:?} has an empty host");
        Ok(HostPort {
            host,
            port: parse_port(&port)?,
        })
    }
}

/// Splits on `:` outside square brackets and drops the brackets, so
/// `[::1]:80` is `["::1", "80"]`.
fn split_fields(s: &str) -> Result<Vec<String>> {
    let mut fields = vec![String::new()];
    let mut bracket = false;
    for c in s.chars() {
        match c {
            '[' if !bracket => bracket = true,
            ']' if bracket => bracket = false,
            ':' if !bracket => fields.push(String::new()),
            '[' | ']' => bail!("unbalanced brackets in {s:?}"),
            c => fields.last_mut().unwrap().push(c),
        }
    }
    ensure!(!bracket, "unbalanced brackets in {s:?}");
    Ok(fields)
}

fn parse_port(s: &str) -> Result<u16> {
    s.parse()
        .with_context(|| format!("{s:?} is not a port number"))
}

/// Where a forward listens when its spec names no bind address.
pub const DEFAULT_BIND: &str = "127.0.0.1";

/// `[BIND:]PORT:HOST:HOSTPORT`, as in `ssh -L` and `ssh -R`. An empty or `*`
/// bind address means every interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardSpec {
    pub listen: HostPort,
    pub target: HostPort,
}

impl FromStr for ForwardSpec {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let fields = split_fields(s)?;
        let (bind, port, host, hostport) = match fields.as_slice() {
            [port, host, hostport] => (DEFAULT_BIND, port, host, hostport),
            [bind, port, host, hostport] => {
                let bind = match bind.as_str() {
                    "" | "*" => "0.0.0.0",
                    other => other,
                };
                (bind, port, host, hostport)
            }
            _ => bail!("{s:?} is not [BIND:]PORT:HOST:HOSTPORT"),
        };
        ensure!(!host.is_empty(), "{s:?} has an empty target host");
        Ok(ForwardSpec {
            listen: HostPort {
                host: bind.to_string(),
                port: parse_port(port)?,
            },
            target: HostPort {
                host: host.clone(),
                port: parse_port(hostport)?,
            },
        })
    }
}

impl fmt::Display for ForwardSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.listen, self.target)
    }
}

/// `HOST:PORT` where either side may be `*`. Hosts compare as written,
/// ignoring ASCII case: `localhost` does not match `127.0.0.1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    host: Option<String>,
    port: Option<u16>,
}

impl FromStr for Pattern {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        if s == "*" {
            return Ok(Pattern {
                host: None,
                port: None,
            });
        }
        let fields = split_fields(s)?;
        let [host, port] =
            <[String; 2]>::try_from(fields).map_err(|_| anyhow!("{s:?} is not HOST:PORT"))?;
        ensure!(!host.is_empty(), "{s:?} has an empty host");
        Ok(Pattern {
            host: (host != "*").then(|| host.to_ascii_lowercase()),
            port: match port.as_str() {
                "*" => None,
                p => Some(parse_port(p)?),
            },
        })
    }
}

impl Pattern {
    pub fn matches(&self, hp: &HostPort) -> bool {
        self.host
            .as_ref()
            .is_none_or(|h| h.eq_ignore_ascii_case(&hp.host))
            && self.port.is_none_or(|p| p == hp.port)
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = self.host.as_deref().unwrap_or("*");
        let port = self.port.map_or("*".to_string(), |p| p.to_string());
        if host.contains(':') {
            write!(f, "[{host}]:{port}")
        } else {
            write!(f, "{host}:{port}")
        }
    }
}

/// What one client key may do: open connections to (`-L`), and listen on
/// the server (`-R`). Empty lists allow nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Permits {
    pub open: Vec<Pattern>,
    pub listen: Vec<Pattern>,
}

impl Permits {
    pub fn may_open(&self, target: &HostPort) -> bool {
        self.open.iter().any(|p| p.matches(target))
    }

    pub fn may_listen(&self, bind: &HostPort) -> bool {
        self.listen.iter().any(|p| p.matches(bind))
    }
}

/// The server's authorized keys and what each may do. A key whose
/// authorized-keys line carries `permitopen` or `permitlisten` options gets
/// exactly those; every other key gets the server-wide defaults.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    keys: Vec<PublicKey>,
    own: HashMap<PublicKey, Permits>,
    default: Permits,
}

impl Policy {
    pub fn new(entries: &[AuthorizedKey], default: Permits) -> Result<Self> {
        let mut policy = Policy {
            keys: Vec::new(),
            own: HashMap::new(),
            default,
        };
        for entry in entries {
            if !policy.keys.contains(&entry.key) {
                policy.keys.push(entry.key);
            }
            if entry.options.is_empty() {
                continue;
            }
            let own = policy.own.entry(entry.key).or_default();
            for (name, value) in &entry.options {
                let pattern = value
                    .parse()
                    .with_context(|| format!("{name}={value:?} for key {}", entry.key))?;
                match name.as_str() {
                    "permitopen" => own.open.push(pattern),
                    "permitlisten" => own.listen.push(pattern),
                    other => bail!("unknown key option {other:?}"),
                }
            }
        }
        Ok(policy)
    }

    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }

    pub fn for_key(&self, key: &PublicKey) -> &Permits {
        self.own.get(key).unwrap_or(&self.default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::PrivateKey;

    fn hp(host: &str, port: u16) -> HostPort {
        HostPort {
            host: host.into(),
            port,
        }
    }

    #[test]
    fn forward_specs() {
        let spec: ForwardSpec = "8080:db.internal:5432".parse().unwrap();
        assert_eq!(spec.listen, hp("127.0.0.1", 8080));
        assert_eq!(spec.target, hp("db.internal", 5432));
        let spec: ForwardSpec = "*:80:[::1]:8080".parse().unwrap();
        assert_eq!(spec.listen, hp("0.0.0.0", 80));
        assert_eq!(spec.target, hp("::1", 8080));
        let spec: ForwardSpec = "[::1]:80:web:80".parse().unwrap();
        assert_eq!(spec.listen, hp("::1", 80));
        assert_eq!(spec.to_string(), "[::1]:80 -> web:80");
        for bad in [
            "80:web",
            "a:80:web:80:1",
            "x:web:80",
            "80::80",
            "[::1:80:web:80",
        ] {
            assert!(bad.parse::<ForwardSpec>().is_err(), "{bad}");
        }
    }

    #[test]
    fn host_ports() {
        assert_eq!("web:80".parse::<HostPort>().unwrap(), hp("web", 80));
        assert_eq!(
            "[fe80::1]:22".parse::<HostPort>().unwrap(),
            hp("fe80::1", 22)
        );
        assert_eq!(hp("fe80::1", 22).to_string(), "[fe80::1]:22");
        assert!("web".parse::<HostPort>().is_err());
        assert!(":80".parse::<HostPort>().is_err());
        assert!("web:99999".parse::<HostPort>().is_err());
    }

    #[test]
    fn patterns() {
        let p: Pattern = "DB:5432".parse().unwrap();
        assert!(p.matches(&hp("db", 5432)));
        assert!(!p.matches(&hp("db", 5433)));
        assert!(!p.matches(&hp("db.internal", 5432)));
        let any_port: Pattern = "localhost:*".parse().unwrap();
        assert!(any_port.matches(&hp("localhost", 1)));
        assert!(!any_port.matches(&hp("127.0.0.1", 1)));
        let any_host: Pattern = "*:22".parse().unwrap();
        assert!(any_host.matches(&hp("anything", 22)));
        let all: Pattern = "*".parse().unwrap();
        assert!(all.matches(&hp("x", 9)));
        assert_eq!(all.to_string(), "*:*");
        let v6: Pattern = "[::1]:22".parse().unwrap();
        assert!(v6.matches(&hp("::1", 22)));
        assert!("db".parse::<Pattern>().is_err());
    }

    #[test]
    fn per_key_options_replace_the_defaults() {
        let (a, b) = (
            PrivateKey::generate().public_key(),
            PrivateKey::generate().public_key(),
        );
        let entries = vec![
            AuthorizedKey {
                key: a,
                options: vec![("permitlisten".into(), "127.0.0.1:9000".into())],
            },
            AuthorizedKey {
                key: b,
                options: vec![],
            },
        ];
        let default = Permits {
            open: vec!["db:5432".parse().unwrap()],
            listen: vec![],
        };
        let policy = Policy::new(&entries, default).unwrap();
        assert_eq!(policy.keys(), &[a, b]);
        assert!(!policy.for_key(&a).may_open(&hp("db", 5432)));
        assert!(policy.for_key(&a).may_listen(&hp("127.0.0.1", 9000)));
        assert!(policy.for_key(&b).may_open(&hp("db", 5432)));
        assert!(!policy.for_key(&b).may_listen(&hp("127.0.0.1", 9000)));
    }
}
