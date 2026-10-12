//! Bounded CONNECT-IP configuration capsules; addresses/routes never change the OS.
use super::{Config, encode_varint, varint};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq)]
pub struct Assignment {
    pub id: u64,
    pub prefix: IpNet,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Route {
    pub start: IpAddr,
    pub end: IpAddr,
    pub protocol: u8,
}

pub enum Event<'a> {
    Packet(&'a [u8]),
    Assign(Vec<Assignment>),
    Request(Vec<Assignment>),
    Routes(Vec<Route>),
}

fn ip(input: &mut &[u8], version: u8) -> Result<IpAddr> {
    let size = match version {
        4 => 4,
        6 => 16,
        _ => anyhow::bail!("invalid IP version in capsule"),
    };
    ensure!(input.len() >= size, "truncated capsule IP address");
    let address = if version == 4 {
        IpAddr::from(<[u8; 4]>::try_from(&input[..size])?)
    } else {
        IpAddr::from(<[u8; 16]>::try_from(&input[..size])?)
    };
    *input = &input[size..];
    Ok(address)
}

fn byte(input: &mut &[u8]) -> Result<u8> {
    let value = *input.first().context("truncated capsule field")?;
    *input = &input[1..];
    Ok(value)
}

pub fn decode(
    kind: u64,
    mut body: &[u8],
    mut event: impl FnMut(Event<'_>) -> Result<()>,
) -> Result<()> {
    match kind {
        0 => {
            let (context, size) = varint(body).context("truncated datagram context")?;
            if context == 0 {
                event(Event::Packet(&body[size..]))?;
            }
        }
        1 | 2 => {
            let mut assignments = Vec::new();
            while !body.is_empty() {
                ensure!(assignments.len() < 64, "too many capsule addresses");
                let (id, size) = varint(body).context("truncated request ID")?;
                body = &body[size..];
                ensure!(kind != 2 || id != 0, "zero ADDRESS_REQUEST ID");
                ensure!(
                    !assignments
                        .iter()
                        .any(|entry: &Assignment| entry.id == id && id != 0),
                    "duplicate address request ID"
                );
                let version = byte(&mut body)?;
                let address = ip(&mut body, version)?;
                let prefix = IpNet::new(address, byte(&mut body)?)?;
                ensure!(
                    prefix.addr() == prefix.network(),
                    "noncanonical address prefix"
                );
                assignments.push(Assignment { id, prefix });
            }
            ensure!(
                kind != 2 || !assignments.is_empty(),
                "empty ADDRESS_REQUEST"
            );
            event(if kind == 1 {
                Event::Assign(assignments)
            } else {
                Event::Request(assignments)
            })?;
        }
        3 => {
            let mut routes: Vec<Route> = Vec::new();
            while !body.is_empty() {
                ensure!(routes.len() < 64, "too many capsule routes");
                let version = byte(&mut body)?;
                let start = ip(&mut body, version)?;
                let end = ip(&mut body, version)?;
                let protocol = byte(&mut body)?;
                ensure!(start <= end, "reversed route range");
                if let Some(previous) = routes.last() {
                    let prev_version = if previous.start.is_ipv4() { 4 } else { 6 };
                    ensure!(
                        prev_version < version
                            || (prev_version == version
                                && (previous.protocol < protocol
                                    || (previous.protocol == protocol && previous.end < start))),
                        "unordered/overlapping route advertisement"
                    );
                }
                ensure!(
                    !routes.iter().any(|r| r.start.is_ipv4() == start.is_ipv4()
                        && (r.protocol == 0 || protocol == 0)
                        && r.start <= end
                        && start <= r.end),
                    "overlapping wildcard route"
                );
                routes.push(Route {
                    start,
                    end,
                    protocol,
                });
            }
            event(Event::Routes(routes))?;
        }
        _ => (),
    }
    Ok(())
}

fn put_ip(address: IpAddr, body: &mut Vec<u8>) {
    match address {
        IpAddr::V4(ip) => body.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => body.extend_from_slice(&ip.octets()),
    }
}

fn capsule(kind: usize, body: &[u8]) -> Bytes {
    let mut result = Vec::with_capacity(body.len() + 9);
    encode_varint(kind, &mut result);
    encode_varint(body.len(), &mut result);
    result.extend_from_slice(body);
    Bytes::from(result)
}

fn encode_assignments(kind: usize, assignments: &[Assignment]) -> Bytes {
    let mut body = Vec::new();
    for entry in assignments {
        // Request IDs from the wire may use the full 62-bit range.
        if entry.id < (1 << 30) {
            encode_varint(entry.id as usize, &mut body);
        } else {
            body.extend_from_slice(&(entry.id | (3 << 62)).to_be_bytes());
        }
        body.push(if entry.prefix.addr().is_ipv4() { 4 } else { 6 });
        put_ip(entry.prefix.addr(), &mut body);
        body.push(entry.prefix.prefix_len());
    }
    capsule(kind, &body)
}

pub fn assign(assignments: &[Assignment]) -> Bytes {
    encode_assignments(1, assignments)
}

pub fn advertised(config: &Config) -> Vec<Route> {
    let mut networks = config.local_routes.clone();
    networks.extend(config.local.iter().copied().map(IpNet::from));
    // Remove redundant contained prefixes, including endpoint addresses in a subnet.
    networks.sort();
    networks.dedup();
    let snapshot = networks.clone();
    networks.retain(|net| {
        !snapshot
            .iter()
            .any(|other| other != net && other.contains(net))
    });
    let mut routes: Vec<_> = networks
        .into_iter()
        .map(|prefix| Route {
            start: prefix.network(),
            end: prefix.broadcast(),
            protocol: 0,
        })
        .collect();
    routes.sort_by_key(|r| r.start);
    routes
}

pub fn advertise(config: &Config) -> Bytes {
    let mut body = Vec::new();
    for route in advertised(config) {
        body.push(if route.start.is_ipv4() { 4 } else { 6 });
        put_ip(route.start, &mut body);
        put_ip(route.end, &mut body);
        body.push(0);
    }
    capsule(3, &body)
}

#[derive(Default)]
pub struct State {
    assigned: Vec<IpNet>,
    routes: Vec<Route>,
    saw_assign: bool,
    saw_routes: bool,
    pending_requests: std::collections::HashMap<u64, IpNet>,
    issued_requests: std::collections::HashSet<u64>,
    seen_requests: std::collections::HashSet<u64>,
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn assigned(&self) -> &[IpNet] {
        &self.assigned
    }
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }
    pub fn confirmed(&self) -> bool {
        self.saw_assign && self.saw_routes
    }
    /// Register outgoing IDs before sending. This does not dynamically reconfigure host addresses.
    pub fn request(&mut self, entries: &[Assignment]) -> Result<Bytes> {
        ensure!(
            !entries.is_empty() && entries.len() <= 60,
            "invalid request count"
        );
        ensure!(
            self.issued_requests.len() + entries.len() <= 1024,
            "too many request IDs"
        );
        let mut ids = std::collections::HashSet::new();
        for entry in entries {
            ensure!(
                entry.id != 0
                    && entry.id < (1 << 62)
                    && !self.issued_requests.contains(&entry.id)
                    && ids.insert(entry.id),
                "invalid/reused request ID"
            );
        }
        let encoded = encode_assignments(2, entries);
        for entry in entries {
            self.pending_requests.insert(entry.id, entry.prefix);
            self.issued_requests.insert(entry.id);
        }
        Ok(encoded)
    }
    pub fn apply(&mut self, event: Event<'_>, config: &Config) -> Result<Option<Bytes>> {
        match event {
            Event::Assign(entries) => {
                let mut ids = std::collections::HashSet::new();
                let mut assigned = Vec::new();
                for entry in &entries {
                    if entry.id != 0 {
                        ensure!(ids.insert(entry.id), "duplicate assignment ID");
                        let requested = self
                            .pending_requests
                            .get(&entry.id)
                            .context("unsolicited/replayed assignment ID")?;
                        ensure!(
                            requested.addr().is_ipv4() == entry.prefix.addr().is_ipv4(),
                            "assignment address family mismatch"
                        );
                        if entry.prefix.addr().is_unspecified() {
                            ensure!(
                                entry.prefix.prefix_len()
                                    == if entry.prefix.addr().is_ipv4() {
                                        32
                                    } else {
                                        128
                                    },
                                "invalid denied assignment"
                            );
                            continue;
                        }
                        ensure!(
                            requested.addr().is_unspecified()
                                || requested.contains(&entry.prefix.addr()),
                            "assignment outside requested range"
                        );
                    }
                    ensure!(
                        config
                            .local
                            .iter()
                            .any(|ip| entry.prefix == IpNet::from(*ip)),
                        "assignment differs from prepared local addresses"
                    );
                    assigned.push(entry.prefix);
                }
                for id in ids {
                    self.pending_requests.remove(&id);
                }
                self.assigned = assigned;
                self.saw_assign = true;
            }
            Event::Routes(routes) => {
                ensure!(
                    routes.iter().all(|route| route.protocol == 0
                        && (config
                            .peer
                            .iter()
                            .any(|ip| route.start == *ip && route.end == *ip)
                            || config
                                .peer_routes
                                .iter()
                                .any(|prefix| prefix.contains(&route.start)
                                    && prefix.contains(&route.end)))),
                    "advertised route outside configured peer prefixes or unsupported protocol scope"
                );
                self.routes = routes;
                self.saw_routes = true;
            }
            Event::Request(entries) => {
                let mut assignments: Vec<_> = config
                    .peer
                    .iter()
                    .map(|ip| Assignment {
                        id: 0,
                        prefix: IpNet::from(*ip),
                    })
                    .collect();
                for entry in entries {
                    ensure!(
                        self.seen_requests.len() < 1024 && self.seen_requests.insert(entry.id),
                        "reused/too many ADDRESS_REQUEST IDs"
                    );
                    let candidate = config.peer.iter().find(|ip| {
                        ip.is_ipv4() == entry.prefix.addr().is_ipv4()
                            && (entry.prefix.addr().is_unspecified() || entry.prefix.contains(*ip))
                    });
                    let prefix = match candidate {
                        Some(ip) => IpNet::from(*ip),
                        None => IpNet::from(if entry.prefix.addr().is_ipv4() {
                            "0.0.0.0".parse::<IpAddr>()?
                        } else {
                            "::".parse::<IpAddr>()?
                        }),
                    };
                    assignments.retain(|a| a.prefix != prefix || a.id != 0);
                    assignments.push(Assignment {
                        id: entry.id,
                        prefix,
                    });
                }
                return Ok(Some(assign(&assignments)));
            }
            Event::Packet(_) => (),
        }
        Ok(None)
    }

    pub fn outbound(&self, config: &Config, source: IpAddr, dest: IpAddr) -> bool {
        (if config.local.contains(&source) {
            self.assigned.iter().any(|net| net.contains(&source))
        } else {
            config.local_routes.iter().any(|net| net.contains(&source))
        }) && self
            .routes
            .iter()
            .any(|r| r.start.is_ipv4() == dest.is_ipv4() && r.start <= dest && dest <= r.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            local: vec!["192.0.2.1".parse().unwrap()],
            peer: vec!["192.0.2.2".parse().unwrap()],
            local_routes: Vec::new(),
            peer_routes: vec!["198.51.100.0/24".parse().unwrap()],
        }
    }
    #[test]
    fn rfc_address_example_and_request_ids() {
        let entries = vec![Assignment {
            id: 0,
            prefix: "192.0.2.11/32".parse().unwrap(),
        }];
        assert_eq!(&assign(&entries)[..], &[1, 7, 0, 4, 192, 0, 2, 11, 32]);
        let config = config();
        let mut state = State::new();
        let request = Assignment {
            id: (1 << 40) + 7,
            prefix: "0.0.0.0/32".parse().unwrap(),
        };
        let reply = state
            .apply(Event::Request(vec![request.clone()]), &config)
            .unwrap()
            .unwrap();
        let (_, kind_len) = varint(&reply).unwrap();
        let (_, length_len) = varint(&reply[kind_len..]).unwrap();
        decode(1, &reply[kind_len + length_len..], |event| {
            if let Event::Assign(entries) = event {
                assert_eq!(
                    entries,
                    vec![Assignment {
                        id: request.id,
                        prefix: "192.0.2.2/32".parse().unwrap()
                    }]
                );
            } else {
                panic!("wrong capsule");
            }
            Ok(())
        })
        .unwrap();
        assert!(state.apply(Event::Request(vec![request]), &config).is_err());
    }
    #[test]
    fn malformed_fields_ranges_and_order() {
        for (kind, body) in [
            (1, vec![0, 4, 192, 0, 2]),
            (1, vec![0, 4, 192, 0, 2, 1, 24]),
            (2, vec![]),
            (2, vec![0, 4, 0, 0, 0, 0, 32]),
            (3, vec![4, 198, 51, 100, 8, 198, 51, 100, 1, 0]),
        ] {
            assert!(decode(kind, &body, |_| Ok(())).is_err());
        }
        let route = [4, 198, 51, 100, 0, 198, 51, 100, 255, 0];
        let mut duplicate = route.to_vec();
        duplicate.extend_from_slice(&route);
        assert!(decode(3, &duplicate, |_| Ok(())).is_err());
    }
    #[test]
    fn route_policy_and_withdrawal() {
        let config = config();
        let mut state = State::new();
        state
            .apply(
                Event::Assign(vec![Assignment {
                    id: 0,
                    prefix: IpNet::from(config.local[0]),
                }]),
                &config,
            )
            .unwrap();
        let route = Route {
            start: "198.51.100.0".parse().unwrap(),
            end: "198.51.100.255".parse().unwrap(),
            protocol: 0,
        };
        state.apply(Event::Routes(vec![route]), &config).unwrap();
        assert!(state.outbound(&config, config.local[0], "198.51.100.42".parse().unwrap()));
        assert!(!state.outbound(
            &config,
            "192.0.2.99".parse().unwrap(),
            "198.51.100.42".parse().unwrap()
        ));
        assert!(
            state
                .apply(
                    Event::Routes(vec![Route {
                        start: "0.0.0.0".parse().unwrap(),
                        end: "255.255.255.255".parse().unwrap(),
                        protocol: 0
                    }]),
                    &config
                )
                .is_err()
        );
        state.apply(Event::Routes(Vec::new()), &config).unwrap();
        assert!(!state.outbound(&config, config.local[0], "198.51.100.42".parse().unwrap()));
        let mut config = config;
        config.local_routes.push("192.0.2.0/24".parse().unwrap());
        state
            .apply(
                Event::Routes(vec![Route {
                    start: "198.51.100.0".parse().unwrap(),
                    end: "198.51.100.255".parse().unwrap(),
                    protocol: 0,
                }]),
                &config,
            )
            .unwrap();
        state.apply(Event::Assign(Vec::new()), &config).unwrap();
        assert!(!state.outbound(&config, config.local[0], "198.51.100.42".parse().unwrap()));
        assert!(state.outbound(
            &config,
            "192.0.2.42".parse().unwrap(),
            "198.51.100.42".parse().unwrap()
        ));
    }
}
#[cfg(test)]
mod request_tests {
    use super::*;
    #[test]
    fn request_reply_cycle_denial_and_replay_are_checked() {
        let client_config = Config {
            local: vec!["192.0.2.1".parse().unwrap()],
            peer: vec!["192.0.2.2".parse().unwrap()],
            local_routes: vec![],
            peer_routes: vec![],
        };
        let server_config = Config {
            local: client_config.peer.clone(),
            peer: client_config.local.clone(),
            local_routes: vec![],
            peer_routes: vec![],
        };
        let request = Assignment {
            id: (1 << 40) + 7,
            prefix: "0.0.0.0/32".parse().unwrap(),
        };
        let mut client = State::new();
        let encoded = client.request(std::slice::from_ref(&request)).unwrap();
        let mut server = State::new();
        let mut response = None;
        super::super::Decoder::default()
            .feed_events(&encoded, |event| {
                response = server.apply(event, &server_config)?;
                Ok(())
            })
            .unwrap();
        let response = response.unwrap();
        let mut decode = super::super::Decoder::default();
        decode
            .feed_events(&response, |event| {
                client.apply(event, &client_config)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(client.assigned(), &["192.0.2.1/32".parse().unwrap()]);
        assert!(
            decode
                .feed_events(&response, |event| {
                    client.apply(event, &client_config)?;
                    Ok(())
                })
                .is_err()
        );
        assert!(client.request(&[request]).is_err());
        let request = Assignment {
            id: 8,
            prefix: "0.0.0.0/32".parse().unwrap(),
        };
        client.request(&[request]).unwrap();
        assert!(
            client
                .apply(
                    Event::Assign(vec![Assignment {
                        id: 8,
                        prefix: "192.0.2.99/32".parse().unwrap()
                    }]),
                    &client_config
                )
                .is_err()
        );
        client
            .apply(
                Event::Assign(vec![Assignment {
                    id: 8,
                    prefix: "0.0.0.0/32".parse().unwrap(),
                }]),
                &client_config,
            )
            .unwrap();
        assert!(client.assigned().is_empty());
        assert!(
            client
                .apply(
                    Event::Assign(vec![Assignment {
                        id: 99,
                        prefix: "192.0.2.1/32".parse().unwrap()
                    }]),
                    &client_config
                )
                .is_err()
        );
    }
}
