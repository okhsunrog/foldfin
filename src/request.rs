//! Validate CONNECT syntax before calling any application-owned authorization code.
use crate::authorization::RequestedMode;

pub(crate) fn validate<B>(
    request: &http::Request<B>,
    protocol: Option<&str>,
) -> Option<RequestedMode> {
    if request.method() != http::Method::CONNECT
        || request.headers().get_all("authorization").iter().count() > 1
        || ["content-length", "content-type", "transfer-encoding"]
            .iter()
            .any(|h| request.headers().contains_key(*h))
    {
        return None;
    }
    let authority = request.uri().authority()?;
    if authority.host().is_empty() || authority.as_str().contains('@') {
        return None;
    }
    match protocol {
        Some("connect-ip")
            if request.uri().scheme_str() == Some("https")
                && request.uri().path_and_query()?.as_str() == crate::vpn::PATH
                && request.headers().get_all("capsule-protocol").iter().count() == 1
                && request.headers().get("capsule-protocol")?.as_bytes() == b"?1" =>
        {
            Some(RequestedMode::Ip)
        }
        Some(_) => None,
        None if request.uri().scheme().is_none()
            && request.uri().path_and_query().is_none()
            && authority.port_u16().is_some_and(|p| p != 0) =>
        {
            Some(RequestedMode::Tcp {
                target: authority.to_string(),
            })
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_requests_before_access_decision() {
        for (uri, protocol, capsule) in [
            ("https://example.com/wrong", "connect-ip", "?1"),
            (
                "https://example.com/.well-known/masque/ip/*/*/?x",
                "connect-ip",
                "?1",
            ),
            (
                "https://example.com/.well-known/masque/ip/*/*/",
                "unknown",
                "?1",
            ),
            (
                "https://example.com/.well-known/masque/ip/*/*/",
                "connect-ip",
                "?0",
            ),
            (
                "http://example.com/.well-known/masque/ip/*/*/",
                "connect-ip",
                "?1",
            ),
        ] {
            let req = http::Request::builder()
                .method("CONNECT")
                .uri(uri)
                .header("capsule-protocol", capsule)
                .body(())
                .unwrap();
            assert!(validate(&req, Some(protocol)).is_none());
        }
        let ip = http::Request::builder()
            .method("CONNECT")
            .uri(format!("https://example.com{}", crate::vpn::PATH))
            .header("capsule-protocol", "?1")
            .body(())
            .unwrap();
        assert!(matches!(
            validate(&ip, Some("connect-ip")),
            Some(RequestedMode::Ip)
        ));
        for uri in [
            "example.com",
            "example.com:0",
            "https://example.com:443/",
            "user@example.com:443",
        ] {
            let req = http::Request::builder()
                .method("CONNECT")
                .uri(uri)
                .body(())
                .unwrap();
            assert!(validate(&req, None).is_none(), "{uri}");
        }
        let mut tcp = http::Request::builder()
            .method("CONNECT")
            .uri("example.com:443")
            .body(())
            .unwrap();
        assert!(matches!(
            validate(&tcp, None),
            Some(RequestedMode::Tcp { .. })
        ));
        tcp.headers_mut()
            .append("authorization", "one".parse().unwrap());
        tcp.headers_mut()
            .append("authorization", "two".parse().unwrap());
        assert!(validate(&tcp, None).is_none());
    }
}
