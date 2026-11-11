//! Outbound HTTP with SSRF protection.
//!
//! SCIM base URLs are entered by customers, so every outbound connection is checked: the
//! host must resolve only to public addresses (checked at connect time, which also defeats
//! DNS rebinding), redirects are not followed and plain HTTP is refused outside dev mode.

use anyhow::{anyhow, bail, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
struct PublicOnlyResolver {
    allow_private: bool,
}

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow_private = self.allow_private;
        Box::pin(async move {
            let host = name.as_str().to_string();
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| allow_private || is_public(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!("{host} does not resolve to a public address").into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            let seg0 = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg0 & 0xfe00) == 0xfc00 // unique local
                || (seg0 & 0xffc0) == 0xfe80 // link local
                || v6 == Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0))
        }
    }
}

fn is_public_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    !(v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // carrier-grade NAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking
        || o[0] >= 240)
}

/// Validates a customer-supplied base URL and returns it normalised (no trailing slash).
pub fn validate_base_url(raw: &str, dev_mode: bool) -> Result<String> {
    let url = url::Url::parse(raw.trim()).map_err(|_| anyhow!("Enter a full URL, for example https://example.com/scim/v2"))?;
    match url.scheme() {
        "https" => {}
        "http" if dev_mode => {}
        _ => bail!("The URL must start with https://"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("Put credentials in the token field, not in the URL");
    }
    let host = url.host_str().ok_or_else(|| anyhow!("The URL has no host"))?;
    if !dev_mode {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            if !is_public(ip) {
                bail!("The URL points to a private network address");
            }
        }
        if host.eq_ignore_ascii_case("localhost") || host.ends_with(".internal") || host.ends_with(".local") {
            bail!("The URL points to a private host");
        }
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("The URL should not contain ? or #");
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

pub fn outbound_client(dev_mode: bool) -> reqwest::Client {
    reqwest::Client::builder()
        .dns_resolver(Arc::new(PublicOnlyResolver { allow_private: dev_mode }))
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!dev_mode)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("AppDoorman/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("http client")
}

/// Client for Google and Stripe APIs (fixed, trusted hosts).
pub fn trusted_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("AppDoorman/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("http client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_private_targets() {
        assert!(!is_public("127.0.0.1".parse().unwrap()));
        assert!(!is_public("10.1.2.3".parse().unwrap()));
        assert!(!is_public("169.254.169.254".parse().unwrap()));
        assert!(!is_public("::1".parse().unwrap()));
        assert!(!is_public("::ffff:192.168.1.1".parse().unwrap()));
        assert!(!is_public("fd00::1".parse().unwrap()));
        assert!(is_public("8.8.8.8".parse().unwrap()));
        assert!(validate_base_url("https://169.254.169.254/latest", false).is_err());
        assert!(validate_base_url("http://example.com/scim", false).is_err());
        assert!(validate_base_url("https://localhost/scim", false).is_err());
        assert_eq!(validate_base_url("https://api.example.com/scim/v2/", false).unwrap(), "https://api.example.com/scim/v2");
    }
}
