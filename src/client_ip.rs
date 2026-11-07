//! Chave do rate limit: IP do cliente (IPv6 agregado por /64).

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request};
use tower_governor::GovernorError;
use tower_governor::key_extractor::KeyExtractor;

/// Normaliza o IP: IPv4 mapeado em IPv6 vira IPv4; IPv6 é truncado no /64
/// (um cliente IPv6 costuma controlar o /64 inteiro).
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

/// IP mais à direita de `X-Forwarded-For` (o adicionado pelo proxy confiável).
pub fn rightmost_xff(headers: &HeaderMap) -> Option<IpAddr> {
    let last = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .rfind(|s| !s.is_empty())?;
    last.parse::<IpAddr>().ok()
}

/// Resolve o IP do cliente: XFF só se `trust_xff`; senão (ou se inválido) o peer TCP.
pub fn client_ip(headers: &HeaderMap, peer: Option<IpAddr>, trust_xff: bool) -> Option<IpAddr> {
    let ip = if trust_xff {
        rightmost_xff(headers).or(peer)
    } else {
        peer
    };
    ip.map(normalize)
}

#[derive(Debug, Clone, Copy)]
pub struct ClientIpKey {
    pub trust_xff: bool,
}

impl KeyExtractor for ClientIpKey {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .or_else(|| req.extensions().get::<SocketAddr>().map(|a| a.ip()));
        client_ip(req.headers(), peer, self.trust_xff).ok_or(GovernorError::UnableToExtractKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn ipv6_agregado_por_64() {
        assert_eq!(
            normalize(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd")),
            ip("2001:db8:1:2::")
        );
        assert_eq!(
            normalize(ip("2001:db8:1:2::1")),
            normalize(ip("2001:db8:1:2:ffff::9"))
        );
        assert_ne!(
            normalize(ip("2001:db8:1:2::1")),
            normalize(ip("2001:db8:1:3::1"))
        );
        assert_eq!(normalize(ip("::ffff:10.0.0.1")), ip("10.0.0.1"));
        assert_eq!(normalize(ip("10.0.0.1")), ip("10.0.0.1"));
    }

    #[test]
    fn xff_so_quando_confiavel_e_mais_a_direita() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "1.1.1.1, 2.2.2.2".parse().expect("hv"));
        let peer = Some(ip("9.9.9.9"));
        assert_eq!(client_ip(&h, peer, false), Some(ip("9.9.9.9")));
        assert_eq!(client_ip(&h, peer, true), Some(ip("2.2.2.2")));
        let mut lixo = HeaderMap::new();
        lixo.insert("x-forwarded-for", "nao-e-ip".parse().expect("hv"));
        assert_eq!(client_ip(&lixo, peer, true), Some(ip("9.9.9.9")));
    }

    #[test]
    fn extrator_usa_connect_info() {
        let mut req = Request::new(());
        req.extensions_mut().insert(ConnectInfo(SocketAddr::from((
            ip("2001:db8::abcd").to_canonical(),
            1234,
        ))));
        let key = ClientIpKey { trust_xff: false }.extract(&req).expect("key");
        assert_eq!(key, ip("2001:db8::"));
        let sem = Request::new(());
        assert!(ClientIpKey { trust_xff: false }.extract(&sem).is_err());
    }
}
