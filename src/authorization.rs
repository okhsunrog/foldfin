//! Application-owned access decisions. The protocol never reads users, plans or a database.
use crate::{credential::Credential, server::VpnConfig};
use std::{future::Future, pin::Pin, sync::Arc, time::Instant};
use subtle::ConstantTimeEq;
use tokio::sync::{Semaphore, watch};

#[derive(Clone, Debug)]
pub enum RequestedMode {
    Tcp { target: String },
    Ip,
}

pub struct AccessRequest {
    pub mode: RequestedMode,
    authorization: http::HeaderValue,
}
impl AccessRequest {
    pub(crate) fn new(mode: RequestedMode, authorization: http::HeaderValue) -> Self {
        Self {
            mode,
            authorization,
        }
    }
    /// Secret header; implementations must not log it. TLS is already established.
    pub fn authorization(&self) -> &[u8] {
        self.authorization.as_bytes()
    }
}
impl std::fmt::Debug for AccessRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessRequest")
            .field("mode", &self.mode)
            .field("authorization", &"[REDACTED]")
            .finish()
    }
}

/// Shared grant lifetime. Renewing an active deadline preserves open flows;
/// revocation or loss of the sender cancels them. Never revive a revoked/expired lease.
#[derive(Clone, Debug)]
pub enum LeaseState {
    Active { expires_at: Option<Instant> },
    Revoked,
}
#[derive(Clone)]
pub struct AccessLease(watch::Receiver<LeaseState>);
impl AccessLease {
    pub fn new(expires_at: Option<Instant>) -> (watch::Sender<LeaseState>, Self) {
        let (sender, receiver) = watch::channel(LeaseState::Active { expires_at });
        (sender, Self(receiver))
    }
    pub fn valid(&self) -> bool {
        if self.0.has_changed().is_err() {
            return false;
        }
        match *self.0.borrow() {
            LeaseState::Active { expires_at } => {
                expires_at.is_none_or(|deadline| Instant::now() < deadline)
            }
            LeaseState::Revoked => false,
        }
    }
    async fn cancelled(&mut self) {
        loop {
            if !self.valid() {
                return;
            }
            let deadline = match *self.0.borrow_and_update() {
                LeaseState::Active { expires_at } => expires_at,
                LeaseState::Revoked => return,
            };
            tokio::select! {
                result = self.0.changed() => { if result.is_err() { return; } }
                _ = async {
                    if let Some(deadline) = deadline { tokio::time::sleep_until(deadline.into()).await; }
                    else { std::future::pending::<()>().await; }
                } => (),
            }
        }
    }
}

#[derive(Clone)]
pub struct AccessGrant {
    pub proxy: bool,
    pub allow_private: bool,
    pub vpn: Option<VpnConfig>,
    pub vpn_slots: Arc<Semaphore>,
    pub lease: AccessLease,
    /// Optional per-session lifetime, independent of device credential revocation.
    pub session: Option<AccessLease>,
}
impl AccessGrant {
    pub fn valid(&self) -> bool {
        self.lease.valid() && self.session.as_ref().is_none_or(AccessLease::valid)
    }
    pub(crate) async fn cancelled(&mut self) {
        tokio::select! {
            _ = self.lease.cancelled() => (),
            _ = async { if let Some(session) = &mut self.session { session.cancelled().await; }
                else { std::future::pending::<()>().await; } } => (),
        }
    }
}

pub trait Authorizer: Send + Sync {
    /// None denies access; errors fail closed. Called for every CONNECT, including reused carriers.
    fn authorize(
        &self,
        request: AccessRequest,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<Option<AccessGrant>>> + Send + '_>>;
}

pub(crate) struct StaticAuthorizer {
    pub credential: Credential,
    pub grant: AccessGrant,
    pub _keepalive: watch::Sender<LeaseState>,
}
impl Authorizer for StaticAuthorizer {
    fn authorize(
        &self,
        request: AccessRequest,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<Option<AccessGrant>>> + Send + '_>> {
        Box::pin(async move {
            Ok(bool::from(
                request
                    .authorization()
                    .ct_eq(self.credential.header().as_bytes()),
            )
            .then(|| self.grant.clone()))
        })
    }
}
