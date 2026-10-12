//! Receive credit, distinct from send buffering and operating-system socket buffers.

/// Enough credit for a single long-lived CONNECT-IP stream on a high-RTT link.
pub(crate) const RECEIVE_WINDOW: u32 = 32 * 1024 * 1024;

#[cfg(feature = "server")]
use std::sync::Arc;
#[cfg(feature = "server")]
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[cfg(feature = "server")]
const BASE_WINDOW: u32 = 65_535;
#[cfg(feature = "server")]
const CREDIT_UNIT: u32 = 64 * 1024;
#[cfg(feature = "server")]
const EXTRA_CREDIT_BUDGET: u32 = 128 * 1024 * 1024;

/// Shared by all clones of one server; reserves credit, not actual allocations.
#[cfg(feature = "server")]
pub(crate) struct ReceiveBudget(Arc<Semaphore>);

#[cfg(feature = "server")]
pub(crate) struct ReceiveCredit {
    _permit: Option<OwnedSemaphorePermit>,
    pub(crate) window: u32,
}

#[cfg(feature = "server")]
impl ReceiveBudget {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Semaphore::new(
            (EXTRA_CREDIT_BUDGET / CREDIT_UNIT) as usize,
        )))
    }

    pub(crate) fn reserve(&self) -> ReceiveCredit {
        // Do not wait for a different carrier to exit. A busy pool reduces this
        // carrier's credit instead of introducing another connection limit.
        let mut units = RECEIVE_WINDOW / CREDIT_UNIT;
        while units != 0 {
            if let Ok(permit) = self.0.clone().try_acquire_many_owned(units) {
                return ReceiveCredit {
                    _permit: Some(permit),
                    window: BASE_WINDOW + units * CREDIT_UNIT,
                };
            }
            units /= 2;
        }
        ReceiveCredit {
            _permit: None,
            window: BASE_WINDOW,
        }
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

    #[test]
    fn exhaustion_preserves_base_credit_and_teardown_restores_budget() {
        let budget = ReceiveBudget::new();
        let mut credits: Vec<_> = (0..128).map(|_| budget.reserve()).collect();
        let total_extra: u32 = credits.iter().map(|c| c.window - BASE_WINDOW).sum();
        assert_eq!(total_extra, EXTRA_CREDIT_BUDGET);
        assert_eq!(
            credits[(EXTRA_CREDIT_BUDGET / RECEIVE_WINDOW) as usize].window,
            BASE_WINDOW
        );
        assert_eq!(budget.0.available_permits(), 0);

        drop(credits.remove(0));
        let replacement = budget.reserve();
        assert_eq!(replacement.window, BASE_WINDOW + RECEIVE_WINDOW);
        assert_eq!(budget.0.available_permits(), 0);
        drop(replacement);
        drop(credits);
        assert_eq!(
            budget.0.available_permits(),
            (EXTRA_CREDIT_BUDGET / CREDIT_UNIT) as usize
        );
    }

    #[test]
    fn concurrent_reservations_never_exceed_shared_budget() {
        let budget = Arc::new(ReceiveBudget::new());
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let budget = budget.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    budget.reserve()
                })
            })
            .collect();
        let credits: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
        let total_extra: u32 = credits.iter().map(|c| c.window - BASE_WINDOW).sum();
        assert!(total_extra <= EXTRA_CREDIT_BUDGET);
        assert!(
            credits
                .iter()
                .all(|c| c.window <= BASE_WINDOW + RECEIVE_WINDOW)
        );
        drop(credits);
        assert_eq!(
            budget.0.available_permits(),
            (EXTRA_CREDIT_BUDGET / CREDIT_UNIT) as usize
        );
    }
}
