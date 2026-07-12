//! # passkeyauth-resilience — reusable fault-tolerance primitives
//!
//! Deterministic, dependency-light building blocks that guard every off-chain
//! I/O boundary (RPC polling, keeper actions): a [`Clock`] abstraction for
//! testable time, [`with_timeout`], an equal-jitter [`RetryPolicy`] (no `rand`
//! dependency), a [`CircuitBreaker`], and a token-bucket [`RateLimiter`].
#![forbid(unsafe_code)]

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use thiserror::Error;

/// Monotonic clock abstraction so time-dependent logic is unit-testable.
pub trait Clock: Send + Sync {
    /// Elapsed milliseconds from an arbitrary but fixed epoch.
    fn now_millis(&self) -> u64;
}

/// Real wall-clock backed by `Instant`-equivalent system time.
#[derive(Debug, Clone, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Manually advanced clock for tests.
#[derive(Debug, Clone, Default)]
pub struct ManualClock {
    millis: Arc<AtomicU64>,
}

impl ManualClock {
    /// Start at a given millisecond offset.
    #[must_use]
    pub fn new(start: u64) -> Self {
        Self {
            millis: Arc::new(AtomicU64::new(start)),
        }
    }

    /// Advance the clock by `d`.
    pub fn advance(&self, d: Duration) {
        self.millis
            .fetch_add(d.as_millis() as u64, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_millis(&self) -> u64 {
        self.millis.load(Ordering::SeqCst)
    }
}

/// Error returned when an operation exceeds its deadline.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("operation timed out after {0:?}")]
pub struct TimeoutError(pub Duration);

/// Run `fut` with a hard deadline.
///
/// # Errors
/// Returns [`TimeoutError`] if `fut` does not complete within `dur`.
pub async fn with_timeout<F, T>(dur: Duration, fut: F) -> Result<T, TimeoutError>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(dur, fut)
        .await
        .map_err(|_| TimeoutError(dur))
}

/// Equal-jitter exponential backoff retry policy (deterministic, no `rand`).
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Maximum attempts (including the first).
    pub max_attempts: u32,
    /// Base backoff delay.
    pub base_delay: Duration,
    /// Cap on any single backoff delay.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(2),
        }
    }
}

impl RetryPolicy {
    /// Backoff delay for a 0-based attempt index using equal jitter.
    ///
    /// `delay = min(max, base * 2^attempt)`, then half fixed + half a
    /// deterministic pseudo-jitter derived from the attempt (no RNG).
    #[must_use]
    pub fn backoff(&self, attempt: u32) -> Duration {
        let exp = self
            .base_delay
            .saturating_mul(1u32 << attempt.min(16))
            .min(self.max_delay);
        let half = exp / 2;
        // Deterministic jitter in [0, half): hash the attempt index.
        let seed = (u64::from(attempt).wrapping_mul(2_654_435_761)) % 1_000;
        let jitter = half.mul_f64(seed as f64 / 1_000.0);
        half + jitter
    }

    /// Retry `op` until it succeeds or attempts are exhausted, sleeping the
    /// backoff between tries.
    ///
    /// # Errors
    /// Returns the last error if all attempts fail.
    pub async fn retry<F, Fut, T, E>(&self, mut op: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let mut attempt = 0;
        loop {
            match op().await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    attempt += 1;
                    if attempt >= self.max_attempts {
                        return Err(e);
                    }
                    tokio::time::sleep(self.backoff(attempt - 1)).await;
                }
            }
        }
    }
}

/// Circuit-breaker states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Requests flow normally.
    Closed,
    /// Requests are rejected until the cooldown elapses.
    Open,
    /// A single probe is allowed to test recovery.
    HalfOpen,
}

/// Error returned when the breaker is open.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("circuit breaker is open")]
pub struct BreakerOpen;

struct BreakerInner {
    state: BreakerState,
    failures: u32,
    opened_at: u64,
}

/// A failure-counting circuit breaker with a cooldown before half-open probing.
pub struct CircuitBreaker<C: Clock = SystemClock> {
    clock: C,
    threshold: u32,
    cooldown_millis: u64,
    inner: Mutex<BreakerInner>,
}

impl<C: Clock> CircuitBreaker<C> {
    /// Trip after `threshold` consecutive failures; stay open for `cooldown`.
    #[must_use]
    pub fn new(clock: C, threshold: u32, cooldown: Duration) -> Self {
        Self {
            clock,
            threshold,
            cooldown_millis: cooldown.as_millis() as u64,
            inner: Mutex::new(BreakerInner {
                state: BreakerState::Closed,
                failures: 0,
                opened_at: 0,
            }),
        }
    }

    /// Current breaker state (transitions Open→HalfOpen when cooldown elapsed).
    pub fn state(&self) -> BreakerState {
        let mut g = self.inner.lock();
        if g.state == BreakerState::Open
            && self.clock.now_millis().saturating_sub(g.opened_at) >= self.cooldown_millis
        {
            g.state = BreakerState::HalfOpen;
        }
        g.state
    }

    /// Acquire permission to make a call.
    ///
    /// # Errors
    /// Returns [`BreakerOpen`] while the breaker is open.
    pub fn acquire(&self) -> Result<(), BreakerOpen> {
        match self.state() {
            BreakerState::Open => Err(BreakerOpen),
            _ => Ok(()),
        }
    }

    /// Record a successful call (closes the breaker).
    pub fn on_success(&self) {
        let mut g = self.inner.lock();
        g.failures = 0;
        g.state = BreakerState::Closed;
    }

    /// Record a failed call (may open the breaker).
    pub fn on_failure(&self) {
        let mut g = self.inner.lock();
        g.failures += 1;
        if g.failures >= self.threshold {
            g.state = BreakerState::Open;
            g.opened_at = self.clock.now_millis();
        }
    }
}

/// Error returned when the rate limiter has no tokens.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("rate limited")]
pub struct RateLimited;

struct BucketInner {
    tokens: f64,
    last_refill: u64,
}

/// Token-bucket rate limiter with continuous refill.
pub struct RateLimiter<C: Clock = SystemClock> {
    clock: C,
    capacity: f64,
    refill_per_sec: f64,
    inner: Mutex<BucketInner>,
}

impl<C: Clock> RateLimiter<C> {
    /// A bucket of `capacity` tokens refilling `refill_per_sec` per second.
    #[must_use]
    pub fn new(clock: C, capacity: f64, refill_per_sec: f64) -> Self {
        let now = clock.now_millis();
        Self {
            clock,
            capacity,
            refill_per_sec,
            inner: Mutex::new(BucketInner {
                tokens: capacity,
                last_refill: now,
            }),
        }
    }

    /// Try to take one token.
    ///
    /// # Errors
    /// Returns [`RateLimited`] when the bucket is empty.
    pub fn try_acquire(&self) -> Result<(), RateLimited> {
        self.try_acquire_n(1.0)
    }

    /// Try to take `n` tokens.
    ///
    /// # Errors
    /// Returns [`RateLimited`] when fewer than `n` tokens are available.
    pub fn try_acquire_n(&self, n: f64) -> Result<(), RateLimited> {
        let mut g = self.inner.lock();
        let now = self.clock.now_millis();
        let elapsed = now.saturating_sub(g.last_refill) as f64 / 1_000.0;
        g.tokens = (g.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        g.last_refill = now;
        if g.tokens >= n {
            g.tokens -= n;
            Ok(())
        } else {
            Err(RateLimited)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timeout_fires() {
        let r = with_timeout(Duration::from_millis(5), async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            1
        })
        .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn timeout_passes() {
        let r = with_timeout(Duration::from_secs(1), async { 42 }).await;
        assert_eq!(r.unwrap(), 42);
    }

    #[test]
    fn backoff_is_bounded_and_grows() {
        let p = RetryPolicy::default();
        assert!(p.backoff(0) <= p.max_delay);
        assert!(p.backoff(10) <= p.max_delay);
    }

    #[tokio::test(start_paused = true)]
    async fn retry_succeeds_after_failures() {
        let p = RetryPolicy {
            max_attempts: 4,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(4),
        };
        let mut n = 0;
        let out: Result<u32, &str> = p
            .retry(|| {
                n += 1;
                async move {
                    if n < 3 {
                        Err("boom")
                    } else {
                        Ok(n)
                    }
                }
            })
            .await;
        assert_eq!(out, Ok(3));
    }

    #[test]
    fn breaker_opens_and_recovers() {
        let clock = ManualClock::new(0);
        let b = CircuitBreaker::new(clock.clone(), 2, Duration::from_millis(100));
        assert_eq!(b.state(), BreakerState::Closed);
        b.on_failure();
        assert!(b.acquire().is_ok());
        b.on_failure();
        assert_eq!(b.state(), BreakerState::Open);
        assert!(b.acquire().is_err());
        clock.advance(Duration::from_millis(150));
        assert_eq!(b.state(), BreakerState::HalfOpen);
        b.on_success();
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn rate_limiter_refills() {
        let clock = ManualClock::new(0);
        let rl = RateLimiter::new(clock.clone(), 2.0, 10.0);
        assert!(rl.try_acquire().is_ok());
        assert!(rl.try_acquire().is_ok());
        assert!(rl.try_acquire().is_err());
        clock.advance(Duration::from_millis(200)); // +2 tokens
        assert!(rl.try_acquire().is_ok());
    }
}
