//! token-bucket rate limiting for inbound control messages.
//!
//! control messages are unauthenticated up to the point where they are decoded,
//! so a flood of them — from one peer, or spoofed from many source addresses —
//! must not be able to make us burn unbounded cpu. this module adds a cheap,
//! deterministic limiter the control plane consults before it authenticates or
//! decodes anything.
//!
//! two buckets are checked: a per-source bucket (so one noisy peer cannot crowd
//! out the others) and a global bucket (so a spoofed-source flood still has a
//! ceiling). both are token buckets, refilled continuously and capped at a
//! burst. the per-source map is bounded and evicts idle entries, so a flood from
//! ever-changing source addresses cannot grow memory without limit.
//!
//! time is passed in, so the limiter is deterministic and testable without
//! sleeping.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// rate-limit parameters. `per_second == 0` disables limiting.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// most messages accepted from one source at once (per-source burst).
    pub burst: f64,
    /// per-source refill rate, messages per second.
    pub per_second: f64,
    /// hard ceiling across all sources, in messages.
    pub global_burst: f64,
    /// global refill rate, messages per second.
    pub global_per_second: f64,
    /// most source buckets kept before the least-recently-used is evicted.
    pub max_sources: usize,
    /// a source bucket idle for this long is dropped.
    pub idle: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            burst: 64.0,
            per_second: 32.0,
            global_burst: 4096.0,
            global_per_second: 1024.0,
            max_sources: 1024,
            idle: Duration::from_secs(30),
        }
    }
}

impl RateLimitConfig {
    /// a configuration with the given per-source and global rates, keeping the
    /// other defaults. used by the cli.
    pub fn with_rate(per_second: u32, global_per_second: u32) -> Self {
        Self {
            per_second: f64::from(per_second),
            burst: f64::from(per_second.max(1)) * 2.0,
            global_per_second: f64::from(global_per_second),
            global_burst: f64::from(global_per_second.max(1)) * 2.0,
            ..Self::default()
        }
    }

    /// is limiting switched off?
    pub fn disabled(&self) -> bool {
        self.per_second <= 0.0 || self.global_per_second <= 0.0
    }
}

/// one token bucket.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            updated: now,
        }
    }

    /// refill for the elapsed time and spend a token if one is available.
    fn take(&mut self, burst: f64, per_second: f64, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * per_second).min(burst);
        self.updated = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// a per-source plus global token-bucket limiter.
pub struct RateLimiter {
    config: RateLimitConfig,
    global: Bucket,
    sources: HashMap<SocketAddr, Bucket>,
}

impl RateLimiter {
    /// build a limiter with full buckets.
    pub fn new(config: RateLimitConfig, now: Instant) -> Self {
        Self {
            global: Bucket::full(config.global_burst, now),
            sources: HashMap::new(),
            config,
        }
    }

    /// the configuration in use.
    pub fn config(&self) -> RateLimitConfig {
        self.config
    }

    /// should a message from `from` be accepted now? consumes a token if so.
    pub fn check(&mut self, from: SocketAddr, now: Instant) -> bool {
        if self.config.disabled() {
            return true;
        }
        if !self
            .global
            .take(self.config.global_burst, self.config.global_per_second, now)
        {
            return false;
        }
        self.evict_if_full(now);
        let config = self.config;
        let bucket = self
            .sources
            .entry(from)
            .or_insert_with(|| Bucket::full(config.burst, now));
        bucket.take(config.burst, config.per_second, now)
    }

    /// drop idle source buckets and recompute the global bucket. called from the
    /// control-plane tick so state is reclaimed even without traffic.
    pub fn prune(&mut self, now: Instant) {
        let idle = self.config.idle;
        self.sources
            .retain(|_, bucket| now.saturating_duration_since(bucket.updated) < idle);
        // refresh the global bucket timestamp so a long idle period does not
        // hand out a stale burst later.
        self.global
            .take(self.config.global_burst, self.config.global_per_second, now);
    }

    /// how many source buckets are tracked.
    pub fn tracked_sources(&self) -> usize {
        self.sources.len()
    }

    fn evict_if_full(&mut self, now: Instant) {
        if self.sources.len() < self.config.max_sources {
            return;
        }
        let idle = self.config.idle;
        self.sources
            .retain(|_, bucket| now.saturating_duration_since(bucket.updated) < idle);
        while self.sources.len() >= self.config.max_sources {
            // still full: evict the least recently used source.
            let Some(oldest) = self
                .sources
                .iter()
                .min_by_key(|(_, bucket)| bucket.updated)
                .map(|(addr, _)| *addr)
            else {
                break;
            };
            self.sources.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn limiter() -> (RateLimiter, Instant) {
        let now = Instant::now();
        let config = RateLimitConfig {
            burst: 4.0,
            per_second: 2.0,
            global_burst: 1000.0,
            global_per_second: 1000.0,
            max_sources: 4,
            idle: Duration::from_secs(10),
        };
        (RateLimiter::new(config, now), now)
    }

    #[test]
    fn a_burst_is_allowed_then_the_source_is_limited() {
        let (mut r, now) = limiter();
        let a = addr(1);
        for _ in 0..4 {
            assert!(r.check(a, now), "within burst");
        }
        assert!(!r.check(a, now), "over burst");
        assert!(!r.check(a, now), "still over burst at the same instant");
    }

    #[test]
    fn tokens_refill_over_time() {
        let (mut r, now) = limiter();
        let a = addr(1);
        for _ in 0..4 {
            assert!(r.check(a, now));
        }
        assert!(!r.check(a, now));
        // after half a second at 2/s the bucket has >= 1 token.
        assert!(r.check(a, now + Duration::from_millis(500)));
    }

    #[test]
    fn sources_are_limited_independently() {
        let (mut r, now) = limiter();
        for _ in 0..4 {
            assert!(r.check(addr(1), now));
        }
        assert!(!r.check(addr(1), now));
        assert!(r.check(addr(2), now), "another source has its own bucket");
    }

    #[test]
    fn the_source_map_is_bounded() {
        let (mut r, now) = limiter();
        for port in 0..1000 {
            let _ = r.check(addr(port), now);
        }
        assert!(
            r.tracked_sources() <= 4,
            "tracked {} sources",
            r.tracked_sources()
        );
    }

    #[test]
    fn idle_sources_are_pruned() {
        let (mut r, now) = limiter();
        let _ = r.check(addr(1), now);
        assert_eq!(r.tracked_sources(), 1);
        r.prune(now + Duration::from_secs(11));
        assert_eq!(r.tracked_sources(), 0);
    }

    #[test]
    fn the_global_bucket_caps_a_spoofed_flood() {
        let now = Instant::now();
        let config = RateLimitConfig {
            burst: 1000.0,
            per_second: 1000.0,
            global_burst: 3.0,
            global_per_second: 0.1,
            max_sources: 1000,
            idle: Duration::from_secs(10),
        };
        let mut r = RateLimiter::new(config, now);
        // three distinct sources pass, then the global bucket is empty.
        assert!(r.check(addr(1), now));
        assert!(r.check(addr(2), now));
        assert!(r.check(addr(3), now));
        assert!(!r.check(addr(4), now), "global ceiling");
    }
}
