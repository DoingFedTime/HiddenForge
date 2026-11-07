//! Full vanguards (opt-in, `HIDDENFORGE_VANGUARDS=full`): pinned layer-2 and
//! layer-3 guard sets, a port of the selection in Vanguards 0.3.1
//! (`vanguards/vanguards.py`, `NodeSelection.py`).
//!
//! Tor's built-in vanguards-lite pins a small layer 2 and nothing at layer 3;
//! proposal 333 says long-lived, high-risk onion services should still run the
//! full set. This keeps NUM_LAYER2_GUARDS=3 (each lives max(U(1d,45d), U(1d,45d)))
//! and NUM_LAYER3_GUARDS=8 (max(U(1h,48h), U(1h,48h))), chosen bandwidth-weighted
//! for the middle position from Fast+Stable+Valid relays without the Authority
//! flag, replaced when they expire or leave the consensus, and applied with
//! SETCONF HSLayer2Nodes / HSLayer3Nodes (plus NumEntryGuards=2,
//! NumPrimaryGuards=2), exactly as the addon does.
//!
//! The cost, stated plainly: Tor's `Sandbox 1` rejects every SETCONF, so this
//! mode needs `TOR_SANDBOX=0`. The engine's seccomp profile still applies.
//!
//! Differences from the addon, both deliberate: randomness comes from the
//! kernel CSPRNG (getrandom), not Python's Mersenne Twister; and ExcludeNodes is
//! not consulted, because HiddenForge's generated torrc never sets it.
//! The state is a small text file, not a pickle.

use std::collections::BTreeMap;

pub const NUM_LAYER1_GUARDS: u32 = 2;
pub const NUM_LAYER2_GUARDS: usize = 3;
pub const NUM_LAYER3_GUARDS: usize = 8;
const HOUR: f64 = 3600.0;
const MIN_LAYER2_LIFETIME: f64 = 24.0 * HOUR;
const MAX_LAYER2_LIFETIME: f64 = 24.0 * 45.0 * HOUR;
const MIN_LAYER3_LIFETIME: f64 = HOUR;
const MAX_LAYER3_LIFETIME: f64 = 48.0 * HOUR;
const WEIGHT_SCALE: f64 = 10000.0;

#[derive(Debug, Clone, PartialEq)]
pub struct GuardNode {
    pub idhex: String,
    pub chosen_at: f64,
    pub expires_at: f64,
}

#[derive(Debug, Default, PartialEq)]
pub struct Layers {
    pub layer2: Vec<GuardNode>,
    pub layer3: Vec<GuardNode>,
}

/// A uniform f64 in [0, 1), from the kernel CSPRNG.
pub fn csprng_unit() -> f64 {
    let mut b = [0u8; 8];
    let mut filled = 0;
    while filled < b.len() {
        // SAFETY: getrandom(2) into our own buffer.
        let n = unsafe { libc::getrandom(b[filled..].as_mut_ptr().cast(), b.len() - filled, 0) };
        if n > 0 {
            filled += n as usize;
        } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            // No randomness means no safe choice: stop rather than guess.
            panic!("getrandom failed");
        }
    }
    (u64::from_le_bytes(b) >> 11) as f64 / (1u64 << 53) as f64
}

fn uniform(rng: &mut dyn FnMut() -> f64, lo: f64, hi: f64) -> f64 {
    lo + (hi - lo) * rng()
}

/// The addon's flag_to_weight for POSITION_MIDDLE.
fn middle_weight(flags: &[String], w: &BTreeMap<String, f64>) -> f64 {
    let has = |f: &str| flags.iter().any(|x| x == f);
    let k = if has("Guard") && has("Exit") {
        "Wmd"
    } else if has("Exit") {
        "Wme"
    } else if has("Guard") {
        "Wmg"
    } else {
        "Wmm"
    };
    w.get(k).copied().unwrap_or(0.0) / WEIGHT_SCALE
}

/// The candidates and their weights: sorted by measured bandwidth, descending
/// (a stable sort, as Python's), restricted to Fast+Stable+Valid, not Authority.
pub fn candidates(
    routers: &[crate::guards::Router],
    weights: &BTreeMap<String, f64>,
) -> Vec<(String, f64)> {
    let mut sorted: Vec<&crate::guards::Router> = routers.iter().collect();
    sorted.sort_by(|a, b| {
        b.measured
            .partial_cmp(&a.measured)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    sorted
        .into_iter()
        .filter(|r| {
            ["Fast", "Stable", "Valid"]
                .iter()
                .all(|m| r.flags.iter().any(|f| f == m))
                && !r.flags.iter().any(|f| f == "Authority")
        })
        .map(|r| {
            (
                r.fingerprint.clone(),
                r.measured * middle_weight(&r.flags, weights),
            )
        })
        .collect()
}

/// BwWeightedGenerator.generate(): one bandwidth-weighted pick.
fn pick<'a>(cands: &'a [(String, f64)], total: f64, rng: &mut dyn FnMut() -> f64) -> &'a str {
    let choice = uniform(rng, 0.0, total);
    let mut acc = 0.0;
    let mut idx = 0;
    while acc < choice && idx < cands.len() {
        acc += cands[idx].1;
        idx += 1;
    }
    &cands[idx.saturating_sub(1)].0
}

impl Layers {
    /// consensus_update(): drop guards that left the consensus or expired, trim,
    /// and replenish. Returns false if there were no usable candidates.
    pub fn update(
        &mut self,
        routers: &[crate::guards::Router],
        weights: &BTreeMap<String, f64>,
        now: f64,
        rng: &mut dyn FnMut() -> f64,
    ) -> bool {
        let present: std::collections::HashSet<&str> =
            routers.iter().map(|r| r.fingerprint.as_str()).collect();
        for layer in [&mut self.layer2, &mut self.layer3] {
            layer.retain(|g| present.contains(g.idhex.as_str()));
            layer.retain(|g| g.expires_at >= now);
        }
        self.layer2.truncate(NUM_LAYER2_GUARDS);
        self.layer3.truncate(NUM_LAYER3_GUARDS);
        let cands = candidates(routers, weights);
        let total: f64 = cands.iter().map(|c| c.1).sum();
        if cands.is_empty() || total <= 0.0 {
            return false;
        }
        let distinct = cands.iter().filter(|c| c.1 > 0.0).count();
        for (layer, want, lo, hi) in [
            (
                &mut self.layer2,
                NUM_LAYER2_GUARDS,
                MIN_LAYER2_LIFETIME,
                MAX_LAYER2_LIFETIME,
            ),
            (
                &mut self.layer3,
                NUM_LAYER3_GUARDS,
                MIN_LAYER3_LIFETIME,
                MAX_LAYER3_LIFETIME,
            ),
        ] {
            let want = want.min(distinct);
            let mut attempts = 0;
            while layer.len() < want && attempts < 100_000 {
                attempts += 1;
                let fp = pick(&cands, total, rng).to_string();
                if layer.iter().any(|g| g.idhex == fp) {
                    continue;
                }
                let life = uniform(rng, lo, hi).max(uniform(rng, lo, hi));
                layer.push(GuardNode {
                    idhex: fp,
                    chosen_at: now,
                    expires_at: now + life,
                });
            }
        }
        true
    }

    pub fn guardset(layer: &[GuardNode]) -> String {
        layer
            .iter()
            .map(|g| g.idhex.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The SETCONF the addon's configure_tor() sends.
    pub fn setconf(&self) -> String {
        format!(
            "SETCONF NumEntryGuards={NUM_LAYER1_GUARDS} NumPrimaryGuards={NUM_LAYER1_GUARDS} HSLayer2Nodes={} HSLayer3Nodes={}",
            Self::guardset(&self.layer2),
            Self::guardset(&self.layer3)
        )
    }

    pub fn to_text(&self) -> String {
        let mut s =
            String::from("# HiddenForge full vanguards state: layer idhex chosen_at expires_at\n");
        for (tag, layer) in [("L2", &self.layer2), ("L3", &self.layer3)] {
            for g in layer {
                s.push_str(&format!(
                    "{tag} {} {:.0} {:.0}\n",
                    g.idhex, g.chosen_at, g.expires_at
                ));
            }
        }
        s
    }

    /// Lenient: an unreadable line is dropped (that guard is simply re-chosen).
    pub fn from_text(s: &str) -> Layers {
        let mut l = Layers::default();
        for line in s.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() != 4 || f[1].len() != 40 || !f[1].bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let (Ok(c), Ok(e)) = (f[2].parse::<f64>(), f[3].parse::<f64>()) else {
                continue;
            };
            let g = GuardNode {
                idhex: f[1].to_ascii_uppercase(),
                chosen_at: c,
                expires_at: e,
            };
            match f[0] {
                "L2" => l.layer2.push(g),
                "L3" => l.layer3.push(g),
                _ => {}
            }
        }
        l
    }

    pub fn load(path: &str) -> Layers {
        crate::fsops::read_small_regular_file(path, 64 * 1024)
            .map(|d| Layers::from_text(&String::from_utf8_lossy(&d)))
            .unwrap_or_default()
    }

    /// Atomic replace: temp file, fsync, rename.
    pub fn save(&self, path: &str) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = format!("{path}.{}.tmp", std::process::id());
        let r = (|| -> std::io::Result<()> {
            let _ = std::fs::remove_file(&tmp);
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(self.to_text().as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        })();
        if r.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        r.map_err(|e| format!("Cannot write state to {path}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guards::Router;

    fn router(fp: char, flags: &str, bw: f64) -> Router {
        Router {
            fingerprint: fp.to_string().repeat(40),
            flags: flags.split(' ').map(String::from).collect(),
            measured: bw,
        }
    }

    fn weights() -> BTreeMap<String, f64> {
        ["Wmm", "Wmg", "Wme", "Wmd"]
            .iter()
            .map(|k| (k.to_string(), 10000.0))
            .collect()
    }

    fn many() -> Vec<Router> {
        "ABCDEF0123456789"
            .chars()
            .map(|c| router(c, "Fast Running Stable Valid", 100.0))
            .collect()
    }

    #[test]
    fn restriction_matches_the_addon() {
        let rs = vec![
            router('A', "Fast Stable Valid", 10.0),
            router('B', "Fast Valid", 10.0), // not Stable
            router('C', "Authority Fast Stable Valid", 10.0), // Authority
            router('D', "Fast Stable Valid Guard", 30.0),
        ];
        let c = candidates(&rs, &weights());
        let ids: Vec<char> = c.iter().map(|x| x.0.chars().next().unwrap()).collect();
        assert_eq!(
            ids,
            vec!['D', 'A'],
            "sorted by bandwidth, Stable required, Authority excluded"
        );
    }

    #[test]
    fn middle_weights_by_flag() {
        let mut w = weights();
        w.insert("Wmg".into(), 5000.0);
        w.insert("Wme".into(), 0.0);
        w.insert("Wmd".into(), 2500.0);
        let f = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        assert_eq!(middle_weight(&f("Guard"), &w), 0.5);
        assert_eq!(middle_weight(&f("Exit"), &w), 0.0);
        assert_eq!(middle_weight(&f("Guard Exit"), &w), 0.25);
        assert_eq!(middle_weight(&f("Fast"), &w), 1.0);
    }

    #[test]
    fn fills_layers_with_distinct_guards_and_lifetimes_in_range() {
        let mut l = Layers::default();
        assert!(l.update(&many(), &weights(), 1000.0, &mut csprng_unit));
        assert_eq!(l.layer2.len(), NUM_LAYER2_GUARDS);
        assert_eq!(l.layer3.len(), NUM_LAYER3_GUARDS);
        for (layer, lo, hi) in [
            (&l.layer2, MIN_LAYER2_LIFETIME, MAX_LAYER2_LIFETIME),
            (&l.layer3, MIN_LAYER3_LIFETIME, MAX_LAYER3_LIFETIME),
        ] {
            let mut ids: Vec<&str> = layer.iter().map(|g| g.idhex.as_str()).collect();
            ids.sort_unstable();
            ids.dedup();
            assert_eq!(ids.len(), layer.len(), "a guard twice in one layer");
            for g in layer.iter() {
                let life = g.expires_at - g.chosen_at;
                assert!(
                    life >= lo && life <= hi,
                    "lifetime {life} outside [{lo}, {hi}]"
                );
            }
        }
    }

    #[test]
    fn keeps_live_guards_replaces_expired_and_departed() {
        let rs = many();
        let mut l = Layers::default();
        l.update(&rs, &weights(), 0.0, &mut csprng_unit);
        let kept = l.layer2[0].clone();
        l.layer2[1].expires_at = 5.0; // expired at t=10
        let gone = l.layer2[2].idhex.clone();
        let rs2: Vec<Router> = rs.into_iter().filter(|r| r.fingerprint != gone).collect();
        l.update(&rs2, &weights(), 10.0, &mut csprng_unit);
        assert_eq!(l.layer2.len(), NUM_LAYER2_GUARDS);
        assert_eq!(
            l.layer2[0], kept,
            "a live, unexpired guard must stay pinned"
        );
        assert!(!l.layer2.iter().any(|g| g.idhex == gone));
    }

    #[test]
    fn weighted_pick_follows_bandwidth() {
        let cands = vec![("A".to_string(), 1.0), ("B".to_string(), 999.0)];
        let mut n = 0.0f64;
        let mut seq = move || {
            n = (n + 0.618_033_988_75) % 1.0;
            n
        };
        let b = (0..1000)
            .filter(|_| pick(&cands, 1000.0, &mut seq) == "B")
            .count();
        assert!(b > 990, "B carries 99.9% of the weight, picked {b}/1000");
    }

    #[test]
    fn never_spins_on_a_tiny_consensus() {
        let rs = vec![
            router('A', "Fast Stable Valid", 1.0),
            router('B', "Fast Stable Valid", 1.0),
        ];
        let mut l = Layers::default();
        assert!(l.update(&rs, &weights(), 0.0, &mut csprng_unit));
        assert_eq!(
            l.layer3.len(),
            2,
            "as many as there are distinct candidates"
        );
    }

    #[test]
    fn state_round_trips_and_ignores_garbage() {
        let mut l = Layers::default();
        l.update(&many(), &weights(), 1000.0, &mut csprng_unit);
        let text = l.to_text() + "L2 nothex 1 2\nbogus\n";
        let back = Layers::from_text(&text);
        assert_eq!(Layers::guardset(&back.layer2), Layers::guardset(&l.layer2));
        assert_eq!(Layers::guardset(&back.layer3), Layers::guardset(&l.layer3));
        assert!(l
            .setconf()
            .starts_with("SETCONF NumEntryGuards=2 NumPrimaryGuards=2 HSLayer2Nodes="));
    }
}
