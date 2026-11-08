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

    /// A scratch directory that is removed even when the test panics.
    struct Tmp(std::path::PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Tmp {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let d = std::env::temp_dir().join(format!(
                "hf-vg-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&d).unwrap();
            Tmp(d)
        }
        fn p(&self, rel: &str) -> String {
            self.0.join(rel).to_string_lossy().into_owned()
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A deterministic stand-in for the CSPRNG that also counts its draws.
    fn golden(draws: &std::cell::Cell<u64>) -> impl FnMut() -> f64 + '_ {
        let mut n = 0.0f64;
        move || {
            draws.set(draws.get() + 1);
            n = (n + 0.618_033_988_75) % 1.0;
            n
        }
    }

    fn fp(c: char) -> String {
        c.to_string().repeat(40)
    }

    fn node(c: char, chosen: f64, expires: f64) -> GuardNode {
        GuardNode {
            idhex: fp(c),
            chosen_at: chosen,
            expires_at: expires,
        }
    }

    #[test]
    fn constants_are_the_vanguards_values_in_seconds() {
        // vanguards.py: NUM_LAYER{1,2,3}_GUARDS, MIN/MAX_LAYER2_LIFETIME_HOURS = 24*1 / 24*45,
        // MIN/MAX_LAYER3_LIFETIME_HOURS = 1 / 48.
        assert_eq!(NUM_LAYER1_GUARDS, 2);
        assert_eq!(NUM_LAYER2_GUARDS, 3);
        assert_eq!(NUM_LAYER3_GUARDS, 8);
        assert_eq!(MIN_LAYER2_LIFETIME, 86_400.0);
        assert_eq!(MAX_LAYER2_LIFETIME, 3_888_000.0);
        assert_eq!(MIN_LAYER3_LIFETIME, 3_600.0);
        assert_eq!(MAX_LAYER3_LIFETIME, 172_800.0);
        assert_eq!(WEIGHT_SCALE, 10_000.0);
    }

    #[test]
    fn uniform_is_the_low_end_plus_the_span_times_the_draw() {
        assert_eq!(uniform(&mut || 0.25, 10.0, 20.0), 12.5);
        assert_eq!(uniform(&mut || 0.0, 10.0, 20.0), 10.0);
        assert_eq!(uniform(&mut || 1.0, 10.0, 20.0), 20.0);
        assert_eq!(uniform(&mut || 0.5, 0.0, 8.0), 4.0);
    }

    #[test]
    fn csprng_unit_is_in_the_unit_interval_and_not_constant() {
        let xs: Vec<f64> = (0..2000).map(|_| csprng_unit()).collect();
        assert!(xs.iter().all(|x| (0.0..1.0).contains(x)));
        let mean = xs.iter().sum::<f64>() / xs.len() as f64;
        assert!((0.45..0.55).contains(&mean), "mean {mean}");
        let mut sorted = xs.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        sorted.dedup();
        assert!(sorted.len() > 1990, "{} distinct of 2000", sorted.len());
    }

    #[test]
    fn candidates_carry_bandwidth_times_the_middle_weight() {
        let mut w = weights();
        w.insert("Wmg".into(), 5000.0);
        let rs = vec![
            router('A', "Fast Stable Valid", 10.0),
            router('D', "Fast Stable Valid Guard", 30.0),
        ];
        assert_eq!(
            candidates(&rs, &w),
            vec![(fp('D'), 15.0), (fp('A'), 10.0)],
            "Guard 30 x Wmg 5000/10000 = 15, plain 10 x Wmm 1.0 = 10"
        );
        assert!(candidates(&[], &w).is_empty());
    }

    #[test]
    fn a_pick_stops_at_the_first_candidate_whose_running_total_reaches_the_draw() {
        let cands = vec![("A".to_string(), 1.0), ("B".to_string(), 1.0)];
        let at = |r: f64, total: f64| pick(&cands, total, &mut || r).to_string();
        assert_eq!(at(0.25, 2.0), "A");
        assert_eq!(at(0.5, 2.0), "A", "a draw equal to A's weight is still A");
        assert_eq!(at(0.5000001, 2.0), "B");
        assert_eq!(at(0.999, 2.0), "B");
        // a total larger than the weights add up to: the last candidate, not a panic
        assert_eq!(at(0.5, 10.0), "B");
        let three = vec![
            ("A".to_string(), 1.0),
            ("B".to_string(), 2.0),
            ("C".to_string(), 3.0),
        ];
        let at3 = |r: f64| pick(&three, 6.0, &mut || r).to_string();
        assert_eq!(at3(0.2), "B");
        assert_eq!(at3(0.5), "B", "3.0 is exactly A+B");
        assert_eq!(at3(0.51), "C");
    }

    #[test]
    fn nothing_is_chosen_without_usable_candidates() {
        let zero: BTreeMap<String, f64> = ["Wmm", "Wmg", "Wme", "Wmd"]
            .iter()
            .map(|k| (k.to_string(), 0.0))
            .collect();
        let mut l = Layers::default();
        assert!(
            !l.update(&many(), &zero, 0.0, &mut csprng_unit),
            "all weights 0"
        );
        assert!(l.layer2.is_empty() && l.layer3.is_empty());
        assert!(
            !l.update(&[], &weights(), 0.0, &mut csprng_unit),
            "empty consensus"
        );
        let no_wmm: BTreeMap<String, f64> = BTreeMap::new();
        assert!(
            !l.update(&many(), &no_wmm, 0.0, &mut csprng_unit),
            "no weights at all"
        );
    }

    #[test]
    fn a_guard_lives_for_the_longer_of_two_uniform_draws() {
        let one = vec![router('A', "Fast Stable Valid", 5.0)];
        let script = [0.5, 0.2, 0.9, 0.5, 0.6, 0.1];
        let mut i = 0;
        let mut rng = || {
            i += 1;
            script[i - 1]
        };
        let mut l = Layers::default();
        assert!(l.update(&one, &weights(), 1000.0, &mut rng));
        assert_eq!(i, 6, "pick, two lifetime draws, for each layer");
        let l2 = &l.layer2[0];
        let l3 = &l.layer3[0];
        assert_eq!((l2.chosen_at, l3.chosen_at), (1000.0, 1000.0));
        // 86_400 + (3_888_000 - 86_400) * 0.9 and 3_600 + (172_800 - 3_600) * 0.6
        assert!((l2.expires_at - (1000.0 + 86_400.0 + 3_801_600.0 * 0.9)).abs() < 1e-6);
        assert!((l3.expires_at - (1000.0 + 3_600.0 + 169_200.0 * 0.6)).abs() < 1e-6);
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under miri")]
    fn a_stuck_generator_ends_after_a_bounded_number_of_draws() {
        let draws = std::cell::Cell::new(0u64);
        let mut stuck = || {
            draws.set(draws.get() + 1);
            0.5
        };
        let mut l = Layers::default();
        assert!(l.update(&many(), &weights(), 0.0, &mut stuck));
        assert_eq!(
            (l.layer2.len(), l.layer3.len()),
            (1, 1),
            "only one distinct pick"
        );
        // per layer: 100_000 picks plus the 2 lifetime draws of the one accepted guard
        assert_eq!(draws.get(), 2 * 100_002);
    }

    #[test]
    fn zero_weight_relays_are_never_wanted_and_never_chosen() {
        let mut w = weights();
        w.insert("Wmg".into(), 0.0);
        let mut rs = vec![
            router('A', "Fast Stable Valid", 10.0),
            router('B', "Fast Stable Valid", 10.0),
        ];
        rs.extend(
            "CDEFG"
                .chars()
                .map(|c| router(c, "Fast Stable Valid Guard", 10.0)),
        );
        let draws = std::cell::Cell::new(0u64);
        let mut l = Layers::default();
        assert!(l.update(&rs, &w, 0.0, &mut golden(&draws)));
        for layer in [&l.layer2, &l.layer3] {
            let mut ids: Vec<&str> = layer.iter().map(|g| g.idhex.as_str()).collect();
            ids.sort_unstable();
            assert_eq!(ids, vec![fp('A'), fp('B')], "only the two with weight");
        }
        assert!(
            draws.get() < 1000,
            "{} draws: it kept trying for impossible picks",
            draws.get()
        );
    }

    #[test]
    fn expiry_and_trimming_follow_consensus_update() {
        let rs = many();
        let mut l = Layers {
            layer2: vec![
                node('A', 0.0, 100.0),
                node('B', 0.0, 99.0),
                node('C', 0.0, 200.0),
                node('D', 0.0, 300.0),
                node('E', 0.0, 400.0),
            ],
            layer3: vec![],
        };
        assert!(l.update(&rs, &weights(), 100.0, &mut csprng_unit));
        // B expired (99 < 100); A expires exactly now and stays (vanguards: `expires_at < now`)
        let kept: Vec<&str> = l.layer2.iter().map(|g| g.idhex.as_str()).collect();
        assert_eq!(kept, vec![fp('A'), fp('C'), fp('D')], "{kept:?}");
        assert_eq!(l.layer3.len(), NUM_LAYER3_GUARDS);

        // five live layer-3 guards are kept; twelve are cut to eight
        let many3: Vec<GuardNode> = "ABCDEF012345".chars().map(|c| node(c, 0.0, 1e9)).collect();
        let mut l = Layers {
            layer2: vec![],
            layer3: many3.clone(),
        };
        l.update(&rs, &weights(), 0.0, &mut csprng_unit);
        assert_eq!(l.layer3, many3[..NUM_LAYER3_GUARDS].to_vec());
    }

    #[test]
    fn the_state_text_is_exact() {
        let l = Layers {
            layer2: vec![node('A', 1000.0, 2000.0)],
            layer3: vec![node('B', 3.0, 4.0), node('C', 5.0, 6.0)],
        };
        assert_eq!(
            l.to_text(),
            format!(
                "# HiddenForge full vanguards state: layer idhex chosen_at expires_at\nL2 {} 1000 2000\nL3 {} 3 4\nL3 {} 5 6\n",
                fp('A'),
                fp('B'),
                fp('C')
            )
        );
        assert_eq!(Layers::from_text(&l.to_text()), l);
        assert_eq!(
            l.setconf(),
            format!(
                "SETCONF NumEntryGuards=2 NumPrimaryGuards=2 HSLayer2Nodes={} HSLayer3Nodes={},{}",
                fp('A'),
                fp('B'),
                fp('C')
            )
        );
    }

    #[test]
    fn unreadable_state_lines_are_dropped_and_ids_are_uppercased() {
        let lower = "abcdef0123".repeat(4);
        let upper = lower.to_ascii_uppercase();
        let (short, long, nonhex) = (&lower[..39], format!("{lower}0"), "g".repeat(40));
        let text = format!(
            "# comment\n\
             L2 {lower} 1 2\n\
             L3 {upper} 3.5 4.5\n\
             L2 {short} 1 2\n\
             L2 {long} 1 2\n\
             L2 {nonhex} 1 2\n\
             L2 abcd 1 2\n\
             L2 {upper} 1\n\
             L2 {upper} 1 2 3\n\
             L2 {upper} x y\n\
             L4 {upper} 1 2\n\
             bogus\n\n",
        );
        let l = Layers::from_text(&text);
        assert_eq!(
            l,
            Layers {
                layer2: vec![GuardNode {
                    idhex: upper.clone(),
                    chosen_at: 1.0,
                    expires_at: 2.0
                }],
                layer3: vec![GuardNode {
                    idhex: upper,
                    chosen_at: 3.5,
                    expires_at: 4.5
                }],
            }
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn saved_state_loads_back_whatever_its_padding() {
        use std::os::unix::fs::PermissionsExt;
        let t = Tmp::new("state");
        let path = t.p("vanguards.state");
        let l = Layers {
            layer2: vec![node('A', 10.0, 20.0)],
            layer3: vec![node('B', 30.0, 40.0)],
        };
        l.save(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), l.to_text());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        let names: Vec<_> = std::fs::read_dir(&t.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["vanguards.state"], "no temp file left");
        assert_eq!(Layers::load(&path), l);

        assert_eq!(Layers::load(&t.p("missing")), Layers::default());

        // The state file is read up to 64 KiB, however much padding it carries.
        let padded = |total: usize| {
            let mut s = l.to_text().into_bytes();
            s.resize(total, b'\n');
            s
        };
        for (total, want) in [(2000, true), (65536, true), (65537, false)] {
            std::fs::write(t.p("padded"), padded(total)).unwrap();
            let got = Layers::load(&t.p("padded"));
            assert_eq!(got == l, want, "{total} bytes");
            if !want {
                assert_eq!(
                    got,
                    Layers::default(),
                    "{total} bytes: too large, start fresh"
                );
            }
        }
        std::os::unix::fs::symlink(t.p("vanguards.state"), t.p("link")).unwrap();
        assert_eq!(
            Layers::load(&t.p("link")),
            Layers::default(),
            "never follows a link"
        );

        let err = l.save(&t.p("no-such-dir/x")).unwrap_err();
        assert!(err.starts_with("Cannot write state to "), "{err}");
    }
}
