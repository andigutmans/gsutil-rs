//! Python `difflib.SequenceMatcher` / `get_close_matches` port for exact
//! `Did you mean this?` command suggestion parity.

use std::collections::HashMap;

/// Compute Python `difflib.SequenceMatcher(None, a, b).ratio()`.
pub fn similarity_ratio(a: &str, b: &str) -> f64 {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let total = a_chars.len() + b_chars.len();
    if total == 0 {
        return 1.0;
    }

    let mut b2j: HashMap<char, Vec<usize>> = HashMap::new();
    for (i, &ch) in b_chars.iter().enumerate() {
        b2j.entry(ch).or_default().push(i);
    }

    let mut queue: Vec<(usize, usize, usize, usize)> = vec![(0, a_chars.len(), 0, b_chars.len())];
    let mut matches = 0usize;

    while let Some((alo, ahi, blo, bhi)) = queue.pop() {
        let (i, j, k) = find_longest_match(&a_chars, &b_chars, &b2j, alo, ahi, blo, bhi);
        if k > 0 {
            matches += k;
            if alo < i && blo < j {
                queue.push((alo, i, blo, j));
            }
            if i + k < ahi && j + k < bhi {
                queue.push((i + k, ahi, j + k, bhi));
            }
        }
    }

    (2.0 * matches as f64) / (total as f64)
}

fn find_longest_match(
    a: &[char],
    b: &[char],
    b2j: &HashMap<char, Vec<usize>>,
    alo: usize,
    ahi: usize,
    blo: usize,
    bhi: usize,
) -> (usize, usize, usize) {
    let mut best_i = alo;
    let mut best_j = blo;
    let mut best_size = 0usize;

    let mut j2len: HashMap<usize, usize> = HashMap::new();
    for (i, ch) in a.iter().enumerate().take(ahi).skip(alo) {
        let mut new_j2len: HashMap<usize, usize> = HashMap::new();
        if let Some(positions) = b2j.get(ch) {
            for &j in positions {
                if j < blo {
                    continue;
                }
                if j >= bhi {
                    break;
                }
                let k = j
                    .checked_sub(1)
                    .and_then(|p| j2len.get(&p))
                    .copied()
                    .unwrap_or(0)
                    + 1;
                new_j2len.insert(j, k);
                if k > best_size {
                    best_i = i + 1 - k;
                    best_j = j + 1 - k;
                    best_size = k;
                }
            }
        }
        j2len = new_j2len;
    }

    // Extend matches across any adjacent identical elements (usually no-op without junk).
    while best_i > alo && best_j > blo && a[best_i - 1] == b[best_j - 1] {
        best_i -= 1;
        best_j -= 1;
        best_size += 1;
    }
    while best_i + best_size < ahi
        && best_j + best_size < bhi
        && a[best_i + best_size] == b[best_j + best_size]
    {
        best_size += 1;
    }

    (best_i, best_j, best_size)
}

/// Port of Python `difflib.get_close_matches(word, possibilities, n=n, cutoff=cutoff)`.
pub fn get_close_matches<'a>(
    word: &str,
    possibilities: &[&'a str],
    n: usize,
    cutoff: f64,
) -> Vec<&'a str> {
    if n == 0 {
        return Vec::new();
    }
    let mut scored: Vec<(f64, &'a str)> = possibilities
        .iter()
        .filter_map(|&cand| {
            let ratio = similarity_ratio(word, cand);
            if ratio >= cutoff {
                Some((ratio, cand))
            } else {
                None
            }
        })
        .collect();

    // Sort descending by score, then lexicographically descending (matching Python's tuple sort on (score, x)).
    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.1.cmp(a.1))
    });

    scored.into_iter().take(n).map(|(_, s)| s).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_close_matches_gsutil_commands() {
        let cmds = [
            "ls", "cp", "mv", "rm", "mb", "rb", "stat", "hash", "version", "help", "setmeta",
        ];
        assert_eq!(get_close_matches("lss", &cmds, 1, 0.6), vec!["ls"]);
        assert_eq!(get_close_matches("versin", &cmds, 1, 0.6), vec!["version"]);
        assert_eq!(get_close_matches("setmet", &cmds, 1, 0.6), vec!["setmeta"]);
        assert!(get_close_matches("zzzzzz", &cmds, 1, 0.6).is_empty());
    }
}
