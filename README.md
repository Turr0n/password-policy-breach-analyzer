# Password Policy Breach Analyzer

[![CI](https://github.com/Turr0n/password-policy-breach-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Turr0n/password-policy-breach-analyzer/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Most password tools tell you whether *one* password is strong. This one asks a
more useful question for anyone **designing a policy**:

> Given a real password breach, **how many of those already-leaked passwords
> would still satisfy my policy?**

Every leaked password your policy *allows* is a weak password you failed to
block — and it is already sitting in every attacker's dictionary, so it will be
cracked instantly no matter how good your hashing is. This tool measures that
leak rate against a real corpus (e.g. the 14-million-entry `rockyou.txt`) and
estimates how long the **weakest password your policy still permits** would
survive a brute-force attack on different hardware and hash algorithms.

> ⚠️ **Ethical use only.** This is a defensive analysis tool. It evaluates
> passwords against a policy *locally* — it never contacts any online service
> and performs no attack. Use it to design better policies and for education.

---

## Why it's useful

- **Policy design is guesswork without data.** "8 characters + a digit" sounds
  reasonable until you learn how many breached passwords sail right through it.
- **Complexity ≠ strength.** The tool shows that a short "complex" password can
  fall faster than a long simple one, and that the choice of hash algorithm
  (MD5 vs bcrypt) matters more than most complexity rules.
- **Grounded numbers.** Crack-time estimates use *real benchmarked* hash rates
  for a CPU (i5-12400F), a consumer GPU (RTX 2060 SUPER) and a GPU rig.

## Install

```bash
git clone https://github.com/Turr0n/password-policy-breach-analyzer.git
cd password-policy-breach-analyzer
pip install -e .          # installs the `ppa` command
```

Pure standard library — no runtime dependencies. Python 3.10+.

## Quick start

Get a breach corpus (not shipped with this repo — it is large and sensitive):

```bash
# rockyou.txt is the classic teaching corpus (14.3M real leaked passwords)
curl -L -o rockyou.txt \
  https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

Analyze a policy:

```bash
# "8 chars + a digit" — a very common, weak policy
ppa --wordlist rockyou.txt --min-length 8 --require-digit

# A stricter policy from a JSON file, as an HTML report
ppa --wordlist rockyou.txt --policy examples/policy.example.json \
    --format html --output report.html
```

Try it immediately with the bundled sample (no download needed):

```bash
ppa --wordlist data/sample_passwords.txt --min-length 8 --require-digit
```

## Example output

```
============================================================
PASSWORD POLICY BREACH ANALYSIS
============================================================
Policy: length >= 8; requires digit
Passwords examined: 18

Breach passwords ALLOWED by policy : 4 (22.22%)  [#######-----------------------]
Breach passwords BLOCKED by policy : 14 (77.78%)  [#######################-------]

NOTE: 'allowed' passwords are real leaked passwords your policy does NOT stop.
They are already in every attacker's dictionary, so they are effectively
cracked instantly regardless of hash algorithm.

Top reasons passwords were blocked:
  - missing digit: 12
  - shorter than min_length: 8

Brute-force time for the WEAKEST password the policy allows:
  (keyspace = 10^8)
  cpu / md5     @ 146,000,000 H/s  ->  < 1 second
  cpu / bcrypt  @         38 H/s  ->  15.2 days
  gpu / md5     @ 25,000,000,000 H/s  ->  < 1 second
  gpu / bcrypt  @     18,000 H/s  ->  46.3 minutes
  rig / bcrypt  @    500,000 H/s  ->  1.7 minute
============================================================
```

The takeaway in one screen: the same policy that looks fine on paper leaks a
fifth of a real breach, and its weakest allowed password dies in **under a
second** on MD5 but survives on bcrypt. That is the whole argument for slow
hashing, made with data.

Run a **strict** policy (12 chars, all four character classes) against the full
14-million-entry rockyou.txt and the contrast is stark:

```
Policy: length >= 12; requires lowercase; requires uppercase; requires digit; requires symbol
Passwords examined: 14,344,390

Breach passwords ALLOWED by policy : 11,618 (0.08%)   [------------------------------]
Breach passwords BLOCKED by policy : 14,332,772 (99.92%) [##############################]

Brute-force time for the WEAKEST password the policy allows:
  (keyspace = 94^12)
  gpu / md5     @ 25,000,000,000 H/s  ->  301.8 thousand years
  gpu / bcrypt  @         18,000 H/s  ->  419.2 billion years
```

A good policy both **shrinks the breach leak rate toward zero** and **pushes
brute-force time out of reach** — and you can now measure both.

## Usage

```
ppa --wordlist PATH [policy options] [output options]

Policy options:
  --min-length N         Minimum length (default 8)
  --max-length N         Maximum length (optional)
  --require-lower        Require a lowercase letter
  --require-upper        Require an uppercase letter
  --require-digit        Require a digit
  --require-symbol       Require a symbol
  --min-char-classes N   Require at least N distinct character classes
  --policy FILE          Load a JSON policy (CLI flags override its fields)

Output options:
  -f, --format {text,json,html}   Report format (default: text)
  -o, --output FILE               Write to a file instead of stdout
  --limit N                       Only examine the first N passwords
```

A policy file is plain JSON (see [`examples/policy.example.json`](examples/policy.example.json)):

```json
{
  "min_length": 12,
  "require_upper": true,
  "require_lower": true,
  "require_digit": true,
  "require_symbol": true
}
```

## How it works

```
wordlist ──▶ analyzer ──▶ result ──▶ report (text / json / html)
             │
             ├─ policy.py      evaluate each password against the rules
             └─ crack_time.py  keyspace = charset^min_length, time = keyspace/2 / hashrate
```

- The wordlist is **streamed** line by line, so the full multi-gigabyte
  rockyou.txt is handled with constant memory. A full 14M-entry pass takes a
  couple of minutes in pure Python; use `--limit` for a quick look.
- **Crack-time model.** For the *weakest password the policy allows* we take a
  deliberately conservative charset (only the required classes, lowercase if
  none are required) and compute `charset ** min_length`. Average attack time is
  half the keyspace divided by the hash rate. It is an order-of-magnitude guide,
  not a forensic figure — which is exactly what you want for comparing policies.

## What I learned building this

- Why NIST now recommends **blocking known-breached passwords** and favoring
  **length over complexity rules** — the leak rate makes the reason obvious.
- The practical gap between **fast hashes (MD5/SHA)** and **slow, salted hashes
  (bcrypt/scrypt/argon2)**, measured with hashcat rather than taken on faith.
- Streaming large corpora, a clean CLI with `argparse`, a dependency-free
  Python package layout, unit tests, and CI with GitHub Actions.

## Roadmap

- [ ] Offline check against the Have I Been Pwned hash list
- [ ] zxcvbn-style pattern detection (keyboard walks, l33t-speak)
- [ ] Compare several policies side by side in one report
- [ ] CSV export of the length / character-class histograms

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
