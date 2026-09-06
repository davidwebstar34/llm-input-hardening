from __future__ import annotations

import argparse
import base64
import json
import random
from dataclasses import dataclass
from pathlib import Path


REMOVE_REQUIRED_LABELS = {
    "bidi_control",
    "junk_invisible",
    "default_ignorable",
    "tag_char",
    "control_or_format",
}

BIDI_CONTROLS = ["\u202e", "\u202d", "\u2066", "\u2067", "\u2068", "\u2069", "\u202c"]
INVISIBLE_SUFFIXES = [
    "\ufe0f" * 32,
    "".join(chr(0xE0100 + i) for i in range(16)),
    "".join(chr(0xE0061 + (i % 10)) for i in range(20)) + chr(0xE007F),
    "\u200d" * 40,
]
HOMOGLYPH_MAP = {
    "a": "а",  # Cyrillic small a
    "c": "с",  # Cyrillic small es
    "e": "е",  # Cyrillic small ie
    "i": "і",  # Cyrillic small byelorussian-ukrainian i
    "o": "о",  # Cyrillic small o
    "p": "р",  # Cyrillic small er
    "x": "х",  # Cyrillic small ha
    "y": "у",  # Cyrillic small u
}

SEED_PHRASES = [
    "review payment account status",
    "deploy staging build",
    "rotate secrets for service",
    "validate customer identity",
    "run migration in dry mode",
    "summarize incident timeline",
    "reset webhook endpoint",
    "audit privileged access logs",
    "publish release candidate",
    "approve batch transaction",
]


@dataclass(frozen=True)
class Case:
    name: str
    kind: str
    policy: str
    text: str
    must_detect: list[str]
    expected_action: str
    must_not_contain_codepoints: list[str]

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "kind": self.kind,
            "policy": self.policy,
            "text": self.text,
            "expected": {
                "must_detect": self.must_detect,
                "expected_action": self.expected_action,
                "postconditions": {
                    "must_not_contain_codepoints": self.must_not_contain_codepoints
                },
            },
        }


def _attack_case(name: str, text: str, label: str, *, policy: str = "balanced_chat") -> Case:
    expected_action = "remove" if label in REMOVE_REQUIRED_LABELS else "flag_only"
    must_not = [label] if expected_action == "remove" else []
    return Case(
        name=name,
        kind="attack",
        policy=policy,
        text=text,
        must_detect=[label],
        expected_action=expected_action,
        must_not_contain_codepoints=must_not,
    )


def _mutate_homoglyph(text: str, rng: random.Random) -> str:
    out: list[str] = []
    for ch in text:
        lowered = ch.lower()
        repl = HOMOGLYPH_MAP.get(lowered)
        if repl and rng.random() < 0.45:
            out.append(repl if ch.islower() else repl.upper())
        else:
            out.append(ch)
    mutated = "".join(out)
    if not any(any(ch.isascii() for ch in word) and any(not ch.isascii() for ch in word) for word in mutated.split()):
        # A random no-op or wholly replaced word does not satisfy this case's
        # mixed-script label. Seed phrases contain multi-letter eligible words.
        for index, ch in enumerate(text):
            if ch.lower() in HOMOGLYPH_MAP:
                return text[:index] + HOMOGLYPH_MAP[ch.lower()] + text[index + 1:]
        raise ValueError("Homoglyph seed has no eligible character")
    return mutated


def _mutate_bidi_weave(text: str, rng: random.Random) -> str:
    out: list[str] = []
    for ch in text:
        out.append(ch)
        if ch == " ":
            continue
        if rng.random() < 0.18:
            out.append(rng.choice(BIDI_CONTROLS))
    mutated = "".join(out)
    return mutated if mutated != text else text + BIDI_CONTROLS[0]


def _gen_base64_blob(rng: random.Random, n_bytes: int) -> str:
    raw = bytes(rng.randrange(0, 256) for _ in range(n_bytes))
    return base64.b64encode(raw).decode("ascii")


def _gen_base64url_blob(rng: random.Random, n_bytes: int) -> str:
    raw = bytes(rng.randrange(0, 256) for _ in range(n_bytes))
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _gen_hex_blob(rng: random.Random, n_bytes: int) -> str:
    raw = bytes(rng.randrange(0, 256) for _ in range(n_bytes))
    return raw.hex()


def _gen_high_entropy_ascii(rng: random.Random, n_chars: int) -> str:
    alphabet = "".join(chr(c) for c in range(33, 127))
    return "".join(rng.choice(alphabet) for _ in range(n_chars))


def _generate_cases(count_per_operator: int, seed: int) -> list[dict[str, object]]:
    rng = random.Random(seed)
    cases: list[Case] = []

    for idx in range(count_per_operator):
        phrase = SEED_PHRASES[idx % len(SEED_PHRASES)]
        text = _mutate_homoglyph(phrase, rng)
        cases.append(
            _attack_case(
                f"mutation_homoglyph_{idx + 1}",
                text,
                "confusable_mixed_script",
            )
        )

    for idx in range(count_per_operator):
        phrase = SEED_PHRASES[idx % len(SEED_PHRASES)]
        text = _mutate_bidi_weave(phrase, rng)
        cases.append(
            _attack_case(
                f"mutation_bidi_weave_{idx + 1}",
                text,
                "bidi_control",
            )
        )

    for idx in range(count_per_operator):
        phrase = SEED_PHRASES[idx % len(SEED_PHRASES)]
        suffix = INVISIBLE_SUFFIXES[idx % len(INVISIBLE_SUFFIXES)]
        text = f"{phrase}{suffix}"
        cases.append(
            _attack_case(
                f"mutation_invisible_suffix_{idx + 1}",
                text,
                "tag_char" if any(0xE0000 <= ord(ch) <= 0xE00FF for ch in suffix) else "default_ignorable",
                policy="strict_exec",
            )
        )

    for idx in range(count_per_operator):
        bucket = idx % 4
        if bucket == 0:
            text = _gen_base64_blob(rng, 96)
            label = "base64ish_blob"
        elif bucket == 1:
            text = _gen_hex_blob(rng, 64)
            label = "hex_blob"
        elif bucket == 2:
            text = _gen_base64url_blob(rng, 192)
            label = "high_entropy"
        else:
            text = _gen_high_entropy_ascii(rng, 320)
            label = "high_entropy"

        cases.append(
            _attack_case(
                f"mutation_encoded_blob_{idx + 1}",
                text,
                label,
            )
        )

    return [case.as_dict() for case in cases]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate nightly mutation/fuzz bake-off corpus."
    )
    parser.add_argument(
        "--out",
        default="bench/obfuscation_corpus/nightly_mutations.json",
        help="Output corpus path.",
    )
    parser.add_argument(
        "--count-per-operator",
        type=int,
        default=12,
        help="Number of cases generated for each mutation operator family.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1337,
        help="Deterministic PRNG seed.",
    )
    args = parser.parse_args()

    count_per_operator = max(1, int(args.count_per_operator))
    cases = _generate_cases(count_per_operator, int(args.seed))
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(cases, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(
        "Wrote mutation corpus: "
        f"{out_path} "
        f"(cases={len(cases)}, operators=4, count_per_operator={count_per_operator}, seed={int(args.seed)})"
    )


if __name__ == "__main__":
    main()
