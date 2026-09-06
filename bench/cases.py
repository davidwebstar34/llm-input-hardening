from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BenchmarkCase:
    """One benchmark case.

    Attributes:
        name: Stable identifier used in output JSON and plots.
        text: The text input to sanitize.
        policy: Policy name to pass to sanitize.
        enabled: Allows quickly disabling a case without deleting it.
    """
    name: str
    text: str
    policy: str = "balanced_chat"
    enabled: bool = True


def default_cases() -> list[BenchmarkCase]:
    """Return a representative set of benchmark cases.

    These are deterministic and stable across runs so performance comparisons are meaningful.
    """
    ascii_1k = ("Hello world! " * 90)[:1024]
    ascii_32k = ("The quick brown fox jumps over the lazy dog. " * 800)[:32768]

    unicode_mixed_4k = ("café naïve fiancé — " * 80) + ("🙂" * 400) + ("a\u0301" * 400)
    unicode_mixed_4k = unicode_mixed_4k[:4096]

    # Bidi controls + invisibles (examples). The sanitizer should remove them.
    bidi_attack = ("SAFE " + "\u202E" + "EVIL " + "\u202C" + "SAFE ")*200
    bidi_attack = bidi_attack[:4096]

    invis_attack = ("hello" + "\u200b" + "world" + "\ufeff" + "!" + "\u2060") * 300
    invis_attack = invis_attack[:4096]

    # Encoded-looking payloads
    base64_blob = ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" * 256)[:8192]
    hex_blob = ("deadbeef" * 1024)[:8192]

    whitespace_explosion = ("word" + (" " * 40) + "\t\t") * 600
    whitespace_explosion = (whitespace_explosion + ("\n\n\n" * 200))[:16384]

    chat_prompt = (
        "SYSTEM: You are a helpful assistant.\n"
        "USER: Summarize the following text:\n"
        + ("lorem ipsum " * 250)
        + "\nASSISTANT: Sure — here is a summary.\n"
        "USER: Now extract the key points as bullets.\n"
    )
    chat_prompt = chat_prompt[:8192]

    return [
        BenchmarkCase("ascii_clean_1k", ascii_1k, "balanced_chat"),
        BenchmarkCase("ascii_clean_32k", ascii_32k, "balanced_chat"),
        BenchmarkCase("unicode_mixed_4k", unicode_mixed_4k, "balanced_chat"),
        BenchmarkCase("bidi_attack_4k", bidi_attack, "balanced_chat"),
        BenchmarkCase("invisible_attack_4k", invis_attack, "balanced_chat"),
        BenchmarkCase("base64_blob_8k", base64_blob, "balanced_chat"),
        BenchmarkCase("hex_blob_8k", hex_blob, "balanced_chat"),
        BenchmarkCase("whitespace_explosion_16k", whitespace_explosion, "balanced_chat"),
        BenchmarkCase("chat_prompt_8k", chat_prompt, "balanced_chat"),
    ]
