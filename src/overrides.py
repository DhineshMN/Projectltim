# src/overrides.py
import re

# --- Blocklist Categories (Upgrade Risk to TOXIC) ---
# ... (All your blocklist patterns like THREAT_PATTERNS, OBSCENE_PATTERNS, etc. remain here) ...
# 1. Patterns for severe threats or wishes of harm.
THREAT_PATTERNS = [
    re.compile(r"\b(i wish|hope)\s(you|he|she|they)\s(die|dies|died)\b", re.IGNORECASE),
    re.compile(r"\b(kill\syour\s?self|k\s?y\s?s)\b", re.IGNORECASE),
]
# 2. Patterns for vulgar or obscene sexual references.
OBSCENE_PATTERNS = [
    re.compile(r"\b(his|my|your)\s(third|3rd)\s(leg)\b", re.IGNORECASE),
]
# 3. Patterns for insults, humiliation, and social attacks.
INSULT_PATTERNS = [
    re.compile(r"\b(i wish|hope)\s(you|he|she|they)\b.*?\b(humiliating|fail|suffer)\b", re.IGNORECASE),
    re.compile(r"\b(idiot|moron|stupid|dumb|loser|pathetic|bitch|fuck)\b", re.IGNORECASE), # Added common profanity here
]
# 4. Patterns for veiled insults & passive-aggression.
PASSIVE_AGGRESSIVE_PATTERNS = [
    re.compile(r"(?:bless\syour\s(little\s)?heart)", re.IGNORECASE),
    re.compile(r"(?:i'm\ssure\syou\sthink)", re.IGNORECASE),
    re.compile(r"(?:must\sbe\snice\sto\sbe)", re.IGNORECASE),
]
# 5. Patterns for dog whistles & coded hate speech (add with care).
DOG_WHISTLE_PATTERNS = [
    re.compile(r"\b(13/52|13/90)\b"),
    re.compile(r"\b(globalist\sagenda)\b", re.IGNORECASE),
]
# 6. Patterns for glorification of violence.
GLORIFICATION_PATTERNS = [
    re.compile(r"\b(got\swhat\s(he|she|they)\sdeserved)\b", re.IGNORECASE),
    re.compile(r"\b(is\sa\shero\sfor\swhat\s(he|she)\sdid)\b", re.IGNORECASE),
]
# 7. Patterns for subtle self-harm encouragement.
SUBTLE_THREAT_PATTERNS = [
    re.compile(r"\b(world\swould\sbe\sbetter\swithout\syou)\b", re.IGNORECASE),
    re.compile(r"\b(nobody\swould\seven\snotice\sif\syou\swere\sgone)\b", re.IGNORECASE),
]
# 8. Patterns for identity-based insults without slurs.
IDENTITY_ATTACK_PATTERNS = [
    re.compile(r"\b(of\scourse\sa\s(woman|man)\swould)\b", re.IGNORECASE),
    re.compile(r"\b(typical\s(french|american|german|etc)\sbehavior)\b", re.IGNORECASE),
]
# 9. Patterns for spam and malicious links.
SPAM_PATTERNS = [
    re.compile(r"\b(free\sfollowers|buy\sfollwers|crypto\sgains)\b", re.IGNORECASE),
    re.compile(r"(bit\.ly/|tinyurl\.com/)", re.IGNORECASE),
]

BLOCKLIST_PATTERNS = (
    THREAT_PATTERNS + OBSCENE_PATTERNS + INSULT_PATTERNS + 
    PASSIVE_AGGRESSIVE_PATTERNS + DOG_WHISTLE_PATTERNS + 
    GLORIFICATION_PATTERNS + SUBTLE_THREAT_PATTERNS + 
    IDENTITY_ATTACK_PATTERNS + SPAM_PATTERNS
)


# --- Safelist Categories (Downgrade Risk to SAFE) ---
NEGATIVE_VERBS = r"(killed|dead|destroyed|attacked|shot|poison|cancer|disease)"
HARMLESS_OBJECTS = r"(plant|battery|phone|car|game|server|computer|process|task|job|engine|ui|feature|logic)"

# NEW: High-priority patterns for meta-discussion about words
META_PATTERNS = [
    re.compile(r"\b(words\slike|the\sword|saying)\s(bitch|fuck|idiot|stupid)\b", re.IGNORECASE),
]

# General safelist patterns
GENERAL_SAFELIST_PATTERNS = [
    re.compile(r"\b(my\s)?" + NEGATIVE_VERBS + r"(\smy)?\s" + HARMLESS_OBJECTS + r"\b", re.IGNORECASE),
    re.compile(r"\b(the\s)?" + HARMLESS_OBJECTS + r"(\sis|\swas)?\s(dead|died)\b", re.IGNORECASE),
    re.compile(r"\b(kill the|killing the)\s(process|job|server|task)\b", re.IGNORECASE),
    re.compile(r"\b(this|your)\s" + HARMLESS_OBJECTS + r"\s(is|is\san)\s(absolute\s)?(cancer|poison|disease)\b", re.IGNORECASE),
]

SAFELIST_PATTERNS = META_PATTERNS + GENERAL_SAFELIST_PATTERNS


# --- Main Override Function ---
def apply_overrides(text: str, original_prob: float, original_tier: str):
    """
    Applies both safelist and blocklist rules. 
    Crucially, meta-discussion safelists run BEFORE the blocklist.
    """
    # 1. Check for META-DISCUSSION safelists first. This is a high-priority override.
    for pattern in META_PATTERNS:
        if pattern.search(text):
            return 0.01, "OVERRIDE_SAFE"

    # 2. If it wasn't a meta-comment, check the BLOCKLIST.
    for pattern in BLOCKLIST_PATTERNS:
        if pattern.search(text):
            return 0.99, "OVERRIDE_TOXIC"

    # 3. If no blocklist pattern matched, check the GENERAL SAFELIST.
    if original_tier in ["MEDIUM", "HIGH"]:
        for pattern in GENERAL_SAFELIST_PATTERNS:
            if pattern.search(text):
                return 0.01, "OVERRIDE_SAFE"

    # 4. If no rules triggered, return the model's original prediction.
    return original_prob, original_tier