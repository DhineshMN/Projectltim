# src/text_normalize.py
import re
import unicodedata
import ftfy
import emoji

# This dictionary is used to remove zero-width characters that can interfere with text processing.
ZERO_WIDTH = dict.fromkeys([0x200B, 0x200C, 0x200D, 0xFEFF], None)

# This mapping helps defend against "leetspeak" (e.g., replacing '0' with 'o').
LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a", "!": "i"
})

def normalize_text(s: str) -> str:
    """
    A robust function to clean and normalize user-generated content.
    It handles Unicode issues, leetspeak, repeated characters, and emojis.
    """
    if not isinstance(s, str):
        s = str(s)
    
    # 1. Fix encoding issues and inconsistencies (e.g., mojibake).
    s = ftfy.fix_text(s)
    
    # 2. Normalize Unicode to a standard form (NFKC).
    s = unicodedata.normalize("NFKC", s)
    
    # 3. Remove zero-width characters.
    s = s.translate(ZERO_WIDTH)
    
    # 4. Convert to lowercase.
    s = s.lower()
    
    # 5. Collapse characters repeated 3 or more times down to 2 (e.g., "heellooo" -> "heelloo").
    s = re.sub(r"(.)\1{2,}", r"\1\1", s)
    
    # 6. Convert emojis to their text representation (e.g., 😊 -> ":smiling_face_with_smiling_eyes:").
    s = emoji.replace_emoji(s, replace=lambda ch, _: f" {emoji.demojize(ch)} ")
    
    # 7. Apply the leetspeak map.
    s = s.translate(LEET_MAP)
    
    # 8. Remove any characters that are not letters, numbers, or basic punctuation.
    s = re.sub(r"[^a-z0-9\s:,_\-\.\!\?@#\$%]", " ", s)
    
    # 9. Collapse multiple spaces into a single space and trim whitespace.
    s = " ".join(s.split())
    
    return s