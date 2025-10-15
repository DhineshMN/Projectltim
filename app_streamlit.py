# app_streamlit.py
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
import torch
import time
from pathlib import Path

# Import your custom modules from the src/ folder
from src.text_normalize import normalize_text
from src.pii import detect_pii, redact
from src.overrides import apply_overrides # Import the comprehensive override function

# --- Page Configuration ---
st.set_page_config(
    page_title="Toxicity & PII Early Warning System",
    page_icon="🛡️",
    layout="wide",
)

# --- Caching: Load Models and Artifacts ---
@st.cache_resource
def load_artifacts():
    """Load all models, tokenizers, and policy from the outputs directory."""
    artifacts = {}
    output_dir = Path("outputs")
    
    artifacts["vectorizer"] = joblib.load(output_dir / "tfidf_char_3_4.joblib")
    artifacts["calibrated_lr"] = joblib.load(output_dir / "lr_calibrated.joblib")

    with open(output_dir / "policy.json", "r") as f:
        artifacts["policy"] = json.load(f)

    bert_dir = output_dir / "bert_bin"
    iso_path = output_dir / "bert_iso.pkl"
    if bert_dir.is_dir() and iso_path.exists():
        artifacts["has_bert"] = True
        device = "cuda" if torch.cuda.is_available() else "cpu"
        artifacts["device"] = device
        
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        
        artifacts["bert_tokenizer"] = AutoTokenizer.from_pretrained(bert_dir)
        artifacts["bert_model"] = AutoModelForSequenceClassification.from_pretrained(bert_dir).to(device).eval()
        artifacts["bert_calibrator"] = joblib.load(iso_path)
    else:
        artifacts["has_bert"] = False
        st.warning("BERT model artifacts not found. The app will run in fast, LR-only mode.")

    return artifacts

ARTIFACTS = load_artifacts()
POLICY = ARTIFACTS["policy"]

# --- Core Scoring Logic (The Cascade Function with Overrides) ---
def score_comment_cascade(text: str):
    """
    Scores a single comment using the cascade model and applies safelist/blocklist overrides.
    """
    if not isinstance(text, str) or not text.strip():
        return { "prob_final": 0.0, "tier": "VERY_LOW", "pii_hits": [], "redacted": text, "escalated_to_bert": False }

    text_norm = normalize_text(text)
    
    vec = ARTIFACTS["vectorizer"]
    cal_lr = ARTIFACTS["calibrated_lr"]
    prob_lr = float(cal_lr.predict_proba(vec.transform([text_norm]))[0, 1])
    
    prob_final = prob_lr
    escalated = False

    LR_GRAY_LOW, LR_GRAY_HIGH = 0.10, 0.60
    if ARTIFACTS["has_bert"] and (LR_GRAY_LOW <= prob_lr < LR_GRAY_HIGH):
        escalated = True
        tok = ARTIFACTS["bert_tokenizer"]
        mdl = ARTIFACTS["bert_model"]
        iso = ARTIFACTS["bert_calibrator"]
        device = ARTIFACTS["device"]

        with torch.no_grad():
            enc = tok(text_norm, truncation=True, max_length=128, return_tensors="pt").to(device)
            logits = mdl(**enc).logits
            prob_raw = float(torch.softmax(logits, dim=-1)[0, 1].item())
        
        prob_final = float(iso.predict([prob_raw])[0])

    initial_tier = "HIGH" if prob_final >= POLICY["high"] else \
                   "MEDIUM" if prob_final >= POLICY["medium"] else \
                   "LOW" if prob_final >= POLICY["low"] else "VERY_LOW"

    # Apply the comprehensive safelist/blocklist override rules from overrides.py
    prob_final, final_tier = apply_overrides(text, prob_final, initial_tier)
    
    pii_hits = detect_pii(text)
    redacted_text = redact(text, pii_hits)
    
    return {
        "prob_final": prob_final,
        "tier": final_tier,
        "pii_hits": [(kind, val) for kind, _, val in pii_hits],
        "redacted": redacted_text,
        "escalated_to_bert": escalated
    }

# --- Streamlit User Interface ---

st.title("🛡️ Community Moderation Early Warning System")
st.markdown("This application analyzes user-generated comments for toxicity and PII in real-time using a fast cascade model with rule-based overrides.")

st.header("Analyze Comments")

input_text = st.text_area(
    "Enter one or more comments below, separated by new lines:",
    height=200,
    value="Have a nice day!\nyou killed my plant\ni wish he dies on the field naked\nmy opponent team cricketer is playing great and i wish he dies on the field naked with his third leg standing\nschool advised pupils not to use words like bitch,fuck"
)

if st.button("Analyze", type="primary", use_container_width=True):
    comments = [c.strip() for c in input_text.split('\n') if c.strip()]
    if comments:
        with st.spinner(f"Analyzing {len(comments)} comment(s)..."):
            start_time = time.time()
            results = [score_comment_cascade(c) for c in comments]
            end_time = time.time()
            
            total_time = end_time - start_time
            latency_ms = (total_time / len(comments)) * 1000
            st.success(f"Analyzed {len(comments)} comments in {total_time:.2f} seconds ({latency_ms:.1f} ms/comment avg).")
        
        st.header("Analysis Results")
        
        display_data = []
        for i, res in enumerate(results):
            display_data.append({
                "Comment": comments[i],
                "Toxicity Score": f"{res['prob_final']:.3f}",
                "Risk Tier": res["tier"],
                "PII Detected": ", ".join([k for k, v in res["pii_hits"]]) if res["pii_hits"] else "None",
                "Redacted Text": res["redacted"],
                "Model Used": "BERT" if res["escalated_to_bert"] else "LR"
            })
        
        df_results = pd.DataFrame(display_data)
        
        # This function handles all of our custom tiers with appropriate colors.
        def style_tier(tier):
            color = {
                "HIGH": "#FF4B4B",              # Red for high-risk model predictions
                "OVERRIDE_TOXIC": "#B22222",    # Darker Red for blocklist rule triggers
                "MEDIUM": "#FFA500",            # Orange for medium risk
                "LOW": "#1F77B4",               # Blue for low risk
                "VERY_LOW": "#2CA02C",           # Green for safe
                "OVERRIDE_SAFE": "#800080"      # Purple for safelist rule triggers
            }.get(tier, "grey")
            return f'background-color: {color}; color: white; font-weight: bold;'

        st.dataframe(
            df_results.style.apply(lambda col: col.map(style_tier), subset=['Risk Tier']),
            use_container_width=True,
            hide_index=True
        )

    else:
        st.warning("Please enter at least one comment to analyze.")

# --- Sidebar ---
with st.sidebar:
    st.header("System Information")
    st.markdown("""
    This app uses a three-stage system for robust content moderation:
    
    1.  **Fast Baseline (LR):** A lightweight `TF-IDF + Logistic Regression` model provides an initial score.
    
    2.  **Advanced Gate (BERT):** If the LR score is ambiguous, the comment is escalated to a `DistilBERT` model.

    3.  **Overrides:** A final layer of safelist/blocklist rules checks the text to correct known model errors and catch nuanced toxicity.
    """)
    
    st.subheader("Risk Tiers & Actions")
    st.markdown(f"""
    - **<span style='color:#B22222; font-weight:bold;'>OVERRIDE_TOXIC</span>:** Matched a high-severity blocklist rule.
    - **<span style='color:#FF4B4B; font-weight:bold;'>HIGH</span> (`>={POLICY['high']:.2f}`):** Strong toxic signal from model.
    - **<span style='color:#FFA500; font-weight:bold;'>MEDIUM</span> (`>={POLICY['medium']:.2f}`):** Borderline content.
    - **<span style='color:#1F77B4; font-weight:bold;'>LOW</span> (`>={POLICY['low']:.2f}`):** Potentially problematic.
    - **<span style='color:#2CA02C; font-weight:bold;'>VERY_LOW</span>:** Likely safe.
    - **<span style='color:#800080; font-weight:bold;'>OVERRIDE_SAFE</span>:** Matched a safelist rule.
    """, unsafe_allow_html=True)

    st.subheader("PII Detection")
    st.markdown("Detects and redacts Emails, Phone Numbers, and Credit Card-like numbers.")