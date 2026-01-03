import streamlit as st
import pandas as pd

from preprocess import preprocess_logs
from detection_engine import run_detections
from agent import enrich_with_ai

# -------------------------------------------------
# PAGE CONFIG
# -------------------------------------------------
st.set_page_config(
    page_title="AI SOC Assistant",
    layout="wide"
)

# -------------------------------------------------
# CLEAN WHITE + VIBRANT CSS
# -------------------------------------------------
st.markdown("""
<style>

/* Main background */
.stApp {
    background-color: #ffffff;
    color: #1f2933;
    font-family: 'Segoe UI', sans-serif;
}

/* Headings */
h1 {
    color: #2563eb;
    font-weight: 700;
}
h2, h3 {
    color: #111827;
}

/* Info text */
.subtitle {
    color: #6b7280;
    font-size: 1rem;
    margin-bottom: 20px;
}

/* Threat card */
.threat-card {
    background-color: #f9fafb;
    padding: 22px;
    border-radius: 16px;
    margin-bottom: 24px;
    border-left: 8px solid #2563eb;
    box-shadow: 0 10px 25px rgba(0,0,0,0.05);
}

/* Severity styles */
.sev-CRITICAL {
    color: #dc2626;
    font-weight: 700;
}
.sev-HIGH {
    color: #ea580c;
    font-weight: 700;
}
.sev-MEDIUM {
    color: #d97706;
    font-weight: 700;
}
.sev-LOW {
    color: #16a34a;
    font-weight: 700;
}

/* Section labels */
.section {
    font-size: 0.85rem;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 18px;
}

/* Evidence list */
.evidence-box {
    background-color: #ffffff;
    padding: 12px;
    border-radius: 10px;
    border: 1px solid #e5e7eb;
    margin-top: 8px;
}

</style>
""", unsafe_allow_html=True)

# -------------------------------------------------
# HEADER
# -------------------------------------------------
st.markdown("<h1>AI-Powered SOC Assistant</h1>", unsafe_allow_html=True)
st.markdown(
    "<div class='subtitle'>Structured threat detection, AI-assisted analysis, and actionable security insights.</div>",
    unsafe_allow_html=True
)

# -------------------------------------------------
# FILE UPLOAD
# -------------------------------------------------
uploaded_file = st.file_uploader(
    "Upload Authentication Logs (CSV)",
    type=["csv"]
)

# -------------------------------------------------
# MAIN LOGIC
# -------------------------------------------------
if uploaded_file:
    try:
        logs = pd.read_csv(uploaded_file)
        logs = preprocess_logs(logs)

        detections = run_detections(logs)

        if not detections:
            st.success("No malicious activity detected. System behavior appears normal.")
        else:
            st.warning("Security threats detected. Review the findings below.")

            for threat in detections:
                threat = enrich_with_ai(threat)
                severity = threat["severity"]

                st.markdown(f"""
                <div class="threat-card">
                    <h3>{threat['threat']}</h3>
                    <p class="sev-{severity}">Severity: {severity}</p>

                    <div class="section">AI Insight</div>
                    <p>{threat['ai_summary']}</p>

                    <div class="section">What Happened</div>
                    <p>{threat['why']}</p>

                    <div class="section">Who Was Involved</div>
                    <div class="evidence-box">
                """, unsafe_allow_html=True)

                # Who section
                for key, values in threat["who"].items():
                    st.write(f"**{key.capitalize()}**: {', '.join(map(str, values))}")

                st.markdown("<div class='section'>Evidence</div>", unsafe_allow_html=True)
                st.markdown("<div class='evidence-box'>", unsafe_allow_html=True)

                # Evidence section
                for k, v in threat["evidence"].items():
                    st.write(f"IP `{k}` → {v} events")

                st.markdown("</div>", unsafe_allow_html=True)

                st.markdown("<div class='section'>Recommended Actions</div>", unsafe_allow_html=True)
                for action in threat["action"]:
                    st.write(f"• {action}")

                st.markdown("</div>", unsafe_allow_html=True)

    except Exception as e:
        st.error("Error processing the uploaded log file.")
        st.code(str(e))
