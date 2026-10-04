import streamlit as st

from url_analyzer import analyze_url
from email_analyzer import analyze_email


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="Phishing Detection System",
    page_icon="🛡️",
    layout="wide"
)


# ---------------------------------------------------------
# CUSTOM CSS
# ---------------------------------------------------------

st.markdown(
    """
    <style>

    .main {
        background-color: #0b1120;
    }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }

    .main-title {
        font-size: 42px;
        font-weight: 700;
        text-align: center;
        color: #ffffff;
        margin-bottom: 5px;
    }

    .subtitle {
        text-align: center;
        color: #94a3b8;
        font-size: 17px;
        margin-bottom: 35px;
    }

    .section-title {
        font-size: 25px;
        font-weight: 600;
        color: #e2e8f0;
        margin-top: 10px;
    }

    .risk-high {
        padding: 15px;
        border-radius: 10px;
        background-color: #3f1515;
        border: 1px solid #ef4444;
        color: #fecaca;
        font-weight: 600;
    }

    .risk-medium {
        padding: 15px;
        border-radius: 10px;
        background-color: #3f3012;
        border: 1px solid #f59e0b;
        color: #fde68a;
        font-weight: 600;
    }

    .risk-low {
        padding: 15px;
        border-radius: 10px;
        background-color: #12351f;
        border: 1px solid #22c55e;
        color: #bbf7d0;
        font-weight: 600;
    }

    .indicator {
        padding: 10px;
        margin-bottom: 8px;
        border-radius: 7px;
        background-color: #172033;
        border-left: 4px solid #64748b;
        color: #e2e8f0;
    }

    .footer {
        text-align: center;
        color: #64748b;
        margin-top: 40px;
        font-size: 13px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------

st.markdown(
    '<div class="main-title">🛡️ PHISHING DETECTION SYSTEM</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'URL & Email Security Analysis using Cybersecurity Heuristics'
    '</div>',
    unsafe_allow_html=True
)


# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------

with st.sidebar:

    st.header("🛡️ Security Analyzer")

    analysis_type = st.radio(
        "Choose analysis type:",
        [
            "🔗 URL Analysis",
            "📧 Email Analysis"
        ]
    )

    st.divider()

    st.markdown("### 🔎 Detection Methods")

    st.write("• Suspicious keywords")
    st.write("• HTTP / HTTPS analysis")
    st.write("• IP address detection")
    st.write("• URL shorteners")
    st.write("• Suspicious TLDs")
    st.write("• URL structure analysis")
    st.write("• Urgency & social engineering")
    st.write("• Sensitive information requests")

    st.divider()

    st.caption(
        "Educational cybersecurity project. "
        "Results are heuristic-based."
    )


# ---------------------------------------------------------
# RESULT DISPLAY FUNCTION
# ---------------------------------------------------------

def display_result(result):

    score = result["score"]
    risk_level = result["risk_level"]
    classification = result["classification"]

    st.divider()

    st.subheader("📊 Analysis Result")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Risk Score",
            f"{score}/100"
        )

    with col2:
        st.metric(
            "Risk Level",
            risk_level
        )

    with col3:
        st.metric(
            "Classification",
            classification
        )

    # Risk message
    if risk_level == "High":

        st.markdown(
            """
            <div class="risk-high">
            🔴 HIGH RISK — Multiple strong phishing indicators detected.
            </div>
            """,
            unsafe_allow_html=True
        )

    elif risk_level == "Medium":

        st.markdown(
            """
            <div class="risk-medium">
            🟡 MEDIUM RISK — Suspicious characteristics were detected.
            </div>
            """,
            unsafe_allow_html=True
        )

    else:

        if score == 0:

            message = (
                "🟢 LOW RISK — No major phishing indicators detected."
            )

        else:

            message = (
                "🟢 LOW RISK — Only minor security indicators detected."
            )

        st.markdown(
            f"""
            <div class="risk-low">
            {message}
            </div>
            """,
            unsafe_allow_html=True
        )

    # Indicators
    st.subheader("🔎 Detected Indicators")

    for indicator in result["indicators"]:

        st.markdown(
            f"""
            <div class="indicator">
            • {indicator}
            </div>
            """,
            unsafe_allow_html=True
        )


# =========================================================
# URL ANALYSIS
# =========================================================

if analysis_type == "🔗 URL Analysis":

    st.markdown(
        '<div class="section-title">🔗 Analyze a URL</div>',
        unsafe_allow_html=True
    )

    st.write(
        "Enter a website URL to check for common phishing indicators."
    )

    url = st.text_input(
        "Website URL",
        placeholder="Example: https://www.google.com"
    )

    col1, col2 = st.columns([1, 5])

    with col1:

        analyze_button = st.button(
            "🔍 Analyze URL",
            use_container_width=True
        )

    if analyze_button:

        if not url.strip():

            st.error("Please enter a URL.")

        else:

            result = analyze_url(url)

            display_result(result)


# =========================================================
# EMAIL ANALYSIS
# =========================================================

else:

    st.markdown(
        '<div class="section-title">📧 Analyze an Email</div>',
        unsafe_allow_html=True
    )

    st.write(
        "Paste an email message to identify possible phishing "
        "and social-engineering indicators."
    )

    email_text = st.text_area(
        "Email Content",
        height=250,
        placeholder=(
            "Example:\n\n"
            "URGENT! Your account has been suspended.\n"
            "Click here to verify your password immediately."
        )
    )

    col1, col2 = st.columns([1, 5])

    with col1:

        analyze_button = st.button(
            "🔍 Analyze Email",
            use_container_width=True
        )

    if analyze_button:

        if not email_text.strip():

            st.error("Please enter email content.")

        else:

            result = analyze_email(email_text)

            display_result(result)


# ---------------------------------------------------------
# FOOTER
# ---------------------------------------------------------

st.markdown(
    """
    <div class="footer">
    Phishing Detection System • Cybersecurity Internship Project
    <br>
    Rule-based heuristic analysis — educational use only
    </div>
    """,
    unsafe_allow_html=True
)