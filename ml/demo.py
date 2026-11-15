
from pathlib import Path
import streamlit as st
from predict import predict_url

st.set_page_config(
    page_title="WebShield ML Detector",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ WebShield")
st.subheader("Machine Learning Phishing URL Detector")
st.write(
    "Enter a URL to analyze it using the trained "
    "Random Forest model."
)

url = st.text_input(
    "Website URL",
    placeholder="https://example.com"
)

if st.button("Check URL", type="primary"):
    if not url.strip():
        st.warning("Please enter a URL first.")
    else:
       
            
        try:
            artifact_dir = Path(__file__).resolve().parent / "artifacts"
            result = predict_url(url.strip(), artifact_dir)

            st.write("### Prediction")
            prediction = result.get("prediction", "Unknown")

            st.write("### Prediction")
            prediction = result.get("prediction", "Unknown")

            if prediction == "phishing":
                st.error("⚠️ Potential phishing URL")
            elif prediction == "legitimate":
                st.success("✅ Predicted legitimate")
            else:
                st.info(f"Prediction: {prediction}")

            st.write("### Model details")
            st.write("Model:", result.get("model", "Unknown"))

            probabilities = result.get("probabilities", {})
            if probabilities:
                st.write("### Predicted probabilities")
                st.json(probabilities)

            st.write("### Extracted URL features")
            st.json(result.get("features", {}))

            st.caption(
                "This is an ML prediction, not a guarantee "
                "that a website is safe or malicious."
            )

        except Exception as exc:
            st.error(f"Prediction failed: {exc}")
            st.info(
                "Check that the saved model exists and that "
                "the prediction module is working."
            )
