import google.generativeai as genai
import sys

# Ensure UTF-8 output even on Windows
sys.stdout.reconfigure(encoding='utf-8')

GEMINI_API_KEY = "AIzaSyA8LdcAaaSBEuGTV6jD4HEvKDSrY8L6TOI"
genai.configure(api_key=GEMINI_API_KEY)

try:
    print("AVAILABLE_MODELS_START")
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(f"MODEL: {m.name}")
    print("AVAILABLE_MODELS_END")
except Exception as e:
    print(f"ERROR: {e}")
