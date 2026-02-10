import google.generativeai as genai

GEMINI_API_KEY = "AIzaSyA8LdcAaaSBEuGTV6jD4HEvKDSrY8L6TOI"
genai.configure(api_key=GEMINI_API_KEY)

try:
    print("Testing gemini-1.5-flash-latest...")
    model = genai.GenerativeModel('gemini-1.5-flash-latest')
    response = model.generate_content("Hi")
    print(f"SUCCESS: {response.text}")
except Exception as e:
    print(f"ERROR: {e}")
