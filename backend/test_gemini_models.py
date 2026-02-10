import google.generativeai as genai

GEMINI_API_KEY = "AIzaSyA8LdcAaaSBEuGTV6jD4HEvKDSrY8L6TOI"
genai.configure(api_key=GEMINI_API_KEY)

models_to_test = ['gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-1.5-flash-latest']

for model_name in models_to_test:
    try:
        print(f"Testing {model_name}...")
        model = genai.GenerativeModel(model_name)
        response = model.generate_content("Hello")
        print(f"SUCCESS with {model_name}")
        break
    except Exception as e:
        print(f"FAILED with {model_name}: {e}")
