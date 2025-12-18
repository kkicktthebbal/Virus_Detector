import google.generativeai as genai

genai.configure(api_key="AIzaSyAmq7WT2kE0pnp7Vo5ASGpsDcSoxYRfUJI")

for m in genai.list_models():
    if "generateContent" in m.supported_generation_methods:
        print(m.name)
