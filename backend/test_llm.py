import os
import sys
import json
import urllib.request
import urllib.error

def load_env(env_path=".env"):
    """Robust .env parser without external dependencies."""
    candidates = [env_path, os.path.join("..", env_path)]
    target_path = None
    for p in candidates:
        if os.path.exists(p):
            target_path = p
            break
    if not target_path:
        return

    with open(target_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                os.environ[k] = v

def test_gemini(api_key):
    print("Testing Google Gemini API...")
    preferred_model = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
    models_to_try = [preferred_model]
    for fallback in ["gemini-flash-lite-latest", "gemini-3.1-flash-lite", "gemini-3.8-flash"]:
        if fallback not in models_to_try:
            models_to_try.append(fallback)

    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "contents": [
            {"parts": [{"text": "Respond with exactly: 'LLM connection successful! PhishLens is ready.'"}]}
        ]
    }
    data = json.dumps(payload).encode("utf-8")

    last_error = None
    for model in models_to_try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            print(f"Connecting using model '{model}'...")
            with urllib.request.urlopen(req, timeout=15) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                reply = res_data["candidates"][0]["content"]["parts"][0]["text"]
                print(f"\n[Gemini Response ({model})]:\n{reply.strip()}\n")
                return True
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            last_error = f"HTTP {e.code}: {err_body}"
            print(f"Model {model} returned HTTP {e.code}, attempting fallback if available...")
        except Exception as e:
            last_error = str(e)
            print(f"Model {model} error: {e}, attempting fallback if available...")

    raise RuntimeError(f"Gemini API call failed across attempted models: {last_error}")

def test_anthropic(api_key):
    print("Testing Anthropic Claude API...")
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    payload = {
        "model": os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022"),
        "max_tokens": 100,
        "messages": [
            {"role": "user", "content": "Respond with: 'LLM connection successful! PhishLens is ready.'"}
        ]
    }
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as response:
        res_data = json.loads(response.read().decode("utf-8"))
        reply = res_data["content"][0]["text"]
        print(f"\n[Anthropic Response]:\n{reply.strip()}\n")
        return True

def test_openai(api_key):
    print("Testing OpenAI API...")
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "content-type": "application/json"
    }
    payload = {
        "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        "messages": [
            {"role": "user", "content": "Respond with: 'LLM connection successful! PhishLens is ready.'"}
        ]
    }
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as response:
        res_data = json.loads(response.read().decode("utf-8"))
        reply = res_data["choices"][0]["message"]["content"]
        print(f"\n[OpenAI Response]:\n{reply.strip()}\n")
        return True

def test_groq(api_key):
    print("Testing Groq API...")
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "content-type": "application/json"
    }
    payload = {
        "model": os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"),
        "messages": [
            {"role": "user", "content": "Respond with: 'LLM connection successful! PhishLens is ready.'"}
        ]
    }
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as response:
        res_data = json.loads(response.read().decode("utf-8"))
        reply = res_data["choices"][0]["message"]["content"]
        print(f"\n[Groq Response]:\n{reply.strip()}\n")
        return True

def main():
    load_env(".env")

    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    groq_key = os.getenv("GROQ_API_KEY")

    try:
        if gemini_key and not gemini_key.startswith("your_"):
            test_gemini(gemini_key)
        elif anthropic_key and not anthropic_key.startswith("your_"):
            test_anthropic(anthropic_key)
        elif openai_key and not openai_key.startswith("your_"):
            test_openai(openai_key)
        elif groq_key and not groq_key.startswith("your_"):
            test_groq(groq_key)
        else:
            print("No valid API key found in .env!")
            print("Please add one of the following to your .env file:")
            print("  GEMINI_API_KEY=...")
            print("  ANTHROPIC_API_KEY=sk-ant-...")
            print("  OPENAI_API_KEY=sk-...")
            print("  GROQ_API_KEY=gsk_...")
            sys.exit(1)

        print("[OK] Hour 1, Task 1 completed: LLM API key verified and working!")
    except Exception as e:
        print(f"Error testing LLM: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
