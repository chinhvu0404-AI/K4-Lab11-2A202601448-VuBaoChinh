"""Lab configuration and local API-key setup."""
import os
from dotenv import load_dotenv

def setup_api_key():
    """Load .env without ever printing the key."""
    load_dotenv()
    if "GOOGLE_API_KEY" not in os.environ:
        raise RuntimeError("GOOGLE_API_KEY is required; add it to .env or the environment.")
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print("API key loaded.")

ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer", "loan", "interest", "savings",
    "credit", "deposit", "withdrawal", "balance", "payment", "tai khoan", "giao dich",
    "tiet kiem", "lai suat", "chuyen tien", "the tin dung", "so du", "vay", "ngan hang", "atm",
]
BLOCKED_TOPICS = ["hack", "exploit", "weapon", "drug", "illegal", "violence", "gambling", "bomb", "kill", "steal"]

