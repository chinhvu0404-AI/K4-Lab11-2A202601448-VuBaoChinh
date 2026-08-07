"""Sliding-window per-user rate limiter."""
from __future__ import annotations
from collections import defaultdict, deque
import time
from google.adk.plugins import base_plugin
from google.genai import types

class RateLimitPlugin(base_plugin.BasePlugin):
    """Block a user after max_requests in a rolling time window."""
    def __init__(self, max_requests: int = 10, window_seconds: int = 60, clock=None):
        super().__init__(name="rate_limiter")
        self.max_requests, self.window_seconds = max_requests, window_seconds
        self.clock = clock or time.time
        self.user_windows = defaultdict(deque)
        self.blocked_count = self.total_count = 0
    def _block_response(self, message: str) -> types.Content:
        return types.Content(role="model", parts=[types.Part.from_text(text=message)])
    async def on_user_message_callback(self, *, invocation_context, user_message):
        self.total_count += 1
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        now, window = self.clock(), self.user_windows[user_id]
        while window and window[0] <= now - self.window_seconds:
            window.popleft()
        if len(window) >= self.max_requests:
            self.blocked_count += 1
            wait = max(0, self.window_seconds - (now - window[0]))
            return self._block_response(f"Rate limit exceeded. Try again in {wait:.0f}s.")
        window.append(now)
        return None

