"""Sliding time-window rate limiter used on POST /auth."""

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    """Allow at most `limit` requests per `window` seconds for each client.

    Each client (keyed by IP) has a queue of the times its allowed requests
    came in. Times older than the window are dropped, and if the queue is
    still full the request is refused. A lock keeps this correct when Flask
    handles requests on several threads at once.
    """

    def __init__(self, limit=10, window=1.0, clock=time.monotonic):
        self.limit = limit
        self.window = window
        self.clock = clock
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, client):
        """Return True and count the request if the client is under the limit."""
        now = self.clock()
        with self._lock:
            hits = self._hits[client]
            while hits and hits[0] <= now - self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True
