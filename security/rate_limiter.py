import time


class RateLimiter:

    def __init__(self, limit_per_sec=50):
        self.limit = limit_per_sec
        self.requests = {}   # ✅ MUST exist

    def is_allowed(self, node_id):

        now = time.time()

        if node_id not in self.requests:
            self.requests[node_id] = []

        # keep only last 1 second
        self.requests[node_id] = [
            t for t in self.requests[node_id] if now - t < 1
        ]

        if len(self.requests[node_id]) >= self.limit:
            return False

        self.requests[node_id].append(now)
        return True


# singleton instance
rate_limiter = RateLimiter()