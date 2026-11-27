from rate_limiter import RateLimiter


class FakeClock:
    """A clock the test can move forward by hand."""

    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def test_allows_up_to_limit_then_blocks():
    limiter = RateLimiter(limit=10, window=1.0, clock=FakeClock())
    assert all(limiter.allow("1.2.3.4") for _ in range(10))
    assert not limiter.allow("1.2.3.4")


def test_window_slides():
    clock = FakeClock()
    limiter = RateLimiter(limit=2, window=1.0, clock=clock)
    assert limiter.allow("ip") and limiter.allow("ip")
    clock.now += 0.5
    assert not limiter.allow("ip")
    clock.now += 0.5  # the first two hits are now a full second old
    assert limiter.allow("ip")


def test_clients_are_limited_separately():
    limiter = RateLimiter(limit=1, window=1.0, clock=FakeClock())
    assert limiter.allow("a")
    assert not limiter.allow("a")
    assert limiter.allow("b")
