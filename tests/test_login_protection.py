from blockwart.services.login_protection import LoginProtector


def _protector(clock, *, max_password_concurrency: int = 2) -> LoginProtector:
    return LoginProtector(
        window_seconds=60,
        source_attempt_limit=2,
        account_attempt_limit=2,
        global_attempt_limit=10,
        source_challenge_limit=2,
        global_challenge_limit=10,
        max_password_concurrency=max_password_concurrency,
        clock=lambda: clock[0],
    )


def test_login_protector_bounds_sources_accounts_and_challenges_without_raw_keys() -> None:
    clock = [100.0]
    protector = _protector(clock)

    assert protector.allow_challenge(source="198.51.100.10")
    assert protector.allow_challenge(source="198.51.100.10")
    assert not protector.allow_challenge(source="198.51.100.10")

    first = protector.acquire_password_attempt(
        source="198.51.100.10",
        login="Sensitive.Account",
    )
    second = protector.acquire_password_attempt(
        source="198.51.100.10",
        login="sensitive.account",
    )
    denied = protector.acquire_password_attempt(
        source="198.51.100.10",
        login="different.account",
    )
    assert first.allowed
    assert second.allowed
    assert not denied.allowed
    assert denied.event_due
    assert "198.51.100.10" not in repr(protector.__dict__)
    assert "sensitive.account" not in repr(protector.__dict__).casefold()
    first.__exit__(None, None, None)
    second.__exit__(None, None, None)

    clock[0] += 61
    assert protector.allow_challenge(source="198.51.100.10")
    allowed_again = protector.acquire_password_attempt(
        source="198.51.100.10",
        login="sensitive.account",
    )
    assert allowed_again.allowed
    allowed_again.__exit__(None, None, None)


def test_login_protector_rejects_burst_when_argon_capacity_is_full() -> None:
    clock = [100.0]
    protector = _protector(clock, max_password_concurrency=1)

    first = protector.acquire_password_attempt(
        source="198.51.100.1",
        login="first.account",
    )
    assert first.allowed

    blocked = protector.acquire_password_attempt(
        source="198.51.100.2",
        login="second.account",
    )
    repeated = protector.acquire_password_attempt(
        source="198.51.100.3",
        login="third.account",
    )
    assert not blocked.allowed
    assert blocked.reason == "password_capacity"
    assert blocked.event_due
    assert not repeated.allowed
    assert not repeated.event_due

    first.__exit__(None, None, None)
    admitted = protector.acquire_password_attempt(
        source="198.51.100.4",
        login="fourth.account",
    )
    assert admitted.allowed
    admitted.__exit__(None, None, None)
