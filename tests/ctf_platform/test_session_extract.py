import pytest

from vulnclaw.ctf_platform import session


class _FakeTok:
    def __init__(self, raw):
        self._raw = raw

    def group(self, _n=0):
        return self._raw

    def start(self):
        return 0

    def end(self):
        return len(self._raw)


# header.payload.signature with a decodable payload
def _jwt(exp: int) -> str:
    import base64, json

    def b64(s: bytes) -> str:
        return base64.urlsafe_b64encode(s).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"username": "awyeh", "role": "user", "exp": exp}).encode())
    sig = b64(b"signature-bytes-for-testing-0123456789")
    return f"{header}.{payload}.{sig}"


def test_jwt_exp_parses():
    assert session._jwt_exp(_jwt(2000000000)) == 2000000000
    assert session._jwt_exp("not-a-jwt") is None


def test_scan_prefers_live_token(monkeypatch, tmp_path):
    level = tmp_path / "leveldb"
    level.mkdir()
    (level / "x.ldb").write_bytes(b"pad " + _jwt(100).encode() + b" pad")
    (level / "y.ldb").write_bytes(b"pad " + _jwt(2000000000).encode() + b" pad")
    found = session._scan_leveldb_dir(str(level))
    exps = sorted(e for e, _ in found)
    assert exps == [100, 2000000000]


def test_read_edge_session_token_skips_expired(monkeypatch):
    monkeypatch.setattr(
        "vulnclaw.ctf_platform.session._profiles",
        lambda: [],
    )
    assert session.read_edge_session_token() == ""