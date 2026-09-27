"""`MemoryStore`'s durable map must not lose a write made by another store instance.

Round5 residual item: `save`/`delete` mutated the in-memory cache OUTSIDE the file lock and
`_save` then wrote that cache wholesale, so the lock protected the FILE write but not the
read-modify-write around it. Two stores sharing a directory therefore both started from the
same base state and the later writer silently dropped the earlier writer's key.

Measured on HEAD (two instances, sequential calls, one process):

    a = MemoryStore(store_dir=d); b = MemoryStore(store_dir=d)
    a.save('k1', 'from-A')
    b.save('k2', 'from-B')
    # file keys -> ['k2']      <- k1 was lost, with no error anywhere
"""

from __future__ import annotations

import json
from pathlib import Path

from vulnclaw.agent.memory import MemoryStore


def _keys(store_dir: Path) -> list[str]:
    return sorted(json.loads((store_dir / "long_term.json").read_text(encoding="utf-8")))


class TestNoLostUpdateBetweenInstances:
    def test_a_second_instance_does_not_drop_the_first_ones_key(self, tmp_path):
        first = MemoryStore(store_dir=tmp_path)
        second = MemoryStore(store_dir=tmp_path)   # loads the same (empty) base state

        first.save("k1", "from-A")
        second.save("k2", "from-B")

        assert _keys(tmp_path) == ["k1", "k2"]

    def test_the_writer_sees_the_other_writers_data_afterwards(self, tmp_path):
        """Re-reading inside the lock refreshes this instance's cache as a side effect."""
        first = MemoryStore(store_dir=tmp_path)
        second = MemoryStore(store_dir=tmp_path)

        first.save("k1", "from-A")
        second.save("k2", "from-B")

        assert second.retrieve("k1") == "from-A"
        assert first.retrieve("k1") == "from-A"

    def test_a_delete_does_not_resurrect_a_key_from_a_stale_cache(self, tmp_path):
        """The delete direction is the same defect: a stale base state re-adds what was gone."""
        seed = MemoryStore(store_dir=tmp_path)
        seed.save("k1", "v1")

        stale = MemoryStore(store_dir=tmp_path)
        seed.delete("k1")
        stale.save("k2", "v2")          # must not write k1 back from its stale cache

        assert _keys(tmp_path) == ["k2"]
        assert stale.retrieve("k1") is None

    def test_concurrent_writers_keep_every_key(self, tmp_path):
        """Many interleaved writers, each with its own store instance."""
        import threading

        stores = [MemoryStore(store_dir=tmp_path) for _ in range(6)]
        barrier = threading.Barrier(len(stores), timeout=10)

        def write(index: int) -> None:
            barrier.wait()
            stores[index].save(f"k{index}", index)

        threads = [threading.Thread(target=write, args=(i,)) for i in range(len(stores))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)

        assert _keys(tmp_path) == [f"k{i}" for i in range(len(stores))]


class TestTheDurabilityPropertiesAreUnchanged:
    def test_the_map_is_written_atomically_and_owner_only(self, tmp_path):
        store = MemoryStore(store_dir=tmp_path)
        store.save("k", {"nested": True})

        path = tmp_path / "long_term.json"
        assert json.loads(path.read_text(encoding="utf-8"))["k"]["value"] == {"nested": True}
        assert not list(tmp_path.glob(".long_term.*.tmp")), "a temp file lingered"
        import os

        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600

    def test_a_corrupt_file_does_not_break_a_write(self, tmp_path):
        """`_load` falls back to an empty map; the next write must still land."""
        (tmp_path / "long_term.json").write_text("{not json", encoding="utf-8")
        store = MemoryStore(store_dir=tmp_path)
        store.save("k", "v")
        assert store.retrieve("k") == "v"
        assert _keys(tmp_path) == ["k"]
