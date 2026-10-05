import os
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import aw_import_screentime.__main__ as mod
from test_activitywatch_sink import FakeActivityWatchClient


def focus_bytes(cf: float, foreground: bool = True, bundle: str = "com.example.app"):
    return mod.AppInFocusEventPb(
        bundle_id=bundle, cf_absolute_time=cf, in_foreground=int(foreground)
    ).SerializeToString()


@pytest.fixture
def source_files(monkeypatch, tmp_path):
    """Real enumeration/protobuf decoding, with only the SEGB boundary faked."""
    monkeypatch.setattr(mod, "STREAMS_DIR", tmp_path / "streams")
    records = {}

    def add(name, payloads, mtime, device="device-1"):
        path = mod.STREAMS_DIR / device / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic SEGB placeholder")
        os.utime(path, (mtime, mtime))
        records[path] = list(payloads)
        return path

    def read(path):
        for payload in records[Path(path)]:
            if isinstance(payload, Exception):
                raise payload
            yield SimpleNamespace(data=payload)

    monkeypatch.setattr(mod.ccl_segb, "read_segb_file", read)
    return add, records


def test_scan_recovers_backlog_outside_mtime_window_and_unchanged_append(source_files):
    add, records = source_files
    active = add("z-active", [focus_bytes(150)], 10)
    add("middle", [focus_bytes(80)], 20)
    old = add("a-old-new-mtime", [focus_bytes(50)], 30)
    state = mod.DeviceState(last_cf=100)

    # Explicit events commands retain their file limit; watch must not use it.
    assert mod.tail_device_files("device-1", limit=2) == [active.parent / "middle", old]
    result = mod.read_new_events_for_device("device-1", state)
    assert [ev.cf_absolute_time for ev in result.events] == [150]
    assert result.new_last_cf == 150
    assert result.dirty is True
    assert state.last_cf == 100  # Reader cannot commit state before upload.

    state.last_cf = result.new_last_cf
    state.last_file = result.new_last_file
    metadata = active.stat()
    records[active].append(focus_bytes(160, False))
    assert active.stat() == metadata
    result = mod.read_new_events_for_device("device-1", state)
    assert [ev.cf_absolute_time for ev in result.events] == [160]
    assert result.new_last_cf == 160


@pytest.mark.parametrize(
    "failure",
    [
        PermissionError("synthetic permission failure"),
        OSError("synthetic read failure"),
        FileNotFoundError(2, "synthetic rotation during read"),
        b"\xff",
    ],
    ids=["permission", "mid-file-read", "vanished-file", "malformed-protobuf"],
)
def test_failed_scan_discards_partial_batch_and_retries(source_files, caplog, failure):
    add, records = source_files
    add("later-events", [focus_bytes(200)], 10)
    broken = add("unread", [focus_bytes(120), failure, focus_bytes(140)], 20)
    state = mod.DeviceState(
        last_cf=100, open_interval=mod.OpenIntervalState("com.example.app", 90)
    )

    result = mod.read_new_events_for_device("device-1", state)
    assert result == mod.NewEvents([], None, None, False)
    assert state.last_cf == 100
    assert state.open_interval == mod.OpenIntervalState("com.example.app", 90)
    assert "checkpoint unchanged" in caplog.text
    assert "next scan" in caplog.text
    assert "unread" in caplog.text

    records[broken] = [focus_bytes(120), focus_bytes(140)]
    result = mod.read_new_events_for_device("device-1", state)
    assert sorted(ev.cf_absolute_time for ev in result.events) == [120, 140, 200]
    assert result.new_last_cf == 200


@pytest.mark.parametrize("directory_exists", [False, True])
def test_missing_or_empty_directory_leaves_checkpoint_unchanged(
    source_files, directory_exists
):
    if directory_exists:
        (mod.STREAMS_DIR / "device-1").mkdir(parents=True)
    state = mod.DeviceState(last_cf=100)
    assert mod.read_new_events_for_device("device-1", state) == mod.NewEvents(
        [], None, None, False
    )
    assert state.last_cf == 100


def test_empty_records_are_skipped_and_non_sources_are_excluded(source_files):
    add, _ = source_files
    add("records", [b"", b"\x00\x00", focus_bytes(150)], 10)
    add(".hidden", [focus_bytes(200)], 20)
    (mod.STREAMS_DIR / "device-1" / "subdirectory").mkdir()
    result = mod.read_new_events_for_device("device-1", mod.DeviceState(last_cf=100))
    assert [ev.cf_absolute_time for ev in result.events] == [150]
    assert result.new_last_cf == 150


@pytest.mark.parametrize("payloads", [[], [b"", b"\x00\x00"]])
def test_stream_without_decodable_records_does_not_advance_checkpoint(
    source_files, payloads
):
    add, _ = source_files
    add("empty-stream", payloads, 10)
    state = mod.DeviceState(last_cf=100)
    assert mod.read_new_events_for_device("device-1", state) == mod.NewEvents(
        [], None, None, False
    )
    assert state.last_cf == 100


def test_non_strict_cli_decoder_keeps_existing_parse_error_handling(source_files):
    add, _ = source_files
    path = add("records", [b"", b"\x00", b"\xff", focus_bytes(150)], 10)
    assert [ev.cf_absolute_time for ev in mod.iter_app_in_focus_events(path)] == [150]


@pytest.mark.parametrize("contents", [b"", b"not a supported SEGB file"])
def test_real_segb_reader_failure_holds_checkpoint(
    monkeypatch, tmp_path, caplog, contents
):
    monkeypatch.setattr(mod, "STREAMS_DIR", tmp_path)
    base = tmp_path / "device-1"
    base.mkdir()
    source = base / "synthetic-source"
    source.write_bytes(contents)
    state = mod.DeviceState(last_cf=100)
    assert mod.read_new_events_for_device("device-1", state) == mod.NewEvents(
        [], None, None, False
    )
    assert state.last_cf == 100
    assert "checkpoint unchanged" in caplog.text


@pytest.mark.parametrize("disappear_on", [1, 2])
def test_stat_failure_during_enumeration_is_retryable(
    source_files, monkeypatch, caplog, disappear_on
):
    add, _ = source_files
    path = add("disappearing", [focus_bytes(150)], 10)
    add("later", [focus_bytes(200)], 20)
    stat = Path.stat
    calls = 0

    def disappearing_stat(self, *args, **kwargs):
        nonlocal calls
        if self == path:
            calls += 1
            if calls == disappear_on:  # Disappears during filtering or sorting.
                raise FileNotFoundError(2, "synthetic rotation")
        return stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", disappearing_stat)
    state = mod.DeviceState(last_cf=100)
    assert mod.read_new_events_for_device("device-1", state) == mod.NewEvents(
        [], None, None, False
    )
    assert "checkpoint unchanged" in caplog.text
    assert mod.read_new_events_for_device("device-1", state).new_last_cf == 200


@pytest.fixture
def watcher(monkeypatch, tmp_path):
    """Run the real watcher, sink and state persistence without threads or network."""
    monkeypatch.setattr(mod, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(mod, "STATE_FILE", tmp_path / "state" / "state.json")
    monkeypatch.setattr(mod, "LEGACY_STATE_FILE", tmp_path / "legacy.json")
    # Title enrichment is an external service, unrelated to source selection.
    monkeypatch.setattr(mod, "lookup_app_title", lambda *args, **kwargs: None)

    class StopWatch(BaseException):
        pass

    class Client(FakeActivityWatchClient):
        fail_next_insert = False

        def create_bucket(self, bucket_id, bucket_type):
            self.events_by_bucket.setdefault(bucket_id, [])

        def insert_events(self, bucket_id, events):
            if self.fail_next_insert:
                self.fail_next_insert = False
                raise mod.requests.ConnectionError("synthetic upload outage")
            super().insert_events(bucket_id, events)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class Observer:
        def schedule(self, handler, path, recursive):
            pass

        def start(self):
            pass

        def stop(self):
            pass

        def join(self, timeout):
            pass

    client = Client()
    monkeypatch.setattr(mod, "ActivityWatchClient", lambda *args, **kwargs: client)
    monkeypatch.setattr(mod, "Observer", Observer)

    def run(after_scans, devices=("device-1",)):
        callbacks = iter(after_scans)
        monkeypatch.setattr(
            mod, "get_device_ids", lambda *args, **kwargs: list(devices)
        )

        class Wake:
            signaled = False
            first = True

            def set(self):
                self.signaled = True

            def clear(self):
                self.signaled = False

            def wait(self, timeout):
                assert timeout == mod.WATCH_SAFETY_RESCAN_SECONDS
                if self.first:
                    self.first = False
                else:
                    callback = next(callbacks, None)
                    if callback is None:
                        raise StopWatch()
                    callback()
                return self.signaled

        monkeypatch.setattr(mod.threading, "Event", Wake)
        config = mod.AppConfig(
            path=tmp_path / "config.toml",
            activitywatch=mod.ActivityWatchDefaults(
                testing=True, bucket_suffix="synthetic"
            ),
            runtime=mod.RuntimeDefaults(retry_delay_seconds=0),
        )
        ctx = SimpleNamespace(
            obj={"ctx": mod.Ctx(timezone.utc, 20, config, config.path)}
        )
        with pytest.raises(StopWatch):
            mod.cmd_watch(ctx, device=None, testing=None, port=None, storefront=None)

    return run, client


def test_watcher_catchup_orders_files_dedupes_and_preserves_open_state_on_restart(
    source_files, watcher
):
    add, records = source_files
    run, client = watcher
    # The close is read before the gain; the final file contains only old data.
    add("first", [focus_bytes(140, False), focus_bytes(150)], 10)
    active = add("second", [focus_bytes(120), focus_bytes(120)], 20)
    add("last", [focus_bytes(50)], 30)
    mod.save_device_states({"device-1": mod.DeviceState(last_cf=100)})
    bucket = "aw-import-screentime_ios_ios-device-1_synthetic"

    def after_catchup():
        state = mod.load_device_states()["device-1"]
        assert state.last_cf == 150
        assert state.open_interval == mod.OpenIntervalState("com.example.app", 150)
        assert len(client.events_by_bucket[bucket]) == 1
        event = client.events_by_bucket[bucket][0]
        assert event.timestamp == datetime(2001, 1, 1, 0, 2, tzinfo=timezone.utc)
        assert event.duration.total_seconds() == 20

    # Startup scan and a safety rescan must leave exactly one closed interval.
    run([after_catchup])
    after_catchup()

    # Restart with the saved open interval; an unrelated loss must not close it.
    records[active].append(focus_bytes(160, False, "com.example.unrelated"))
    run([])
    state = mod.load_device_states()["device-1"]
    assert state.last_cf == 160
    assert state.open_interval == mod.OpenIntervalState("com.example.app", 150)
    records[active].append(focus_bytes(170, False))
    run([])
    state = mod.load_device_states()["device-1"]
    assert state.last_cf == 170
    assert state.open_interval is None
    assert [ev.duration.total_seconds() for ev in client.events_by_bucket[bucket]] == [
        20,
        20,
    ]
    run([])
    assert len(client.events_by_bucket[bucket]) == 2


def test_watcher_upload_failure_retries_without_committing_checkpoint(
    source_files, watcher
):
    add, _ = source_files
    run, client = watcher
    add("close", [focus_bytes(140, False)], 10)
    mod.save_device_states(
        {
            "device-1": mod.DeviceState(
                last_cf=120, open_interval=mod.OpenIntervalState("com.example.app", 120)
            )
        }
    )
    client.fail_next_insert = True

    def after_failed_upload():
        state = mod.load_device_states()["device-1"]
        assert state.last_cf == 120
        assert state.open_interval == mod.OpenIntervalState("com.example.app", 120)
        assert client.insert_events_calls == []

    run([after_failed_upload])
    state = mod.load_device_states()["device-1"]
    assert state.last_cf == 140
    assert state.open_interval is None
    assert len(client.insert_events_calls) == 1


def test_failed_source_scan_preserves_device_state_while_other_device_progresses(
    source_files, watcher, caplog
):
    add, records = source_files
    run, client = watcher
    broken = add(
        "broken", [focus_bytes(130, False), OSError("synthetic read failure")], 10
    )
    add("good", [focus_bytes(120), focus_bytes(140, False)], 10, device="device-2")
    mod.save_device_states(
        {
            "device-1": mod.DeviceState(
                last_cf=120, open_interval=mod.OpenIntervalState("com.example.app", 120)
            )
        }
    )

    def after_failed_scan():
        states = mod.load_device_states()
        assert states["device-1"].last_cf == 120
        assert states["device-1"].open_interval == mod.OpenIntervalState(
            "com.example.app", 120
        )
        assert states["device-2"].last_cf == 140
        assert (
            client.events_by_bucket["aw-import-screentime_ios_ios-device-1_synthetic"]
            == []
        )
        records[broken] = [focus_bytes(130, False)]

    run([after_failed_scan], devices=("device-1", "device-2"))
    assert "checkpoint unchanged" in caplog.text
    states = mod.load_device_states()
    assert states["device-1"].last_cf == 130
    assert states["device-1"].open_interval is None
    assert {
        bucket: [ev.duration.total_seconds() for ev in events]
        for bucket, events in client.events_by_bucket.items()
    } == {
        "aw-import-screentime_ios_ios-device-1_synthetic": [10],
        "aw-import-screentime_ios_ios-device-2_synthetic": [20],
    }


def test_determine_watch_scan_targets_uses_timeout_as_safety_rescan() -> None:
    targets = mod.determine_watch_scan_targets(
        woke=False,
        drained_changed=set(),
        all_device_ids=["device-1", "device-2"],
    )

    assert targets == {"device-1", "device-2"}


def test_determine_watch_scan_targets_skips_spurious_wake_without_changes() -> None:
    targets = mod.determine_watch_scan_targets(
        woke=True,
        drained_changed=set(),
        all_device_ids=["device-1", "device-2"],
    )

    assert targets == set()
