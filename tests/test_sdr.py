import tempfile

from nexus_shield import capture, sdr


def test_cfo_estimate():
    for cfo in (-3400.0, 800.0, 1200.0):
        assert abs(sdr.estimate(sdr.synth_iq(cfo), 250_000)[0] - cfo) < 100


def test_cf32_roundtrip():
    p = tempfile.mktemp()
    sdr.write_iq(p, sdr.synth_iq(500.0, n=256))
    assert abs(sdr.from_capture(p, 0).cfo_hz - 500) < 150


def test_cu8_reader():
    s = sdr.synth_iq(2000.0, n=512, snr_db=30)
    p = tempfile.mktemp()
    with open(p, "wb") as fh:
        fh.write(bytes(round(v * 127.5 + 127.5) for z in s for v in (z.real, z.imag)))
    assert abs(sdr.from_capture(p, 0, fmt="cu8").cfo_hz - 2000) < 200


def test_emitters_and_actors():
    from tests.helpers import ev

    es = [ev(["a"], ip="1.1.1.%d" % i, ts=i * 2.0) for i in range(4)]
    obs = [sdr.Obs(e.ts, 0, -10, c) for e, c in zip(es, (1000, 1050, -2000, 1020))]
    sdr.assign_emitters(obs)
    a = sdr.actors(es, sdr.correlate(es, obs))
    assert sorted(v["sessions"] for v in a.values()) == [1, 3]


def test_capture_command_and_runner():
    assert capture.command(433.92e6, 250000, 4096, "x", gain=20)[:3] == ["rtl_sdr", "-f", "433920000"]
    p = tempfile.mktemp()
    obs = tempfile.mktemp()

    def fake(cmd, **kw):
        s = sdr.synth_iq(1500.0, n=2048, snr_db=30)
        with open(cmd[-1], "wb") as fh:
            fh.write(bytes(round(v * 127.5 + 127.5) for z in s for v in (z.real, z.imag)))

    o = capture.capture_once(433.92e6, 250000, 2048, p, obs, runner=fake)
    assert abs(o.cfo_hz - 1500) < 200 and len(sdr.load(obs)) == 1
