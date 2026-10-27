from nexus_shield import bench


def test_corpus_is_deterministic():
    a, b = bench.corpus(1), bench.corpus(1)
    assert [e.payloads for v in a[0].values() for e in v] == [e.payloads for v in b[0].values() for e in v]


def test_vaccine_beats_exact_match_without_false_positives():
    d = bench.detection(0)
    assert d["vaccine"]["recall"] >= 0.9 and d["vaccine"]["benign_fp_rate"] == 0.0
    assert d["exact_match"]["recall"] < 0.5  # mutated variants defeat exact signatures


def test_attribution_curve():
    rows = {r["snr_db"]: r for r in bench.attribution(0, trials=10, snrs=(5, 20))}
    assert rows[20]["mean_abs_err_hz"] < 50 and rows[20]["separation_accuracy"] == 1.0
    assert rows[5]["mean_abs_err_hz"] > rows[20]["mean_abs_err_hz"]  # noise hurts, as documented
