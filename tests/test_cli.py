# -*- coding: utf-8 -*-
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(REPO, "examples")


def run_cli(*argv):
    return subprocess.run(
        [sys.executable, "-m", "protoforge", *argv],
        capture_output=True, text=True, cwd=REPO,
        env={**os.environ, "PYTHONUTF8": "1"},
    )


def test_selftest():
    r = run_cli("selftest")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "[PASS]" in r.stdout


def test_generate_and_verify(tmp_path):
    out = tmp_path / "smsp.lua"
    r = run_cli("generate", os.path.join(EXAMPLES, "smsp.json"), "-o", str(out))
    assert r.returncode == 0, r.stderr
    assert out.exists()
    assert 'Proto("smsp"' in out.read_text(encoding="utf-8")

    from tests.conftest import smsp_frame, telemetry_payload
    frame = smsp_frame(1, 1, 7, telemetry_payload([]))
    r = run_cli("verify", str(out), "--hex", frame.hex())
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Magic: 0x5A5A" in r.stdout
    assert "[correct]" in r.stdout


def test_generate_csv(tmp_path):
    csv_path = os.path.join(EXAMPLES, "flat.csv")
    if not os.path.exists(csv_path):
        import pytest
        pytest.skip("examples/flat.csv 不存在")
    out = tmp_path / "flat.lua"
    r = run_cli("generate", csv_path, "-o", str(out))
    assert r.returncode == 0, r.stderr


def test_verify_pcap(tmp_path):
    out = tmp_path / "smsp.lua"
    assert run_cli("generate", os.path.join(EXAMPLES, "smsp.json"), "-o", str(out)).returncode == 0
    pcap = os.path.join(EXAMPLES, "demo.pcap")
    if not os.path.exists(pcap):
        import pytest
        pytest.skip("demo.pcap 未生成")
    r = run_cli("verify", str(out), "--pcap", pcap, "--port", "5566")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "帧 4" in r.stdout and "[incorrect" in r.stdout


def test_deploy_to_dir(tmp_path):
    out = tmp_path / "x.lua"
    out.write_text("-- x", encoding="utf-8")
    d = tmp_path / "plugins"
    r = run_cli("deploy", str(out), "--name", "demoproto", "--dir", str(d))
    assert r.returncode == 0, r.stderr
    assert (d / "demoproto.lua").read_text(encoding="utf-8") == "-- x"


def test_bad_spec_returns_error():
    r = run_cli("generate", os.path.join(EXAMPLES, "nope.json"), "-o", "x.lua")
    assert r.returncode == 2
