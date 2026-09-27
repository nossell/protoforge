# -*- coding: utf-8 -*-
import os

from protoforge.core import deploy


def test_install_uninstall(tmp_path):
    path = deploy.install("-- demo lua", "myproto", tmp_path / "plugins")
    assert path.exists() and path.name == "myproto.lua"
    assert path.read_text(encoding="utf-8") == "-- demo lua"
    assert deploy.uninstall("myproto", tmp_path / "plugins") is True
    assert deploy.uninstall("myproto", tmp_path / "plugins") is False


def test_install_bad_name(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        deploy.install("x", "../evil", tmp_path)


def test_plugin_dirs_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(deploy.sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(tmp_path))
    dirs = deploy.plugin_dirs()
    assert dirs[0] == tmp_path / "Wireshark" / "plugins"
    # 父目录存在即可作为默认
    (tmp_path / "Wireshark").mkdir()
    assert deploy.default_plugin_dir() == tmp_path / "Wireshark" / "plugins"


def test_find_tshark_on_this_machine():
    exe = deploy.find_tshark()
    if exe is None:
        import pytest
        pytest.skip("本机未安装 Wireshark/tshark")
    ver = deploy.tshark_version(exe)
    assert ver and "Wireshark" in ver
