#!/usr/bin/env python3
"""Shared setup for the Thanos experiments. Mirrors case1/scripts/gravityrat.py."""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import managed_runtime as mr      # noqa: E402

EXE = ROOT / "case2" / "samples" / "extracted" / "thanos.exe"
SO = pathlib.Path(str(EXE) + ".so")

SOURCES = [ROOT / "tools" / "callsite_map.py",
           ROOT / "tools" / "managed_runtime.py",
           ROOT / "tools" / "managed_call_explorer.py",
           ROOT / "tools" / "aot_bridge.py"]


def base_models(captures=None, stores=None):
    """The models every Thanos experiment installs.

    Everything outbound is capture-only: arguments are read out of the state and
    appended to a list. No socket, no DNS lookup, no FTP session.
    """
    m = {
        "stelem.ref": mr.StelemRef(),
        "System.Text.Encoding::GetString": mr.EncodingGetString(),
        "System.Text.Encoding::GetBytes": mr.EncodingGetBytes(),
    }
    if captures is not None:
        m.update({
            "System.Net.WebRequest::set_Method": mr.CaptureCall(
                label="FtpWebRequest.set_Method", log=captures,
                argspec=(("obj", "this"), ("str", "method"))),
            "System.Net.WebRequest::set_ContentLength": mr.CaptureCall(
                label="FtpWebRequest.set_ContentLength", log=captures,
                argspec=(("obj", "this"), ("int", "length"))),
            "System.Net.WebRequest::set_Credentials": mr.CaptureCall(
                label="FtpWebRequest.set_Credentials", log=captures,
                argspec=(("obj", "this"), ("obj", "credentials"))),
            "System.Net.WebRequest::GetRequestStream": mr.CaptureCall(
                label="FtpWebRequest.GetRequestStream", kind="ref",
                log=captures, argspec=(("obj", "this"),)),
            "System.Net.WebRequest::GetResponse": mr.CaptureCall(
                label="WebRequest.GetResponse", kind="ref", log=captures,
                argspec=(("obj", "this"),)),
            "System.IO.Stream::Write": mr.CaptureCall(
                label="Stream.Write  (the request body)", log=captures,
                argspec=(("obj", "this"), ("bytes", "buffer"),
                         ("int", "offset"), ("int", "count"))),
        })
    return m


def build(models=None, fixtures=None):
    rt = mr.ManagedRuntime(str(EXE), str(SO))
    rt.install(models or {})
    described = [
        "mono AOT linkage table resolved (every plt_FOO -> FOO)",
        f"{len(rt.alloc_types)} allocation sites typed from their `newobj`",
        f"{len(rt.literals)} `ldstr` literals written into their GOT slots",
        "array allocation records its element count; stelem.ref modelled",
        "System.Convert.FromBase64String decoded for real",
        "per-object header so unbox/null checks read concrete",
        "mono throw helpers modelled as not returning",
        "String.Concat modelled at each arity the image uses, arrays included",
        "uninitialised memory reads as zero",
    ]
    fixed = []
    for match, text in (fixtures or {}).items():
        fixed += rt.fixture(match, text)
        described.append(f"fixture: {match} -> {text!r}")
    for name in (models or {}):
        described.append(f"model: {name}")
    rt.fixtures = sorted(set(fixed))
    return rt, described


def walk(simgr, budget, cap=400):
    steps = peak = 0
    while simgr.active and steps < budget and len(simgr.active) < cap:
        simgr.step()
        steps += 1
        peak = max(peak, len(simgr.active))
    return steps, peak


def all_states(simgr):
    out = []
    for stash in simgr.stashes.values():
        out.extend(stash)
    for rec in getattr(simgr, "errored", []):
        if getattr(rec, "state", None) is not None:
            out.append(rec.state)
    return out


def blocks_touched(simgr):
    out = set()
    for st in all_states(simgr):
        out.update(st.history.bbl_addrs)
    return out
