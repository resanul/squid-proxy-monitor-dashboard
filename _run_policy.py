#!/usr/bin/env python3
"""Test driver: run squid-policy in-process with self_check bypassed.

The helper refuses to run as non-root (correctly), so exercising it in a
sandbox needs that one guard stubbed. Everything else runs for real.
"""
import importlib.machinery
import importlib.util
import sys

_l = importlib.machinery.SourceFileLoader("sp", "/agent/workspace/squid-policy")
sp = importlib.util.module_from_spec(importlib.util.spec_from_loader("sp", _l))
sys.modules["sp"] = sp
_l.exec_module(sp)
sp.self_check = lambda: None
sys.exit(sp.main())
