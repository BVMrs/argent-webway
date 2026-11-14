"""Dump AgentDojo payloads (no LLM). usage: dump.py <version> <attack> -> JSON on stdout.
Needs `pip install agentdojo` (or a clone). Lab-only; the product fetch script must not need Python."""
import sys, json
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
import agentdojo.attacks  # registers

class P(BasePipelineElement):
    name = "gpt-4o-2024-05-13"
    def query(self, *a, **k): raise NotImplementedError

ver, atk = sys.argv[1], sys.argv[2]
out = {"version": ver, "attack": atk, "suites": {}}
for sname, suite in get_suites(ver).items():
    a = load_attack(atk, suite, P())
    inj = {i: {"goal": t.GOAL, "id": i} for i, t in suite.injection_tasks.items()}
    cases = []
    for uid, ut in suite.user_tasks.items():
        for iid, it in suite.injection_tasks.items():
            try:
                d = a.attack(ut, it)
            except Exception as e:
                d = {"__error__": repr(e)}
            cases.append({"u": uid, "i": iid, "inj": d})
    out["suites"][sname] = {"injection_tasks": inj, "cases": cases}
json.dump(out, sys.stdout)
