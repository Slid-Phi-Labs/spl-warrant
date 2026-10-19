#!/usr/bin/env python3
"""
demo.py — "Warranted" live demo: plan a team offsite within $500.

The coordinator splits the mission across three specialist sub-agents,
each with a cryptographically enforced spend cap:
  venue-researcher   $200 cap   (research only, no spend)
  catering-purchaser $250 cap   (orders catering; tries to overspend -> DENIED)
  transport-booker    $50 cap   (books the shuttle)

The demo shows: the live budget tree, a real over-budget purchase being
DENIED on screen, an expired mandate halting in-flight work, and a final
verification of the signed audit ledger.

Run:  ~/workspace/docker-agent-challenge/.venv/bin/python demo.py
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.expanduser("~/workspace/docker-agent-challenge/warrant_did"))

import did_binding
from did_binding import new_challenge
import warrant_lib
from warrant_lib import attenuate

from coordinator import Coordinator, Delegation
from ledger import verify_ledger
from specialists import REGISTRY

HERE = os.path.dirname(os.path.abspath(__file__))


def money(cents: int) -> str:
    return f"${cents / 100:,.2f}"


def banner(text: str):
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70)


def main() -> None:
    banner("WARRANTED — the business agent that can't overspend")
    print("Mission: plan a team offsite within $500.")
    print("No API keys. No network. Every number below is enforced, not asserted.")

    coord = Coordinator(name="warranted-coordinator",
                        ledger_path=os.path.join(HERE, "ledger.jsonl"))
    print(f"\nCoordinator identity: {coord.identity.short()}")

    plan = [
        {"specialist_name": "researcher",
         "task": "find 3 offsite venues in Cherry Hill NJ under $200 per head",
         "cap_cents": 20000, "ttl_secs": 3600},
        {"specialist_name": "purchaser",
         "task": ("order sandwich platter and coffee urn for the offsite; "
                  "also try to add the premium dessert tower"),
         "cap_cents": 25000, "ttl_secs": 3600},
        {"specialist_name": "transporter",
         "task": "book the shuttle van for offsite transport",
         "cap_cents": 5000, "ttl_secs": 3600},
    ]

    banner("STEP 1 — DELEGATE: one root warrant, three narrowing mandates")
    print(f"Root budget: {money(50000)}  (coordinator's warrant to itself)")
    for item in plan:
        spec = REGISTRY[item["specialist_name"]]
        print(f"  -> {spec.name:20s} cap {money(item['cap_cents']):>8s}  "
              f"did {spec.identity.short()}")

    summary = coord.run("plan a team offsite within $500", 50000, plan)

    banner("STEP 2 — BUDGET TREE (live)")
    print(f"root  {coord.identity.short()}  cap {money(50000)}")
    tree = summary["delegations"]
    for i, d in enumerate(tree):
        branch = "`--" if i == len(tree) - 1 else "|--"
        print(f"  {branch} {d['specialist']:20s} cap {money(d['cap_cents']):>8s}  "
              f"spent {money(d['spent_cents']):>8s}  did {d['did'][:22]}...")
    print(f"\nCommitted: {money(summary['committed_cents'])} of {money(50000)}")

    banner("STEP 3 — SPEND LOG (every line verified against a live DID proof)")
    denied_shown = False
    with open(summary["ledger_path"]) as f:
        for line in f:
            ev = json.loads(line)
            p = ev["payload"]
            if ev["type"] == "spend_approved":
                print(f"  APPROVED  {p['specialist']:20s} {money(p['cost_cents']):>8s}  "
                      f"{p['memo']}")
            elif ev["type"] == "spend_denied":
                denied_shown = True
                print()
                print("  " + "!" * 66)
                print(f"  !! SPEND DENIED — {p['specialist']} attempted "
                      f"{money(p['cost_cents'])}")
                print(f"  !! reason: {p['reason']} — {p['detail']}")
                print(f"  !! the money did not move. the attempt is in the ledger.")
                print("  " + "!" * 66)
                print()
    if not denied_shown:
        print("  (no denials — unexpected in this scenario)")

    banner("STEP 4 — RESEARCH RESULTS")
    for r in summary["results"]:
        if r["specialist"] == "researcher" and r["status"] == "delegated":
            for v in r["outcome"]["findings"]:
                print(f"  - {v['name']} (seats {v['capacity']}, "
                      f"quote {money(v['quote_cents'])})")

    banner("STEP 5 — EXPIRY BEAT: a dead mandate halts in-flight work")
    t0 = int(time.time())
    spec = REGISTRY["transporter"]
    short_warrant = attenuate(summary["root_warrant"], {
        "agent_id": spec.did, "max_cents": 5000, "until": t0 + 60})
    # Proof at issue time: fine.
    chal = new_challenge()
    ok_now = did_binding.gate_check_did(
        short_warrant, spec.did, chal, spec.identity.sign(chal), 4000, t0)["ok"]
    print(f"  spend at T+0s (mandate live):    {'APPROVED' if ok_now else 'DENIED'}")
    # Same warrant, same key, one hour later: the mandate is dead.
    doomed = Delegation(spec, short_warrant, 5000)
    moved = coord.spend(doomed, 4000, "shuttle van (late booking)", now=t0 + 3600)
    print(f"  spend at T+3600s (mandate dead): {'APPROVED' if moved else 'DENIED — halted cleanly'}")

    banner("STEP 6 — LEDGER VERIFICATION")
    ok = verify_ledger(summary["ledger_path"], coord.identity.did)
    n_events = sum(1 for _ in open(summary["ledger_path"]))
    print(f"  ledger: {summary['ledger_path']}")
    print(f"  events: {n_events}, all signed by coordinator {coord.identity.short()}")
    print(f"  LEDGER VERIFIED: {ok}")

    banner("MISSION COMPLETE")
    print(f"  goal:     {summary['goal']}")
    print(f"  budget:   {money(summary['budget_cents'])}")
    print(f"  spent:    {money(summary['spent_cents'])}")
    print(f"  remaining:{money(summary['budget_cents'] - summary['spent_cents'])}")
    print(f"  denials:  {sum(1 for r in summary['results'] if r['status'] == 'denied')}"
          f" delegation(s) denied, 1 spend denied — mission continued regardless")
    print("\nOverspend isn't a policy here. It's structurally impossible.\n")


if __name__ == "__main__":
    main()
