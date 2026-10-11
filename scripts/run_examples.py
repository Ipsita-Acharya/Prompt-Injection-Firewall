import json
import subprocess
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.call import pack_request
from pif.engncore import Firewall
from pif.schemas import ScanRequest
from pif.settings import Settings


def main():
    samples_dir = Path(__file__).resolve().parents[1] / "sample_clean_and_infected_files"
    manifest_path = samples_dir / "manifest.json"
    if not manifest_path.exists():
        print("Manifest not found. Generating fixtures first...")
        from scripts.generate_fixtures import generate
        generate(samples_dir, overwrite=True)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest["cases"]

    print("=" * 85)
    print(f"PIF TEST SUITE VALIDATION: {len(cases)} SPECIMENS ACROSS 9 FILE TYPES & 9 ATTACKS")
    print("=" * 85)

    firewall = Firewall(Settings.load())

    passed_count = 0
    failed_count = 0

    print(f"{'Case ID':<26} {'Type':<10} {'Expected':<10} {'Result':<10} {'Status':<10} {'Attacks'}")
    print("-" * 85)

    for case in cases:
        case_id = case["id"]
        source_type = case["source_type"]
        expected_decision = case["expected"]["decision"]
        expected_status = case["expected"]["status"]
        expected_attacks = case["expected"]["attacks"]

        if len(case["requests"]) > 1:
            sess_id = None
            last_res = None
            for req_rel in case["requests"]:
                req = pack_request(samples_dir / req_rel)
                if sess_id:
                    req["session_id"] = sess_id
                last_res = firewall.scan(ScanRequest.model_validate(req))
                sess_id = last_res.session_id
            res = last_res
        else:
            req = pack_request(samples_dir / case["requests"][0])
            res = firewall.scan(ScanRequest.model_validate(req))

        decision_ok = res.decision == expected_decision
        status_ok = res.status == expected_status
        attacks_ok = set(expected_attacks).issubset(set(res.attacks))
        warning_ok = True
        if case["expected"].get("warning_contains"):
            warning_ok = any(case["expected"]["warning_contains"] in w for w in res.warnings)

        if decision_ok and status_ok and attacks_ok and warning_ok:
            passed_count += 1
            verdict = "[PASS]"
        else:
            failed_count += 1
            verdict = "[FAIL]"

        attacks_str = ", ".join(res.attacks) if res.attacks else "none"
        print(f"{case_id:<26} {source_type:<10} {expected_decision:<10} {res.decision:<10} {verdict:<10} {attacks_str}")

    print("-" * 85)
    print(f"Summary: {passed_count}/{len(cases)} PASSED, {failed_count} FAILED")
    print("=" * 85)

    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
