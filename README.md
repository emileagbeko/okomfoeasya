# okomfoeasya
Tamper-proof driver safety &amp; defect logs on Algorand — verifiable, auditable compliance for transport operators.

README.md — Okomfo Compliance Core (Algorand)
Pitch (≤150 chars): Tamper-proof driver safety & defect logs on Algorand — verifiable, auditable compliance for transport operators.

Canva link: https://www.canva.com/design/DAG2Ij9BucA/qDeF2DRoQKRA8Vdo5dzCwA/edit?utm_content=DAG2Ij9BucA&utm_campaign=designshare&utm_medium=link2&utm_source=sharebutton 

Screenshot of Operator Dashboard
 
Screenshot of Driver App (below)
 
Overview
Problem. Driver checks and vehicle defect reports live in spreadsheets, PDFs, and email chains. Audits are slow; trust is manual; records can be tampered with.
Solution. A minimal, production-minded Algorand smart contract (PyTeal, AVM v8) that anchors each inspection/defect on-chain. Every record gets a unique key (defect_id), is written to a Box, and is retrievable via logs for verification against off-chain artifacts (PDF/JSON/IPFS).
Why Algorand. Instant finality, low fees, high throughput; Application Boxes for scalable per-record storage; application logs for verifiable reads without complex indexers.
 
Features
•	Record: record(defect_id, defect_hash, vehicle_id, severity, timestamp) — stores a serialized record in a Box and increments a global counter.
•	Verify: verify(defect_id) — asserts existence and logs the stored bytes so any party can validate off-chain.
•	V1.1 Improvements: ABI router, input validation, uniqueness checks, structured byte layout with length prefixes, safe log reads.
 
On-Chain Data Model (v1.1)
Box key: defect_id (bytes)
Box value (bytes):
[ hash:32 | ts_be:8 | sev_be:1 | veh_len_be:2 | vehicle_id:veh_len ]
•	hash:32 — SHA-256 (or CID multihash truncated/padded to 32 bytes).
•	ts_be:8 — big-endian uint64 UNIX timestamp.
•	sev_be:1 — uint8 (0–255), e.g. 0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL.
•	veh_len_be:2 — big-endian uint16 length of vehicle_id.
•	vehicle_id — ASCII/UTF-8 identifier, max 64 bytes (enforced on-chain).
Note: We intentionally do not store PII on-chain. Only hashes/IDs.
 
Quickstart
Prerequisites
•	Python 3.10+
•	pip install pyteal py-algorand-sdk
•	Algorand TestNet access via Sandbox/Algokit/goal
Compile & Deploy
1)	Compile
python contracts/defect_check_contract_v1_1.py > build/approval.teal
2)	Create App (adapt to your env)
# Accounts & network configured
APP_ID=$(goal app create \
  --creator $ADDR \
  --approval-prog build/approval.teal \
  --clear-prog build/clear.teal \
  --global-byteslices 2 --global-ints 1 \
  --local-byteslices 0 --local-ints 0 | awk '/Created app with app index/ {print $6}')
echo $APP_ID
If using Algokit, provide your algokit project run deploy mapping instead.
Record a Defect
DEFECT_ID="DEFECT-2025-0001"
VEH="BUS-42"
SEV=2                   # 0..255
TS=1739900000           # unix ts
HASH_HEX=0123...89ab    # 32 bytes hex
HASH_B64=$(xxd -r -p <<< "$HASH_HEX" | base64)

goal app call \
  --app-id $APP_ID \
  --from $ADDR \
  --app-arg method:record \
  --app-arg b64:$DEFECT_ID \
  --app-arg b64:$HASH_B64 \
  --app-arg str:$VEH \
  --app-arg uint:$SEV \
  --app-arg uint:$TS \
  --boxes $APP_ID,$DEFECT_ID
Verify a Defect
goal app call \
  --app-id $APP_ID \
  --from $ADDR \
  --app-arg method:verify \
  --app-arg b64:$DEFECT_ID \
  --boxes $APP_ID,$DEFECT_ID
# Inspect transaction logs; decode to recover the stored layout
Explorer Link (Asset Hub)
748021714 
Demo Assets (for judges)
•	Loom video (with audio, 3–5 min): 
•	UI screenshots:  (submit form, success toast, verify screen)
•	Explorer screenshot:  (app call showing logs)
 
How We Meet Judging Criteria
•	Innovation: Replaces manual audits with verifiable, tamper-evident on-chain anchors.
•	Usability: One-click record/verify from UI; simple method interface.
•	Impact: Operators, councils, regulators, insurers — improved trust and faster investigations.
•	Feasibility: Minimal on-chain footprint; storage scales via Boxes; low fees.
•	Blockchain Use: Purpose-fit use of Boxes + Logs on Algorand; ABI router and validations.
•	Technical Implementation: Custom PyTeal, AVM v8, safe encoding, uniqueness & bounds checks.
 
Security & Limitations
•	Caller identity: v1.1 records Txn.sender implicitly; production can add RBAC (allow-list box).
•	Field bounds: Enforced: 32-byte hash, veh_id ≤ 64, severity ≤ 255.
•	Uniqueness: New record rejected if defect_id exists (prevent overwrite).
•	Privacy: Never store PII; keep payloads off-chain (hash/CID only).
 
Repo Structure (suggested)
/contracts
  defect_check_contract_v1_1.py
/build
  approval.teal
  clear.teal
/scripts
  compile.py
  deploy.py
  record.py
  verify.py
README.md
LICENSE
 
Loom Script (talk track)
1.	What & Why (20s): “We anchor driver checks/defects on Algorand for tamper-proof audits.”
2.	Demo (60s): Submit record → show txn ID → click Verify → fetch & decode logs.
3.	Contract (60s): Walk through record/verify, Boxes, global counter.
4.	Explorer (30s): Show logs payload.
5.	Code Structure (40s): contracts/, scripts/.
6.	Criteria (30s): Call out innovation, feasibility, Algorand features.
7.	Next (20s): RBAC, ABI tuples, Okomfo integration.
 
License
MIT (open source as required by hackathon rules).
 
contracts/defect_check_contract_v1_1.py (PyTeal)
from pyteal import *
from pyteal.ast.abi import DynamicBytes, Uint8, Uint64

# Okomfo Compliance Core — v1.1 (ABI, validations, uniqueness, structured layout)
# Box layout: [ hash:32 | ts_be:8 | sev_be:1 | veh_len_be:2 | vehicle_id:veh_len ]

TOTAL_DEFECTS_KEY = Bytes("total_defects")
VERSION_KEY = Bytes("version")
VERSION = Bytes("1.1.0")

# Helpers
@Subroutine(TealType.bytes)
def u16be(n: Expr) -> Expr:
    """Return the last 2 bytes of Itob(n) (big-endian uint16)."""
    return Extract(Itob(n), Int(6), Int(2))

@Subroutine(TealType.bytes)
def u8be(n: Expr) -> Expr:
    """Return the last 1 byte of Itob(n) (big-endian uint8)."""
    return Extract(Itob(n), Int(7), Int(1))

@Subroutine(TealType.none)
def assert_len_eq(b: Expr, n: Expr) -> Expr:
    return Assert(Len(b) == n)

@Subroutine(TealType.none)
def assert_len_lte(b: Expr, n: Expr) -> Expr:
    return Assert(Len(b) <= n)

@Subroutine(TealType.none)
def box_put_struct(key: Expr, h: Expr, ts: Expr, sev: Expr, veh: Expr) -> Expr:
    veh_len = ScratchVar(TealType.uint64)
    total_len = ScratchVar(TealType.uint64)
    return Seq(
        veh_len.store(Len(veh)),
        total_len.store(Int(32) + Int(8) + Int(1) + Int(2) + veh_len.load()),
        App.box_create(key, total_len.load()),
        App.box_put(key, Concat(h, Itob(ts), u8be(sev), u16be(veh_len.load()), veh)),
    )

@Subroutine(TealType.none)
def ensure_box_absent(key: Expr) -> Expr:
    bl = App.box_length(key)
    return Seq(
        Assert(Not(bl.hasValue())),
    )

@Subroutine(TealType.none)
def ensure_box_present(key: Expr) -> Expr:
    bl = App.box_length(key)
    return Seq(
        Assert(bl.hasValue()),
    )

router = Router(
    "OkomfoDefectCheck",
    BareCallActions(
        no_op=OnCompleteAction.create_only(Seq(
            App.globalPut(TOTAL_DEFECTS_KEY, Int(0)),
            App.globalPut(VERSION_KEY, VERSION),
            Approve(),
        )),
        opt_in=OnCompleteAction.never(),
        close_out=OnCompleteAction.never(),
        clear_state=OnCompleteAction.call_only(Approve()),
        update_application=OnCompleteAction.never(),
        delete_application=OnCompleteAction.never(),
    ),
)

@router.method("record")
def record(
    defect_id: DynamicBytes,          # key for the Box
    defect_hash: DynamicBytes,        # must be 32 bytes
    vehicle_id: DynamicBytes,         # max 64 bytes
    severity: Uint8,                  # 0..255
    timestamp: Uint64,                # unix ts
):
    did = ScratchVar(TealType.bytes)
    h = ScratchVar(TealType.bytes)
    veh = ScratchVar(TealType.bytes)
    sev = ScratchVar(TealType.uint64)
    ts = ScratchVar(TealType.uint64)

    return Seq(
        defect_id.get().store_into(did),
        defect_hash.get().store_into(h),
        vehicle_id.get().store_into(veh),
        severity.get().store_into(sev),
        timestamp.get().store_into(ts),

        # validations
        assert_len_eq(h.load(), Int(32)),
        assert_len_lte(veh.load(), Int(64)),

        # uniqueness: must not exist yet
        ensure_box_absent(did.load()),

        # write struct
        box_put_struct(did.load(), h.load(), ts.load(), sev.load(), veh.load()),

        # bump counter
        App.globalPut(TOTAL_DEFECTS_KEY, App.globalGet(TOTAL_DEFECTS_KEY) + Int(1)),

        Approve(),
    )

@router.method("verify")
def verify(defect_id: DynamicBytes):
    did = ScratchVar(TealType.bytes)
    val = App.box_get(did.load())
    return Seq(
        defect_id.get().store_into(did),
        ensure_box_present(did.load()),
        # safe get & log
        val,
        Assert(val.hasValue()),
        Log(val.value()),
        Approve(),
    )

if __name__ == "__main__":
    approval, clear, _, _ = router.compile_program(version=8)
    # Print approval to stdout; write clear to file via shell redirection if needed
    print(approval)
    # For clear program, run: python contracts/defect_check_contract_v1_1.py > build/approval.teal
    # And separately compile clear: echo "$clear" > build/clear.teal
 
Notes
•	goal method arg encoding uses the method: selector automatically with ABI Router; older tooling can pass raw strings and selector.
•	Ensure you pass the box reference (--boxes $APP_ID,$DEFECT_ID) on any call that touches the box.
•	Frontend should pre-hash the checklist payload and pass defect_hash as 32 bytes.
•	Verification flow: fetch logs → parse layout → compare hash with recomputed checksum from the off-chain artifact.
<img width="468" height="470" alt="image" src="https://github.com/user-attachments/assets/70808210-da6e-4778-8350-09c8c9dabca4" />
