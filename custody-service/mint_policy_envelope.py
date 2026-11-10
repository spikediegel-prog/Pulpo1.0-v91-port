#!/usr/bin/env python3
"""Mint a signed policy envelope for one disposable sandbox run.

The sandbox authority is the operator for one disposable run: it mints a
fresh Ed25519 issuer keypair and a signed policy envelope for the exact
sandbox policy, the same way it already mints fresh kernel and custody
secrets. The service holds only the authority public key and cannot sign a
policy itself, so the envelope must be supplied by the issuer (here: this
script). The fixed test-vector public key previously used in the container
isolation proofs has no private key in the repository, so no envelope could
ever be minted for it.

Prints two lines, suitable for capture in a shell step without eval:

    PULPO_AUTHORITY_PUBLIC_KEY_HEX=<hex>
    PULPO_POLICY_ENVELOPE_JSON=<compact JSON>

The private key is held only in this process and never printed.
"""

import argparse
import json
import sys
from dataclasses import asdict, replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from pulpo import (
    AuthorityTrust,
    Ed25519ApprovalVerifier,
    Policy,
    PolicyEnvelope,
)
from pulpo.kernel import policy_hash_for


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority-id", required=True)
    parser.add_argument("--verifier-id", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--max-ttl-seconds", type=int, default=300)
    parser.add_argument("--budget-cents", type=int, default=3000)
    args = parser.parse_args()

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    verifier = Ed25519ApprovalVerifier(
        authority_id=args.authority_id,
        verifier_id=args.verifier_id,
        key_id=args.key_id,
        public_key=public,
    )
    trust = AuthorityTrust(
        authority_id=verifier.authority_id,
        verifier_id=verifier.verifier_id,
        key_id=verifier.key_id,
        algorithm=verifier.algorithm,
        key_fingerprint=verifier.key_fingerprint,
        deployment_id=args.deployment_id,
        max_approval_ttl_ns=args.max_ttl_seconds * 1_000_000_000,
    )
    policy = Policy(
        frozenset({"purchase_domain"}),
        args.budget_cents,
        frozenset({"purchase_domain"}),
        authority_trust=trust,
    )
    unsigned = PolicyEnvelope(
        policy_hash=policy_hash_for(policy),
        version=policy.version,
        previous_policy_hash=policy.previous_policy_hash,
        authority_id=trust.authority_id,
        verifier_id=trust.verifier_id,
        key_id=trust.key_id,
        deployment_id=trust.deployment_id,
        trust_hash=trust.trust_hash,
        signature="",
    )
    envelope = replace(
        unsigned, signature=private.sign(unsigned.signing_bytes()).hex()
    )
    payload = json.dumps(asdict(envelope), separators=(",", ":"))
    print(f"PULPO_AUTHORITY_PUBLIC_KEY_HEX={public.hex()}")
    print(f"PULPO_POLICY_ENVELOPE_JSON={payload}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
