#!/usr/bin/env python3
"""Open a short, time-bounded impersonation window on a target service account.

Runs only inside the approved job of .github/workflows/open-window.yml. It uses the
job's GitHub OIDC token, exchanges it through Workload Identity Federation for a
short-lived token as the gate service account, and then:

  1. adds one roles/iam.workloadIdentityUser binding for the configured member on
     the target service account, conditioned on request.time < expiry, and drops
     any earlier window bindings for that member;
  2. then records the approved plan digest as an approval object (create-only: an
     existing object is never overwritten, so each digest is approved at most once).

The window comes first so that a failed or re-run attempt (for example an etag
conflict) can be retried for the same digest: the record only exists once the
window was opened. A window without a record is harmless, because the consumer
refuses to apply without a matching unexpired record.

Standard library only. Configuration comes from environment variables and is
never printed; HTTP errors report only the step and status code, never a body.
"""

import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ROLE = "roles/iam.workloadIdentityUser"
TITLE_PREFIX = "approval-window-"
MIN_MINUTES = 5
MAX_MINUTES = 60
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
CONFIG_KEYS = ("WIF_PROVIDER", "GATE_SA", "TARGET_SA", "MEMBER", "APPROVAL_BUCKET")


class Refused(Exception):
    """A validation or remote failure; the message is safe to print."""


def validate(digest, minutes):
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise Refused("digest must be 64 lowercase hex characters")
    if not isinstance(minutes, str) or not re.fullmatch(r"[0-9]{1,2}", minutes):
        raise Refused(f"minutes must be an integer from {MIN_MINUTES} to {MAX_MINUTES}")
    value = int(minutes)
    if not MIN_MINUTES <= value <= MAX_MINUTES:
        raise Refused(f"minutes must be an integer from {MIN_MINUTES} to {MAX_MINUTES}")
    return digest, value


def expiry(now, minutes):
    return (now + datetime.timedelta(minutes=minutes)).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_window_binding(binding, member):
    cond = binding.get("condition") or {}
    return (
        binding.get("role") == ROLE
        and str(cond.get("title", "")).startswith(TITLE_PREFIX)
        and binding.get("members") == [member]
    )


def with_window(policy, member, digest, expires):
    """Return a new policy: earlier window bindings for member removed, one new one added.

    Every other binding is kept exactly as it was.
    """
    out = dict(policy)
    kept = [b for b in policy.get("bindings", []) if not is_window_binding(b, member)]
    kept.append({
        "role": ROLE,
        "members": [member],
        "condition": {
            "title": TITLE_PREFIX + digest[:12],
            "description": "approved plan " + digest,
            "expression": f'request.time < timestamp("{expires}")',
        },
    })
    out["bindings"] = kept
    out["version"] = 3
    return out


def _request(step, method, url, token=None, body=None, content_type="application/json", data=None):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        data = json.dumps(body).encode()
    if data is not None:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as err:
        raise Refused(f"{step} failed with HTTP {err.code}") from None
    except urllib.error.URLError:
        raise Refused(f"{step} failed: network error") from None
    return json.loads(raw) if raw else {}


def github_oidc_token(audience):
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise Refused("no OIDC token available to this job")
    sep = "&" if "?" in url else "?"
    resp = _request("oidc", "GET", url + sep + urllib.parse.urlencode({"audience": audience}), token=bearer)
    return resp["value"]


def federated_token(provider, oidc):
    resp = _request("sts", "POST", "https://sts.googleapis.com/v1/token", body={
        "audience": "//iam.googleapis.com/" + provider,
        "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
        "subjectToken": oidc,
    })
    return resp["access_token"]


def gate_token(federated, gate_sa):
    url = ("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
           + urllib.parse.quote(gate_sa) + ":generateAccessToken")
    resp = _request("impersonate", "POST", url, token=federated, body={
        "scope": ["https://www.googleapis.com/auth/cloud-platform"],
        "lifetime": "300s",
    })
    return resp["accessToken"]


def write_approval(token, bucket, digest, expires):
    record = {
        "digest": digest,
        "expires": expires,
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
    }
    url = ("https://storage.googleapis.com/upload/storage/v1/b/" + urllib.parse.quote(bucket, safe="")
           + "/o?" + urllib.parse.urlencode({
               "uploadType": "media",
               "name": f"approvals/{digest}.json",
               "ifGenerationMatch": "0",
           }))
    _request("approval record", "POST", url, token=token, data=json.dumps(record).encode())


def open_window(token, target_sa, member, digest, expires):
    base = "https://iam.googleapis.com/v1/projects/-/serviceAccounts/" + urllib.parse.quote(target_sa)
    policy = _request("read policy", "POST", base + ":getIamPolicy", token=token,
                      body={"options": {"requestedPolicyVersion": 3}})
    _request("write policy", "POST", base + ":setIamPolicy", token=token,
             body={"policy": with_window(policy, member, digest, expires)})


def main():
    try:
        digest, minutes = validate(os.environ.get("INPUT_DIGEST"), os.environ.get("INPUT_MINUTES"))
        if os.environ.get("VALIDATE_ONLY") == "1":
            print(f"inputs valid: digest {digest}, {minutes} minutes")
            return 0
        cfg = {k: os.environ.get(k, "") for k in CONFIG_KEYS}
        missing = [k for k, v in cfg.items() if not v]
        if missing:
            raise Refused("missing configuration: " + ", ".join(missing))
        expires = expiry(datetime.datetime.now(datetime.timezone.utc), minutes)
        oidc = github_oidc_token("//iam.googleapis.com/" + cfg["WIF_PROVIDER"])
        token = gate_token(federated_token(cfg["WIF_PROVIDER"], oidc), cfg["GATE_SA"])
        open_window(token, cfg["TARGET_SA"], cfg["MEMBER"], digest, expires)
        write_approval(token, cfg["APPROVAL_BUCKET"], digest, expires)
        print(f"window open until {expires} for digest {digest}")
        return 0
    except Refused as err:
        print("refused: " + str(err), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
