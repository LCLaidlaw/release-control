import datetime
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import open_window as ow  # noqa: E402

DIGEST = "a" * 64
MEMBER = "principalSet://example/attribute.x/y"
POOL_MEMBER = ("principalSet://iam.googleapis.com/projects/123/locations/global/"
               "workloadIdentityPools/pool-a/attribute.job_workflow_ref/owner/repo/wf.yml@" + "b" * 40)


def good_cfg():
    cfg = {k: "cfg-" + k for k in ow.CONFIG_KEYS}
    cfg["MEMBER"] = POOL_MEMBER
    return cfg


class Validate(unittest.TestCase):
    def test_accepts_bounds(self):
        self.assertEqual(ow.validate(DIGEST, "5"), (DIGEST, 5))
        self.assertEqual(ow.validate(DIGEST, "60"), (DIGEST, 60))

    def test_refuses_bad_digest(self):
        for bad in ["", "A" * 64, "a" * 63, "a" * 65, "g" * 64, DIGEST + "\n", None]:
            with self.assertRaises(ow.Refused):
                ow.validate(bad, "30")

    def test_refuses_bad_minutes(self):
        for bad in ["4", "61", "0", "-5", "5.0", " 30", "30 ", "30\n", "100", "", "1e1", None]:
            with self.assertRaises(ow.Refused):
                ow.validate(DIGEST, bad)


class ConfigPin(unittest.TestCase):
    def test_digest_is_sha256_of_the_ordered_values(self):
        import hashlib
        import json
        cfg = good_cfg()
        expected = hashlib.sha256(json.dumps([cfg[k] for k in ow.CONFIG_KEYS],
                                             separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(ow.config_digest(cfg), expected)

    def test_matching_configuration_passes(self):
        cfg = good_cfg()
        ow.check_config(cfg, ow.config_digest(cfg))

    def test_any_changed_value_is_refused(self):
        cfg = good_cfg()
        pinned = ow.config_digest(cfg)
        for key in ow.CONFIG_KEYS:
            changed = dict(cfg)
            changed[key] = cfg[key] + "x"
            with self.assertRaises(ow.Refused) as ctx:
                ow.check_config(changed, pinned)
            self.assertNotIn(changed[key], str(ctx.exception))

    def test_swapped_values_are_refused(self):
        cfg = good_cfg()
        pinned = ow.config_digest(cfg)
        swapped = dict(cfg, GATE_SA=cfg["TARGET_SA"], TARGET_SA=cfg["GATE_SA"])
        with self.assertRaises(ow.Refused):
            ow.check_config(swapped, pinned)

    def test_unpinned_digest_is_refused(self):
        cfg = good_cfg()
        for pinned in ["", None, "A" * 64, "a" * 63]:
            with self.assertRaises(ow.Refused):
                ow.check_config(cfg, pinned)

    def test_shipped_constant_is_empty_or_a_digest(self):
        self.assertTrue(ow.CONFIG_SHA256 == "" or ow.DIGEST_RE.fullmatch(ow.CONFIG_SHA256))

    def test_member_must_be_a_pool_principal(self):
        for bad in ["allUsers", "allAuthenticatedUsers", "user:someone@example.com",
                    "serviceAccount:x@example", "group:g@example.com", MEMBER,
                    POOL_MEMBER + "\n", " " + POOL_MEMBER,
                    "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/"]:
            cfg = dict(good_cfg(), MEMBER=bad)
            # Even a digest that matches the bad member does not let it through.
            with self.assertRaises(ow.Refused):
                ow.check_config(cfg, ow.config_digest(cfg))
        single = POOL_MEMBER.replace("principalSet://", "principal://")
        cfg = dict(good_cfg(), MEMBER=single)
        ow.check_config(cfg, ow.config_digest(cfg))

    def test_missing_value_is_refused(self):
        cfg = dict(good_cfg(), APPROVAL_BUCKET="")
        with self.assertRaises(ow.Refused):
            ow.check_config(cfg, ow.config_digest(cfg))


class Expiry(unittest.TestCase):
    def test_rfc3339_utc(self):
        now = datetime.datetime(2026, 1, 2, 3, 4, 5, 999, tzinfo=datetime.timezone.utc)
        self.assertEqual(ow.expiry(now, 30), "2026-01-02T03:34:05Z")


class WithWindow(unittest.TestCase):
    def other(self):
        return {"role": "projects/p/roles/gate", "members": ["serviceAccount:gate@example"]}

    def window(self, title="approval-window-old", member=MEMBER):
        return {"role": ow.ROLE, "members": [member],
                "condition": {"title": title, "expression": 'request.time < timestamp("2000-01-01T00:00:00Z")'}}

    def test_adds_one_conditioned_binding_and_keeps_others(self):
        policy = {"etag": "e1", "bindings": [self.other()]}
        out = ow.with_window(policy, MEMBER, DIGEST, "2026-01-01T00:30:00Z")
        self.assertEqual(out["etag"], "e1")
        self.assertEqual(out["version"], 3)
        self.assertIn(self.other(), out["bindings"])
        added = [b for b in out["bindings"] if b["role"] == ow.ROLE]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["members"], [MEMBER])
        self.assertEqual(added[0]["condition"]["expression"], 'request.time < timestamp("2026-01-01T00:30:00Z")')
        self.assertTrue(added[0]["condition"]["title"].startswith(ow.TITLE_PREFIX))

    def test_replaces_earlier_windows_for_the_member_only(self):
        foreign = self.window("approval-window-foreign", member="principalSet://someone/else")
        unconditioned = {"role": ow.ROLE, "members": [MEMBER]}
        policy = {"bindings": [self.window(), self.window("approval-window-older"), foreign, unconditioned]}
        out = ow.with_window(policy, MEMBER, DIGEST, "2026-01-01T00:30:00Z")
        titles = [b.get("condition", {}).get("title") for b in out["bindings"]]
        self.assertNotIn("approval-window-old", titles)
        self.assertNotIn("approval-window-older", titles)
        # Bindings this tool did not create are never removed; the private side's
        # policy-shape check refuses to apply if any unexpected binding exists.
        self.assertIn(foreign, out["bindings"])
        self.assertIn(unconditioned, out["bindings"])

    def test_does_not_mutate_input(self):
        policy = {"bindings": [self.window()]}
        ow.with_window(policy, MEMBER, DIGEST, "2026-01-01T00:30:00Z")
        self.assertEqual(policy, {"bindings": [self.window()]})


class Main(unittest.TestCase):
    def run_main(self, env):
        with mock.patch.dict(os.environ, env, clear=True):
            return ow.main()

    def test_validate_only_needs_no_configuration_or_network(self):
        with mock.patch.object(ow, "_request", side_effect=AssertionError("network")):
            self.assertEqual(self.run_main({"VALIDATE_ONLY": "1", "INPUT_DIGEST": DIGEST, "INPUT_MINUTES": "30"}), 0)

    def test_bad_input_refused_before_any_network(self):
        with mock.patch.object(ow, "_request", side_effect=AssertionError("network")):
            self.assertEqual(self.run_main({"INPUT_DIGEST": "x", "INPUT_MINUTES": "30"}), 1)

    def test_missing_configuration_refused_before_any_network(self):
        with mock.patch.object(ow, "_request", side_effect=AssertionError("network")):
            self.assertEqual(self.run_main({"INPUT_DIGEST": DIGEST, "INPUT_MINUTES": "30"}), 1)

    def test_unpinned_or_mismatched_configuration_refused_before_any_network(self):
        env = dict(good_cfg(), INPUT_DIGEST=DIGEST, INPUT_MINUTES="30")
        for pinned in ["", "c" * 64]:
            with mock.patch.object(ow, "CONFIG_SHA256", pinned), \
                    mock.patch.object(ow, "_request", side_effect=AssertionError("network")):
                self.assertEqual(self.run_main(env), 1)

    def test_opens_window_before_recording_approval_and_pins_requests(self):
        calls = []

        seen = {}

        def fake(step, method, url, token=None, body=None, content_type="application/json", data=None):
            calls.append(step)
            seen[step] = {"url": url, "body": body, "data": data}
            if step == "oidc":
                return {"value": "jwt"}
            if step == "sts":
                return {"access_token": "fed"}
            if step == "impersonate":
                return {"accessToken": "gate"}
            if step == "read policy":
                return {"etag": "e", "bindings": []}
            return {}

        env = good_cfg()
        env.update({"INPUT_DIGEST": DIGEST, "INPUT_MINUTES": "30",
                    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example/token",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t"})
        with mock.patch.object(ow, "CONFIG_SHA256", ow.config_digest(good_cfg())), \
                mock.patch.object(ow, "_request", side_effect=fake):
            self.assertEqual(self.run_main(env), 0)
        self.assertEqual(calls, ["oidc", "sts", "impersonate", "read policy", "write policy", "approval record"])
        # The gate token is short-lived.
        self.assertEqual(seen["impersonate"]["body"]["lifetime"], "300s")
        # The approval record is create-only and names the digest.
        url = seen["approval record"]["url"]
        self.assertIn("ifGenerationMatch=0", url)
        self.assertIn("approvals%2F" + DIGEST + ".json", url)

    def test_refusal_message_never_contains_configuration(self):
        env = {k: "SECRET-LOOKING-" + k for k in ow.CONFIG_KEYS}
        env["MEMBER"] = POOL_MEMBER.replace("pool-a", "secret-looking-pool")
        env.update({"INPUT_DIGEST": DIGEST, "INPUT_MINUTES": "30",
                    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example/token",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t"})
        pinned = ow.config_digest(env)
        with mock.patch.object(ow, "CONFIG_SHA256", pinned), \
                mock.patch.object(ow, "_request", side_effect=ow.Refused("sts failed with HTTP 403")), \
                mock.patch("sys.stderr") as err:
            self.assertEqual(self.run_main(env), 1)
        written = "".join(str(c.args[0]) for c in err.write.call_args_list)
        self.assertNotIn("SECRET-LOOKING", written)
        self.assertNotIn("secret-looking", written)


class HttpErrors(unittest.TestCase):
    def test_http_error_body_is_never_in_the_refusal(self):
        import io
        import urllib.error
        err = urllib.error.HTTPError("https://example/x", 403, "Forbidden", {},
                                     io.BytesIO(b"RESPONSE-BODY-WITH-resource-names"))
        with mock.patch.object(ow._OPENER, "open", side_effect=err):
            with self.assertRaises(ow.Refused) as ctx:
                ow._request("read policy", "POST", "https://example/x", token="t", body={})
        self.assertEqual(str(ctx.exception), "read policy failed with HTTP 403")

    def test_redirects_are_never_followed(self):
        import urllib.request
        handler = ow._NoRedirect()
        req = urllib.request.Request("https://example/x", headers={"Authorization": "Bearer t"})
        self.assertIsNone(handler.redirect_request(req, None, 302, "Found", {}, "https://elsewhere/y"))
        self.assertTrue(any(isinstance(h, ow._NoRedirect) for h in ow._OPENER.handlers))


if __name__ == "__main__":
    unittest.main()
