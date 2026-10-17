import datetime
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import open_window as ow  # noqa: E402

DIGEST = "a" * 64
MEMBER = "principalSet://example/attribute.x/y"


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

    def test_records_approval_before_opening_window(self):
        calls = []

        def fake(step, method, url, token=None, body=None, content_type="application/json", data=None):
            calls.append(step)
            if step == "oidc":
                return {"value": "jwt"}
            if step == "sts":
                return {"access_token": "fed"}
            if step == "impersonate":
                return {"accessToken": "gate"}
            if step == "read policy":
                return {"etag": "e", "bindings": []}
            return {}

        env = {k: "cfg" for k in ow.CONFIG_KEYS}
        env.update({"INPUT_DIGEST": DIGEST, "INPUT_MINUTES": "30",
                    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example/token",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t"})
        with mock.patch.object(ow, "_request", side_effect=fake):
            self.assertEqual(self.run_main(env), 0)
        self.assertEqual(calls, ["oidc", "sts", "impersonate", "approval record", "read policy", "write policy"])

    def test_refusal_message_never_contains_configuration(self):
        env = {k: "SECRET-LOOKING-" + k for k in ow.CONFIG_KEYS}
        env.update({"INPUT_DIGEST": DIGEST, "INPUT_MINUTES": "30",
                    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example/token",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t"})
        with mock.patch.object(ow, "_request", side_effect=ow.Refused("sts failed with HTTP 403")), \
                mock.patch("sys.stderr") as err:
            self.assertEqual(self.run_main(env), 1)
        written = "".join(str(c.args[0]) for c in err.write.call_args_list)
        self.assertNotIn("SECRET-LOOKING", written)


if __name__ == "__main__":
    unittest.main()
