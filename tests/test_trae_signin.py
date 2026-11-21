"""TRAE SOLO CN local-session and check-in tests; never use real credentials/network."""

import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import trae_signin as trae


class AuthFormatTests(unittest.TestCase):
    def test_supported_envelope_derives_key_and_checks_digest(self):
        header = next(iter(trae.FORMAT_SALTS))
        seed = bytes(range(32))
        payload = b'{"token":"synthetic","account":{"scope":"marscode"}}'
        plaintext = hashlib.sha512(payload).digest() + payload
        ciphertext = b"x" * (((len(plaintext) // 16) + 1) * 16)
        envelope = base64.b64encode(header + seed + ciphertext).decode("ascii")
        derived = hashlib.sha512(hashlib.sha512(seed).digest() + trae.FORMAT_SALTS[header]).digest()
        with mock.patch.object(trae, "_aes_cbc_decrypt", return_value=plaintext) as decrypt:
            self.assertEqual(trae.decrypt_auth(envelope), json.loads(payload))
        decrypt.assert_called_once_with(derived[:16], derived[16:32], ciphertext)

    def test_unknown_header_fails_without_decrypting(self):
        envelope = base64.b64encode(b"unknown" + bytes(160)).decode("ascii")
        with mock.patch.object(trae, "_aes_cbc_decrypt") as decrypt:
            with self.assertRaisesRegex(trae.AuthError, "尚不支持"):
                trae.decrypt_auth(envelope)
        decrypt.assert_not_called()

    def test_digest_mismatch_is_rejected(self):
        header = next(iter(trae.FORMAT_SALTS))
        envelope = base64.b64encode(header + bytes(32) + bytes(128)).decode("ascii")
        with mock.patch.object(trae, "_aes_cbc_decrypt", return_value=bytes(80)):
            with self.assertRaisesRegex(trae.AuthError, "完整性校验"):
                trae.decrypt_auth(envelope)

    def test_windows_session_uses_solo_store_and_device_key(self):
        auth = {"token": "synthetic.jwt.token", "expiredAt": "2099-01-01T00:00:00Z",
                "account": {"scope": "marscode"}}
        storage = {trae.AUTH_KEY: "synthetic-envelope",
                   "iCubeAuthInfo://icube-dc:device-synthetic": ""}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / trae.STORAGE_PATH
            file.parent.mkdir(parents=True)
            file.write_text(json.dumps(storage), encoding="utf-8")
            with mock.patch.object(trae, "decrypt_auth", return_value=auth), \
                    mock.patch.dict(trae.os.environ, {"TRAE_AUTH_DIR": ""}, clear=False):
                session = trae.load_session(root)
        self.assertEqual(session["device_id"], "device-synthetic")
        self.assertEqual(session["auth_dir"], str(root.resolve()))
        self.assertIn("synthetic.jwt.token", trae._sensitive_values)

    def test_wrong_product_and_expired_session_are_rejected(self):
        storage = {trae.AUTH_KEY: "synthetic-envelope",
                   "iCubeAuthInfo://icube-dc:device-synthetic": ""}
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / trae.STORAGE_PATH
            file.parent.mkdir(parents=True)
            file.write_text(json.dumps(storage), encoding="utf-8")
            for auth, reason in (
                ({"token": "synthetic", "account": {"scope": "other"}}, "UNSUPPORTED_ACCOUNT"),
                ({"token": "synthetic", "expiredAt": "2000-01-01T00:00:00Z",
                  "account": {"scope": "marscode"}}, "EXPIRED"),
            ):
                with self.subTest(reason=reason), mock.patch.object(trae, "decrypt_auth", return_value=auth):
                    with self.assertRaises(trae.AuthError) as caught:
                        trae.load_session(directory)
                    self.assertEqual(caught.exception.reason, reason)


class CheckinTests(unittest.TestCase):
    def api(self, responses):
        api = trae.Api({"token": "synthetic", "device_id": "device"})
        api.responses = list(responses)
        api._request = lambda operation: api.responses.pop(0)
        return api

    @staticmethod
    def status(*, enable=True, checked_in=False, did_checked_in=False, **extra):
        return 200, {"enable": enable, "checked_in": checked_in,
                     "did_checked_in": did_checked_in, **extra}

    def test_request_targets_solo_cn_and_never_follows_redirect(self):
        api = trae.Api({"token": "synthetic-token", "device_id": "device-id"})
        request = trae.urllib.request.Request(
            "https://api.trae.cn/trae/api/v2/ug/checkin_credits/status",
            data=b'{"req_source":2}', headers=api.headers, method="POST")
        self.assertEqual(request.full_url, trae.BASE_URL + trae.API_PATH + "status")
        self.assertEqual(request.data, b'{"req_source":2}')
        self.assertEqual(request.get_header("Authorization"), "Cloud-IDE-JWT synthetic-token")
        self.assertEqual(request.get_header("X-device-id"), "device-id")
        self.assertTrue(any(isinstance(handler, trae._NoRedirect)
                            for handler in api.opener.handlers))

    def test_already_and_disabled_status_do_not_claim(self):
        for payload in (
            self.status(checked_in=True)[1],
            self.status(checked_in=False, did_checked_in=True)[1],
            self.status(enable=False)[1],
        ):
            with self.subTest(payload=payload):
                api = self.api([(200, payload)])
                out = trae.run_daily(api)
                self.assertIn(out["result"], ("ALREADY", "INACTIVE"))
                self.assertEqual(api.responses, [])

    def test_dry_run_and_claim_rechecked_without_repeating_write(self):
        api = self.api([self.status()])
        self.assertEqual(trae.run_daily(api, dry_run=True)["result"], "DRY_RUN")
        api = self.api([self.status(), (200, {"message": "success"}),
                        self.status(checked_in=True, credits=100)])
        out = trae.run_daily(api)
        self.assertEqual(out["result"], "CLAIMED")
        self.assertEqual(len(api.responses), 0)
        self.assertEqual(out["credits"], 100)

    def test_failed_claim_is_verified_and_does_not_fabricate_success(self):
        api = self.api([self.status(), (200, {"code": 13, "message": "synthetic"}), self.status()])
        out = trae.run_daily(api)
        self.assertEqual(out["result"], "BUSINESS_ERROR")
        self.assertEqual(len(api.responses), 0)

    def test_string_business_code_and_malformed_status_are_rejected(self):
        api = self.api([self.status(), (200, {"code": "0"}), self.status()])
        out = trae.run_daily(api)
        self.assertEqual(out["result"], "PROTOCOL_ERROR")
        self.assertEqual(trae._status_error(200, (None, {"enable": 1, "checked_in": False}))
                         ["result"], "PROTOCOL_ERROR")


if __name__ == "__main__":
    unittest.main()
