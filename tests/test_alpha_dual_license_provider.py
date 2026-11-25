import base64
import ast
import datetime
import hashlib
import json
import logging
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core import licensing
from core import license_protocol

ROOT = Path(__file__).resolve().parents[1]


def public_pem(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def signed_package(private_key, license_id="ALPHA-TEST-1"):
    payload = {
        "license_id": license_id,
        "client_name": "Compatibility fixture",
        "hardware_id": "HW-TEST",
        "instance_id": "INST-TEST",
        "issued_at": "2026-11-24T00:00:00Z",
        "expires_at": None,
        "is_lifetime": True,
        "limits": {"max_subscribers": 5000, "max_nas": 15, "max_managers": 10},
        "features": {},
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {"payload": payload, "signature": base64.b64encode(private_key.sign(encoded)).decode("ascii")}


class DualAuthorityPackageTests(unittest.TestCase):
    def setUp(self):
        self.aman_key = Ed25519PrivateKey.generate()
        self.old_publisher_key = Ed25519PrivateKey.generate()
        self.trust = ((licensing.AMAN_LICENSE_AUTHORITY, public_pem(self.aman_key)),)
        self.hardware = patch.multiple(
            licensing,
            get_machine_id=lambda: "HW-TEST",
            get_instance_uuid=lambda: "INST-TEST",
            TRUSTED_LICENSE_PUBLIC_KEYS=self.trust,
        )

    def verify(self, package):
        with self.hardware:
            return licensing.verify_license_package(package)

    def test_current_aman_package_requires_heartbeat(self):
        valid, _, info = self.verify(signed_package(self.aman_key))
        self.assertTrue(valid)
        self.assertEqual(info["license_authority"], licensing.AMAN_LICENSE_AUTHORITY)
        self.assertTrue(info["requires_heartbeat"])

    def test_package_from_another_publisher_key_is_rejected(self):
        valid, _, info = self.verify(signed_package(self.old_publisher_key, "ALPHA-OLD-1"))
        self.assertFalse(valid)
        self.assertEqual(info, {})

    def test_unknown_or_modified_signature_is_rejected(self):
        package = signed_package(Ed25519PrivateKey.generate())
        valid, message, info = self.verify(package)
        self.assertFalse(valid)
        self.assertIn("التوقيع", message)
        self.assertEqual(info, {})

    def test_payload_cannot_claim_a_different_authority(self):
        package = signed_package(self.old_publisher_key)
        package["payload"]["license_authority"] = licensing.AMAN_LICENSE_AUTHORITY
        # The signature was made before the untrusted field was added.
        valid, _, _ = self.verify(package)
        self.assertFalse(valid)

    def test_default_network_key_is_current_aman_key(self):
        self.assertEqual(
            licensing.get_master_public_key_pem(),
            licensing.AMAN_MASTER_PUBLIC_KEY,
        )
        self.assertEqual(licensing.TRUSTED_LICENSE_PUBLIC_KEYS,
                         ((licensing.AMAN_LICENSE_AUTHORITY, licensing.AMAN_MASTER_PUBLIC_KEY),))
        self.assertEqual(licensing.EMBEDDED_PUBLIC_KEY, licensing.AMAN_MASTER_PUBLIC_KEY)
        # The pre-migration publisher key must never be trusted again.
        self.assertNotIn("MCowBQYDK2VwAyEADT6MJTY7bmDdw6nrAzsUyZ1nGrAxTwNKgE1MQYqAgNE=",
                         (ROOT / "core" / "licensing.py").read_text(encoding="utf-8"))
        with self.assertRaises(ValueError):
            licensing.get_master_public_key_pem("legacy-alpha")


class HeartbeatStatusCompatibilityTests(unittest.TestCase):
    def test_current_server_binding_error_is_a_known_signed_status(self):
        private_key = Ed25519PrivateKey.generate()
        request = {
            "license_id": "ALPHA-TEST-1",
            "hardware_id": "HW-TEST",
            "instance_uuid": "INST-TEST",
            "request_nonce": "11" * 24,
        }
        now = int(time.time())
        response = {
            **request,
            "request_hash": hashlib.sha256(license_protocol.canonical(request)).hexdigest(),
            "issued_epoch": now,
            "expires_epoch": now + 90,
            "valid": False,
            "status": "error",
        }
        envelope = {
            "payload": response,
            "signature": base64.b64encode(private_key.sign(license_protocol.canonical(response))).decode("ascii"),
        }
        verified = license_protocol.verify_response(envelope, request, public_pem(private_key))
        self.assertEqual(verified["status"], "error")


class HeartbeatGraceTests(unittest.TestCase):
    def status(self, authority, requires_heartbeat):
        row = {
            "id": 1,
            "license_id": "ALPHA-LEGACY-1",
            "client_name": "Legacy customer",
            "plan_tier": "Enterprise",
            "hardware_id": "HW-TEST",
            "expires_at": None,
            "status": "grace_expired",
            "raw_package_json": "{}",
            "max_active_sessions": 0,
            "max_subscribers": 5000,
            "max_nas": 15,
            "last_verified_at": datetime.datetime(2020, 1, 1),
            "last_heartbeat_at": datetime.datetime(2020, 1, 1),
            "master_server_url": "https://retired.invalid",
        }
        info = {
            "license_authority": authority,
            "requires_heartbeat": requires_heartbeat,
            "features": {},
            "license_mode": "legacy_subscribers",
            "max_active_sessions": None,
            "max_subscribers": 5000,
            "max_nas": 15,
            "max_managers": 10,
            "is_lifetime": True,
            "days_left": 9999,
        }
        source = (ROOT / "services" / "license_guard_service.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == "get_active_license_status")
        namespace = {
            "_LICENSE_CACHE": {"data": None, "timestamp": 0},
            "DEFAULT_MASTER_SERVER_URL": "https://ls.amtik.online",
            "AMAN_LICENSE_AUTHORITY": licensing.AMAN_LICENSE_AUTHORITY,
            "time": time,
            "datetime": datetime,
            "json": json,
            "logger": logging.getLogger("legacy-grace-test"),
            "ensure_license_tables": lambda: None,
            "get_machine_id": lambda: "HW-TEST",
            "get_instance_uuid": lambda: "INST-TEST",
            "get_combined_binding_code": lambda: "HW-TEST / INST-TEST",
            "get_current_system_counts": lambda: (100, 1, 2),
            "check_and_update_monotonic_time": lambda: (True, ""),
            "query_one": lambda *_: row,
            "verify_license_package": lambda *_args, **_kwargs: (True, "valid", info),
            "is_license_blacklisted": lambda *_: False,
            "get_pending_reservations_count": lambda: 0,
            "get_consumed_license_seats": lambda: 2,
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), "license_guard", "exec"), namespace)
        return namespace["get_active_license_status"](force_refresh=True)

    def test_aman_license_enforces_heartbeat_grace(self):
        status = self.status(licensing.AMAN_LICENSE_AUTHORITY, True)
        self.assertFalse(status["valid"])
        self.assertEqual(status["status"], "grace_expired")


class ManagedHeartbeatRenewalTests(unittest.TestCase):
    """An expired managed package must still reach the server to receive renewal."""

    def run_heartbeat(self, package):
        aman_key = Ed25519PrivateKey.generate()
        trust = ((licensing.AMAN_LICENSE_AUTHORITY, public_pem(aman_key)),)
        package = package(aman_key)
        row = {"id": 1, "license_id": package["payload"]["license_id"], "status": "expired",
               "max_active_sessions": 0, "master_server_url": "https://ls.amtik.online",
               "raw_package_json": json.dumps(package), "signature_b64": package["signature"]}
        calls = []

        class Connection:
            def close(self):
                pass

        def exchange(server_url, payload, storage, public_key):
            calls.append(payload)
            return {"license_id": row["license_id"], "valid": True, "status": "active"}

        source = (ROOT / "services" / "license_guard_service.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == "sync_license_heartbeat_with_server")
        namespace = {
            "json": json, "time": time, "logger": logging.getLogger("heartbeat-renewal-test"),
            "query_one": lambda *_: row, "DEFAULT_MASTER_SERVER_URL": "https://ls.amtik.online",
            "get_current_system_counts": lambda: (1, 1, 1),
            "get_machine_id": lambda: "HW-TEST", "get_instance_uuid": lambda: "INST-TEST",
            "APP_VERSION": "2.7.1", "APP_EDITION": "test", "STORAGE_DIR": "/nonexistent",
            "get_connection": Connection, "is_mysql_conn": lambda _conn: False,
            "identify_license_authority": licensing.identify_license_authority,
            "verify_license_package": licensing.verify_license_package,
            "AMAN_LICENSE_AUTHORITY": licensing.AMAN_LICENSE_AUTHORITY,
            "get_master_public_key_pem": lambda authority=None: "fixture",
            "authenticated_license_exchange": exchange,
            "execute_write": lambda *_: None, "clear_license_cache": lambda: None,
            "is_license_blacklisted": lambda *_: False, "record_license_revocation": lambda *_: None,
            "remove_license_revocation": lambda *_: None,
            "_recover_clock_after_verified_heartbeat": lambda *_: False,
            "check_and_update_monotonic_time": lambda: (True, ""),
            "decode_license_string": licensing.decode_license_string,
            "_apply_verified_package_to_db": lambda *_: None,
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), "license_guard", "exec"), namespace)
        with patch.multiple(licensing, TRUSTED_LICENSE_PUBLIC_KEYS=trust,
                            get_machine_id=lambda: "HW-TEST", get_instance_uuid=lambda: "INST-TEST"):
            result = namespace["sync_license_heartbeat_with_server"](max_retries=1)
        return result, calls

    def test_expired_managed_package_still_sends_heartbeat(self):
        def expired(key):
            package = signed_package(key)
            payload = dict(package["payload"], is_lifetime=False, expires_at="2020-01-01T00:00:00Z")
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            return {"payload": payload, "signature": base64.b64encode(key.sign(encoded)).decode("ascii")}

        (ok, _), calls = self.run_heartbeat(expired)
        self.assertTrue(ok)
        self.assertEqual(len(calls), 1)

    def test_untrusted_package_does_not_contact_server(self):
        (ok, _), calls = self.run_heartbeat(lambda _key: signed_package(Ed25519PrivateKey.generate()))
        self.assertFalse(ok)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
