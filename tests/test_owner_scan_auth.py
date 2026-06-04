import tempfile
import unittest
from pathlib import Path

from owner_scan_auth import enroll_owner_scan, verify_owner_scan


class OwnerScanAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "owner_scans.json"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_allows_login_when_scan_matches_owner(self) -> None:
        enroll_owner_scan("alice", "FaceVector:12345", self.database_path)

        self.assertTrue(verify_owner_scan("alice", "facevector:12345", self.database_path))

    def test_denies_login_when_scan_does_not_match_owner(self) -> None:
        enroll_owner_scan("alice", "FaceVector:12345", self.database_path)

        self.assertFalse(verify_owner_scan("alice", "FaceVector:wrong", self.database_path))

    def test_denies_login_for_unknown_account(self) -> None:
        self.assertFalse(verify_owner_scan("unknown", "FaceVector:12345", self.database_path))


if __name__ == "__main__":
    unittest.main()
