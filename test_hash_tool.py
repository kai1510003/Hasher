import json
import os
import tempfile
import unittest
from hash_tool import (
    is_valid_hash,
    compute_hash,
    compute_text_hash,
    generate_hash_file,
    verify_file,
    verify_from_hash_file,
    hash_directory,
)


class TestHashTool(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.sample_text = "Hello CyberSec World!"
        self.sample_file = os.path.join(self.test_dir.name, "sample.txt")
        with open(self.sample_file, "w", encoding="utf-8") as f:
            f.write(self.sample_text)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_is_valid_hash(self):
        # Valid SHA-256 (64 hex)
        self.assertTrue(is_valid_hash("001f71ce877229d8fe754395f6dd00233166fe9851f2e631af393606bec664f4", "sha256"))
        # Valid MD5 (32 hex)
        self.assertTrue(is_valid_hash("3579c8da7f1e0ad94656e76c886e5125", "md5"))
        # Invalid characters
        self.assertFalse(is_valid_hash("NOT_A_HEX_STRING_12345", "sha256"))
        # Invalid length for algorithm
        self.assertFalse(is_valid_hash("3579c8da7f1e0ad94656e76c886e5125", "sha256"))

    def test_compute_text_hash(self):
        # Known SHA-256 for "Hello CyberSec World!"
        expected_sha256 = "001f71ce877229d8fe754395f6dd00233166fe9851f2e631af393606bec664f4"
        computed = compute_text_hash(self.sample_text, "sha256")
        self.assertEqual(computed, expected_sha256)

    def test_empty_string_hash(self):
        empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(compute_text_hash("", "sha256"), empty_sha256)

    def test_compute_file_hash(self):
        expected_sha256 = compute_text_hash(self.sample_text, "sha256")
        file_hash = compute_hash(self.sample_file, "sha256")
        self.assertEqual(file_hash, expected_sha256)

    def test_verify_file_success(self):
        expected_sha256 = compute_text_hash(self.sample_text, "sha256")
        self.assertTrue(verify_file(self.sample_file, expected_sha256, "sha256"))

    def test_verify_file_mismatch(self):
        mismatch_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
        self.assertFalse(verify_file(self.sample_file, mismatch_sha256, "sha256"))

    def test_verify_file_invalid_hash_format(self):
        with self.assertRaises(ValueError):
            verify_file(self.sample_file, "invalid_hash", "sha256")

    def test_generate_and_verify_hash_file(self):
        created_path = generate_hash_file(self.sample_file, "sha256")
        expected_path = f"{self.sample_file}.sha256"
        self.assertEqual(created_path, expected_path)
        self.assertTrue(os.path.exists(created_path))
        self.assertTrue(verify_from_hash_file(self.sample_file, created_path, "sha256"))

    def test_verify_from_invalid_checksum_file(self):
        # Create a non-checksum file with arbitrary content
        bad_checksum_file = os.path.join(self.test_dir.name, "random.txt")
        with open(bad_checksum_file, "w") as f:
            f.write("This is a document, not a checksum file!\n")

        with self.assertRaises(ValueError):
            verify_from_hash_file(self.sample_file, bad_checksum_file, "sha256")

    def test_hash_directory(self):
        sub_file = os.path.join(self.test_dir.name, "sub", "test.txt")
        os.makedirs(os.path.dirname(sub_file), exist_ok=True)
        with open(sub_file, "w") as f:
            f.write("sub file content")

        results = hash_directory(self.test_dir.name, "md5")
        self.assertIn("sample.txt", results)
        self.assertIn("sub/test.txt", results)

    def test_additional_algorithms(self):
        for algo in ["sha512", "sha1", "blake2b", "blake2s"]:
            digest = compute_text_hash(self.sample_text, algo)
            self.assertTrue(len(digest) > 0)
            file_digest = compute_hash(self.sample_file, algo)
            self.assertEqual(digest, file_digest)

    def test_gui_module_import(self):
        import hash_gui
        self.assertTrue(hasattr(hash_gui, "HashToolGUI"))

    # VirusTotal Unit Tests
    def test_vt_get_api_key(self):
        import vt_client
        self.assertEqual(vt_client.get_api_key("custom_key_123"), "custom_key_123")
        os.environ["VIRUSTOTAL_API_KEY"] = "env_key_456"
        self.assertEqual(vt_client.get_api_key(None), "env_key_456")
        del os.environ["VIRUSTOTAL_API_KEY"]

    def test_vt_check_hash_missing_api_key(self):
        import vt_client
        if "VIRUSTOTAL_API_KEY" in os.environ:
            del os.environ["VIRUSTOTAL_API_KEY"]
        res = vt_client.check_hash_virustotal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", api_key=None)
        self.assertFalse(res["success"])
        self.assertIn("API Key missing", res["error"])

    def test_vt_check_hash_invalid_format(self):
        import vt_client
        res = vt_client.check_hash_virustotal("NOT_A_VALID_HASH", api_key="dummy_key")
        self.assertFalse(res["success"])
        self.assertIn("Invalid hash digest format", res["error"])

    def test_vt_check_hash_found_clean(self):
        from unittest.mock import patch, MagicMock
        import vt_client

        mock_payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 65, "undetected": 5},
                    "last_analysis_results": {
                        "Kaspersky": {"category": "undetected", "result": None},
                    },
                    "meaningful_name": "clean_file.exe",
                    "size": 1024,
                    "type_description": "Executable",
                    "reputation": 10,
                    "last_analysis_date": 1690000000,
                    "popular_threat_classification": {"suggested_threat_label": "None"},
                }
            }
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_payload).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = vt_client.check_hash_virustotal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", api_key="test_key")
            self.assertTrue(res["success"])
            self.assertTrue(res["found"])
            self.assertEqual(res["stats"]["malicious"], 0)
            self.assertEqual(res["meaningful_name"], "clean_file.exe")

    def test_vt_check_hash_found_malicious(self):
        from unittest.mock import patch, MagicMock
        import vt_client

        mock_payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 0, "harmless": 60, "undetected": 10},
                    "last_analysis_results": {
                        "Kaspersky": {"category": "malicious", "result": "Trojan-Ransom.Win32.Wanna", "engine_name": "Kaspersky"},
                        "CrowdStrike": {"category": "malicious", "result": "Win/malicious_type", "engine_name": "CrowdStrike"},
                    },
                    "meaningful_name": "malware.exe",
                    "size": 2048,
                    "type_description": "Executable",
                    "reputation": -50,
                    "last_analysis_date": 1690000000,
                    "popular_threat_classification": {"suggested_threat_label": "trojan.ransom"},
                }
            }
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_payload).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = vt_client.check_hash_virustotal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", api_key="test_key")
            self.assertTrue(res["success"])
            self.assertTrue(res["found"])
            self.assertEqual(res["stats"]["malicious"], 2)
            self.assertIn("Kaspersky", res["detections"])
            self.assertEqual(res["detections"]["Kaspersky"]["result"], "Trojan-Ransom.Win32.Wanna")

    def test_vt_check_hash_404_not_found(self):
        import urllib.error
        from unittest.mock import patch
        import vt_client

        err = urllib.error.HTTPError(url="http://vt", code=404, msg="Not Found", hdrs={}, fp=None)
        with patch("urllib.request.urlopen", side_effect=err):
            res = vt_client.check_hash_virustotal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", api_key="test_key")
            self.assertTrue(res["success"])
            self.assertFalse(res["found"])
            self.assertIn("not found", res["error"].lower())

    def test_vt_upload_file(self):
        from unittest.mock import patch, MagicMock
        import vt_client

        mock_payload = {"data": {"id": "analysis_id_999"}}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_payload).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = vt_client.upload_file_virustotal(self.sample_file, api_key="test_key")
            self.assertTrue(res["success"])
            self.assertEqual(res["analysis_id"], "analysis_id_999")


if __name__ == "__main__":
    import json
    unittest.main()
