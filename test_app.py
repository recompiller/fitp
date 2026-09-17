import importlib
import json
import os
import tempfile
import unittest


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.environ["DATABASE_PATH"] = os.path.join(self.tempdir.name, "gateway.sqlite3")
        os.environ["PUBLIC_BASE_URL"] = "https://portal.example"
        import app

        self.app_module = importlib.reload(app)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_device_registration_creates_public_record(self):
        row = self.app_module.ensure_device("office-pc", "Office PC")
        self.assertIsNotNone(row)

        devices = self.client.get("/api/devices").get_json()
        self.assertEqual(1, len(devices))
        self.assertEqual("Office PC", devices[0]["name"])
        self.assertFalse(devices[0]["online"])

        with self.app_module.db() as connection:
            columns = [row["name"] for row in connection.execute("pragma table_info(devices)").fetchall()]
        self.assertNotIn("token_hash", columns)
        self.assertIn("project_clipboard", columns)
        self.assertIn("app_version", columns)
        self.assertIn("remote_update_enabled", columns)
        self.assertIn("ftp_server_running", columns)

    def test_single_device_status_does_not_require_pattern_token(self):
        self.app_module.ensure_device("office-pc", "Office PC")
        self.app_module.set_setting("pattern_lock", json.dumps({"salt": "x", "hash": "y"}))

        list_response = self.client.get("/api/devices")
        status_response = self.client.get("/api/devices/office-pc")

        self.assertEqual(423, list_response.status_code)
        self.assertEqual(200, status_response.status_code)
        self.assertEqual("office-pc", status_response.get_json()["slug"])
        self.assertFalse(status_response.get_json()["online"])

    def test_device_hello_publishes_project_clipboard_summary(self):
        self.app_module.ensure_device("office-pc", "Office PC")
        self.app_module.handle_device_frame(
            "office-pc",
            {
                "type": "device.hello",
                "data": json.dumps(
                    {
                        "name": "Office PC",
                        "ftpPort": 2121,
                        "webPort": 8088,
                        "ftpServerRunning": False,
                        "remoteWebEnabled": True,
                        "remoteFtpEnabled": True,
                        "remoteUpdateEnabled": True,
                        "appVersion": "1.0.0 (server-20260621-0119)",
                        "projectClipboard": {
                            "displayName": "Pinned",
                            "relativePath": "/Pinned",
                            "isDirectory": True,
                            "pcName": "Office PC",
                            "ipAddress": "192.168.1.5",
                            "macAddress": "AA:BB:CC:DD:EE:FF",
                        },
                    }
                ),
            },
        )

        devices = self.client.get("/api/devices").get_json()

        self.assertEqual("/Pinned", devices[0]["projectClipboard"]["relativePath"])
        self.assertTrue(devices[0]["projectClipboard"]["isDirectory"])
        self.assertEqual("1.0.0 (server-20260621-0119)", devices[0]["appVersion"])
        self.assertTrue(devices[0]["remoteUpdateEnabled"])
        self.assertFalse(devices[0]["ftpServerRunning"])

    def test_project_clipboard_clear_removes_offline_record(self):
        self.app_module.ensure_device("office-pc", "Office PC")
        self.app_module.handle_device_frame(
            "office-pc",
            {
                "type": "device.hello",
                "data": json.dumps(
                    {
                        "name": "Office PC",
                        "projectClipboard": {
                            "displayName": "Pinned",
                            "relativePath": "/Pinned",
                            "isDirectory": True,
                        },
                    }
                ),
            },
        )

        response = self.client.post("/api/devices/office-pc/project-clipboard/clear")

        self.assertEqual(200, response.status_code)
        self.assertFalse(response.get_json()["delivered"])
        devices = self.client.get("/api/devices").get_json()
        self.assertIsNone(devices[0]["projectClipboard"])

    def test_project_clipboard_clear_is_noop_without_pin(self):
        self.app_module.ensure_device("office-pc", "Office PC")

        response = self.client.post("/api/devices/office-pc/project-clipboard/clear")

        self.assertEqual(200, response.status_code)
        self.assertIsNone(response.get_json()["projectClipboard"])

    def test_project_clipboard_clear_unknown_slug_returns_404(self):
        response = self.client.post("/api/devices/missing/project-clipboard/clear")

        self.assertEqual(404, response.status_code)

    def test_project_clipboard_clear_sends_frame_to_online_device(self):
        class FakeWs:
            def __init__(self):
                self.sent = []

            def send(self, payload):
                self.sent.append(json.loads(payload))

        self.app_module.ensure_device("office-pc", "Office PC")
        ws = FakeWs()
        self.app_module.devices["office-pc"] = ws

        response = self.client.post("/api/devices/office-pc/project-clipboard/clear")

        self.assertEqual(200, response.status_code)
        self.assertTrue(response.get_json()["delivered"])
        self.assertEqual("projectClipboard.clear", ws.sent[0]["type"])

    def test_update_status_frame_is_forwarded_to_client(self):
        class FakeWs:
            def __init__(self):
                self.sent = []

            def send(self, payload):
                self.sent.append(json.loads(payload))

        ws = FakeWs()
        self.app_module.update_clients["stream1"] = ws
        self.app_module.handle_device_frame(
            "office-pc",
            {
                "type": "update.status",
                "streamId": "stream1",
                "data": json.dumps({"status": "progress", "message": "Receiving"}),
            },
        )

        self.assertEqual("update.status", ws.sent[0]["type"])
        self.assertEqual("stream1", ws.sent[0]["streamId"])

    def test_remote_html_rewrites_preview_paths(self):
        html = b'<img src="/preview?path=%2Fimage.jpg"><button data-preview-url="/preview?path=%2Fimage.jpg"></button><button data-preview-url="/video-preview?path=%2Fclip.mp4#t=0.1"></button><form action="/login"></form><input value="/browser">'
        rewritten = self.app_module.rewrite_remote_html(html, "office-pc").decode("utf-8")

        self.assertIn('src="/r/office-pc/preview?path=%2Fimage.jpg"', rewritten)
        self.assertIn('data-preview-url="/r/office-pc/preview?path=%2Fimage.jpg"', rewritten)
        self.assertIn('data-preview-url="/r/office-pc/video-preview?path=%2Fclip.mp4#t=0.1"', rewritten)
        self.assertIn('action="/r/office-pc/login"', rewritten)
        self.assertIn('value="/browser"', rewritten)

    def test_remote_proxy_marks_requests_as_remote_access(self):
        with self.app_module.app.test_request_context("/r/office-pc/login", headers={"User-Agent": "test-client"}):
            headers = self.app_module.build_remote_request_headers()

        self.assertEqual("1", headers["X-NAART-Remote-Access"])
        self.assertEqual("test-client", headers["User-Agent"])


if __name__ == "__main__":
    unittest.main()
