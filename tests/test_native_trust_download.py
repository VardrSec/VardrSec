import hashlib
import http.client
import io
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from native_trust import acceptance


URL = "https://example.invalid/caddy.zip"
PAYLOAD = b"verified archive bytes"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


def response(body, *, content_length=None):
    length = len(body) if content_length is None else content_length
    headers = f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n".encode()
    socket = Mock()
    socket.makefile.return_value = io.BytesIO(headers + body)
    stream = http.client.HTTPResponse(socket)
    stream.begin()
    return stream


class NativeTrustDownloadTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.archive = Path(directory.name) / "caddy.zip"
        open_url = patch("urllib.request.urlopen")
        self.urlopen = open_url.start()
        self.addCleanup(open_url.stop)
        sleep = patch("time.sleep")
        self.sleep = sleep.start()
        self.addCleanup(sleep.stop)

    def test_short_response_and_timeout_then_complete_download(self):
        self.urlopen.side_effect = [
            response(PAYLOAD[:3], content_length=len(PAYLOAD)),
            URLError(TimeoutError("connection timed out")),
            response(PAYLOAD),
        ]
        acceptance.download_archive(URL, self.archive, DIGEST)
        self.assertEqual(self.archive.read_bytes(), PAYLOAD)
        self.assertEqual(list(self.archive.parent.iterdir()), [self.archive])
        self.assertEqual(self.urlopen.call_count, 3)

    def test_complete_wrong_bytes_fail_without_retry(self):
        self.urlopen.return_value = response(b"wrong bytes")
        with self.assertRaisesRegex(ValueError, "digest"):
            acceptance.download_archive(URL, self.archive, DIGEST)
        self.urlopen.assert_called_once()
        self.sleep.assert_not_called()
        self.assertEqual(list(self.archive.parent.iterdir()), [])

    def test_service_unavailable_then_success(self):
        unavailable = HTTPError(URL, 503, "Service Unavailable", {}, io.BytesIO())
        self.urlopen.side_effect = [unavailable, response(PAYLOAD)]
        acceptance.download_archive(URL, self.archive, DIGEST)
        self.assertEqual(self.archive.read_bytes(), PAYLOAD)
        self.assertEqual(self.urlopen.call_count, 2)

    def test_permanent_http_error_fails_without_retry(self):
        self.urlopen.side_effect = HTTPError(URL, 404, "Not Found", {}, None)
        with self.assertRaises(HTTPError) as failure:
            acceptance.download_archive(URL, self.archive, DIGEST)
        self.assertEqual(failure.exception.code, 404)
        self.urlopen.assert_called_once()
        self.sleep.assert_not_called()
        self.assertEqual(list(self.archive.parent.iterdir()), [])

    def test_retries_are_bounded_and_leave_no_partial_download(self):
        self.urlopen.side_effect = [
            response(PAYLOAD[:3], content_length=len(PAYLOAD)) for _ in range(3)
        ]
        with self.assertRaises(http.client.IncompleteRead):
            acceptance.download_archive(URL, self.archive, DIGEST)
        self.assertEqual(self.urlopen.call_count, 3)
        self.assertEqual(list(self.archive.parent.iterdir()), [])

    def test_certificate_refusal_fails_without_retry(self):
        reason = ssl.SSLCertVerificationError(1, "certificate verify failed")
        self.urlopen.side_effect = URLError(reason)
        with self.assertRaises(URLError) as failure:
            acceptance.download_archive(URL, self.archive, DIGEST)
        self.assertIs(failure.exception.reason, reason)
        self.urlopen.assert_called_once()
        self.sleep.assert_not_called()
        self.assertEqual(list(self.archive.parent.iterdir()), [])

    def test_existing_archive_is_preserved(self):
        self.archive.write_bytes(b"already here")
        self.urlopen.return_value = response(PAYLOAD)
        with self.assertRaises(FileExistsError):
            acceptance.download_archive(URL, self.archive, DIGEST)
        self.assertEqual(self.archive.read_bytes(), b"already here")
        self.assertEqual(list(self.archive.parent.iterdir()), [self.archive])
