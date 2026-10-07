import json
from pathlib import Path
from mitmproxy import connection, ctx, http
from mitmproxy.io import FlowWriter
from mitmproxy.io import tnetstring
from mitmproxy.addons.savehar import SaveHar
from mitmproxy.websocket import WebSocketData, WebSocketMessage

class Generator:
    def load(self, loader):
        loader.add_option("rea_fixture_root", str, "", "Owned synthetic fixture root")

    def running(self):
        root = Path(ctx.options.rea_fixture_root)
        first = http.HTTPFlow(connection.Client(peername=("127.0.0.1", 1), sockname=("127.0.0.1", 2)), connection.Server(address=("example.test", 80)))
        first.id = "original-producer-id"
        first.request = http.Request.make("POST", "http://example.test/a?token=ordinary", b"\x00\xffbody", [(b"Authorization", b"Bearer native-transport-secret"), (b"X-Duplicate", b"one"), (b"X-Duplicate", b"two")])
        first.request.path = "http://user:password@example.test/a?token=ordinary#fragment"
        first.response = http.Response.make(200, b"\x00\xfeanswer", [(b"Set-Cookie", b"session=cookie-secret"), (b"Location", b"https://redirect-user:redirect-password@example.test/b?token=ordinary")])
        first.metadata = {"big_integer": 9007199254740993, "nonfinite": float("inf"), "isLosslessNumber": True, "value": "ordinary-extension", "response": {"headers": [["Authorization", "ordinary-extension-credential-name"]]}}
        first.websocket = WebSocketData(messages=[WebSocketMessage(2, True, b"\x00\xfdmessage", 123.5)])
        first.backup()
        first.comment = "caller-selected-fixture"
        second = first.copy()
        second.id = first.id
        second.request.raw_content = None
        second.response.raw_content = b""
        second.websocket = None
        with (root / "flows.mitm").open("wb") as handle:
            writer = FlowWriter(handle)
            writer.add(first)
            writer.add(second)
        har_first, har_second = first.copy(), second.copy()
        har_first.request.path = "/a?token=ordinary#fragment"
        har_second.request.path = "/a?token=ordinary#fragment"
        har_first.response.raw_content = b"\x00\xff\x01\xfe"
        markers = {"sensitive": "REDACTED", "bracket": "literal[", "overlap": "secret", "ordinary": "unmarked"}
        har = SaveHar().make_har([har_first, har_second])
        har["log"]["entries"][0]["_markers"] = markers
        (root / "producer.har").write_text(json.dumps(har))
        strings = first.get_state()
        for state in [strings, strings["backup"]]:
            state["request"]["path"] = "https://native-user:string-password@example.test/string-path"
            state["request"]["authority"] = "authority-user:authority-password@example.test"
            state["request"]["headers"] = [(b"Referer", "https://referer-user:referer-password@example.test/from"), (b"Origin", "//origin-user:origin-password@example.test")]
            state["response"]["headers"] = [(b"Location", "https://location-user:location-password@example.test/to")]
            state["metadata"]["_markers"] = dict(markers)
        with (root / "string-urls.mitm").open("wb") as handle:
            tnetstring.dump(strings, handle)
        (root / "oracle.json").write_text(json.dumps({"records": 2, "request_base64": "AP9ib2R5", "response_base64": "AP5hbnN3ZXI=", "websocket_base64": "AP1tZXNzYWdl", "id": first.id}))
        ctx.master.shutdown()

addons = [Generator()]
