"""Field Data: passive Wi-Fi survey upload, evil-twin / weak-own-network correlation, no client MACs stored."""

from __future__ import annotations

from sentinel_server.db import session_scope
from sentinel_server.models import Notification
from sentinel_server.phases.field_data import parse_airodump_csv

from .conftest import Browser


def _ap_row(bssid: str, privacy: str, essid: str) -> str:
    # BSSID, first, last, channel, speed, privacy, cipher, auth, power, beacons, IV, LAN IP, ID-len, ESSID, Key
    t = "2026-10-27 10:00:00"
    return f"{bssid}, {t}, {t}, 6, 130, {privacy}, CCMP, PSK, -45, 100, 0, 0.0.0.0, {len(essid)}, {essid}, "


CSV = "\n".join([
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Auth, Power, beacons, IV,"
    " LAN IP, ID-length, ESSID, Key",
    "",
    _ap_row("AA:BB:CC:DD:EE:FF", "WPA2", "HomeNet"),
    _ap_row("11:22:33:44:55:66", "OPN", "HomeNet"),
    _ap_row("AA:BB:CC:DD:EE:01", "OPN", "MyGuest"),
    _ap_row("99:88:77:66:55:44", "WPA2", "Neighbor"),
    "",
    "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs",
    "DE:AD:BE:EF:00:11, 2026-10-27 10:00:00, 2026-10-27 10:05:00, -50, 10, AA:BB:CC:DD:EE:FF, ",
    "",
])


def _set_known(browser: Browser) -> None:
    r = browser.put("/api/field/known-networks",
                    json={"own_ssids": ["HomeNet"], "own_bssids": ["AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:01"]})
    assert r.status_code == 200


def test_parser_reads_only_access_points():
    aps = parse_airodump_csv(CSV)
    assert [a["bssid"] for a in aps] == ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "AA:BB:CC:DD:EE:01",
                                         "99:88:77:66:55:44"]
    assert "DE:AD:BE:EF:00:11" not in CSV.split("Station MAC")[0]  # the client MAC is only in the ignored section


def test_upload_classifies_evil_twin_and_weak_own(browser: Browser):
    _set_known(browser)
    capture = browser.post("/api/field/captures", json={
        "kind": "wifi_survey", "source_label": "Alfa AWUS036ACHM", "airodump_csv": CSV}).json()
    by_bssid = {o["key"]: o for o in capture["observations"]}
    assert by_bssid["AA:BB:CC:DD:EE:FF"]["classification"] == "own"
    assert by_bssid["11:22:33:44:55:66"]["classification"] == "rogue_suspect"  # HomeNet from an unknown radio
    assert by_bssid["11:22:33:44:55:66"]["severity"] == "high"
    assert by_bssid["AA:BB:CC:DD:EE:01"]["classification"] == "weak_own"  # my own AP, open
    assert by_bssid["99:88:77:66:55:44"]["classification"] == "unknown"  # a neighbour, left alone
    assert capture["summary"]["rogue_suspects"] == 1 and capture["summary"]["weak_own"] == 1
    # no client/station MAC was stored anywhere
    import json as _json

    assert "DE:AD:BE:EF:00:11" not in _json.dumps(capture)
    with session_scope() as db:
        kinds = {n.kind for n in db.query(Notification).all()}
        assert "field" in kinds


def test_known_networks_validate_mac(browser: Browser):
    assert browser.put("/api/field/known-networks", json={"own_bssids": ["not-a-mac"]}).status_code == 422
    assert browser.put("/api/field/known-networks", json={"own_ssids": ["Net"], "own_bssids": []}).status_code == 200


def test_list_detail_summary_and_delete(browser: Browser):
    _set_known(browser)
    cap = browser.post("/api/field/captures", json={"kind": "wifi_survey", "airodump_csv": CSV}).json()
    assert browser.get("/api/field/captures").json()["total"] == 1
    assert browser.get(f"/api/field/captures/{cap['id']}").json()["record_count"] == 4
    summary = browser.get("/api/field/summary").json()
    assert summary["access_points"] == 4 and summary["rogue_suspects"] == 1
    assert summary["known_networks"]["own_ssids"] == ["HomeNet"]
    assert browser.delete(f"/api/field/captures/{cap['id']}").status_code == 204
    assert browser.get("/api/field/captures").json()["total"] == 0


def test_generic_observations_upload(browser: Browser):
    cap = browser.post("/api/field/captures", json={
        "kind": "rf_survey", "source_label": "Flipper Zero + BFFB",
        "observations": [{"kind": "rf_signal", "key": "433.92", "label": "garage remote",
                          "data": {"frequency_mhz": 433.92, "protocol": "unknown"}}]}).json()
    assert cap["record_count"] == 1 and cap["observations"][0]["label"] == "garage remote"
    assert cap["kind"] == "rf_survey"
