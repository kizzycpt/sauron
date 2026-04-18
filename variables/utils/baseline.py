class BaselineManager:
    def __init__(self, baseline, baseline_file):
        self.baseline = baseline
        self.baseline_file = baseline_file

    def build_new_baseline(self, current_devices, current_ip_to_mac, gw_ip, gw_mac, now_iso):
        base_devs = self.baseline.get("devices", {})

        new_baseline = {
            "last_run_at": now_iso,
            "gateway_ip": gw_ip,
            "gateway_mac": gw_mac,
            "ip_to_mac": current_ip_to_mac,
            "devices": {},
        }

        for mac, cur in current_devices.items():
            prev = base_devs.get(mac, {})
            first_seen = prev.get("first_seen", now_iso)

            new_baseline["devices"][mac] = {
                "mac": mac,
                "ips": cur["ips"],
                "hostname": cur["hostname"],
                "open_ports": cur["open_ports"],
                "os_guess": cur["os_guess"],
                "first_seen": first_seen,
                "last_seen": now_iso,
                "missed_runs": 0,
            }

        for mac, prev in base_devs.items():
            if mac not in new_baseline["devices"]:
                preserved = dict(prev)
                preserved["missed_runs"] = int(prev.get("missed_runs", 0)) + 1
                new_baseline["devices"][mac] = preserved

        return new_baseline

    def save(self, new_baseline):
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_text(json.dumps(new_baseline, indent=2))

