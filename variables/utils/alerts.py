class AlertManager:
    SENSITIVE_PORTS = {22, 23, 445, 3389}

    def __init__(self, baseline, is_first_run, gw_ip, gw_mac, now_iso):
        self.baseline = baseline
        self.is_first_run = is_first_run
        self.gw_ip = gw_ip
        self.gw_mac = gw_mac
        self.now_iso = now_iso
        self.alerts = []
        self.offline_this_run = []
        self.opened_by_mac = {}
        self.closed_by_mac = {}

    def add_alert(self, severity, alert_type, message):
        self.alerts.append(f"{self.now_iso} {severity} {alert_type} {message}")

    def compare(self, current_devices, current_ip_to_mac):
        base_devs = self.baseline.get("devices", {})
        base_ip2mac = self.baseline.get("ip_to_mac", {})

        if self.baseline.get("gateway_mac") and self.gw_mac and self.gw_mac != self.baseline["gateway_mac"]:
            if not self.is_first_run:
                self.add_alert(
                    "HIGH",
                    "GATEWAY_MAC_CHANGE",
                    f"ip={self.gw_ip} old={self.baseline['gateway_mac']} new={self.gw_mac}",
                )

        for mac, cur in current_devices.items():
            if mac not in base_devs:
                if not self.is_first_run:
                    self.add_alert(
                        "HIGH",
                        "NEW_DEVICE",
                        f"mac={mac} ips={cur['ips']} ports={cur['open_ports']}",
                    )
                continue

            old = base_devs[mac]
            old_ports = set(old.get("open_ports", []))
            new_ports = set(cur["open_ports"])

            opened = sorted(new_ports - old_ports)
            closed = sorted(old_ports - new_ports)

            if opened:
                self.opened_by_mac[mac] = opened
                if not self.is_first_run:
                    severity = "HIGH" if any(port in self.SENSITIVE_PORTS for port in opened) else "MEDIUM"
                    self.add_alert(
                        severity,
                        "PORT_OPENED",
                        f"mac={mac} ips={cur['ips']} opened={opened}",
                    )

            if closed:
                self.closed_by_mac[mac] = closed
                if not self.is_first_run:
                    self.add_alert(
                        "INFO",
                        "PORT_CLOSED",
                        f"mac={mac} ips={cur['ips']} closed={closed}",
                    )

            old_os = old.get("os_guess")
            new_os = cur.get("os_guess")
            if new_os and old_os and new_os != old_os:
                if not self.is_first_run:
                    self.add_alert(
                        "LOW",
                        "OS_CHANGED",
                        f"mac={mac} from={old_os} to={new_os}",
                    )

        for mac, old in base_devs.items():
            if mac not in current_devices:
                self.offline_this_run.append(mac)
                missed_runs = int(old.get("missed_runs", 0)) + 1
                old["missed_runs"] = missed_runs

                severity = "MEDIUM" if missed_runs >= 3 else "INFO"
                if not self.is_first_run:
                    self.add_alert(
                        severity,
                        "OFFLINE",
                        f"mac={mac} last_seen={old.get('last_seen')} missed_runs={missed_runs}",
                    )

        for ip, mac in current_ip_to_mac.items():
            if ip in base_ip2mac and base_ip2mac[ip] != mac:
                if not self.is_first_run:
                    self.add_alert(
                        "HIGH",
                        "IP_MAC_MISMATCH",
                        f"ip={ip} old_mac={base_ip2mac[ip]} new_mac={mac}",
                    )

        return {
            "alerts": self.alerts,
            "offline_this_run": self.offline_this_run,
            "opened_by_mac": self.opened_by_mac,
            "closed_by_mac": self.closed_by_mac,
        }