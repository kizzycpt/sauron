class DeviceInventory:
    def __init__(self, args, hostname_for, open_ports_for, os_detector, default_ports):
        self.args = args
        self.hostname_for = hostname_for
        self.open_ports_for = open_ports_for
        self.os_detector = os_detector
        self.default_ports = default_ports

    def build(self, hosts, now_iso):
        ports = self.args.ports or self.default_ports
        current_devices = {}
        current_ip_to_mac = {}

        for ip, mac in hosts.items():
            current_ip_to_mac[ip] = mac

            dev = current_devices.setdefault(
                mac,
                {
                    "mac": mac,
                    "ips": set(),
                    "hostname": None,
                    "open_ports": set(),
                    "os_guess": None,
                    "first_seen": None,
                    "last_seen": None,
                    "missed_runs": 0,
                },
            )

            dev["ips"].add(ip)

            hostname = self.hostname_for(ip)
            if hostname and not dev["hostname"]:
                dev["hostname"] = hostname

            open_ports = self.open_ports_for(ip, ports)
            dev["open_ports"].update(open_ports)

            if dev["os_guess"] is None:
                os_name, accuracy = self.os_detector.guess_for(ip)
                if os_name and accuracy >= 80:
                    dev["os_guess"] = os_name

        for dev in current_devices.values():
            dev["ips"] = sorted(dev["ips"])
            dev["open_ports"] = sorted(dev["open_ports"])
            dev["last_seen"] = now_iso

        return current_devices, current_ip_to_mac
