


class IPIntelligence:
    """IP geolocation and threat intelligence with TTL-based caching."""

    _PRIVATE_PREFIXES = (
        "10.", "192.168.", "172.16.", "127.", "localhost",
        "fe80:", "::1", "fc00:", "fd00:",
    )

    _CLOUD_PROVIDERS = ["amazon", "aws", "google cloud", "azure", "digitalocean", "ovh", "hetzner"]
    _HOSTING_KEYWORDS = ["hosting", "server", "datacenter", "vps", "dedicated"]
    _ISP_KEYWORDS = ["telecom", "comcast", "verizon", "att", "broadband", "cable"]

    def __init__(self):
        self.cache: dict = {}
        self.cache_ttl = 3600

    def get_geolocation(self, ip: str) -> dict:
        # Return cached result if still valid
        if ip in self.cache:
            entry = self.cache[ip]
            if time.time() - entry.get("timestamp", 0) < self.cache_ttl:
                return entry["geo"]

        if ip.startswith(self._PRIVATE_PREFIXES):
            return self._cache_and_return(ip, {
                "country": "LOCAL", "countryCode": "LO",
                "city": "Private Network", "isp": "Local Network", "threat": "SAFE",
            })

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as"
            req = urllib.request.Request(url, headers={"User-Agent": "DEATH_STAR/1.7"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read().decode())

            if data.get("status") == "success":
                return self._cache_and_return(ip, {
                    "country":     data.get("country", "Unknown"),
                    "countryCode": data.get("countryCode", "??"),
                    "city":        data.get("city", "Unknown"),
                    "isp":         data.get("isp", "Unknown"),
                    "org":         data.get("org", ""),
                    "as":          data.get("as", ""),
                    "threat":      self._assess_threat(data),
                })

        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
            pass

        return {"country": "Unknown", "countryCode": "??",
                "city": "Unknown", "isp": "Unknown", "threat": "UNKNOWN"}

    def _cache_and_return(self, ip: str, geo: dict) -> dict:
        self.cache[ip] = {"geo": geo, "timestamp": time.time()}
        return geo

    def _assess_threat(self, geo_data: dict) -> str:
        org = geo_data.get("org", "").lower()
        isp = geo_data.get("isp", "").lower()

        if any(x in org or x in isp for x in self._CLOUD_PROVIDERS):
            return "CLOUD"
        if any(x in org or x in isp for x in self._HOSTING_KEYWORDS):
            return "HOSTING"
        if any(x in isp for x in self._ISP_KEYWORDS):
            return "ISP"

        return "UNKNOWN"