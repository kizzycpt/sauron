import math
from frontend.icons import EARTH_MAP


class Globe:
    """3D ASCII Globe renderer."""

    CHARS = [(" ", 0.0), ("`", 0.05), (".", 0.10), ("-", 0.15), ("+", 0.20),
             ("=", 0.30), ("o", 0.40), ("%", 0.60), ("#", 0.80), ("@", 1.0)]

    def __init__(self, width, height, aspect_ratio=2.0):
        self.width        = max(1, width)
        self.height       = max(1, height)
        self.aspect_ratio = aspect_ratio
        self.map_width    = len(EARTH_MAP[0])
        self.map_height   = len(EARTH_MAP)
        self.radius       = max(1.0, min(width / 2.5, height * aspect_ratio / 2.5))
        self.attacks:  list = []
        self.lighting  = False
        self.plus_mode = False

    def add_attack(self, lat, lon, label="*"):
        self.attacks.append((lat, lon, label))

    def sample_earth_at(self, lat, lon):
        y = max(0, min(int(((lat + 90)  / 180) * (self.map_height - 1)), self.map_height - 1))
        x = max(0, min(int(((lon + 180) / 360) * (self.map_width  - 1)), self.map_width  - 1))
        return EARTH_MAP[y][x]

    def project_3d_to_2d(self, lat, lon, rotation):
        adj_lon = (((-lon + 90) + 180) % 360) - 180
        lat_r   = math.radians(lat)
        lon_r   = math.radians(adj_lon + math.degrees(rotation))
        x = math.cos(lat_r) * math.cos(lon_r)
        y = math.sin(lat_r)
        z = math.cos(lat_r) * math.sin(lon_r)

        if z < 0:
            return None, None, False

        sx = int(x * self.radius) + self.width  // 2
        sy = int(-y * self.radius / self.aspect_ratio) + self.height // 2

        if 0 <= sx < self.width and 0 <= sy < self.height:
            return sx, sy, True
        return None, None, False

    def render(self, rotation, rainbow_mode=False, skittles_mode=False):
        screen  = [[(" ", 0, False)] * self.width for _ in range(self.height)]
        density = [[0.0]             * self.width for _ in range(self.height)]
        attack  = [[False]           * self.width for _ in range(self.height)]
        cx, cy  = self.width // 2, self.height // 2

        for lat, lon, _ in self.attacks:
            sx, sy, vis = self.project_3d_to_2d(lat, lon, rotation)
            if vis:
                attack[sy][sx] = True

        for y in range(self.height):
            for x in range(self.width):
                dx   = float(x - cx)
                dy   = float(y - cy) * self.aspect_ratio
                dist = math.sqrt(dx*dx + dy*dy)

                if dist <= self.radius:
                    nx, ny = dx / self.radius, dy / self.radius
                    nz2    = 1 - nx*nx - ny*ny

                    if nz2 >= 0:
                        nz  = math.sqrt(nz2)
                        lat = math.degrees(math.asin(ny))
                        lon = ((math.degrees(math.atan2(nx, nz)) + math.degrees(rotation) + 180) % 360) - 180
                        ch  = self.sample_earth_at(lat, lon)
                        bd  = 1.0 if ch == "#" else (0.6 if ch == "." else (0.8 if ch != " " else 0.0))
                        density[y][x] += bd

                        if bd > 0:
                            aa = 0.05
                            if x > 0:               density[y][x-1] += aa
                            if x < self.width  - 1: density[y][x+1] += aa
                            if y > 0:               density[y-1][x] += aa
                            if y < self.height - 1: density[y+1][x] += aa

                if self.radius - 0.5 < dist < self.radius + 0.5:
                    density[y][x] += 0.2

        for y in range(self.height):
            for x in range(self.width):
                d  = density[y][x]
                ch = next((c for c, thr in reversed(self.CHARS) if d >= thr), " ")

                if self.plus_mode and ch not in (" ", "`", ".", "-"):
                    ch = "+"
                if attack[y][x]:
                    ch = "*"

                cidx = 0
                if ch != " ":
                    if rainbow_mode:
                        cidx = ((x + y) % 7) + 1
                    elif skittles_mode:
                        h    = (((x*2654435761) ^ (y*2246822519) ^ ((x^y)*3266489917)) & 0xFFFFFFFF)
                        cidx = (h % 16) + 1

                screen[y][x] = (ch, cidx, self.lighting and ch != " ")

        return screen