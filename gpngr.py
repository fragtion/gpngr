#!/usr/bin/env python3
# pingtracer.py -- pygame live ping grapher
# pip install pygame
import argparse, math, platform, re, socket, struct, subprocess
import sys, threading, time, os, select

try:
    import pygame
except ImportError:
    print("Error: pygame is required.  Run:  pip install pygame")
    sys.exit(1)

DEBUG        = False
PAYLOAD_SIZE = 0
TIMEOUT      = 3.0
UPDATE_HZ    = 30

C_BG        = (13,  17,  23)
C_GOOD      = (64,  104, 64)
C_WARN      = (140, 140, 0)
C_BAD       = (204, 204, 0)
C_LOSS      = (204, 32,  32)
C_AXIS      = (255, 255, 255)
C_GRID      = (40,  48,  60)
C_ZONE_WARN = (35,  35,  0)
C_ZONE_BAD  = (40,  0,   0)

WARN_DEFAULT = 80.0
BAD_DEFAULT  = 150.0
FONT_SZ      = 13
FONT_SZ_SM   = 10
LABEL_W      = 58
PAD_TOP      = 0
PAD_BOT      = 15

# ---------------------------------------------------------------------------
# Host config
# ---------------------------------------------------------------------------

def split_hosts(tokens):
    out = []
    for token in tokens:
        buf, depth = "", 0
        for ch in token:
            if ch == "{": depth += 1
            if ch == "}": depth -= 1
            if ch == "," and depth == 0:
                if buf.strip(): out.append(buf.strip())
                buf = ""
            else:
                buf += ch
        if buf.strip(): out.append(buf.strip())
    return out

def parse_host(h):
    m = re.match(r"([^{}]+)(\{([^}]*)\})?", h)
    host = m.group(1).strip()
    cfg  = m.group(3)
    rate, ymin, ymax, warn, bad = 2.0, None, None, WARN_DEFAULT, BAD_DEFAULT
    if cfg:
        p = [x.strip() for x in cfg.split(",")]
        def _f(idx, default):
            return float(p[idx]) if idx < len(p) and p[idx] not in ("", "auto") else default
        rate = _f(0, rate)
        ymin = _f(1, None)
        ymax = _f(2, None)
        warn = _f(3, warn)
        bad  = _f(4, bad)
    return host, rate, ymin, ymax, warn, bad

I_HOST=0; I_RATE=1; I_YMIN=2; I_YMAX=3; I_WARN=4; I_BAD=5

# ---------------------------------------------------------------------------
# ICMP with fixed packet construction
# ---------------------------------------------------------------------------

SOCK_MODE = None

def detect_sock_mode():
    global SOCK_MODE
    if SOCK_MODE is not None: return SOCK_MODE
    for mode, stype in (("raw", socket.SOCK_RAW), ("dgram", socket.SOCK_DGRAM)):
        try:
            s = socket.socket(socket.AF_INET, stype, socket.IPPROTO_ICMP)
            s.close()
            SOCK_MODE = mode
            return mode
        except (PermissionError, OSError):
            pass
    SOCK_MODE = "system"
    return "system"

def _checksum(data):
    """Standard ICMP checksum calculation"""
    s = 0
    # Make sure we have even length
    if len(data) % 2 == 1:
        data += b'\x00'
    
    # Sum 16-bit words
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    
    # Fold 32-bit sum to 16 bits
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def _build_packet(identifier, sequence):
    """Build a proper ICMP Echo Request packet (RFC 792 compliant)"""
    # Force values into 16-bit range
    identifier = identifier & 0xFFFF
    sequence = sequence & 0xFFFF
    
    # ICMP header: type=8, code=0, checksum=0, identifier, sequence
    header = struct.pack('!BBHHH', 8, 0, 0, identifier, sequence)
    
    # Create timestamp payload (8 bytes: seconds and microseconds)
    now = time.time()
    sec = int(now) & 0xFFFFFFFF
    usec = int((now - int(now)) * 1000000) & 0xFFFFFFFF
    timestamp = struct.pack('!II', sec, usec)
    
    # Build data payload
    if PAYLOAD_SIZE > 8:
        data = timestamp + b'\xAA' * (PAYLOAD_SIZE - 8)
    elif PAYLOAD_SIZE == 8:
        data = timestamp
    else:
        data = timestamp[:PAYLOAD_SIZE] if PAYLOAD_SIZE > 0 else b''
    
    # Complete packet
    packet = header + data
    
    # Calculate checksum
    chk = _checksum(packet)
    
    # Replace checksum in packet
    return packet[:2] + struct.pack('!H', chk) + packet[4:]

def _system_ping(host, timeout):
    """Fallback to system ping command"""
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", str(max(1, int(timeout*1000))), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=timeout+1)
        # Parse different ping output formats
        m = re.search(r'time[=<>]\s*([\d\.]+)\s*ms', out, re.IGNORECASE)
        if m:
            return float(m.group(1))
        m = re.search(r'round-trip.*?=\s*([\d\.]+)', out, re.IGNORECASE)
        if m:
            return float(m.group(1))
        return None
    except Exception as e:
        if DEBUG:
            sys.stderr.write(f"[system_ping] error: {e}\n")
        return None

class ICMPManager:
    def __init__(self):
        self.lock    = threading.Lock()
        self.pending = {}
        self.sock    = None
        self.mode    = detect_sock_mode()
        self.running = True
        
        if self.mode in ("raw", "dgram"):
            try:
                stype = socket.SOCK_RAW if self.mode == "raw" else socket.SOCK_DGRAM
                self.sock = socket.socket(socket.AF_INET, stype, socket.IPPROTO_ICMP)
                # Set socket options for better performance
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256*1024)
                self.sock.settimeout(0.1)  # Non-blocking with timeout
                
                if DEBUG:
                    sys.stderr.write(f"[icmp] initialized with mode={self.mode}\n")
                
                # Start receiver thread
                self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
                self.recv_thread.start()
                
            except (PermissionError, OSError) as ex:
                if DEBUG:
                    sys.stderr.write(f"[icmp] failed to create socket: {ex}\n")
                self.sock = None
                self.mode = "system"
        
        if self.mode == "system":
            if DEBUG:
                sys.stderr.write("[icmp] using system ping fallback\n")

    def request(self, host, timeout, ident, seq):
        """Send ping and wait for response"""
        # Resolve hostname
        try:
            dest_ip = socket.gethostbyname(host)
        except socket.gaierror:
            if DEBUG:
                sys.stderr.write(f"[icmp] DNS resolution failed: {host}\n")
            return None
        
        # Use system ping if no raw socket
        if self.sock is None or self.mode == "system":
            return _system_ping(host, timeout)
        
        # Force values into 16-bit range
        ident = ident & 0xFFFF
        seq = seq & 0xFFFF
        
        key = (dest_ip, ident, seq)
        ev = threading.Event()
        entry = {
            'event': ev,
            'result': None,
            'send_ts': time.monotonic(),
            'host': host
        }
        
        with self.lock:
            self.pending[key] = entry
        
        # Build and send packet
        packet = _build_packet(ident, seq)
        
        try:
            bytes_sent = self.sock.sendto(packet, (dest_ip, 0))
            if DEBUG:
                sys.stderr.write(f"[icmp] sent {bytes_sent} bytes to {dest_ip} id={ident} seq={seq}\n")
        except Exception as e:
            if DEBUG:
                sys.stderr.write(f"[icmp] sendto error: {e}\n")
            with self.lock:
                self.pending.pop(key, None)
            return _system_ping(host, timeout)
        
        # Wait for response
        ev.wait(timeout)
        
        # Get result
        with self.lock:
            entry = self.pending.pop(key, entry)
            # Cleanup old entries
            now = time.monotonic()
            stale = [k for k, e in self.pending.items() 
                    if now - e['send_ts'] > timeout * 2]
            for k in stale:
                self.pending.pop(k, None)
        
        result = entry.get('result')
        if DEBUG:
            if result is None:
                sys.stderr.write(f"[icmp] timeout for {dest_ip} id={ident} seq={seq}\n")
            else:
                sys.stderr.write(f"[icmp] reply from {dest_ip}: {result:.2f}ms\n")
        
        return result

    def _recv_loop(self):
        """Receive thread for ICMP replies"""
        while self.running:
            try:
                # Set a short timeout to allow checking self.running
                if self.sock:
                    self.sock.settimeout(0.1)
                else:
                    break
                
                try:
                    recvd, addr = self.sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except (socket.error, OSError) as e:
                    if DEBUG and e.errno not in (socket.EAGAIN, socket.EWOULDBLOCK):
                        sys.stderr.write(f"[icmp] recv error: {e}\n")
                    continue
                
                if not recvd:
                    continue
                
                recv_ts = time.monotonic()
                
                # Parse ICMP packet
                # Skip IP header (20 bytes) for raw sockets
                offset = 20 if self.mode == 'raw' else 0
                
                if len(recvd) < offset + 8:
                    continue
                
                # Extract ICMP header
                icmp_type, icmp_code, checksum, icmp_id, icmp_seq = struct.unpack(
                    '!BBHHH', recvd[offset:offset+8]
                )
                
                # Only process Echo Reply (type 0)
                if icmp_type != 0 or icmp_code != 0:
                    continue
                
                # Build key to find pending request
                # For DGRAM sockets, the source IP might be different
                if self.mode == 'dgram':
                    # Try to find by sequence number only (more flexible)
                    with self.lock:
                        found_key = None
                        for key in self.pending:
                            if key[2] == icmp_seq:  # Match by sequence
                                found_key = key
                                break
                        
                        if found_key:
                            entry = self.pending.get(found_key)
                            if entry:
                                elapsed = (recv_ts - entry['send_ts']) * 1000
                                if 0 < elapsed < 60000:
                                    entry['result'] = elapsed
                                else:
                                    entry['result'] = None
                                entry['event'].set()
                                if DEBUG:
                                    sys.stderr.write(f"[icmp] matched reply via seq {icmp_seq}\n")
                else:
                    # For raw sockets, use exact match
                    key = (addr[0], icmp_id, icmp_seq)
                    with self.lock:
                        entry = self.pending.get(key)
                        if entry:
                            elapsed = (recv_ts - entry['send_ts']) * 1000
                            if 0 < elapsed < 60000:
                                entry['result'] = elapsed
                            else:
                                entry['result'] = None
                            entry['event'].set()
            except Exception as e:
                if DEBUG:
                    sys.stderr.write(f"[icmp] recv_loop error: {e}\n")
                time.sleep(0.1)
    
    def shutdown(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

_icmp_manager = None
_mgr_lock = threading.Lock()

def get_manager():
    global _icmp_manager
    with _mgr_lock:
        if _icmp_manager is None:
            _icmp_manager = ICMPManager()
        return _icmp_manager

_ident_counter = 0
_ident_lock = threading.Lock()

def _next_ident():
    global _ident_counter
    with _ident_lock:
        _ident_counter = (_ident_counter + 1) & 0xFFFF  # Use bitmask instead of modulo
        if _ident_counter > 65535:
            _ident_counter = 0
        return _ident_counter

# ---------------------------------------------------------------------------
# Worker  -- stores resolved floats/None in a plain list, oldest first
# ---------------------------------------------------------------------------

class Worker(threading.Thread):
    def __init__(self, host, rate):
        super().__init__(daemon=True)
        self.host       = host
        self.rate       = rate
        self._lock      = threading.Lock()
        self._resolved  = []
        self._seq       = 0
        self._ident     = _next_ident()
        self._running   = True

    def run(self):
        interval = 1.0 / max(0.1, self.rate)
        while self._running:
            start_time = time.monotonic()
            
            # Send ping in a separate thread to not block
            self._seq = (self._seq + 1) & 0xFFFF  # Use bitmask instead of modulo
            if self._seq > 65535:
                self._seq = 0
            seq = self._seq
            thread = threading.Thread(target=self._ping, args=(seq,), daemon=True)
            thread.start()
            
            # Calculate next tick time
            elapsed = time.monotonic() - start_time
            sleep_time = max(0, interval - elapsed)
            if sleep_time > 0:
                time.sleep(sleep_time)
    
    def _ping(self, seq):
        try:
            result = get_manager().request(self.host, TIMEOUT, self._ident, seq)
            
            with self._lock:
                self._resolved.append(result)
                # Keep last 1 hour of data (3600 * rate)
                max_samples = int(3600 * self.rate)
                if len(self._resolved) > max_samples:
                    self._resolved = self._resolved[-max_samples:]
        except Exception as e:
            if DEBUG:
                sys.stderr.write(f"[worker] error: {e}\n")
            with self._lock:
                self._resolved.append(None)
    
    def stop(self):
        self._running = False

    def total(self):
        with self._lock:
            return len(self._resolved)

    def last_n(self, n):
        with self._lock:
            if n <= 0:
                return []
            return self._resolved[-n:] if len(self._resolved) >= n else self._resolved[:]

# ---------------------------------------------------------------------------
# GraphCell (unchanged from previous version)
# ---------------------------------------------------------------------------

def auto_layout(n, forced_rows=None, forced_cols=None):
    if forced_rows and forced_cols: return forced_rows, forced_cols
    if forced_rows: return forced_rows, math.ceil(n / forced_rows)
    if forced_cols: return math.ceil(n / forced_cols), forced_cols
    if n == 1: return 1, 1
    if n == 2: return 2, 1
    if n <= 4: return 2, 2
    c = int(n ** 0.5)
    return math.ceil(n / c), c

def severity_color(val, warn, bad):
    if val is None:  return C_LOSS
    if val > bad:    return C_BAD
    if val > warn:   return C_WARN
    return C_GOOD

class GraphCell:
    def __init__(self, worker, cfg, stretch, font, font_sm, font_bold, font_sm_bold):
        self.worker   = worker
        self.cfg      = cfg
        self.stretch  = stretch
        self.font     = font
        self.font_sm  = font_sm
        self.font_bold = font_bold
        self.font_sm_bold = font_sm_bold
        self.surf     = None
        self.rect     = None
        self._pw      = 0
        self._ph      = 0
        self._rendered_total = 0
        self._last_gmin = None
        self._last_gmax = None

    def _get_warn_row(self, gmin, gmax, ph):
        warn = self.cfg[I_WARN]
        if gmin < warn < gmax:
            return self._val_to_y(warn, gmin, gmax)
        else:
            return 0 if warn >= gmax else ph

    def _get_bad_row(self, gmin, gmax, ph):
        bad = self.cfg[I_BAD]
        if gmin < bad < gmax:
            return self._val_to_y(bad, gmin, gmax)
        else:
            return 0 if bad >= gmax else ph

    def _compute_scale(self, samples):
        ymin = self.cfg[I_YMIN]
        ymax = self.cfg[I_YMAX]
        valid = [v for v in samples if isinstance(v, float)]
        if ymax is not None:
            gmax = float(ymax)
        else:
            gmax = max(valid) * 1.20 if valid else 100.0
        gmax = max(gmax, 1.0)
        
        if ymin is not None:
            gmin = float(ymin)
        else:
            gmin = min(valid) * 0.85 if valid else 0.0
        return gmin, gmax

    def _val_to_y(self, v, gmin, gmax):
        frac = (v - gmin) / max(gmax - gmin, 1e-9)
        return int((1.0 - max(0.0, min(1.0, frac))) * (self._ph - 1))

    def _paint_background(self, gmin, gmax):
        warn = self.cfg[I_WARN]
        bad  = self.cfg[I_BAD]
        ph   = self._ph
        pw   = self._pw

        def to_y(v):
            frac = (v - gmin) / max(gmax - gmin, 1e-9)
            return int((1.0 - max(0.0, min(1.0, frac))) * (ph - 1))

        if gmin < warn < gmax:
            warn_row = to_y(warn)
        else:
            warn_row = 0 if warn >= gmax else ph

        if gmin < bad < gmax:
            bad_row = to_y(bad)
        else:
            bad_row = 0 if bad >= gmax else ph

        self.surf.fill(C_BG)

        if bad_row > 0:
            pygame.draw.rect(self.surf, C_ZONE_BAD, (0, 0, pw, bad_row))
        if warn_row > bad_row:
            pygame.draw.rect(self.surf, C_ZONE_WARN, (0, bad_row, pw, warn_row - bad_row))

    def _paint_col(self, x, val, gmin, gmax):
        warn = self.cfg[I_WARN]
        bad  = self.cfg[I_BAD]
        ph   = self._ph

        if val is None:
            pygame.draw.line(self.surf, C_LOSS, (x, 0), (x, ph - 1))
            return

        clamped  = max(gmin, min(val, gmax))
        data_row = self._val_to_y(clamped, gmin, gmax)
        color    = severity_color(val, warn, bad)

        pygame.draw.line(self.surf, color, (x, data_row), (x, ph - 1))

    def resize(self, rect):
        self.rect = rect
        pw = max(1, rect.width)
        ph = max(1, rect.height - PAD_BOT)
        
        if pw == self._pw and ph == self._ph:
            return
        
        self._pw = pw
        self._ph = ph
        self.surf = pygame.Surface((pw, ph))
        self.surf.fill(C_BG)
        
        self._rendered_total = 0
        self._last_gmin = None
        self._last_gmax = None
        
    def draw(self, screen):
        if self.surf is None or self.rect is None:
            return

        pw   = self._pw
        ph   = self._ph
        rate = self.cfg[I_RATE]
        host = self.cfg[I_HOST]

        total_now = self.worker.total()
        samples   = self.worker.last_n(pw)
        
        if not samples:
            return
            
        gmin, gmax = self._compute_scale(samples)

        scale_changed = False
        if self._last_gmin is not None:
            span = max(gmax - gmin, 1e-9)
            if abs(gmin - self._last_gmin) > span * 0.05 or \
               abs(gmax - self._last_gmax) > span * 0.05:
                scale_changed = True

        new_cols = total_now - self._rendered_total

        if scale_changed or self._rendered_total == 0:
            self._paint_background(gmin, gmax)
            start = max(0, pw - len(samples))
            for i, val in enumerate(samples):
                self._paint_col(start + i, val, gmin, gmax)
            self._rendered_total = total_now
            self._last_gmin = gmin
            self._last_gmax = gmax
        elif new_cols > 0:
            new_cols = min(new_cols, pw)
            self.surf.scroll(-new_cols, 0)
            bg_rect = pygame.Rect(pw - new_cols, 0, new_cols, ph)
            self.surf.fill(C_BG, bg_rect)
            
            warn_row = self._get_warn_row(gmin, gmax, ph)
            bad_row = self._get_bad_row(gmin, gmax, ph)
            
            if bad_row > 0:
                pygame.draw.rect(self.surf, C_ZONE_BAD, 
                               (pw - new_cols, 0, new_cols, bad_row))
            if warn_row > bad_row:
                pygame.draw.rect(self.surf, C_ZONE_WARN, 
                               (pw - new_cols, bad_row, new_cols, warn_row - bad_row))
            
            new_vals = samples[-new_cols:]
            for i, val in enumerate(new_vals):
                self._paint_col(pw - new_cols + i, val, gmin, gmax)
            self._rendered_total = total_now
            self._last_gmin = gmin
            self._last_gmax = gmax

        gx = self.rect.x
        gy = self.rect.y
        screen.blit(self.surf, (gx, gy))

        # Draw grid lines
        grid_surface = pygame.Surface((pw, ph), pygame.SRCALPHA)
        for i in range(5):
            frac = i / 4.0
            y = int(frac * (ph - 1))
            pygame.draw.line(grid_surface, (*C_GRID, 64), (0, y), (pw - 1, y))
        screen.blit(grid_surface, (gx, gy))

        # Helper functions for text rendering
        def render_with_stroke(text, font, color, x, y, stroke_color=(0, 0, 0), stroke_width=2):
            text_surf = font.render(text, True, color)
            w = text_surf.get_width() + stroke_width * 2
            h = text_surf.get_height() + stroke_width * 2
            temp_surf = pygame.Surface((w, h), pygame.SRCALPHA)
            for dx in range(-stroke_width, stroke_width + 1):
                for dy in range(-stroke_width, stroke_width + 1):
                    if dx == 0 and dy == 0:
                        continue
                    if abs(dx) + abs(dy) <= stroke_width:
                        stroke_part = font.render(text, True, stroke_color)
                        temp_surf.blit(stroke_part, (dx + stroke_width, dy + stroke_width))
            temp_surf.blit(text_surf, (stroke_width, stroke_width))
            screen.blit(temp_surf, (x, y))

        def render_with_bg(text, font, color, x, y):
            text_surf = font.render(text, True, color)
            bg_surf = pygame.Surface((text_surf.get_width(), text_surf.get_height()))
            bg_surf.fill((0, 0, 0))
            screen.blit(bg_surf, (x, y))
            screen.blit(text_surf, (x, y))

        # Y-axis labels
        grange = max(gmax - gmin, 1e-9)
        fmt = "%.1f" if grange < 20 else "%.0f"
        for i in range(5):
            frac = i / 4.0
            val = gmax - frac * grange
            y = gy + int(frac * (ph - 1))
            lbl_text = fmt % val
            x_pos = gx + 1
            if i == 0:
                y_pos = gy + 1
            elif i == 4:
                y_pos = gy + ph - FONT_SZ_SM - 1
            else:
                y_pos = y - FONT_SZ_SM // 2
            render_with_bg(lbl_text, self.font_sm_bold, C_AXIS, x_pos, y_pos)

        # Stats
        valid = [v for v in samples if isinstance(v, float)]
        loss_n = sum(1 for v in samples if v is None)
        loss_pct = 100.0 * loss_n / len(samples) if samples else 0.0
        avg = sum(valid) / len(valid) if valid else 0.0
        mn = min(valid) if valid else 0.0
        mx = max(valid) if valid else 0.0
        last = valid[-1] if valid else None

        def format_val(val):
            if val is None:
                return "!    "
            if val < 10:
                return f"{val:.1f}".ljust(4)
            elif val < 100:
                return f"{val:.0f}".ljust(3)
            else:
                return f"{val:.0f}".ljust(4)
        
        stats_line = f"last:{format_val(last)}  min:{format_val(mn)}  max:{format_val(mx)}  avg:{format_val(avg)}"
        lost_line = f"lost:{loss_n} ({loss_pct:.0f}%)"

        host_surf = self.font_bold.render(host, True, C_AXIS)
        host_x = gx + (pw - host_surf.get_width()) // 2
        render_with_stroke(host, self.font_bold, C_AXIS, host_x, gy + 0)
        render_with_stroke(stats_line, self.font_bold, C_AXIS, gx + 4, gy + FONT_SZ + 2)
        render_with_stroke(lost_line, self.font_bold, C_AXIS, gx + 4, gy + FONT_SZ + 2 + FONT_SZ + 1)

        # Time labels
        num_ticks = max(2, pw // 100)
        ty = gy + ph + 0
        for i in range(num_ticks + 1):
            frac = i / num_ticks
            x = gx + int(frac * (pw - 1))
            secs_ago = int((1.0 - frac) * pw / max(rate, 0.01))
            if secs_ago == 0:
                label = "now"
            elif secs_ago < 60:
                label = f"-{secs_ago}s"
            elif secs_ago < 3600:
                label = f"-{secs_ago//60}m"
            elif secs_ago < 86400:
                label = f"-{secs_ago//3600}h"
            else:
                label = f"-{secs_ago//86400}d"
            
            if i == 0:
                x_pos = x + 2
            elif i == num_ticks:
                lbl_w = self.font_sm_bold.size(label)[0]
                x_pos = x - lbl_w - 2
            else:
                lbl_w = self.font_sm_bold.size(label)[0]
                x_pos = x - lbl_w // 2
            render_with_stroke(label, self.font_sm_bold, C_AXIS, x_pos, ty)

        pygame.draw.rect(screen, C_GRID, (gx, gy, pw, ph), 1)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global DEBUG, TIMEOUT, PAYLOAD_SIZE

    ap = argparse.ArgumentParser(prog="pingtracer")
    ap.add_argument("hosts", nargs="+")
    ap.add_argument("--rows",     type=int,   default=None)
    ap.add_argument("--cols",     type=int,   default=None)
    ap.add_argument("--timeout",  type=float, default=3.0)
    ap.add_argument("--payload",  type=int,   default=0)
    ap.add_argument("--fps",      type=int,   default=UPDATE_HZ)
    ap.add_argument("--width",    type=int,   default=1280)
    ap.add_argument("--height",   type=int,   default=720)
    ap.add_argument("--windowed", action="store_true")
    ap.add_argument("--stretch",  action="store_true")
    ap.add_argument("--debug",    action="store_true")
    args = ap.parse_args()

    DEBUG        = args.debug
    TIMEOUT      = max(0.01, args.timeout)
    PAYLOAD_SIZE = max(0, args.payload)
    fps          = max(1, args.fps)

    # Parse hosts and create workers
    hosts   = split_hosts(args.hosts)
    cfgs    = [parse_host(h) for h in hosts]
    workers = [Worker(c[0], c[1]) for c in cfgs]
    for w in workers: 
        w.start()

    os.environ.setdefault("SDL_AUDIODRIVER", "dummy")

    pygame.init()
    pygame.display.set_caption("PingTracer")

    def get_bold_font(size):
        font_names = ['DejaVu Sans Mono', 'Courier New', 'Consolas', 'Monospace']
        for name in font_names:
            try:
                font = pygame.font.SysFont(name, size, bold=True)
                test_surf = font.render("W", True, (255,255,255))
                if test_surf.get_width() > 0:
                    return font
            except:
                continue
        return pygame.font.SysFont("monospace", size, bold=True)

    font = pygame.font.SysFont("monospace", FONT_SZ)
    font_sm = pygame.font.SysFont("monospace", FONT_SZ_SM)
    font_bold = get_bold_font(FONT_SZ)
    font_sm_bold = get_bold_font(FONT_SZ_SM)

    is_wsl = "microsoft" in platform.uname().release.lower() or "WSL_DISTRO_NAME" in os.environ
    want_fs = not args.windowed and not is_wsl

    if want_fs:
        info = pygame.display.Info()
        sw, sh = info.current_w, info.current_h
        screen = pygame.display.set_mode((sw, sh), pygame.FULLSCREEN | pygame.NOFRAME)
    else:
        sw, sh = args.width, args.height
        screen = pygame.display.set_mode((sw, sh), pygame.RESIZABLE)
    fullscreen = want_fs

    gr, gc = auto_layout(len(workers), args.rows, args.cols)
    cells = [GraphCell(w, cfg, args.stretch, font, font_sm, font_bold, font_sm_bold)
             for w, cfg in zip(workers, cfgs)]

    def layout_cells():
        W, H = screen.get_size()
        cw = W // gc
        ch = H // gr
        for idx, cell in enumerate(cells):
            r, c = divmod(idx, gc)
            cell.resize(pygame.Rect(c * cw, r * ch, cw, ch))

    layout_cells()
    clock = pygame.time.Clock()

    print("PingTracer  --  F=fullscreen toggle  Q=quit")
    print("Pinging: %s" % ", ".join(c[I_HOST] for c in cfgs))
    if DEBUG:
        print("Debug mode enabled")

    running = True
    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_q:
                    running = False
                elif event.key == pygame.K_ESCAPE and fullscreen:
                    fullscreen = False
                    screen = pygame.display.set_mode((args.width, args.height), pygame.RESIZABLE)
                    layout_cells()
                    pygame.display.set_caption("PingTracer")
                elif event.key == pygame.K_f:
                    fullscreen = not fullscreen
                    if fullscreen:
                        info = pygame.display.Info()
                        sw, sh = info.current_w, info.current_h
                        screen = pygame.display.set_mode((sw, sh), pygame.FULLSCREEN | pygame.NOFRAME)
                    else:
                        screen = pygame.display.set_mode((args.width, args.height), pygame.RESIZABLE)
                    layout_cells()
            elif event.type == pygame.VIDEORESIZE and not fullscreen:
                sw, sh = event.w, event.h
                screen = pygame.display.set_mode((sw, sh), pygame.RESIZABLE)
                layout_cells()

        screen.fill(C_BG)
        for cell in cells:
            cell.draw(screen)

        W, H = screen.get_size()
        for col in range(1, gc):
            x = col * (W // gc)
            pygame.draw.line(screen, C_GRID, (x, 0), (x, H))
        for row in range(1, gr):
            y = row * (H // gr)
            pygame.draw.line(screen, C_GRID, (0, y), (W, y))

        pygame.display.flip()
        clock.tick(fps)

    # Cleanup
    for worker in workers:
        worker.stop()
    if _icmp_manager:
        _icmp_manager.shutdown()
    pygame.quit()

if __name__ == "__main__":
    main()
