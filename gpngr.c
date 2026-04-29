// gpngr.c -- Cross-platform Graphical Ping Grapher
// Version v1.0 - Windows/Linux support
// By Dimitri Pappas -- github.com/fragtion/gpngr
//
// Uses raw ICMP. Currently ipv4 only - PR for IPv6 welcome.
// Build Windows: gcc -O2 -o gpngr.exe gpngr.c -lws2_32 -lwinmm -lgdi32 -luser32 -lmsimg32 -mwindows
// Build Linux:   gcc -O2 -o gpngr gpngr.c -lm -lpthread -lrt -lX11 -lXext -lXft
// Build macOS:   gcc -O2 -o gpngr gpngr.c -lm -lpthread -lX11 -lXext -lXft
// Run as root on Linux only if net.ipv4.ping_group_range does not cover your GID.
// On modern distros (and macOS) unprivileged ICMP works out of the box.

#ifdef __linux__
#  define _POSIX_C_SOURCE 200809L
#  define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

// ---------------------------------------------------------------------------
// Ring buffer design notes
// ---------------------------------------------------------------------------
// Each worker owns a heap-allocated ring of exactly `ring_cap` samples.
// ring_cap is determined once at worker-creation time:
//   - explicit config  (cfg.max_samples > 0): ring_cap = cfg.max_samples
//   - auto config      (cfg.max_samples == 0): ring_cap = startup cell width
//                       (updated on first WM_SIZE / ConfigureNotify)
//
// When the window is resized the main thread calls resize_worker_ring():
//   - new_cap > old_cap : ring is expanded; older slots are zeroed (empty).
//   - new_cap < old_cap : ring is trimmed to the most-recent new_cap samples.
//   - After trimming, stats (min/max/avg, sent/received) are recomputed from
//     the retained samples so they always reflect what is actually stored.
//
// The send/recv threads use ring_cap (never a global MAX_SAMPLES constant)
// for all modulo arithmetic, so nothing escapes the buffer.
//
// MAX_RING_CAP is a hard upper bound only -- it is not the default allocation.
//
// When entering focused (exclusive) view of a single graph, workers that are
// not focused are NOT resized -- they continue running with their existing
// ring so their history is preserved when returning to the multi-graph view.
// ---------------------------------------------------------------------------

#define MAX_RING_CAP  18000   // hard ceiling; no worker may exceed this
#define MAX_HOSTS        32

#ifdef _WIN32
// ========================================================================
// WINDOWS IMPLEMENTATION
// ========================================================================
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <mmsystem.h>
#include <wingdi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "msimg32.lib")

#define GPNGR_VERSION "v1.0"

// Colours
#define C_BG        RGB(0,    0,    0)
#define C_GOOD      RGB(64,  104,  64)
#define C_WARN      RGB(140, 140,   0)
#define C_BAD       RGB(204, 204,   0)
#define C_LOSS      RGB(204,  32,  32)
#define C_AXIS      RGB(255, 255, 255)
#define C_GRID_R    80
#define C_GRID_G    95
#define C_GRID_B   112
#define C_GRID_ALPHA 60
#define C_ZONE_WARN RGB(22,   22,   0)
#define C_ZONE_BAD  RGB(28,    0,   0)
#define C_PENDING   RGB(60,   60,  60)

// ICMP
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0

#pragma pack(push, 1)
typedef struct {
    unsigned char  type, code;
    unsigned short checksum, id, sequence;
} icmp_hdr_t;

typedef struct {
    unsigned char  ver_ihl, tos;
    unsigned short total_len, id, frag_off;
    unsigned char  ttl, protocol;
    unsigned short checksum;
    unsigned int   src, dst;
} ip_hdr_t;
#pragma pack(pop)

static unsigned short icmp_checksum(unsigned short *buf, int len) {
    unsigned long s = 0;
    while (len > 1) { s += *buf++; len -= 2; }
    if (len)         { s += *(unsigned char*)buf; }
    s  = (s >> 16) + (s & 0xffff);
    s += (s >> 16);
    return (unsigned short)(~s);
}

// Per-host configuration parsed from command-line arguments.
// Fields with has_* flags are only applied when explicitly set by the user.
typedef struct {
    char   host[256];
    double rate;          // pings per second
    double ymin, ymax;    // y-axis range (ms)
    double warn, bad;     // RTT thresholds (ms) for colour zones
    int    has_ymin, has_ymax;
    // User-specified sample limit (0 = auto: match graph pixel width).
    // Read-only after parsing; never mutated at draw/resize time.
    int    max_samples;
} host_cfg_t;

// Sample states stored in the ring buffer
#define STATE_EMPTY   0
#define STATE_PENDING 1
#define STATE_OK      2
#define STATE_LOST    3

typedef struct {
    int    state;
    double rtt;       // RTT in microseconds
    LONGLONG send_ts; // QueryPerformanceCounter tick at send time
} sample_t;

// Per-host worker: owns the socket pair, ring buffer, and two threads.
typedef struct {
    host_cfg_t  cfg;
    SOCKET      sock;
    struct sockaddr_in dest;
    unsigned short ident;
    unsigned short next_seq;
    CRITICAL_SECTION  lock;
    HANDLE            send_thread;
    HANDLE            recv_thread;
    HANDLE            timeout_thread;
    volatile int      running;

    // Dynamic ring buffer (heap-allocated, size = ring_cap)
    sample_t      *ring;       // [ring_cap]
    int           *seq_slot;   // sequence# -> slot mapping [ring_cap]
    int           *seq_valid;  // validity flag per seq slot [ring_cap]
    int           *seq_seqno;  // actual sequence number per slot, for collision detection
    int            ring_cap;   // current allocated capacity
    int            head;       // next write position
    int            count;      // live samples in ring (0..ring_cap)

    double rtt_min, rtt_max, rtt_avg;
    int    sent, received;
    double frozen_gmin, frozen_gmax;
    int    has_frozen;
    int    pending_count;      // number of in-flight (STATE_PENDING) samples
    int    pending_head;       // head index of circular pending list
    int    pending_tail;       // tail index of circular pending list
    int    pending_list[MAX_RING_CAP];  // ring slot indices of pending samples
} worker_t;

// Globals
static int       g_num_workers = 0;
static worker_t *g_workers[MAX_HOSTS];
static int  g_rows = 0, g_cols = 0;
static int  g_focused = -1;
static HWND    g_hwnd;
static HDC     g_back_dc  = NULL;
static HBITMAP g_back_bmp = NULL;
static int     g_back_w = 0, g_back_h = 0;
static DWORD g_last_click_t = 0;
static int   g_last_click_x = 0, g_last_click_y = 0;
static int             g_fullscreen      = 0;
static WINDOWPLACEMENT g_saved_placement = { sizeof(WINDOWPLACEMENT) };
static int g_start_fullscreen = 0;
static int g_opt_display      = -1;

// Function prototypes
static int split_hosts(const char *src, char out[][512], int max_out);
static void parse_host_cfg(const char *token, host_cfg_t *c);
static DWORD WINAPI send_thread(LPVOID arg);
static DWORD WINAPI recv_thread(LPVOID arg);
static worker_t* create_worker(const host_cfg_t *cfg, int worker_index, int initial_cap);
static void stop_worker(worker_t *w);
static void resize_worker_ring(worker_t *w, int new_cap);
static void auto_layout(int n, int forced_rows, int forced_cols, int *rows_out, int *cols_out);
static void compute_scale(worker_t *w, int width, double *gmin_out, double *gmax_out);
static void fill_rect(HDC hdc, int x, int y, int w, int h, COLORREF c);
static void draw_line_blended(HDC hdc, int x1, int y1, int x2, int y2,
                              int r, int g, int b, int alpha);
static HFONT make_font(int sz, int bold);
static int text_width(HDC hdc, const char *s, int sz, int bold);
static void draw_text(HDC hdc, int x, int y, const char *s, COLORREF c, int sz, int bold);
static void draw_text_stroke(HDC hdc, int x, int y, const char *s, COLORREF c, int sz, int bold);
static void draw_cell(HDC hdc, worker_t *w, RECT r);
static void ensure_backbuf(HDC screen_dc, int w, int h);
static void repaint(HWND hwnd);
static void toggle_fullscreen(HWND hwnd);
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
static BOOL CALLBACK MonitorEnumProc(HMONITOR hmon, HDC hdc_unused, LPRECT lpr, LPARAM lp);
static BOOL get_monitor_by_index(int n, MONITORINFO *out);
static void update_ring_sizes(int win_w, int win_h);
static int cell_cap_for_worker(int worker_idx, int win_w, int win_h);

// ---------------------------------------------------------------------------
// Command-line parsing helpers
// ---------------------------------------------------------------------------

// Split a comma-separated host list, respecting {}-enclosed parameter blocks.
static int split_hosts(const char *src, char out[][512], int max_out) {
    int n = 0, depth = 0;
    char buf[512]; int bi = 0;
    for (const char *p = src; *p; p++) {
        if (*p == '{') depth++;
        if (*p == '}') depth--;
        if (*p == ',' && depth == 0) {
            buf[bi] = 0;
            while (bi > 0 && buf[bi-1] == ' ') buf[--bi] = 0;
            char *s = buf; while (*s == ' ') s++;
            if (*s && n < max_out) { strcpy(out[n++], s); }
            bi = 0;
        } else {
            if (bi < 511) buf[bi++] = *p;
        }
    }
    buf[bi] = 0;
    char *s = buf; while (*s == ' ') s++;
    int tl = (int)strlen(s);
    while (tl > 0 && s[tl-1] == ' ') s[--tl] = 0;
    if (*s && n < max_out) strcpy(out[n++], s);
    return n;
}

// Parse a single host token of the form "hostname{rate,ymin,ymax,warn,bad,samples}".
// Any parameter may be blank or "auto" to use the default value.
// The samples parameter also accepts a time input instead (e.g. "60m"), in which
// case that duration's worth of samples will be calculated and stored instead.
static void parse_host_cfg(const char *token, host_cfg_t *c) {
    c->rate    = 2.0;
    c->ymin    = 0;  c->has_ymin = 0;
    c->ymax    = 0;  c->has_ymax = 0;
    c->warn    = 80.0;
    c->bad     = 150.0;
    c->max_samples = 0;

    const char *lb = strchr(token, '{');
    if (lb) {
        int hlen = (int)(lb - token);
        if (hlen > 255) hlen = 255;
        strncpy(c->host, token, hlen);
        c->host[hlen] = 0;
        int l = (int)strlen(c->host);
        while (l > 0 && c->host[l-1] == ' ') c->host[--l] = 0;

        char params[256] = {0};
        const char *rb = strchr(lb, '}');
        int plen = rb ? (int)(rb - lb - 1) : (int)strlen(lb+1);
        if (plen > 255) plen = 255;
        strncpy(params, lb+1, plen);

        // Split on commas manually to preserve empty fields (blank parameters).
        char *fields[6];
        int nf = 0;
        char tmp[256]; strcpy(tmp, params);
        char *p = tmp;
        while (nf < 6) {
            fields[nf++] = p;
            char *comma = strchr(p, ',');
            if (!comma) break;
            *comma = '\0';
            p = comma + 1;
        }

        // field[0]: ping rate in pings per second (plain decimal number).
        if (0 < nf && fields[0][0] && strcmp(fields[0], "auto") != 0)
            c->rate = atof(fields[0]);

        // fields[1-4]: ymin, ymax, warn, bad -- all specified by the user in ms.
        // Stored internally in µs (multiply by 1000) since RTT values are in µs.
        if (1 < nf && fields[1][0] && strcmp(fields[1], "auto") != 0) { c->ymin = atof(fields[1]) * 1000.0; c->has_ymin = 1; }
        if (2 < nf && fields[2][0] && strcmp(fields[2], "auto") != 0) { c->ymax = atof(fields[2]) * 1000.0; c->has_ymax = 1; }
        if (3 < nf && fields[3][0] && strcmp(fields[3], "auto") != 0) c->warn = atof(fields[3]);
        if (4 < nf && fields[4][0] && strcmp(fields[4], "auto") != 0) c->bad  = atof(fields[4]);

        // field[5]: max_samples -- absolute count or time string (e.g. "1h").
        if (5 < nf && fields[5][0]) {
            const char *s = fields[5];
            char *endptr;
            long val = strtol(s, &endptr, 10);
            if (endptr != s && *endptr == '\0') {
                c->max_samples = (int)val;
            } else {
                size_t len = strlen(s);
                if (len > 1) {
                    char unit = s[len-1];
                    char numbuf[32];
                    strncpy(numbuf, s, len-1);
                    numbuf[len-1] = '\0';
                    double num = atof(numbuf);
                    double multiplier = 1.0;
                    switch (unit) {
                        case 's': multiplier = 1.0;     break;
                        case 'm': multiplier = 60.0;    break;
                        case 'h': multiplier = 3600.0;  break;
                        case 'd': multiplier = 86400.0; break;
                        default:  multiplier = 1.0;     break;
                    }
                    c->max_samples = (int)(c->rate * num * multiplier);
                    if (c->max_samples <= 0) c->max_samples = 1;
                }
            }
        }
        if (c->max_samples > MAX_RING_CAP) c->max_samples = MAX_RING_CAP;

        // warn/bad are specified in ms by the user; convert to µs for internal use
        // since all RTT values are stored in microseconds.
        c->warn *= 1000.0;
        c->bad  *= 1000.0;
    } else {
        strncpy(c->host, token, 255);
        c->host[255] = 0;
        int l = (int)strlen(c->host);
        while (l > 0 && c->host[l-1] == ' ') c->host[--l] = 0;
        // Apply default warn/bad thresholds in µs.
        c->warn *= 1000.0;
        c->bad  *= 1000.0;
    }
}

// ---------------------------------------------------------------------------
// Compute the desired ring capacity for a given worker index and window size.
// For explicit configs this is always cfg.max_samples.
// For auto configs it is the pixel width of that worker's cell in the
// multi-graph layout (focused view does NOT shrink non-focused workers).
// ---------------------------------------------------------------------------
static int cell_cap_for_worker(int worker_idx, int win_w, int win_h) {
    (void)win_h;
    worker_t *w = g_workers[worker_idx];
    if (w->cfg.max_samples > 0)
        return w->cfg.max_samples;   // explicit -- never touch

    int rows, cols;
    auto_layout(g_num_workers, g_rows, g_cols, &rows, &cols);

    // Focused worker gets the full window width; non-focused workers keep their
    // multi-graph cell width so their history is preserved when returning.
    int cell_w = (g_focused == worker_idx) ? win_w : win_w / cols;
    if (cell_w < 1)           cell_w = 1;
    if (cell_w > MAX_RING_CAP) cell_w = MAX_RING_CAP;
    return cell_w;
}

// ---------------------------------------------------------------------------
// Resize a worker's ring to new_cap.
// Must be called from the main thread while the worker threads are running;
// the function acquires the worker lock internally.
//
// Algorithm:
//   1. Snapshot the most-recent min(count, new_cap) samples into a temp buffer.
//   2. Reallocate ring/seq_slot/seq_valid.
//   3. Rewrite the ring in chronological order (oldest at index 0).
//   4. Recompute sent/received/rtt_min/max/avg from retained samples.
// ---------------------------------------------------------------------------
static void resize_worker_ring(worker_t *w, int new_cap) {
    if (new_cap < 1)          new_cap = 1;
    if (new_cap > MAX_RING_CAP) new_cap = MAX_RING_CAP;

    // Quick check under lock, then do all heavy work outside it
    EnterCriticalSection(&w->lock);
    if (new_cap == w->ring_cap) {
        LeaveCriticalSection(&w->lock);
        return;
    }
    int old_cap   = w->ring_cap;
    int old_count = w->count;
    int old_head  = w->head;
    LeaveCriticalSection(&w->lock);

    int keep = old_count < new_cap ? old_count : new_cap;

    sample_t *new_ring      = (sample_t*)malloc(new_cap * sizeof(sample_t));
    int      *new_seq_slot  = (int*)malloc(new_cap * sizeof(int));
    int      *new_seq_valid = (int*)malloc(new_cap * sizeof(int));
    int      *new_seq_seqno = (int*)malloc(new_cap * sizeof(int));
    if (new_ring) memset(new_ring, 0, new_cap * sizeof(sample_t));

    if (!new_ring || !new_seq_slot || !new_seq_valid || !new_seq_seqno) {
        free(new_ring); free(new_seq_slot);
        free(new_seq_valid); free(new_seq_seqno);
        return;
    }

    // Copy outside the lock -- we use the snapshot of old_head/old_cap/old_count.
    // The send thread may advance w->head during this, but we only read slots
    // older than old_head which are no longer being written to.
    for (int i = 0; i < keep; i++) {
        int src_age = keep - 1 - i;
        int src_idx = ((old_head - 1 - src_age) + old_cap * 2) % old_cap;
        new_ring[i] = w->ring[src_idx];
    }

    // Recompute stats and pending list outside the lock -- new_ring is not yet
    // visible to any other thread so no synchronisation is needed here.
    double new_rtt_min = 1e18, new_rtt_max = -1e18, new_rtt_avg = 0.0;
    int    new_received = 0;
    int    new_lost     = 0;
    int    new_pending_count = 0;
    int    new_pending_head  = 0;
    int    new_pending_tail  = 0;
    // pending_list entries are written here then copied in under the lock
    // pending_list is MAX_RING_CAP so no bounds issue
    int    tmp_pending_list[MAX_RING_CAP];
    for (int i = 0; i < keep; i++) {
        if (new_ring[i].state == STATE_OK) {
            double v = new_ring[i].rtt;
            if (v < new_rtt_min) new_rtt_min = v;
            if (v > new_rtt_max) new_rtt_max = v;
            new_rtt_avg += v;
            new_received++;
        } else if (new_ring[i].state == STATE_LOST) {
            new_lost++;
        } else if (new_ring[i].state == STATE_PENDING) {
            tmp_pending_list[new_pending_tail] = i;
            new_pending_tail = (new_pending_tail + 1) % MAX_RING_CAP;
            new_pending_count++;
        }
    }
    if (new_received > 0)
        new_rtt_avg /= new_received;
    else {
        new_rtt_min = 0.0;
        new_rtt_max = 0.0;
    }

    // Now lock only for the pointer swap -- this is now just a handful of
    // assignments and a memcpy, releasing as fast as possible.
    EnterCriticalSection(&w->lock);
    w->rtt_min  = new_rtt_min;
    w->rtt_max  = new_rtt_max;
    w->rtt_avg  = new_received > 0 ? new_rtt_avg : 0.0;
    w->received = new_received;
    w->sent     = new_received + new_lost + new_pending_count;

    free(w->ring);
    free(w->seq_slot);
    free(w->seq_valid);
    free(w->seq_seqno);
    w->ring      = new_ring;
    w->seq_slot  = new_seq_slot;
    w->seq_valid = new_seq_valid;
    w->seq_seqno = new_seq_seqno;
    w->ring_cap  = new_cap;
    w->head      = keep % new_cap;
    w->count     = keep;

    // Swap in the pre-computed pending list
    w->pending_count = new_pending_count;
    w->pending_head  = new_pending_head;
    w->pending_tail  = new_pending_tail;
    if (new_pending_count > 0)
        memcpy(w->pending_list, tmp_pending_list,
               new_pending_count * sizeof(int));
    LeaveCriticalSection(&w->lock);
}

// ---------------------------------------------------------------------------
// Update ring sizes for all auto-configured workers on window resize.
// Workers with explicit max_samples are never resized.
// Non-focused workers are sized to their normal multi-graph cell width so
// their ring is preserved when entering/leaving focused view.
// ---------------------------------------------------------------------------
static void update_ring_sizes(int win_w, int win_h) {
    for (int i = 0; i < g_num_workers; i++) {
        worker_t *w = g_workers[i];
        if (w->cfg.max_samples > 0) continue;  // explicit -- never resize
        int new_cap = cell_cap_for_worker(i, win_w, win_h);
        if (new_cap != w->ring_cap)
            resize_worker_ring(w, new_cap);
    }
}

// ---------------------------------------------------------------------------
// High-resolution microsecond timer using QueryPerformanceCounter.
// ---------------------------------------------------------------------------
static LONGLONG get_tick_us_win(void) {
    static LARGE_INTEGER freq;
    static int init = 0;
    if (!init) {
        QueryPerformanceFrequency(&freq);
        init = 1;
    }
    LARGE_INTEGER pc;
    QueryPerformanceCounter(&pc);
    return (pc.QuadPart * 1000000LL) / freq.QuadPart;
}

// ---------------------------------------------------------------------------
// ICMP send thread -- timestamps in microseconds via QueryPerformanceCounter
// ---------------------------------------------------------------------------
static DWORD WINAPI send_thread(LPVOID arg) {
    worker_t *w = (worker_t*)arg;
    double interval_ms = 1000.0 / (w->cfg.rate > 0 ? w->cfg.rate : 2.0);

    while (w->running) {
        DWORD t0_ms = timeGetTime();

        // Build packet before taking lock to minimise lock duration
        unsigned short current_seq;
        int current_slot;
        char pkt[sizeof(icmp_hdr_t)];

        EnterCriticalSection(&w->lock);
        int cap  = w->ring_cap;
        int slot = w->head;
        w->head  = (w->head + 1) % cap;
        if (w->count < cap) w->count++;

        current_seq  = w->next_seq++;
        current_slot = slot;
        sample_t *s  = &w->ring[slot];
	s->state     = STATE_PENDING;
        s->rtt       = 0;
        s->send_ts   = get_tick_us_win();  // capture before unlock, before sendto

        int map_idx = (int)(current_seq % cap);
        w->seq_slot[map_idx]  = slot;
        w->seq_seqno[map_idx] = current_seq;
        w->seq_valid[map_idx] = 1;
        w->sent++;

        int pending_idx = w->pending_tail;
        w->pending_list[pending_idx] = current_slot;
        w->pending_tail = (w->pending_tail + 1) % MAX_RING_CAP;
        w->pending_count++;
        LeaveCriticalSection(&w->lock);

        // Build and send packet outside lock
        icmp_hdr_t *h = (icmp_hdr_t*)pkt;
        h->type     = ICMP_ECHO_REQUEST;
        h->code     = 0;
        h->id       = w->ident;
        h->sequence = current_seq;
        h->checksum = 0;
        h->checksum = icmp_checksum((unsigned short*)pkt, sizeof(pkt));

        sendto(w->sock, pkt, sizeof(pkt), 0,
               (struct sockaddr*)&w->dest, sizeof(w->dest));

        InvalidateRect(g_hwnd, NULL, FALSE);

        DWORD elapsed = timeGetTime() - t0_ms;
        double sleep_ms = interval_ms - (double)elapsed;
        if (sleep_ms > 0) Sleep((DWORD)sleep_ms);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// ICMP recv thread -- also marks pending samples as lost after timeout.
// RTT is measured in microseconds using QueryPerformanceCounter.
// ---------------------------------------------------------------------------
#define LOSS_TIMEOUT_MS 2000

static DWORD WINAPI recv_thread(LPVOID arg) {
    worker_t *w = (worker_t*)arg;
    
    while (w->running) {
        fd_set fds; FD_ZERO(&fds); FD_SET(w->sock, &fds);
        struct timeval tv = { 0, 50000 };
        int sel = select(0, &fds, NULL, NULL, &tv);

        if (sel > 0) {
            char rbuf[1024];
            struct sockaddr_in from; int fromlen = sizeof(from);
            int r = recvfrom(w->sock, rbuf, sizeof(rbuf), 0,
                             (struct sockaddr*)&from, &fromlen);
            if (r >= (int)(sizeof(ip_hdr_t) + sizeof(icmp_hdr_t))) {
                ip_hdr_t  *ip  = (ip_hdr_t*)rbuf;
                int         ihl = (ip->ver_ihl & 0x0F) * 4;
                if (r >= ihl + (int)sizeof(icmp_hdr_t)) {
                    icmp_hdr_t *rep = (icmp_hdr_t*)(rbuf + ihl);

                    int byteswapped = (rep->id != w->ident && rep->id == htons(w->ident));
                    if (rep->type == ICMP_ECHO_REPLY && (rep->id == w->ident || byteswapped)) {
                        LONGLONG now_us = get_tick_us_win();
                        unsigned short seq = rep->sequence;
                        if (byteswapped) seq = htons(seq);

                        EnterCriticalSection(&w->lock);
                        int cap     = w->ring_cap;
                        int map_idx = (int)(seq % cap);
                        if (w->seq_valid[map_idx] && w->seq_slot[map_idx] >= 0 && w->seq_seqno[map_idx] == seq) {  // Verify sequence number matches
                            int slot2    = w->seq_slot[map_idx];
                            sample_t *s2 = &w->ring[slot2];
                            if (s2->state == STATE_PENDING) {
                                double rtt = (double)(now_us - s2->send_ts);
                                if (rtt < 0.0) rtt = 0.0;
                                s2->rtt   = rtt;
                                s2->state = STATE_OK;
                                w->received++;
                                if (w->received == 1) {
                                    w->rtt_min = rtt;
                                    w->rtt_max = rtt;
                                    w->rtt_avg = rtt;
                                } else {
                                    if (rtt < w->rtt_min) w->rtt_min = rtt;
                                    if (rtt > w->rtt_max) w->rtt_max = rtt;
                                    w->rtt_avg = w->rtt_avg * 0.95 + rtt * 0.05;
                                }
                            }
                            w->seq_valid[map_idx] = 0;
                        }
                        LeaveCriticalSection(&w->lock);
                        InvalidateRect(g_hwnd, NULL, FALSE);
                    }
                }
            }
        }

    }
    return 0;
}

// ---------------------------------------------------------------------------
// Dedicated timeout thread - checks for lost packets without blocking receive
// ---------------------------------------------------------------------------
static DWORD WINAPI timeout_thread(LPVOID arg) {
    worker_t *w = (worker_t*)arg;
    
    while (w->running) {
        Sleep(100);  // check every 100ms for efficiency
        
        // Quick check without lock -- if no pending samples, skip
        if (w->pending_count == 0) continue;
        
        EnterCriticalSection(&w->lock);
        LONGLONG now_us = get_tick_us_win();
        
        // Check only the oldest pending samples (cap at 50 per iteration)
        int max_check = w->pending_count;
        if (max_check > 50) max_check = 50;
        
        for (int i = 0; i < max_check && w->pending_count > 0; i++) {
            int pending_idx = w->pending_head % MAX_RING_CAP;
            int slot_idx = w->pending_list[pending_idx];
            
            // Safety check for invalid slot
            if (slot_idx < 0 || slot_idx >= w->ring_cap) {
                w->pending_head = (w->pending_head + 1) % MAX_RING_CAP;
                w->pending_count--;
                continue;
            }
            
            sample_t *s = &w->ring[slot_idx];
            if (s->state == STATE_PENDING) {
                if (s->send_ts == 0) continue;  // timestamp not yet written, skip
                if ((now_us - s->send_ts) >= (LONGLONG)LOSS_TIMEOUT_MS * 1000LL) {
                    s->state = STATE_LOST;
                    w->pending_head = (w->pending_head + 1) % MAX_RING_CAP;
                    w->pending_count--;
                    InvalidateRect(g_hwnd, NULL, FALSE);
                } else {
                    // samples are in time order (oldest first), so stop checking
                    break;
                }
            } else {
                // sample already resolved (STATE_OK), remove from pending list
                w->pending_head = (w->pending_head + 1) % MAX_RING_CAP;
                w->pending_count--;
            }
        }
        
        LeaveCriticalSection(&w->lock);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Worker lifecycle
// ---------------------------------------------------------------------------
static worker_t* create_worker(const host_cfg_t *cfg, int worker_index, int initial_cap) {
    worker_t *w = (worker_t*)calloc(1, sizeof(worker_t));
    if (!w) return NULL;
    w->cfg = *cfg;

    // Explicit override takes priority; otherwise use initial_cap (cell width).
    int cap = (cfg->max_samples > 0) ? cfg->max_samples : initial_cap;
    if (cap < 1)           cap = 1;
    if (cap > MAX_RING_CAP) cap = MAX_RING_CAP;

    w->ring      = (sample_t*)calloc(cap, sizeof(sample_t));
    w->seq_slot  = (int*)calloc(cap, sizeof(int));
    w->seq_valid = (int*)calloc(cap, sizeof(int));
    w->seq_seqno = (int*)calloc(cap, sizeof(int));
    if (!w->ring || !w->seq_slot || !w->seq_valid || !w->seq_seqno) {
        free(w->ring); free(w->seq_slot); free(w->seq_valid); free(w->seq_seqno); free(w);
        return NULL;
    }
    w->ring_cap = cap;
    w->head     = 0;
    w->count    = 0;

    w->pending_count = 0;
    w->pending_head = 0;
    w->pending_tail = 0;
    memset(w->pending_list, 0, sizeof(w->pending_list));

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;
    if (getaddrinfo(cfg->host, NULL, &hints, &res) != 0) {
        free(w->ring); free(w->seq_slot); free(w->seq_valid); free(w);
        return NULL;
    }
    w->dest = *(struct sockaddr_in*)res->ai_addr;
    freeaddrinfo(res);

    w->sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (w->sock == INVALID_SOCKET) {
        free(w->ring); free(w->seq_slot); free(w->seq_valid); free(w);
        return NULL;
    }

    int toms = 100;
    setsockopt(w->sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&toms, sizeof(toms));

    w->ident = (unsigned short)(((GetCurrentProcessId() & 0xFF) << 8) | (worker_index & 0xFF));
    w->next_seq = 0;
    w->running  = 1;
    InitializeCriticalSectionAndSpinCount(&w->lock, 4000);
    w->timeout_thread = CreateThread(NULL, 0, timeout_thread, w, 0, NULL);
    if (!w->timeout_thread) {
        w->running = 0;
        DeleteCriticalSection(&w->lock);
        closesocket(w->sock);
        free(w->ring); free(w->seq_slot); free(w->seq_valid); free(w->seq_seqno); free(w);
        return NULL;
    }
    w->recv_thread = CreateThread(NULL, 0, recv_thread, w, 0, NULL);
    if (!w->recv_thread) {
        DeleteCriticalSection(&w->lock);
        closesocket(w->sock);
        free(w->ring); free(w->seq_slot); free(w->seq_valid); free(w);
        return NULL;
    }

    w->send_thread = CreateThread(NULL, 0, send_thread, w, 0, NULL);
    if (!w->send_thread) {
        w->running = 0;
        WaitForSingleObject(w->recv_thread, 2000);
        CloseHandle(w->recv_thread);
        DeleteCriticalSection(&w->lock);
        closesocket(w->sock);
        free(w->ring); free(w->seq_slot); free(w->seq_valid); free(w);
        return NULL;
    }
    //SetThreadPriority(w->recv_thread, THREAD_PRIORITY_HIGHEST);
    //SetThreadPriority(w->send_thread, THREAD_PRIORITY_TIME_CRITICAL);
    return w;
}

static void stop_worker(worker_t *w) {
    if (!w) return;
    w->running = 0;
    WaitForSingleObject(w->timeout_thread, 4000);
    WaitForSingleObject(w->send_thread, 4000);
    WaitForSingleObject(w->recv_thread, 4000);
    CloseHandle(w->timeout_thread);
    CloseHandle(w->send_thread);
    CloseHandle(w->recv_thread);
    DeleteCriticalSection(&w->lock);
    closesocket(w->sock);
    free(w->ring);
    free(w->seq_slot);
    free(w->seq_valid);
    free(w);
}

// ---------------------------------------------------------------------------
// Layout helpers
// ---------------------------------------------------------------------------
static void auto_layout(int n, int forced_rows, int forced_cols, int *rows_out, int *cols_out) {
    if (forced_rows && forced_cols) { *rows_out = forced_rows; *cols_out = forced_cols; return; }
    if (forced_rows) { *rows_out = forced_rows; *cols_out = (n + forced_rows - 1) / forced_rows; return; }
    if (forced_cols) { *cols_out = forced_cols; *rows_out = (n + forced_cols - 1) / forced_cols; return; }
    if (n == 1) { *rows_out = 1; *cols_out = 1; return; }
    if (n == 2) { *rows_out = 2; *cols_out = 1; return; }
    if (n <= 4) { *rows_out = 2; *cols_out = 2; return; }
    int c = (int)sqrt((double)n);
    *cols_out = c;
    *rows_out = (n + c - 1) / c;
}

// ---------------------------------------------------------------------------
// Scale computation -- scans the most-recent `width` samples in the ring
// ---------------------------------------------------------------------------
static void compute_scale(worker_t *w, int width, double *gmin_out, double *gmax_out) {
    host_cfg_t *c = &w->cfg;
    if (c->has_ymin && c->has_ymax) {
        *gmin_out = c->ymin; *gmax_out = c->ymax; return;
    }

    EnterCriticalSection(&w->lock);
    double mn = 1e18, mx = -1e18;
    int    valid = 0;
    int cap   = w->ring_cap;
    int total = w->count < width ? w->count : width;
    for (int i = 0; i < total; i++) {
        int idx = ((w->head - 1 - i) + cap * 2) % cap;
        sample_t *s = &w->ring[idx];
        if (s->state == STATE_OK) {
            double v = s->rtt;
            if (v < mn) mn = v;
            if (v > mx) mx = v;
            valid++;
        }
    }
    LeaveCriticalSection(&w->lock);

    if (valid > 0) {
        double gmax = c->has_ymax ? c->ymax : mx * 1.20;
        double gmin = c->has_ymin ? c->ymin : mn * 0.85;
        if (gmax < 1.0) gmax = 1.0;
        if (gmin < 0.0) gmin = 0.0;
        w->frozen_gmin = gmin; w->frozen_gmax = gmax; w->has_frozen = 1;
        *gmin_out = gmin; *gmax_out = gmax;
    } else if (w->has_frozen) {
        *gmin_out = w->frozen_gmin; *gmax_out = w->frozen_gmax;
    } else {
        *gmin_out = 0.0; *gmax_out = 100.0;
    }
}

// ---------------------------------------------------------------------------
// GDI helpers
// ---------------------------------------------------------------------------
static void fill_rect(HDC hdc, int x, int y, int w, int h, COLORREF c) {
    RECT r = {x, y, x+w, y+h};
    HBRUSH br = CreateSolidBrush(c);
    FillRect(hdc, &r, br);
    DeleteObject(br);
}

static void draw_line_blended(HDC hdc, int x1, int y1, int x2, int y2,
                              int r, int g, int b, int alpha) {
    int lw = abs(x2 - x1) + 1;
    int lh = abs(y2 - y1) + 1;
    int lx = x1 < x2 ? x1 : x2;
    int ly = y1 < y2 ? y1 : y2;

    HDC mem = CreateCompatibleDC(hdc);
    BITMAPINFO bmi;
    ZeroMemory(&bmi, sizeof(bmi));
    bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth       = 1;
    bmi.bmiHeader.biHeight      = 1;
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    void *bits = NULL;
    HBITMAP bmp = CreateDIBSection(mem, &bmi, DIB_RGB_COLORS, &bits, NULL, 0);
    if (!bmp) { DeleteDC(mem); return; }

    SelectObject(mem, bmp);

    unsigned char *p = (unsigned char*)bits;
    p[0] = (unsigned char)(b * alpha / 255);
    p[1] = (unsigned char)(g * alpha / 255);
    p[2] = (unsigned char)(r * alpha / 255);
    p[3] = (unsigned char)alpha;

    BLENDFUNCTION bf;
    bf.BlendOp             = AC_SRC_OVER;
    bf.BlendFlags          = 0;
    bf.SourceConstantAlpha = 255;
    bf.AlphaFormat         = AC_SRC_ALPHA;

    AlphaBlend(hdc, lx, ly, lw, lh, mem, 0, 0, 1, 1, bf);

    DeleteObject(bmp);
    DeleteDC(mem);
}

static HFONT make_font(int sz, int bold) {
    HFONT f = CreateFont(sz, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL, 0, 0, 0,
                         DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                         DEFAULT_PITCH|FF_DONTCARE, "Consolas");
    if (!f) f = CreateFont(sz, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL, 0, 0, 0,
                           DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH|FF_DONTCARE, "Courier New");
    return f;
}

static int text_width(HDC hdc, const char *s, int sz, int bold) {
    HFONT f = make_font(sz, bold);
    HFONT old = (HFONT)SelectObject(hdc, f);
    SIZE sz2; GetTextExtentPoint32(hdc, s, (int)strlen(s), &sz2);
    SelectObject(hdc, old); DeleteObject(f);
    return sz2.cx;
}

static void draw_text(HDC hdc, int x, int y, const char *s, COLORREF c, int sz, int bold) {
    HFONT f = make_font(sz, bold);
    HFONT old = (HFONT)SelectObject(hdc, f);
    SetTextColor(hdc, c);
    SetBkMode(hdc, TRANSPARENT);
    TextOut(hdc, x, y, s, (int)strlen(s));
    SelectObject(hdc, old); DeleteObject(f);
}

static void draw_text_stroke(HDC hdc, int x, int y, const char *s, COLORREF c, int sz, int bold) {
    draw_text(hdc, x-1, y,   s, RGB(0,0,0), sz, bold);
    draw_text(hdc, x+1, y,   s, RGB(0,0,0), sz, bold);
    draw_text(hdc, x,   y-1, s, RGB(0,0,0), sz, bold);
    draw_text(hdc, x,   y+1, s, RGB(0,0,0), sz, bold);
    draw_text(hdc, x,   y,   s, c,          sz, bold);
}

// ---------------------------------------------------------------------------
// Draw one graph cell
// ---------------------------------------------------------------------------
#define FONT_SZ     13
#define FONT_SZ_SM  10
#define PAD_BOT     14

static void draw_cell(HDC hdc, worker_t *w, RECT r) {
    int rx = r.left, ry = r.top;
    int rw = r.right  - r.left;
    int rh = r.bottom - r.top;
    int ph = rh - PAD_BOT;
    if (rw < 2 || ph < 2) return;

    // Draw at most rw columns (one sample per pixel column).
    int draw_count;
    EnterCriticalSection(&w->lock);
    draw_count = w->count < rw ? w->count : rw;
    LeaveCriticalSection(&w->lock);

    double gmin, gmax;
    compute_scale(w, rw, &gmin, &gmax);
    double grange = gmax - gmin;
    if (grange < 1e-9) grange = 1e-9;

    #define VAL_TO_Y(v) (ry + (int)((1.0 - ((v)-gmin)/grange) * (ph-1)))

    double warn = w->cfg.warn, bad = w->cfg.bad;
    int warn_y = (warn > gmin && warn < gmax) ? VAL_TO_Y(warn) : (warn >= gmax ? ry : ry+ph);
    int bad_y  = (bad  > gmin && bad  < gmax) ? VAL_TO_Y(bad)  : (bad  >= gmax ? ry : ry+ph);

    fill_rect(hdc, rx, ry, rw, ph, C_BG);
    if (bad_y > ry) fill_rect(hdc, rx, ry, rw, bad_y - ry, C_ZONE_BAD);
    if (warn_y > bad_y) fill_rect(hdc, rx, bad_y, rw, warn_y - bad_y, C_ZONE_WARN);

    EnterCriticalSection(&w->lock);
    int cap = w->ring_cap;
    for (int i = 0; i < draw_count; i++) {
        int idx = ((w->head - 1 - i) + cap * 2) % cap;
        int x = rx + rw - 1 - i;
        sample_t *s = &w->ring[idx];
        HPEN pen; HPEN old_pen;
        switch (s->state) {
        case STATE_PENDING:
            pen = CreatePen(PS_SOLID, 1, C_PENDING);
            old_pen = (HPEN)SelectObject(hdc, pen);
            MoveToEx(hdc, x, ry, NULL);
            LineTo(hdc, x, ry + ph - 1);
            SelectObject(hdc, old_pen); DeleteObject(pen);
            break;
        case STATE_LOST:
            pen = CreatePen(PS_SOLID, 1, C_LOSS);
            old_pen = (HPEN)SelectObject(hdc, pen);
            MoveToEx(hdc, x, ry, NULL);
            LineTo(hdc, x, ry+ph-1);
            SelectObject(hdc, old_pen); DeleteObject(pen);
            break;
        case STATE_OK: {
            double v = s->rtt;
            double clamped = v < gmin ? gmin : (v > gmax ? gmax : v);
            int bar_y = VAL_TO_Y(clamped);
            COLORREF col = (v >= bad) ? C_BAD : (v >= warn) ? C_WARN : C_GOOD;
            pen = CreatePen(PS_SOLID, 1, col);
            old_pen = (HPEN)SelectObject(hdc, pen);
            MoveToEx(hdc, x, bar_y, NULL);
            LineTo(hdc, x, ry+ph-1);
            SelectObject(hdc, old_pen); DeleteObject(pen);
            break;
        }
        default: break;
        }
    }
    LeaveCriticalSection(&w->lock);

    // Blended horizontal grid lines at 25% intervals
    for (int i = 0; i <= 4; i++) {
        int gy = ry + (int)((double)i / 4.0 * (ph-1));
        draw_line_blended(hdc, rx, gy, rx+rw-1, gy,
                          C_GRID_R, C_GRID_G, C_GRID_B, C_GRID_ALPHA);
    }

    // Y-axis labels: scale values are in µs; display in ms.
    // Show one decimal place below 100ms, integer at 100ms and above.
    char lbl[32];
    for (int i = 0; i <= 4; i++) {
        double val_us = gmax - (double)i / 4.0 * grange;
        double val_ms = val_us / 1000.0;
        if (val_ms >= 100.0 || (grange / 1000.0) >= 20.0)
            sprintf(lbl, "%.0f", val_ms);
        else
            sprintf(lbl, "%.1f", val_ms);
        int ly;
        if (i == 0) ly = ry + 1;
        else if (i == 4) ly = ry + ph - FONT_SZ_SM - 1;
        else ly = ry + (int)((double)i/4.0*(ph-1)) - FONT_SZ_SM/2;
        int lw = text_width(hdc, lbl, FONT_SZ_SM, 1);
        fill_rect(hdc, rx+1, ly, lw, FONT_SZ_SM+1, RGB(0,0,0));
        draw_text(hdc, rx+1, ly, lbl, C_AXIS, FONT_SZ_SM, 1);
    }

    int hw = text_width(hdc, w->cfg.host, FONT_SZ, 1);
    int hx = rx + (rw - hw) / 2;
    draw_text_stroke(hdc, hx, ry+2, w->cfg.host, C_AXIS, FONT_SZ, 1);

    EnterCriticalSection(&w->lock);
    double rmin = 1e18, rmax_v = -1e18, racc = 0.0;
    double last = -1.0;
    int rcv = 0, ring_lost = 0, ring_pending = 0;
    int total_scan = w->count < cap ? w->count : cap;
    for (int i = 0; i < total_scan; i++) {
        int idx = ((w->head - 1 - i) + cap * 2) % cap;
        sample_t *rs = &w->ring[idx];
        switch (rs->state) {
            case STATE_OK:
                if (last < 0) last = rs->rtt / 1000.0;
                if (rs->rtt < rmin) rmin = rs->rtt;
                if (rs->rtt > rmax_v) rmax_v = rs->rtt;
                racc += rs->rtt;
                rcv++;
                break;
            case STATE_LOST:    ring_lost++;    break;
            case STATE_PENDING: ring_pending++; break;
        }
    }
    double ravg   = rcv > 0 ? (racc / rcv) / 1000.0 : 0.0;
    rmin   = rcv > 0 ? rmin   / 1000.0 : 0.0;
    rmax_v = rcv > 0 ? rmax_v / 1000.0 : 0.0;
    int snt    = rcv + ring_lost + ring_pending;
    int lost_n = ring_lost;
    LeaveCriticalSection(&w->lock);

    double loss_pct = snt > 0 ? 100.0 * lost_n / snt : 0.0;

    char fmt_last[16], fmt_min[16], fmt_max[16], fmt_avg[16];
    // Display in ms: one decimal below 100ms, integer at 100ms and above.
    #define FMT_RTT(dst, v) \
        if ((v) < 0) sprintf((dst), "!"); \
        else if ((v) >= 100.0) sprintf((dst), "%.0f", (v)); \
        else sprintf((dst), "%.1f", (v));
    FMT_RTT(fmt_last, last)
    FMT_RTT(fmt_min,  rcv > 0 ? rmin   : -1.0)
    FMT_RTT(fmt_max,  rcv > 0 ? rmax_v : -1.0)
    FMT_RTT(fmt_avg,  rcv > 0 ? ravg   : -1.0)

    char seg[4][32];
    sprintf(seg[0], "last:%s", fmt_last);
    sprintf(seg[1], "min:%s",  fmt_min);
    sprintf(seg[2], "max:%s",  fmt_max);
    sprintf(seg[3], "avg:%s",  fmt_avg);

    int seg_w[4];
    for (int i = 0; i < 4; i++) seg_w[i] = text_width(hdc, seg[i], FONT_SZ, 1);
    int gap2 = text_width(hdc, "  ", FONT_SZ, 1);
    int gap1 = text_width(hdc, " ",  FONT_SZ, 1);

    char widest_lbl_w[32];
	double widest_val_ms_w = gmax / 1000.0;
	if (widest_val_ms_w >= 100.0 || (grange / 1000.0) >= 20.0)
		sprintf(widest_lbl_w, "%.0f", widest_val_ms_w);
	else
		sprintf(widest_lbl_w, "%.1f", widest_val_ms_w);
	int sx = rx + text_width(hdc, widest_lbl_w, FONT_SZ_SM, 1) + 6;
    int avail = rx + rw - 4 - sx;
    int stats_y = ry + FONT_SZ + 4;
    int line_h = FONT_SZ + 2;

    int tw2 = seg_w[0] + gap2 + seg_w[1] + gap2 + seg_w[2] + gap2 + seg_w[3];
    int tw1 = seg_w[0] + gap1 + seg_w[1] + gap1 + seg_w[2] + gap1 + seg_w[3];

    if (tw2 <= avail) {
        int spare = avail - tw2;
        int g = gap2 + (spare > 0 ? spare / 6 : 0);
        if (g > gap2 * 2) g = gap2 * 2;
        int cx = sx;
        for (int i = 0; i < 4; i++) {
            draw_text_stroke(hdc, cx, stats_y, seg[i], C_AXIS, FONT_SZ, 1);
            if (i < 3) cx += seg_w[i] + g;
        }
    } else if (tw1 <= avail) {
        int spare = avail - (seg_w[0]+seg_w[1]+seg_w[2]+seg_w[3]);
        int g = spare / 3;
        if (g < 0) g = 0;
        int cx = sx;
        for (int i = 0; i < 4; i++) {
            draw_text_stroke(hdc, cx, stats_y, seg[i], C_AXIS, FONT_SZ, 1);
            if (i < 3) cx += seg_w[i] + g;
        }
    } else {
        int fit = 1;
        int used = seg_w[0];
        for (int i = 1; i < 4; i++) {
            int next = used + gap1 + seg_w[i];
            if (next <= avail) { used = next; fit = i + 1; }
            else break;
        }
        int cx = sx;
        for (int i = 0; i < fit; i++) {
            draw_text_stroke(hdc, cx, stats_y, seg[i], C_AXIS, FONT_SZ, 1);
            if (i < fit-1) cx += seg_w[i] + gap1;
        }
        if (fit < 4) {
            int cx2 = sx;
            for (int i = fit; i < 4; i++) {
                draw_text_stroke(hdc, cx2, stats_y + line_h, seg[i], C_AXIS, FONT_SZ, 1);
                if (i < 3) cx2 += seg_w[i] + gap1;
            }
            stats_y += line_h;
        }
    }

    char lost_s[64];
    sprintf(lost_s, "lost:%d (%.0f%%)", lost_n, loss_pct);
    draw_text_stroke(hdc, sx, stats_y + line_h, lost_s, C_AXIS, FONT_SZ, 1);

    double rate = w->cfg.rate > 0 ? w->cfg.rate : 2.0;
    // The graph shows rw samples (one per pixel column); the time span shown
    // is rw/rate seconds.  When the window is resized, more/fewer pixels means
    // more/fewer samples and a proportionally different time span.
    int num_ticks = rw / 100;
    if (num_ticks < 2) num_ticks = 2;
    int ty = ry + ph + 2;

    for (int i = 0; i <= num_ticks; i++) {
        double frac = (double)i / num_ticks;
        int tx = rx + (int)(frac * (rw-1));
        int secs_ago = (int)((1.0 - frac) * rw / rate);
        char tlbl[16];
        if (secs_ago == 0) strcpy(tlbl, "now");
        else if (secs_ago < 60) sprintf(tlbl, "-%ds", secs_ago);
        else if (secs_ago < 3600) sprintf(tlbl, "-%dm", secs_ago/60);
        else if (secs_ago < 86400) sprintf(tlbl, "-%dh", secs_ago/3600);
        else sprintf(tlbl, "-%dd", secs_ago/86400);

        int tw = text_width(hdc, tlbl, FONT_SZ_SM, 1);
        int tx2;
        if (i == 0) tx2 = tx + 2;
        else if (i == num_ticks) tx2 = tx - tw - 2;
        else tx2 = tx - tw/2;
        draw_text_stroke(hdc, tx2, ty, tlbl, C_AXIS, FONT_SZ_SM, 1);
    }

    #undef VAL_TO_Y
    #undef FMT_RTT
}

// ---------------------------------------------------------------------------
// Back-buffer management
// ---------------------------------------------------------------------------
static void ensure_backbuf(HDC screen_dc, int w, int h) {
    if (g_back_dc && g_back_w == w && g_back_h == h) return;
    if (g_back_bmp) { DeleteObject(g_back_bmp); g_back_bmp = NULL; }
    if (g_back_dc)  { DeleteDC(g_back_dc);       g_back_dc  = NULL; }
    g_back_dc  = CreateCompatibleDC(screen_dc);
    g_back_bmp = CreateCompatibleBitmap(screen_dc, w, h);
    SelectObject(g_back_dc, g_back_bmp);
    g_back_w = w; g_back_h = h;
}

static void repaint(HWND hwnd) {
    RECT client; GetClientRect(hwnd, &client);
    int W = client.right, H = client.bottom;
    if (W < 1 || H < 1) return;

    HDC hdc = GetDC(hwnd);
    ensure_backbuf(hdc, W, H);

    RECT full = {0, 0, W, H};
    HBRUSH bg = CreateSolidBrush(C_BG);
    FillRect(g_back_dc, &full, bg);
    DeleteObject(bg);

    int rows, cols;
    auto_layout(g_num_workers, g_rows, g_cols, &rows, &cols);

    if (g_focused >= 0 && g_focused < g_num_workers) {
        RECT r = {0, 0, W, H};
        draw_cell(g_back_dc, g_workers[g_focused], r);
    } else {
        int cw = W / cols;
        int ch = H / rows;
        for (int i = 0; i < g_num_workers; i++) {
            int row = i / cols, col = i % cols;
            RECT r = { col*cw, row*ch, (col+1)*cw, (row+1)*ch };
            draw_cell(g_back_dc, g_workers[i], r);
        }
        // Draw single-pixel separator lines between adjacent cells only.
        // Vertical separators between columns (not at left/right window edges).
        for (int c2 = 1; c2 < cols; c2++)
            draw_line_blended(g_back_dc, c2*cw, 0, c2*cw, H,
                              C_GRID_R, C_GRID_G, C_GRID_B, C_GRID_ALPHA);
        // Horizontal separators between rows (not at top/bottom window edges).
        for (int r2 = 1; r2 < rows; r2++)
            draw_line_blended(g_back_dc, 0, r2*ch, W, r2*ch,
                              C_GRID_R, C_GRID_G, C_GRID_B, C_GRID_ALPHA);
    }

    BitBlt(hdc, 0, 0, W, H, g_back_dc, 0, 0, SRCCOPY);
    ReleaseDC(hwnd, hdc);
}

// ---------------------------------------------------------------------------
// Fullscreen toggle
// ---------------------------------------------------------------------------
static void toggle_fullscreen(HWND hwnd) {
    if (!g_fullscreen) {
        g_saved_placement.length = sizeof(WINDOWPLACEMENT);
        GetWindowPlacement(hwnd, &g_saved_placement);
        DWORD style = GetWindowLong(hwnd, GWL_STYLE);
        SetWindowLong(hwnd, GWL_STYLE, style & ~(WS_CAPTION | WS_THICKFRAME));

        HMONITOR hmon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi = { sizeof(mi) };
        GetMonitorInfo(hmon, &mi);
        RECT mr = mi.rcMonitor;
        SetWindowPos(hwnd, HWND_TOP, mr.left, mr.top,
                     mr.right - mr.left, mr.bottom - mr.top,
                     SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
        g_fullscreen = 1;
    } else {
        DWORD style = GetWindowLong(hwnd, GWL_STYLE);
        SetWindowLong(hwnd, GWL_STYLE, style | WS_CAPTION | WS_THICKFRAME);
        SetWindowPlacement(hwnd, &g_saved_placement);
        SetWindowPos(hwnd, NULL, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER |
                     SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
        g_fullscreen = 0;
    }
    g_back_w = 0; g_back_h = 0;
    InvalidateRect(hwnd, NULL, FALSE);
}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        BeginPaint(hwnd, &ps);
        repaint(hwnd);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_SIZE: {
        g_back_w = 0; g_back_h = 0;
        InvalidateRect(hwnd, NULL, FALSE);
        // Debounce: resize ring only after the user stops dragging (150ms idle)
        SetTimer(hwnd, 2, 150, NULL);
        return 0;
    }
    case WM_TIMER:
        if (wp == 2) {
            KillTimer(hwnd, 2);
            RECT cl; GetClientRect(hwnd, &cl);
            update_ring_sizes(cl.right, cl.bottom);
        }
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    case WM_KEYDOWN:
        if (wp == VK_ESCAPE) {
            if (g_focused >= 0) {
                g_focused = -1;
                RECT cl; GetClientRect(hwnd, &cl);
                update_ring_sizes(cl.right, cl.bottom);
                InvalidateRect(hwnd, NULL, FALSE);
            } else if (g_fullscreen) {
                toggle_fullscreen(hwnd);
            } else {
                PostQuitMessage(0);
            }
        } else if (wp == 'F' || wp == VK_F11) {
            toggle_fullscreen(hwnd);
        } else if (wp == 'Q' || wp == 'q') {
            PostQuitMessage(0);
        }
        return 0;
    case WM_LBUTTONDOWN: {
        DWORD now = timeGetTime();
        int mx = LOWORD(lp), my = HIWORD(lp);
        int dx = abs(mx - g_last_click_x), dy = abs(my - g_last_click_y);
        DWORD dt = now - g_last_click_t;

        if (dt < 400 && dx < 20 && dy < 20) {
            if (g_focused >= 0) {
                g_focused = -1;
            } else {
                RECT cl; GetClientRect(hwnd, &cl);
                int W = cl.right, H = cl.bottom;
                int rows, cols;
                auto_layout(g_num_workers, g_rows, g_cols, &rows, &cols);
                int cw = W / cols, ch = H / rows;
                int idx = (my / ch) * cols + (mx / cw);
                if (idx >= 0 && idx < g_num_workers) g_focused = idx;
            }
            g_last_click_t = 0;
            RECT cl; GetClientRect(hwnd, &cl);
            update_ring_sizes(cl.right, cl.bottom);
            InvalidateRect(hwnd, NULL, FALSE);
        } else {
            g_last_click_t = now;
            g_last_click_x = mx;
            g_last_click_y = my;
        }
        return 0;
    }
    case WM_NCLBUTTONDOWN:
        // Disable redraws while dragging
        SendMessage(hwnd, WM_SETREDRAW, FALSE, 0);
        DefWindowProc(hwnd, msg, wp, lp);
        return 0;

    case WM_CAPTURECHANGED:
        // Re-enable redraws when drag finishes
        SendMessage(hwnd, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

// ---------------------------------------------------------------------------
// Monitor enumeration for --display N
// ---------------------------------------------------------------------------
static BOOL CALLBACK MonitorEnumProc(HMONITOR hmon, HDC hdc_unused, LPRECT lpr, LPARAM lp) {
    typedef struct { int index; int target; HMONITOR found; MONITORINFO mi; } MonitorEnum_t;
    MonitorEnum_t *e = (MonitorEnum_t*)lp;
    (void)hdc_unused; (void)lpr;
    if (e->index == e->target) {
        e->found = hmon;
        e->mi.cbSize = sizeof(MONITORINFO);
        GetMonitorInfo(hmon, &e->mi);
    }
    e->index++;
    return TRUE;
}

static BOOL get_monitor_by_index(int n, MONITORINFO *out) {
    typedef struct { int index; int target; HMONITOR found; MONITORINFO mi; } MonitorEnum_t;
    MonitorEnum_t e;
    memset(&e, 0, sizeof(e));
    e.target = n;
    EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, (LPARAM)&e);
    if (!e.found) return FALSE;
    *out = e.mi;
    return TRUE;
}

// ---------------------------------------------------------------------------
// WinMain -- entry point, argument parsing, window creation, message loop
// ---------------------------------------------------------------------------
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdline, int show) {
    (void)hPrev;
    int g_argc = 0;
    char **g_argv = NULL;
    {
        static char argbuf[4096];
        strncpy(argbuf, cmdline, sizeof(argbuf)-1);
        static char *argv_store[64];
        int argc = 0;
        char *p = argbuf;
        while (*p && argc < 63) {
            while (*p == ' ' || *p == '\t') p++;
            if (!*p) break;
            if (*p == '"') {
                p++;
                argv_store[argc++] = p;
                while (*p && *p != '"') p++;
                if (*p) *p++ = '\0';
            } else {
                argv_store[argc++] = p;
                while (*p && *p != ' ' && *p != '\t') p++;
                if (*p) *p++ = '\0';
            }
        }
        g_argc = argc;
        g_argv = argv_store;
    }

    // Helper: write a string to the console (works from GUI subsystem).
    // Attaches to the parent console if available, otherwise allocates one.
    #define CONSOLE_WRITE(str) do { \
        if (!AttachConsole(ATTACH_PARENT_PROCESS)) AllocConsole(); \
        HANDLE hout = CreateFileA("CONOUT$", GENERIC_WRITE, \
                                  FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL); \
        if (hout != INVALID_HANDLE_VALUE) { \
            DWORD written; \
            WriteFile(hout, (str), (DWORD)strlen(str), &written, NULL); \
            CloseHandle(hout); \
        } \
        FreeConsole(); \
    } while(0)

    for (int i = 0; i < g_argc; i++) {
        if (strcmp(g_argv[i], "--version") == 0) {
            char vbuf[256];
            sprintf(vbuf, "gpngr %s\r\nBy Dimitri Pappas -- github.com/fragtion/gpngr\r\n",
                    GPNGR_VERSION);
            CONSOLE_WRITE(vbuf);
            return 0;
        }
        if (strcmp(g_argv[i], "--help") == 0 || strcmp(g_argv[i], "-h") == 0) {
            char hbuf[4096];
            sprintf(hbuf,
                "gpngr %s -- Graphical Ping Grapher\r\n"
                "By Dimitri Pappas -- github.com/fragtion/gpngr\r\n"
                "\r\n"
                "Usage:\r\n"
                "  gpngr.exe [options] \"host1{params},host2{params},...\"\r\n"
                "\r\n"
                "Host parameters (all optional, use blank or 'auto' to skip):\r\n"
                "  {rate,ymin,ymax,warn,bad,samples}\r\n"
                "    rate    - pings per second (default: 2)\r\n"
                "    ymin    - y-axis minimum in ms (default: auto)\r\n"
                "    ymax    - y-axis maximum in ms (default: auto)\r\n"
                "    warn    - RTT warn threshold in ms (default: 80)\r\n"
                "    bad     - RTT bad threshold in ms (default: 150)\r\n"
                "    samples - max samples: integer count or time string (e.g. '1h')\r\n"
                "              (default: auto = graph pixel width)\r\n"
                "\r\n"
                "Options:\r\n"
                "  --rows N         force N rows in the grid layout\r\n"
                "  --cols N         force N columns in the grid layout\r\n"
                "  --width N        initial window width  (default: 1280)\r\n"
                "  --height N       initial window height (default: 720)\r\n"
                "  --full           start in fullscreen mode\r\n"
                "  --fullscreen     same as --full\r\n"
                "  --display N      open on monitor N (0-based)\r\n"
                "  --version        print version and exit\r\n"
                "  --help, -h       show this help\r\n"
                "\r\n"
                "Keyboard / mouse:\r\n"
                "  Double-click     zoom into / out of a single graph\r\n"
                "  F / F11          toggle fullscreen\r\n"
                "  Escape           exit zoom, exit fullscreen, or quit\r\n"
                "  Q                exit program immediately\r\n"
                "\r\n"
                "Examples:\r\n"
                "  # Two hosts, 2 rows, default settings:\r\n"
                "  gpngr.exe --rows 2 \"8.8.8.8,1.1.1.1\"\r\n"
                "\r\n"
                "  # Named parameters -- 1 ping/sec, warn at 50ms, bad at 100ms,\r\n"
                "  # keep 1 hour of history; second host uses all defaults:\r\n"
                "  gpngr.exe \"8.8.8.8{1,,,,50,100,1h},1.1.1.1\"\r\n",
                GPNGR_VERSION);
            CONSOLE_WRITE(hbuf);
            return 0;
        }
    }
    #undef CONSOLE_WRITE

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa)) return 1;
    //timeBeginPeriod(1);

    // even higher resolution
    TIMECAPS tc;
    timeGetDevCaps(&tc, sizeof(tc));
    timeBeginPeriod(tc.wPeriodMin);  // Use minimum possible period (usually 1ms)

    int opt_rows = 0, opt_cols = 0;
    int opt_width = 1280, opt_height = 720;
    char host_tokens[MAX_HOSTS][512];
    int num_tokens = 0;

    for (int i = 0; i < g_argc; i++) {
        if (strcmp(g_argv[i], "--rows") == 0 && i+1 < g_argc) opt_rows = atoi(g_argv[++i]);
        else if (strcmp(g_argv[i], "--cols") == 0 && i+1 < g_argc) opt_cols = atoi(g_argv[++i]);
        else if (strcmp(g_argv[i], "--width") == 0 && i+1 < g_argc) opt_width = atoi(g_argv[++i]);
        else if (strcmp(g_argv[i], "--height") == 0 && i+1 < g_argc) opt_height = atoi(g_argv[++i]);
        else if (strcmp(g_argv[i], "--full") == 0 || strcmp(g_argv[i], "--fullscreen") == 0) g_start_fullscreen = 1;
        else if (strcmp(g_argv[i], "--display") == 0 && i+1 < g_argc) g_opt_display = atoi(g_argv[++i]);
        else if (g_argv[i][0] != '-') {
            int n = split_hosts(g_argv[i], host_tokens + num_tokens, MAX_HOSTS - num_tokens);
            num_tokens += n;
        }
    }

    g_rows = opt_rows; g_cols = opt_cols;

    if (num_tokens == 0) {
        MessageBox(NULL,
            "gpngr " GPNGR_VERSION "\n"
            "By Dimitri Pappas -- github.com/fragtion/gpngr\n\n"
            "Usage: gpngr.exe [options] \"host1{rate,ymin,ymax,warn,bad,samples},...\"\n\n"
            "Run with --help for full usage information.",
            "gpngr", MB_OK);
        timeEndPeriod(1); WSACleanup(); return 1;
    }

    RECT mon_rcWork, mon_rcMonitor;
    {
        MONITORINFO mi = { sizeof(mi) };
        BOOL got = FALSE;
        if (g_opt_display >= 0) got = get_monitor_by_index(g_opt_display, &mi);
        if (!got) {
            POINT pt = {0,0};
            HMONITOR hm = MonitorFromPoint(pt, MONITOR_DEFAULTTOPRIMARY);
            got = GetMonitorInfo(hm, &mi);
        }
        if (got) { mon_rcWork = mi.rcWork; mon_rcMonitor = mi.rcMonitor; }
        else { mon_rcWork.left=0; mon_rcWork.top=0; mon_rcWork.right=1920; mon_rcWork.bottom=1080; mon_rcMonitor=mon_rcWork; }
    }
    (void)mon_rcMonitor;

    int work_w = mon_rcWork.right - mon_rcWork.left;
    int work_h = mon_rcWork.bottom - mon_rcWork.top;
    if (opt_width  > work_w) opt_width  = work_w;
    if (opt_height > work_h) opt_height = work_h;

    // Parse host configs first so we know which are explicit vs auto.
    host_cfg_t cfgs[MAX_HOSTS];
    int num_cfgs = 0;
    for (int i = 0; i < num_tokens && num_cfgs < MAX_HOSTS; i++) {
        parse_host_cfg(host_tokens[i], &cfgs[num_cfgs]);
        num_cfgs++;
    }

    // Compute initial cell width for auto workers.
    int init_rows, init_cols;
    {
        int saved = g_num_workers;
        g_num_workers = num_cfgs;
        auto_layout(num_cfgs, opt_rows, opt_cols, &init_rows, &init_cols);
        g_num_workers = saved;
    }
    int init_cell_w = opt_width / (init_cols > 0 ? init_cols : 1);
    if (init_cell_w < 1) init_cell_w = 1;

    for (int i = 0; i < num_cfgs; i++) {
        worker_t *wk = create_worker(&cfgs[i], g_num_workers, init_cell_w);
        if (wk) g_workers[g_num_workers++] = wk;
        else {
            char msg[512];
            sprintf(msg, "Failed to create socket for: %s\n\nRun as Administrator!", cfgs[i].host);
            MessageBox(NULL, msg, "gpngr warning", MB_OK|MB_ICONWARNING);
        }
    }

    if (g_num_workers == 0) {
        MessageBox(NULL, "No valid hosts.", "gpngr", MB_OK);
        timeEndPeriod(1); WSACleanup(); return 1;
    }

    WNDCLASS wc = {0};
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL;
    wc.lpszClassName = "GpngrWnd";
    RegisterClass(&wc);

    int win_x = mon_rcWork.left + (work_w - opt_width) / 2;
    int win_y = mon_rcWork.top  + (work_h - opt_height) / 2;

    g_hwnd = CreateWindowEx(0, "GpngrWnd", "gpngr " GPNGR_VERSION,
                            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                            win_x, win_y, opt_width, opt_height,
                            NULL, NULL, hInst, NULL);
    if (!g_hwnd) {
        MessageBox(NULL, "CreateWindow failed", "gpngr", MB_OK);
        timeEndPeriod(1); WSACleanup(); return 1;
    }

    ShowWindow(g_hwnd, show);
    UpdateWindow(g_hwnd);
    if (g_start_fullscreen) toggle_fullscreen(g_hwnd);
    SetTimer(g_hwnd, 1, 100, NULL);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }

    for (int i = 0; i < g_num_workers; i++) stop_worker(g_workers[i]);
    if (g_back_bmp) DeleteObject(g_back_bmp);
    if (g_back_dc)  DeleteDC(g_back_dc);
    timeEndPeriod(1);
    WSACleanup();
    return 0;
}

#else
// ========================================================================
// LINUX / macOS / FreeBSD IMPLEMENTATION
// ========================================================================
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <X11/Xatom.h>

#ifdef __has_include
#  if __has_include(<X11/Xft/Xft.h>)
#    include <X11/Xft/Xft.h>
#    ifndef HAS_XFT
#      define HAS_XFT 1
#    endif
#  endif
#endif
#ifndef HAS_XFT
#  define HAS_XFT 0
#endif

#define GPNGR_VERSION "v1.0"

#define COLOR_BG        0x000000ul
#define COLOR_GOOD      0x406840ul
#define COLOR_WARN      0x8c8c00ul
#define COLOR_BAD       0xcccc00ul
#define COLOR_LOSS      0xcc2020ul
#define COLOR_AXIS      0xfffffful
#define COLOR_GRID_R    80
#define COLOR_GRID_G    95
#define COLOR_GRID_B   112
#define COLOR_GRID_X11  0x141a1cul
#define COLOR_ZONE_WARN 0x161600ul
#define COLOR_ZONE_BAD  0x1c0000ul
#define COLOR_PENDING   0x3c3c3cul

#define GPNGR_ICMP_ECHO_REQUEST 8
#define GPNGR_ICMP_ECHO_REPLY   0
#define LOSS_TIMEOUT_MS 2000

typedef struct {
    unsigned char  type, code;
    unsigned short checksum, id, sequence;
} icmp_hdr_t;

static unsigned short icmp_checksum(unsigned short *buf, int len) {
    unsigned long s = 0;
    while (len > 1) { s += *buf++; len -= 2; }
    if (len) { s += *(unsigned char*)buf; }
    s = (s >> 16) + (s & 0xffff);
    s += (s >> 16);
    return (unsigned short)(~s);
}

// Per-host configuration parsed from command-line arguments.
typedef struct {
    char   host[256];
    double rate;          // pings per second
    double ymin, ymax;    // y-axis range (ms)
    double warn, bad;     // RTT thresholds (ms) for colour zones
    int    has_ymin, has_ymax;
    int    max_samples;   // 0 = auto (match graph pixel width)
} host_cfg_t;

// Sample states stored in the ring buffer
#define STATE_EMPTY   0
#define STATE_PENDING 1
#define STATE_OK      2
#define STATE_LOST    3

typedef struct {
    int    state;
    double rtt;
    unsigned long send_ts;
} sample_t;

// Per-host worker: owns the socket, ring buffer, and two threads.
typedef struct {
    host_cfg_t  cfg;
    int         sock;
    int         sock_dgram;
    struct sockaddr_in dest;
    unsigned short ident;
    unsigned short next_seq;
    pthread_mutex_t lock;
    pthread_t send_thread;
    pthread_t recv_thread;
    pthread_t timeout_thread;
    volatile int running;

    // Dynamic ring buffer
    sample_t      *ring;
    int           *seq_slot;
    int           *seq_valid;
    int           *seq_seqno;
    int            ring_cap;
    int            head;
    int            count;

    double rtt_min, rtt_max, rtt_avg;
    int    sent, received;
    double frozen_gmin, frozen_gmax;
    int    has_frozen;
    int    pending_count;
    int    pending_head;
    int    pending_tail;
    int    pending_list[MAX_RING_CAP];
} worker_t;

// Globals
static int g_num_workers = 0;
static worker_t *g_workers[MAX_HOSTS];
static int g_rows = 0, g_cols = 0;
static int g_focused = -1;
static int g_start_fullscreen = 0;

static volatile int g_dirty = 1;
static inline void mark_dirty(void) { g_dirty = 1; }
static volatile int g_pending_resize = 0;
static unsigned long g_resize_time_ms = 0;

typedef struct {
    Display    *display;
    Window      window;
    GC          gc;
    Pixmap      buffer;
    int         screen;
    int         width, height;
    int         fullscreen;
    Atom        wm_delete_window;

    XFontStruct *font;
    XFontStruct *font_small;

#if HAS_XFT
    XftDraw   *xft_draw;
    XftFont   *xft_font;
    XftFont   *xft_font_small;
    Visual    *visual;
    Colormap   colormap;
#endif
} graphics_t;

static graphics_t g_gfx;
static unsigned long g_last_click_time = 0;
static int g_last_click_x = 0, g_last_click_y = 0;

// Forward declarations
static int split_hosts(const char *src, char out[][512], int max_out);
static void parse_host_cfg(const char *token, host_cfg_t *c);
static void* send_thread_func(void* arg);
static void* recv_thread_func(void* arg);
static void* timeout_thread_func(void* arg);
static worker_t* create_worker(const host_cfg_t *cfg, int worker_index, int initial_cap);
static void stop_worker(worker_t *w);
static void resize_worker_ring(worker_t *w, int new_cap);
static void auto_layout(int n, int forced_rows, int forced_cols, int *rows_out, int *cols_out);
static void compute_scale(worker_t *w, int width, double *gmin_out, double *gmax_out);
static void linux_repaint(void);
static unsigned long get_tick_us(void);
static void update_ring_sizes_linux(int win_w, int win_h);
static int cell_cap_for_worker(int worker_idx, int win_w, int win_h);

// Returns monotonic time in microseconds.
static unsigned long get_tick_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long)ts.tv_sec * 1000000UL + ts.tv_nsec / 1000UL;
}

static void auto_layout(int n, int forced_rows, int forced_cols, int *rows_out, int *cols_out) {
    if (forced_rows && forced_cols) { *rows_out = forced_rows; *cols_out = forced_cols; return; }
    if (forced_rows) { *rows_out = forced_rows; *cols_out = (n + forced_rows - 1) / forced_rows; return; }
    if (forced_cols) { *cols_out = forced_cols; *rows_out = (n + forced_cols - 1) / forced_cols; return; }
    if (n == 1) { *rows_out = 1; *cols_out = 1; return; }
    if (n == 2) { *rows_out = 2; *cols_out = 1; return; }
    if (n <= 4) { *rows_out = 2; *cols_out = 2; return; }
    int c = (int)sqrt((double)n);
    *cols_out = c;
    *rows_out = (n + c - 1) / c;
}

// Compute y-axis scale from the most-recent `width` samples in the ring.
static void compute_scale(worker_t *w, int width, double *gmin_out, double *gmax_out) {
    host_cfg_t *c = &w->cfg;
    if (c->has_ymin && c->has_ymax) {
        *gmin_out = c->ymin; *gmax_out = c->ymax; return;
    }

    pthread_mutex_lock(&w->lock);
    double mn = 1e18, mx = -1e18;
    int    valid = 0;
    int cap   = w->ring_cap;
    int total = w->count < width ? w->count : width;
    for (int i = 0; i < total; i++) {
        int idx = ((w->head - 1 - i) + cap * 2) % cap;
        sample_t *s = &w->ring[idx];
        if (s->state == STATE_OK) {
            double v = s->rtt;
            if (v < mn) mn = v;
            if (v > mx) mx = v;
            valid++;
        }
    }
    pthread_mutex_unlock(&w->lock);

    if (valid > 0) {
        double gmax = c->has_ymax ? c->ymax : mx * 1.20;
        double gmin = c->has_ymin ? c->ymin : mn * 0.85;
        if (gmax < 1.0) gmax = 1.0;
        if (gmin < 0.0) gmin = 0.0;
        w->frozen_gmin = gmin; w->frozen_gmax = gmax; w->has_frozen = 1;
        *gmin_out = gmin; *gmax_out = gmax;
    } else if (w->has_frozen) {
        *gmin_out = w->frozen_gmin; *gmax_out = w->frozen_gmax;
    } else {
        *gmin_out = 0.0; *gmax_out = 100.0;
    }
}

// Split a comma-separated host list, respecting {}-enclosed parameter blocks.
static int split_hosts(const char *src, char out[][512], int max_out) {
    int n = 0, depth = 0;
    char buf[512]; int bi = 0;
    for (const char *p = src; *p; p++) {
        if (*p == '{') depth++;
        if (*p == '}') depth--;
        if (*p == ',' && depth == 0) {
            buf[bi] = 0;
            while (bi > 0 && buf[bi-1] == ' ') buf[--bi] = 0;
            char *s = buf; while (*s == ' ') s++;
            if (*s && n < max_out) { strcpy(out[n++], s); }
            bi = 0;
        } else {
            if (bi < 511) buf[bi++] = *p;
        }
    }
    buf[bi] = 0;
    char *s = buf; while (*s == ' ') s++;
    int tl = (int)strlen(s);
    while (tl > 0 && s[tl-1] == ' ') s[--tl] = 0;
    if (*s && n < max_out) strcpy(out[n++], s);
    return n;
}

// Parse a single host token of the form "hostname{rate,ymin,ymax,warn,bad,samples}".
// Any parameter may be blank or "auto" to use the default value.
// The rate parameter also accepts a time suffix (e.g. "60m") to set the ping
// interval so that the given duration of samples fills the graph width.
static void parse_host_cfg(const char *token, host_cfg_t *c) {
    c->rate = 2.0;
    c->ymin = 0; c->has_ymin = 0;
    c->ymax = 0; c->has_ymax = 0;
    c->warn = 80.0;
    c->bad = 150.0;
    c->max_samples = 0;

    const char *lb = strchr(token, '{');
    if (lb) {
        int hlen = (int)(lb - token);
        if (hlen > 255) hlen = 255;
        strncpy(c->host, token, hlen);
        c->host[hlen] = 0;
        int l = (int)strlen(c->host);
        while (l > 0 && c->host[l-1] == ' ') c->host[--l] = 0;

        char params[256] = {0};
        const char *rb = strchr(lb, '}');
        int plen = rb ? (int)(rb - lb - 1) : (int)strlen(lb+1);
        if (plen > 255) plen = 255;
        strncpy(params, lb+1, plen);

        // Split on commas manually to preserve empty fields (blank parameters).
        char *fields[6];
        int nf = 0;
        char tmp[256]; strcpy(tmp, params);
        char *p = tmp;
        while (nf < 6) {
            fields[nf++] = p;
            char *comma = strchr(p, ',');
            if (!comma) break;
            *comma = '\0';
            p = comma + 1;
        }

        // field[0]: ping rate in pings per second (plain decimal number).
        if (0 < nf && fields[0][0] && strcmp(fields[0], "auto") != 0)
            c->rate = atof(fields[0]);

        // fields[1-4]: ymin, ymax, warn, bad -- all specified by the user in ms.
        // Stored internally in µs (multiply by 1000) since RTT values are in µs.
        if (1 < nf && fields[1][0] && strcmp(fields[1], "auto") != 0) { c->ymin = atof(fields[1]) * 1000.0; c->has_ymin = 1; }
        if (2 < nf && fields[2][0] && strcmp(fields[2], "auto") != 0) { c->ymax = atof(fields[2]) * 1000.0; c->has_ymax = 1; }
        if (3 < nf && fields[3][0] && strcmp(fields[3], "auto") != 0) c->warn = atof(fields[3]);
        if (4 < nf && fields[4][0] && strcmp(fields[4], "auto") != 0) c->bad  = atof(fields[4]);

        // field[5]: max_samples -- absolute count or time string (e.g. "1h").
        if (5 < nf && fields[5][0]) {
            const char *s = fields[5];
            char *endptr;
            long val = strtol(s, &endptr, 10);
            if (endptr != s && *endptr == '\0') {
                c->max_samples = (int)val;
            } else {
                size_t len = strlen(s);
                if (len > 1) {
                    char unit = s[len-1];
                    char numbuf[32];
                    strncpy(numbuf, s, len-1);
                    numbuf[len-1] = '\0';
                    double num = atof(numbuf);
                    double multiplier = 1.0;
                    switch (unit) {
                        case 's': multiplier = 1.0;     break;
                        case 'm': multiplier = 60.0;    break;
                        case 'h': multiplier = 3600.0;  break;
                        case 'd': multiplier = 86400.0; break;
                        default:  multiplier = 1.0;     break;
                    }
                    c->max_samples = (int)(c->rate * num * multiplier);
                    if (c->max_samples <= 0) c->max_samples = 1;
                }
            }
        }
        if (c->max_samples > MAX_RING_CAP) c->max_samples = MAX_RING_CAP;

        // warn/bad are specified in ms by the user; convert to µs for internal use
        // since all RTT values are stored in microseconds.
        c->warn *= 1000.0;
        c->bad  *= 1000.0;
    } else {
        strncpy(c->host, token, 255);
        c->host[255] = 0;
        int l = (int)strlen(c->host);
        while (l > 0 && c->host[l-1] == ' ') c->host[--l] = 0;
        // Apply default warn/bad thresholds in µs.
        c->warn *= 1000.0;
        c->bad  *= 1000.0;
    }
}

// ---------------------------------------------------------------------------
// Compute the desired ring capacity for a given worker index and window size.
// For explicit configs this is always cfg.max_samples.
// For auto configs it is the pixel width of that worker's cell in the
// multi-graph layout (focused view does NOT shrink non-focused workers).
// ---------------------------------------------------------------------------
static int cell_cap_for_worker(int worker_idx, int win_w, int win_h) {
    (void)win_h;
    worker_t *w = g_workers[worker_idx];
    if (w->cfg.max_samples > 0)
        return w->cfg.max_samples;

    int rows, cols;
    auto_layout(g_num_workers, g_rows, g_cols, &rows, &cols);

    // Focused worker gets the full window width; non-focused workers keep their
    // multi-graph cell width so their history is preserved when returning.
    int cell_w = (g_focused == worker_idx) ? win_w : win_w / cols;
    if (cell_w < 1)           cell_w = 1;
    if (cell_w > MAX_RING_CAP) cell_w = MAX_RING_CAP;
    return cell_w;
}

// ---------------------------------------------------------------------------
// Resize a worker's ring to new_cap.
// Must be called from the main thread; acquires the worker lock internally.
// ---------------------------------------------------------------------------
static void resize_worker_ring(worker_t *w, int new_cap) {
    if (new_cap < 1)            new_cap = 1;
    if (new_cap > MAX_RING_CAP) new_cap = MAX_RING_CAP;

    // Quick check under lock, then do all heavy work outside it
    pthread_mutex_lock(&w->lock);
    if (new_cap == w->ring_cap) {
        pthread_mutex_unlock(&w->lock);
        return;
    }
    int old_cap   = w->ring_cap;
    int old_count = w->count;
    int old_head  = w->head;
    pthread_mutex_unlock(&w->lock);

    int keep = old_count < new_cap ? old_count : new_cap;

    sample_t *new_ring      = (sample_t*)calloc(new_cap, sizeof(sample_t));
    int      *new_seq_slot  = (int*)calloc(new_cap, sizeof(int));
    int      *new_seq_valid = (int*)calloc(new_cap, sizeof(int));
    int      *new_seq_seqno = (int*)calloc(new_cap, sizeof(int));

    if (!new_ring || !new_seq_slot || !new_seq_valid || !new_seq_seqno) {
        free(new_ring); free(new_seq_slot);
        free(new_seq_valid); free(new_seq_seqno);
        return;
    }

    // Copy outside the lock -- we use the snapshot of old_head/old_cap/old_count.
    // The send thread may advance w->head during this, but we only read slots
    // older than old_head which are no longer being written to.
    for (int i = 0; i < keep; i++) {
        int src_age = keep - 1 - i;
        int src_idx = ((old_head - 1 - src_age) + old_cap * 2) % old_cap;
        new_ring[i] = w->ring[src_idx];
    }

    // Recompute stats and pending list outside the lock -- new_ring is not yet
    // visible to any other thread so no synchronisation is needed here.
    double new_rtt_min = 1e18, new_rtt_max = -1e18, acc = 0.0;
    int    new_received = 0, new_lost = 0;
    int    new_pending_count = 0;
    int    new_pending_head  = 0;
    int    new_pending_tail  = 0;
    int   *tmp_pending_list  = (int*)malloc(MAX_RING_CAP * sizeof(int));
    if (!tmp_pending_list) {
        free(new_ring); free(new_seq_slot);
        free(new_seq_valid); free(new_seq_seqno);
        return;
    }
    for (int i = 0; i < keep; i++) {
        if (new_ring[i].state == STATE_OK) {
            double v = new_ring[i].rtt;
            if (v < new_rtt_min) new_rtt_min = v;
            if (v > new_rtt_max) new_rtt_max = v;
            acc += v;
            new_received++;
        } else if (new_ring[i].state == STATE_LOST) {
            new_lost++;
        } else if (new_ring[i].state == STATE_PENDING) {
            tmp_pending_list[new_pending_tail] = i;
            new_pending_tail = (new_pending_tail + 1) % MAX_RING_CAP;
            new_pending_count++;
        }
    }

    // Now lock only for the pointer swap -- just a handful of assignments
    // and a memcpy, releasing as fast as possible.
    pthread_mutex_lock(&w->lock);
    w->rtt_min  = new_received > 0 ? new_rtt_min : 0.0;
    w->rtt_max  = new_received > 0 ? new_rtt_max : 0.0;
    w->rtt_avg  = new_received > 0 ? acc / new_received : 0.0;
    w->received = new_received;
    w->sent     = new_received + new_lost + new_pending_count;

    free(w->ring);
    free(w->seq_slot);
    free(w->seq_valid);
    free(w->seq_seqno);
    w->ring      = new_ring;
    w->seq_slot  = new_seq_slot;
    w->seq_valid = new_seq_valid;
    w->seq_seqno = new_seq_seqno;
    w->ring_cap  = new_cap;
    w->head      = keep % new_cap;
    w->count     = keep;

    // Swap in the pre-computed pending list
    w->pending_count = new_pending_count;
    w->pending_head  = new_pending_head;
    w->pending_tail  = new_pending_tail;
    if (new_pending_count > 0)
        memcpy(w->pending_list, tmp_pending_list,
               new_pending_count * sizeof(int));
    free(tmp_pending_list);

    pthread_mutex_unlock(&w->lock);
}

// ---------------------------------------------------------------------------
// Update ring sizes for all auto-configured workers on window resize.
// Workers with explicit max_samples are never resized.
// Non-focused workers are sized to their normal multi-graph cell width so
// their ring is preserved when entering/leaving focused view.
// ---------------------------------------------------------------------------
static void update_ring_sizes_linux(int win_w, int win_h) {
    for (int i = 0; i < g_num_workers; i++) {
        worker_t *w = g_workers[i];
        if (w->cfg.max_samples > 0) continue;
        int new_cap = cell_cap_for_worker(i, win_w, win_h);
        if (new_cap != w->ring_cap)
            resize_worker_ring(w, new_cap);
    }
}

// ---------------------------------------------------------------------------
// ICMP send thread
// ---------------------------------------------------------------------------
static void* send_thread_func(void* arg) {
    worker_t *w = (worker_t*)arg;
    double interval_ms = 1000.0 / (w->cfg.rate > 0 ? w->cfg.rate : 2.0);

    while (w->running) {
        unsigned long t0_ms = get_tick_us() / 1000UL;

        // Build packet before taking lock to minimise lock duration
        unsigned short current_seq;
        int current_slot;

        pthread_mutex_lock(&w->lock);
        int cap = w->ring_cap;
        int slot = w->head;
        w->head = (w->head + 1) % cap;
        if (w->count < cap) w->count++;

        current_seq  = w->next_seq++;
        current_slot = slot;
        sample_t *s  = &w->ring[slot];
        s->state     = STATE_PENDING;
        s->rtt       = 0;
        s->send_ts   = get_tick_us();  // capture before unlock, before sendto

        int map_idx = (int)(current_seq % cap);
        w->seq_slot[map_idx]  = slot;
        w->seq_seqno[map_idx] = current_seq;
        w->seq_valid[map_idx] = 1;
        w->sent++;

        int pending_idx = w->pending_tail;
        w->pending_list[pending_idx] = current_slot;
        w->pending_tail = (w->pending_tail + 1) % MAX_RING_CAP;
        w->pending_count++;
        pthread_mutex_unlock(&w->lock);

        // Build and send packet outside lock
        icmp_hdr_t hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.type     = GPNGR_ICMP_ECHO_REQUEST;
        hdr.code     = 0;
        hdr.id       = w->sock_dgram ? 0 : htons(w->ident);
        hdr.sequence = htons(current_seq);
        hdr.checksum = 0;
        hdr.checksum = icmp_checksum((unsigned short*)&hdr, sizeof(hdr));

        sendto(w->sock, (char*)&hdr, sizeof(hdr), 0,
               (struct sockaddr*)&w->dest, sizeof(w->dest));

        mark_dirty();

        unsigned long now_ms = get_tick_us() / 1000UL;
        long sleep_ms = (long)interval_ms - (long)(now_ms - t0_ms);
        if (sleep_ms > 0) usleep((unsigned long)sleep_ms * 1000UL);
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// ICMP receive thread
// ---------------------------------------------------------------------------
static void* recv_thread_func(void* arg) {
    worker_t *w = (worker_t*)arg;

    while (w->running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(w->sock, &fds);
        struct timeval tv = { 0, 50000 };
        int sel = select(w->sock + 1, &fds, NULL, NULL, &tv);

        if (sel > 0) {
            char rbuf[1024];
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            int r = recvfrom(w->sock, rbuf, sizeof(rbuf), 0,
                            (struct sockaddr*)&from, &fromlen);

            // Capture timestamp IMMEDIATELY after recvfrom
            unsigned long now_us = get_tick_us();

            if (r >= (int)sizeof(icmp_hdr_t)) {
                icmp_hdr_t *rep;

                if (w->sock_dgram) {
                    rep = (icmp_hdr_t*)rbuf;
                } else {
                    if (r < (int)sizeof(struct ip)) {
                        // Not enough data for IP header, skip this packet
                        continue;
                    }
                    struct ip *iph = (struct ip*)rbuf;
                    int ihl = iph->ip_hl * 4;
                    if (r < ihl + (int)sizeof(icmp_hdr_t)) {
                        // Not enough data for ICMP header, skip this packet
                        continue;
                    }
                    rep = (icmp_hdr_t*)(rbuf + ihl);
                }

                int id_ok = w->sock_dgram ? 1 : (ntohs(rep->id) == w->ident);
                if (rep->type == GPNGR_ICMP_ECHO_REPLY && id_ok) {
                    unsigned short seq = ntohs(rep->sequence);

                    pthread_mutex_lock(&w->lock);
                    int cap = w->ring_cap;
                    int map_idx = (int)(seq % cap);
                    if (w->seq_valid[map_idx] && w->seq_slot[map_idx] >= 0 &&
                        w->seq_seqno[map_idx] == seq) {  // Verify sequence
                        int slot2 = w->seq_slot[map_idx];
                        sample_t *s2 = &w->ring[slot2];
                        if (s2->state == STATE_PENDING) {
                            double rtt = (double)(now_us - s2->send_ts);
                            if (rtt < 0.0) rtt = 0.0;  // guard against clock anomalies
                            s2->rtt   = rtt;
                            s2->state = STATE_OK;
                            w->received++;
                            if (w->received == 1) {
                                w->rtt_min = rtt;
                                w->rtt_max = rtt;
                                w->rtt_avg = rtt;
                            } else {
                                if (rtt < w->rtt_min) w->rtt_min = rtt;
                                if (rtt > w->rtt_max) w->rtt_max = rtt;
                                w->rtt_avg = w->rtt_avg * 0.95 + rtt * 0.05;
                            }
                        }
                        w->seq_valid[map_idx] = 0;
                    }
                    pthread_mutex_unlock(&w->lock);
                    mark_dirty();
                }
            }
        }
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Dedicated timeout thread - checks for lost packets without blocking receive.
// Timeout is LOSS_TIMEOUT_MS (2 seconds).
// ---------------------------------------------------------------------------
static void* timeout_thread_func(void* arg) {
    worker_t *w = (worker_t*)arg;
    
    while (w->running) {
        usleep(100000);  // check every 100ms for efficiency
        
        // Quick check without lock -- if no pending samples, skip
        if (w->pending_count == 0) continue;
        
        pthread_mutex_lock(&w->lock);
        unsigned long now_us = get_tick_us();
        
        // Check only the oldest pending samples (cap at 50 per iteration)
        int max_check = w->pending_count;
        if (max_check > 50) max_check = 50;
        
        for (int i = 0; i < max_check && w->pending_count > 0; i++) {
            int pending_idx = w->pending_head % MAX_RING_CAP;
            int slot_idx = w->pending_list[pending_idx];
            
            // Safety check for invalid slot
            if (slot_idx < 0 || slot_idx >= w->ring_cap) {
                w->pending_head = (w->pending_head + 1) % MAX_RING_CAP;
                w->pending_count--;
                continue;
            }
            
            sample_t *s = &w->ring[slot_idx];
            if (s->state == STATE_PENDING) {
                if (s->send_ts == 0) continue;  // timestamp not yet written, skip
                if ((now_us - s->send_ts) >= (unsigned long)LOSS_TIMEOUT_MS * 1000UL) {
                    s->state = STATE_LOST;
                    w->pending_head = (w->pending_head + 1) % MAX_RING_CAP;
                    w->pending_count--;
                    mark_dirty();
                } else {
                    // samples are in time order (oldest first), so stop checking
                    break;
                }
            } else {
                // sample already resolved (STATE_OK), remove from pending list
                w->pending_head = (w->pending_head + 1) % MAX_RING_CAP;
                w->pending_count--;
            }
        }
        
        pthread_mutex_unlock(&w->lock);
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Worker lifecycle
// ---------------------------------------------------------------------------
static worker_t* create_worker(const host_cfg_t *cfg, int worker_index, int initial_cap) {
    worker_t *w = (worker_t*)calloc(1, sizeof(worker_t));
    if (!w) return NULL;
    w->cfg = *cfg;

    int cap = (cfg->max_samples > 0) ? cfg->max_samples : initial_cap;
    if (cap < 1)            cap = 1;
    if (cap > MAX_RING_CAP) cap = MAX_RING_CAP;

    w->ring      = (sample_t*)calloc(cap, sizeof(sample_t));
    w->seq_slot  = (int*)calloc(cap, sizeof(int));
    w->seq_valid = (int*)calloc(cap, sizeof(int));
    w->seq_seqno = (int*)calloc(cap, sizeof(int));
    if (!w->ring || !w->seq_slot || !w->seq_valid || !w->seq_seqno) {
        free(w->ring); free(w->seq_slot); free(w->seq_valid); free(w->seq_seqno); free(w);
        return NULL;
    }
    w->ring_cap = cap;
    w->head     = 0;
    w->count    = 0;

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;

    if (getaddrinfo(cfg->host, NULL, &hints, &res) != 0) {
        free(w->ring); free(w->seq_slot); free(w->seq_valid); free(w);
        return NULL;
    }
    w->dest = *(struct sockaddr_in*)res->ai_addr;
    freeaddrinfo(res);

    // Try unprivileged ICMP (SOCK_DGRAM) on Linux only.
    // macOS always includes the IP header even on SOCK_DGRAM ICMP sockets,
    // making it behave identically to SOCK_RAW -- so just use RAW everywhere
    // on non-Linux to keep the receive path simple and correct.
#ifdef __linux__
    w->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (w->sock >= 0) {
        w->sock_dgram = 1;
    } else {
#endif
        w->sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (w->sock < 0) {
            free(w->ring); free(w->seq_slot); free(w->seq_valid); free(w);
            return NULL;
        }
        w->sock_dgram = 0;
#ifdef __linux__
    }
#endif

    struct timeval tv = {0, 100000};
    setsockopt(w->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

#ifdef __linux__
    if (w->sock_dgram) {
        // Bind to get a kernel-assigned port which serves as our ICMP identifier.
        struct sockaddr_in local = {0};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = INADDR_ANY;
        local.sin_port = 0;
        bind(w->sock, (struct sockaddr*)&local, sizeof(local));

        struct sockaddr_in bound = {0};
        socklen_t blen = sizeof(bound);
        getsockname(w->sock, (struct sockaddr*)&bound, &blen);
        w->ident = ntohs(bound.sin_port);
    } else {
#endif
        w->ident = (unsigned short)(((getpid() & 0xFF) << 8) | (worker_index & 0xFF));
#ifdef __linux__
    }
#endif
    w->next_seq = 0;
    w->running  = 1;
    pthread_mutex_init(&w->lock, NULL);

    // Create dedicated timeout thread
    if (pthread_create(&w->timeout_thread, NULL, timeout_thread_func, w) != 0) {
        w->running = 0;
        pthread_mutex_destroy(&w->lock);
        close(w->sock);
        free(w->ring); free(w->seq_slot); free(w->seq_valid); free(w->seq_seqno); free(w);
        return NULL;
    }

    if (pthread_create(&w->recv_thread, NULL, recv_thread_func, w) != 0) {
        pthread_mutex_destroy(&w->lock);
        close(w->sock);
        free(w->ring); free(w->seq_slot); free(w->seq_valid); free(w);
        return NULL;
    }

    if (pthread_create(&w->send_thread, NULL, send_thread_func, w) != 0) {
        w->running = 0;
        pthread_join(w->recv_thread, NULL);
        pthread_mutex_destroy(&w->lock);
        close(w->sock);
        free(w->ring); free(w->seq_slot); free(w->seq_valid); free(w);
        return NULL;
    }
    return w;
}

static void stop_worker(worker_t *w) {
    if (!w) return;
    w->running = 0;
    pthread_join(w->timeout_thread, NULL);
    pthread_join(w->send_thread, NULL);
    pthread_join(w->recv_thread, NULL);
    pthread_mutex_destroy(&w->lock);
    close(w->sock);
    free(w->ring);
    free(w->seq_slot);
    free(w->seq_valid);
    free(w->seq_seqno);
    free(w);
}

// ---------------------------------------------------------------------------
// Linux/X11 drawing helpers
// ---------------------------------------------------------------------------
static void fill_rect_x11(int x, int y, int w, int h, unsigned long col) {
    XSetForeground(g_gfx.display, g_gfx.gc, col);
    XFillRectangle(g_gfx.display, g_gfx.buffer, g_gfx.gc, x, y, w, h);
}

static void draw_line_x11(int x1, int y1, int x2, int y2, unsigned long col) {
    XSetForeground(g_gfx.display, g_gfx.gc, col);
    XDrawLine(g_gfx.display, g_gfx.buffer, g_gfx.gc, x1, y1, x2, y2);
}

// Draw a dotted grid line (every 4 pixels) using the grid colour.
static void draw_grid_line_x11(int x1, int y1, int x2, int y2) {
    XSetLineAttributes(g_gfx.display, g_gfx.gc, 1, LineSolid, CapButt, JoinMiter);
    XSetForeground(g_gfx.display, g_gfx.gc, 0x1a1f22);

    if (x1 == x2) {
        for (int y = y1; y <= y2; y += 4)
            XDrawPoint(g_gfx.display, g_gfx.buffer, g_gfx.gc, x1, y);
    } else {
        for (int x = x1; x <= x2; x += 4)
            XDrawPoint(g_gfx.display, g_gfx.buffer, g_gfx.gc, x, y1);
    }
}

#if HAS_XFT
static int text_width_xft(const char *s, XftFont *font) {
    XGlyphInfo ext;
    XftTextExtentsUtf8(g_gfx.display, font, (const FcChar8*)s,
                       (int)strlen(s), &ext);
    return ext.xOff;
}

static void draw_text_xft(int x, int y_baseline, const char *s,
                          unsigned long pixel, XftFont *font) {
    XRenderColor rc;
    rc.red   = (unsigned short)(((pixel >> 16) & 0xff) * 257);
    rc.green = (unsigned short)(((pixel >>  8) & 0xff) * 257);
    rc.blue  = (unsigned short)(((pixel      ) & 0xff) * 257);
    rc.alpha = 0xffff;

    XftColor xc;
    XftColorAllocValue(g_gfx.display, g_gfx.visual, g_gfx.colormap, &rc, &xc);
    XftDrawStringUtf8(g_gfx.xft_draw, &xc, font, x, y_baseline,
                      (const FcChar8*)s, (int)strlen(s));
    XftColorFree(g_gfx.display, g_gfx.visual, g_gfx.colormap, &xc);
}
#endif

static void draw_text_x11_core(int x, int y, const char *s,
                               unsigned long col, XFontStruct *font) {
    XSetForeground(g_gfx.display, g_gfx.gc, col);
    XSetFont(g_gfx.display, g_gfx.gc, font->fid);
    XDrawString(g_gfx.display, g_gfx.buffer, g_gfx.gc, x, y, s,
                (int)strlen(s));
}

static int text_width_x11(const char *s, XFontStruct *font) {
    XCharStruct overall;
    int direction, ascent, descent;
    XTextExtents(font, s, (int)strlen(s), &direction, &ascent, &descent,
                 &overall);
    return overall.width;
}

// Return pixel width of string using whichever font backend is active.
static int text_width_unified(const char *s, int small) {
#if HAS_XFT
    if (g_gfx.xft_draw) {
        XftFont *f = small ? g_gfx.xft_font_small : g_gfx.xft_font;
        if (f) return text_width_xft(s, f);
    }
#endif
    XFontStruct *f = small ? g_gfx.font_small : g_gfx.font;
    return text_width_x11(s, f);
}

// Return font ascent for the active font backend.
static int font_ascent(int small) {
#if HAS_XFT
    if (g_gfx.xft_draw) {
        XftFont *f = small ? g_gfx.xft_font_small : g_gfx.xft_font;
        if (f) return f->ascent;
    }
#endif
    XFontStruct *f = small ? g_gfx.font_small : g_gfx.font;
    return f ? f->ascent : 10;
}

// Draw text with a 1-pixel black outline for legibility over the graph.
static void draw_text_stroke_x11(int x, int y, const char *s,
                                 unsigned long col, int small) {
    int asc = font_ascent(small);
    int yb  = y + asc;

#if HAS_XFT
    if (g_gfx.xft_draw) {
        XftFont *f = small ? g_gfx.xft_font_small : g_gfx.xft_font;
        if (f) {
            draw_text_xft(x-1, yb,   s, COLOR_BG, f);
            draw_text_xft(x+1, yb,   s, COLOR_BG, f);
            draw_text_xft(x,   yb-1, s, COLOR_BG, f);
            draw_text_xft(x,   yb+1, s, COLOR_BG, f);
            draw_text_xft(x,   yb,   s, col,      f);
            return;
        }
    }
#endif
    XFontStruct *f = small ? g_gfx.font_small : g_gfx.font;
    draw_text_x11_core(x-1, yb,   s, COLOR_BG, f);
    draw_text_x11_core(x+1, yb,   s, COLOR_BG, f);
    draw_text_x11_core(x,   yb-1, s, COLOR_BG, f);
    draw_text_x11_core(x,   yb+1, s, COLOR_BG, f);
    draw_text_x11_core(x,   yb,   s, col,      f);
}

// ---------------------------------------------------------------------------
// Core drawing routine for one graph cell
// ---------------------------------------------------------------------------
static void draw_cell_linux(worker_t *w, int rx, int ry, int rw, int rh) {
    const int PAD_BOT = 14;

    int ph = rh - PAD_BOT;
    if (rw < 2 || ph < 2) return;

    int draw_count;
    pthread_mutex_lock(&w->lock);
    draw_count = w->count < rw ? w->count : rw;
    pthread_mutex_unlock(&w->lock);

    double gmin, gmax;
    compute_scale(w, rw, &gmin, &gmax);
    double grange = gmax - gmin;
    if (grange < 1e-9) grange = 1e-9;
    #define VAL_TO_Y(v) (ry + (int)((1.0 - ((v)-gmin)/grange) * (ph-1)))

    fill_rect_x11(rx, ry, rw, ph, COLOR_BG);
    int warn_y = (w->cfg.warn > gmin && w->cfg.warn < gmax)
                 ? VAL_TO_Y(w->cfg.warn) : (w->cfg.warn >= gmax ? ry : ry+ph);
    int bad_y  = (w->cfg.bad  > gmin && w->cfg.bad  < gmax)
                 ? VAL_TO_Y(w->cfg.bad)  : (w->cfg.bad  >= gmax ? ry : ry+ph);
    if (bad_y > ry)     fill_rect_x11(rx, ry,    rw, bad_y - ry,     COLOR_ZONE_BAD);
    if (warn_y > bad_y) fill_rect_x11(rx, bad_y, rw, warn_y - bad_y, COLOR_ZONE_WARN);

    pthread_mutex_lock(&w->lock);
    int cap = w->ring_cap;
    for (int i = 0; i < draw_count; i++) {
        int idx = ((w->head - 1 - i) + cap * 2) % cap;
        int x   = rx + rw - 1 - i;
        sample_t *s = &w->ring[idx];
        switch (s->state) {
        case STATE_PENDING:
            draw_line_x11(x, ry, x, ry + ph - 1, COLOR_PENDING);
            break;
        case STATE_LOST:
            draw_line_x11(x, ry, x, ry+ph-1, COLOR_LOSS);
            break;
        case STATE_OK: {
            double v = s->rtt;
            double clamped = v < gmin ? gmin : (v > gmax ? gmax : v);
            int bar_y = VAL_TO_Y(clamped);
            unsigned long col = (v >= w->cfg.bad) ? COLOR_BAD
                                 : (v >= w->cfg.warn) ? COLOR_WARN
                                 : COLOR_GOOD;
            draw_line_x11(x, bar_y, x, ry+ph-1, col);
            break;
        }
        default: break;
        }
    }
    pthread_mutex_unlock(&w->lock);

    // Horizontal grid lines at 25% intervals
    for (int i = 0; i <= 4; i++) {
        int gy = ry + (int)((double)i / 4.0 * (ph-1));
        draw_grid_line_x11(rx, gy, rx+rw-1, gy);
    }

    int fsm = 10;
#if HAS_XFT
    if (g_gfx.xft_font_small) fsm = g_gfx.xft_font_small->ascent + g_gfx.xft_font_small->descent;
    else
#endif
    if (g_gfx.font_small) fsm = g_gfx.font_small->ascent + g_gfx.font_small->descent;

    int fmain = 13;
#if HAS_XFT
    if (g_gfx.xft_font) fmain = g_gfx.xft_font->ascent + g_gfx.xft_font->descent;
    else
#endif
    if (g_gfx.font) fmain = g_gfx.font->ascent + g_gfx.font->descent;

    // Y-axis labels: scale values are in µs; display in ms.
    // Show one decimal place below 100ms, integer at 100ms and above.
    char lbl[32];
    for (int i = 0; i <= 4; i++) {
        double val_us = gmax - (double)i / 4.0 * grange;
        double val_ms = val_us / 1000.0;
        if (val_ms >= 100.0 || (grange / 1000.0) >= 20.0)
            sprintf(lbl, "%.0f", val_ms);
        else
            sprintf(lbl, "%.1f", val_ms);
        int ly = (i == 0) ? ry + 1
                   : (i == 4) ? ry + ph - fsm - 1
                   : ry + (int)((double)i/4.0*(ph-1)) - fsm/2;
        int lw = text_width_unified(lbl, 1);
        fill_rect_x11(rx+1, ly, lw, fsm+1, COLOR_BG);
        draw_text_stroke_x11(rx+1, ly, lbl, COLOR_AXIS, 1);
    }

    int hw = text_width_unified(w->cfg.host, 0);
    int hx = rx + (rw - hw) / 2;
    draw_text_stroke_x11(hx, ry + 2, w->cfg.host, COLOR_AXIS, 0);

    double rmin = 1e18, rmax_v = -1e18, racc = 0.0;
    double ravg, last = -1.0;
    int rcv = 0, ring_lost = 0, ring_pending = 0;
    pthread_mutex_lock(&w->lock);
    int total_scan = w->count < cap ? w->count : cap;
    for (int i = 0; i < total_scan; i++) {
        int idx = ((w->head - 1 - i) + cap * 2) % cap;
        sample_t *rs = &w->ring[idx];
        switch (rs->state) {
            case STATE_OK:
                if (last < 0) last = rs->rtt / 1000.0;
                if (rs->rtt < rmin) rmin = rs->rtt;
                if (rs->rtt > rmax_v) rmax_v = rs->rtt;
                racc += rs->rtt;
                rcv++;
                break;
            case STATE_LOST:    ring_lost++;    break;
            case STATE_PENDING: ring_pending++; break;
        }
    }
    ravg   = rcv > 0 ? (racc / rcv) / 1000.0 : 0.0;
    rmin   = rcv > 0 ? rmin   / 1000.0 : 0.0;
    rmax_v = rcv > 0 ? rmax_v / 1000.0 : 0.0;
    int snt = rcv + ring_lost + ring_pending;
    int lost_n = ring_lost;
    pthread_mutex_unlock(&w->lock);

    // Display in ms: one decimal below 100ms, integer at 100ms and above.
    #define FMT_RTT(dst, v) \
        if ((v) < 0) sprintf((dst), "!"); \
        else if ((v) >= 100.0) sprintf((dst), "%.0f", (v)); \
        else sprintf((dst), "%.1f", (v));
    char fmt_last[16], fmt_min[16], fmt_max[16], fmt_avg[16];
    FMT_RTT(fmt_last, last);
    FMT_RTT(fmt_min,  rcv > 0 ? rmin   : -1.0);
    FMT_RTT(fmt_max,  rcv > 0 ? rmax_v : -1.0);
    FMT_RTT(fmt_avg,  rcv > 0 ? ravg   : -1.0);

    char seg[4][32];
    sprintf(seg[0], "last:%s", fmt_last);
    sprintf(seg[1], "min:%s",  fmt_min);
    sprintf(seg[2], "max:%s",  fmt_max);
    sprintf(seg[3], "avg:%s",  fmt_avg);

    int seg_w[4];
    for (int i = 0; i < 4; i++) seg_w[i] = text_width_unified(seg[i], 0);
    int gap1 = text_width_unified(" ",  0);
    int gap2 = text_width_unified("  ", 0);
    char widest_lbl[32];
	double widest_val_ms = gmax / 1000.0;
	if (widest_val_ms >= 100.0 || (grange / 1000.0) >= 20.0)
		sprintf(widest_lbl, "%.0f", widest_val_ms);
	else
		sprintf(widest_lbl, "%.1f", widest_val_ms);
	int sx = rx + text_width_unified(widest_lbl, 1) + 6;
    int avail = rx + rw - 4 - sx;
    int stats_y = ry + fmain + 4;
    int line_h  = fmain + 2;

    int tw2 = seg_w[0] + gap2 + seg_w[1] + gap2 + seg_w[2] + gap2 + seg_w[3];
    int tw1 = seg_w[0] + gap1 + seg_w[1] + gap1 + seg_w[2] + gap1 + seg_w[3];
    if (tw2 <= avail) {
        int spare = avail - tw2;
        int g = gap2 + (spare > 0 ? spare / 6 : 0);
        if (g > gap2 * 2) g = gap2 * 2;
        int cx = sx;
        for (int i = 0; i < 4; i++) {
            draw_text_stroke_x11(cx, stats_y, seg[i], COLOR_AXIS, 0);
            if (i < 3) cx += seg_w[i] + g;
        }
    } else if (tw1 <= avail) {
        int spare = avail - (seg_w[0]+seg_w[1]+seg_w[2]+seg_w[3]);
        int g = spare / 3;
        if (g < 0) g = 0;
        int cx = sx;
        for (int i = 0; i < 4; i++) {
            draw_text_stroke_x11(cx, stats_y, seg[i], COLOR_AXIS, 0);
            if (i < 3) cx += seg_w[i] + g;
        }
    } else {
        int fit = 1, used = seg_w[0];
        for (int i = 1; i < 4; i++) {
            int next = used + gap1 + seg_w[i];
            if (next <= avail) { used = next; fit = i + 1; }
            else break;
        }
        int cx = sx;
        for (int i = 0; i < fit; i++) {
            draw_text_stroke_x11(cx, stats_y, seg[i], COLOR_AXIS, 0);
            if (i < fit-1) cx += seg_w[i] + gap1;
        }
        if (fit < 4) {
            int cx2 = sx;
            for (int i = fit; i < 4; i++) {
                draw_text_stroke_x11(cx2, stats_y + line_h, seg[i], COLOR_AXIS, 0);
                if (i < 3) cx2 += seg_w[i] + gap1;
            }
            stats_y += line_h;
        }
    }
    double loss_pct = snt > 0 ? 100.0 * lost_n / snt : 0.0;
    char lost_s[64];
    sprintf(lost_s, "lost:%d (%.0f%%)", lost_n, loss_pct);
    draw_text_stroke_x11(sx, stats_y + line_h, lost_s, COLOR_AXIS, 0);

    double rate = w->cfg.rate > 0 ? w->cfg.rate : 2.0;
    // The graph shows rw samples (one per pixel column); the time span shown
    // is rw/rate seconds.  When the window is resized, more/fewer pixels means
    // more/fewer samples and a proportionally different time span.
    int num_ticks = rw / 100;
    if (num_ticks < 2) num_ticks = 2;
    int ty = ry + ph + 2;
    for (int i = 0; i <= num_ticks; i++) {
        double frac = (double)i / num_ticks;
        int tx = rx + (int)(frac * (rw-1));
        int secs_ago = (int)((1.0 - frac) * rw / rate);
        char tlbl[16];
        if (secs_ago == 0) strcpy(tlbl, "now");
        else if (secs_ago < 60) sprintf(tlbl, "-%ds", secs_ago);
        else if (secs_ago < 3600) sprintf(tlbl, "-%dm", secs_ago/60);
        else if (secs_ago < 86400) sprintf(tlbl, "-%dh", secs_ago/3600);
        else sprintf(tlbl, "-%dd", secs_ago/86400);

        int tw = text_width_unified(tlbl, 1);
        int tx2 = (i == 0) ? tx + 2
                 : (i == num_ticks) ? tx - tw - 2
                 : tx - tw/2;
        draw_text_stroke_x11(tx2, ty, tlbl, COLOR_AXIS, 1);
    }

    // No cell borders are drawn -- separator lines between cells are handled
    // by linux_repaint() only between adjacent cells, so there are no outer
    // borders and no double-borders where cells touch.

    #undef VAL_TO_Y
    #undef FMT_RTT
}

// ---------------------------------------------------------------------------
// Full repaint -- composites all cells into the off-screen pixmap then blits
// ---------------------------------------------------------------------------
static void linux_repaint(void) {
    if (!g_gfx.display) return;

    XSetForeground(g_gfx.display, g_gfx.gc, COLOR_BG);
    XFillRectangle(g_gfx.display, g_gfx.buffer, g_gfx.gc,
                   0, 0, g_gfx.width, g_gfx.height);

    int rows, cols;
    auto_layout(g_num_workers, g_rows, g_cols, &rows, &cols);

    if (g_focused >= 0 && g_focused < g_num_workers) {
        draw_cell_linux(g_workers[g_focused], 0, 0, g_gfx.width, g_gfx.height);
    } else {
        int cw = g_gfx.width / cols;
        int ch = g_gfx.height / rows;
        for (int i = 0; i < g_num_workers; i++) {
            int row = i / cols, col = i % cols;
            draw_cell_linux(g_workers[i], col*cw, row*ch, cw, ch);
        }
        // Draw single-pixel separator lines between adjacent cells only.
        // Vertical separators between columns (not at left/right window edges).
        for (int c2 = 1; c2 < cols; c2++)
            draw_grid_line_x11(c2*cw, 0, c2*cw, g_gfx.height);
        // Horizontal separators between rows (not at top/bottom window edges).
        for (int r2 = 1; r2 < rows; r2++)
            draw_grid_line_x11(0, r2*ch, g_gfx.width, r2*ch);
    }

    XCopyArea(g_gfx.display, g_gfx.buffer, g_gfx.window, g_gfx.gc,
              0, 0, g_gfx.width, g_gfx.height, 0, 0);
    XFlush(g_gfx.display);
}

// Toggle fullscreen via EWMH _NET_WM_STATE_FULLSCREEN.
static void linux_toggle_fullscreen(void) {
    Atom wm_state   = XInternAtom(g_gfx.display, "_NET_WM_STATE", False);
    Atom fullscreen = XInternAtom(g_gfx.display, "_NET_WM_STATE_FULLSCREEN", False);

    XEvent event;
    memset(&event, 0, sizeof(event));
    event.type = ClientMessage;
    event.xclient.window       = g_gfx.window;
    event.xclient.message_type = wm_state;
    event.xclient.format       = 32;
    event.xclient.data.l[0]   = g_gfx.fullscreen ? 0 : 1;
    event.xclient.data.l[1]   = fullscreen;

    XSendEvent(g_gfx.display, DefaultRootWindow(g_gfx.display), False,
               SubstructureRedirectMask | SubstructureNotifyMask, &event);
    g_gfx.fullscreen = !g_gfx.fullscreen;
}

// ---------------------------------------------------------------------------
// main -- entry point, argument parsing, X11 setup, event loop
// ---------------------------------------------------------------------------
int main(int argc, char *argv[]) {
    int opt_rows = 0, opt_cols = 0;
    int opt_width = 1280, opt_height = 720;
    char host_tokens[MAX_HOSTS][512];
    int num_tokens = 0;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--rows")   == 0 && i+1 < argc) opt_rows   = atoi(argv[++i]);
        else if (strcmp(argv[i], "--cols")   == 0 && i+1 < argc) opt_cols   = atoi(argv[++i]);
        else if (strcmp(argv[i], "--width")  == 0 && i+1 < argc) opt_width  = atoi(argv[++i]);
        else if (strcmp(argv[i], "--height") == 0 && i+1 < argc) opt_height = atoi(argv[++i]);
        else if (strcmp(argv[i], "--full") == 0 || strcmp(argv[i], "--fullscreen") == 0)
            g_start_fullscreen = 1;
        else if (strcmp(argv[i], "--version") == 0) {
            printf("gpngr %s\nBy Dimitri Pappas -- github.com/fragtion/gpngr\n",
                   GPNGR_VERSION);
            return 0;
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf(
                "gpngr %s -- Graphical Ping Grapher\n"
                "By Dimitri Pappas -- github.com/fragtion/gpngr\n"
                "\n"
                "Usage:\n"
                "  gpngr [options] \"host1{params},host2{params},...\"\n"
                "\n"
                "Host parameters (all optional, use blank or 'auto' to skip):\n"
                "  {rate,ymin,ymax,warn,bad,samples}\n"
                "    rate    - pings per second (default: 2)\n"
                "    ymin    - y-axis minimum in ms (default: auto)\n"
                "    ymax    - y-axis maximum in ms (default: auto)\n"
                "    warn    - RTT warn threshold in ms (default: 80)\n"
                "    bad     - RTT bad threshold in ms (default: 150)\n"
                "    samples - max samples: integer count or time string (e.g. '1h')\n"
                "              (default: auto = graph pixel width)\n"
                "\n"
                "Options:\n"
                "  --rows N         force N rows in the grid layout\n"
                "  --cols N         force N columns in the grid layout\n"
                "  --width N        initial window width  (default: 1280)\n"
                "  --height N       initial window height (default: 720)\n"
                "  --full           start in fullscreen mode\n"
                "  --fullscreen     same as --full\n"
                "  --version        print version and exit\n"
                "  --help, -h       show this help\n"
                "\n"
                "Keyboard / mouse:\n"
                "  Double-click     zoom into / out of a single graph\n"
                "  F / F11          toggle fullscreen\n"
                "  Escape           exit zoom, exit fullscreen, or quit\n"
                "  Q                exit program immediately\n"
                "\n"
                "Examples:\n"
                "  # Two hosts, 2 rows, default settings:\n"
                "  gpngr --rows 2 \"8.8.8.8,1.1.1.1\"\n"
                "\n"
                "  # Named parameters -- 1 ping/sec, warn at 50ms, bad at 100ms,\n"
                "  # keep 1 hour of history; second host uses all defaults:\n"
                "  gpngr \"8.8.8.8{1,,,,50,100,1h},1.1.1.1\"\n"
                "\n"
                "  # Blank parameters behave as if not set (use defaults):\n"
                "  gpngr \"1.1.1.1{,,,,10}\"\n",
                GPNGR_VERSION);
            return 0;
        }
        else if (argv[i][0] != '-') {
            int n = split_hosts(argv[i], host_tokens + num_tokens, MAX_HOSTS - num_tokens);
            num_tokens += n;
        }
    }

    g_rows = opt_rows; g_cols = opt_cols;

    if (num_tokens == 0) {
        fprintf(stderr,
                "gpngr %s -- Cross-platform live ping grapher\n"
                "By Dimitri Pappas -- github.com/fragtion/gpngr\n"
                "\n"
                "Usage: %s [options] \"host1{rate,ymin,ymax,warn,bad,samples},...\"\n"
                "Run with --help for full usage information.\n",
                GPNGR_VERSION, argv[0]);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    // Parse all configs first, then compute initial cell width for auto workers.
    host_cfg_t cfgs[MAX_HOSTS];
    int num_cfgs = 0;
    for (int i = 0; i < num_tokens && num_cfgs < MAX_HOSTS; i++) {
        parse_host_cfg(host_tokens[i], &cfgs[num_cfgs]);
        num_cfgs++;
    }

    int init_rows, init_cols;
    {
        int saved = g_num_workers;
        g_num_workers = num_cfgs;
        auto_layout(num_cfgs, opt_rows, opt_cols, &init_rows, &init_cols);
        g_num_workers = saved;
    }
    int init_cell_w = opt_width / (init_cols > 0 ? init_cols : 1);
    if (init_cell_w < 1) init_cell_w = 1;

    for (int i = 0; i < num_cfgs; i++) {
        worker_t *wk = create_worker(&cfgs[i], g_num_workers, init_cell_w);
        if (wk) g_workers[g_num_workers++] = wk;
        else fprintf(stderr,
                     "Failed to create worker for: %s\n"
                     "  On Linux, ensure /proc/sys/net/ipv4/ping_group_range covers your GID,\n"
                     "  or run as root.\n", cfgs[i].host);
    }

    if (g_num_workers == 0) { fprintf(stderr, "No valid hosts.\n"); return 1; }

//    g_gfx.display = X
    g_gfx.display = XOpenDisplay(NULL);
    if (!g_gfx.display) { fprintf(stderr, "Cannot open display\n"); return 1; }

    g_gfx.screen    = DefaultScreen(g_gfx.display);
    g_gfx.width     = opt_width;
    g_gfx.height    = opt_height;
    g_gfx.fullscreen = 0;

#if HAS_XFT
    g_gfx.visual   = DefaultVisual(g_gfx.display, g_gfx.screen);
    g_gfx.colormap = DefaultColormap(g_gfx.display, g_gfx.screen);
#endif

    XSetWindowAttributes swa;
    swa.event_mask = ExposureMask | KeyPressMask | ButtonPressMask | StructureNotifyMask;
    g_gfx.window = XCreateWindow(g_gfx.display,
                                 RootWindow(g_gfx.display, g_gfx.screen),
                                 0, 0, g_gfx.width, g_gfx.height, 0,
                                 CopyFromParent, InputOutput, CopyFromParent,
                                 CWEventMask, &swa);

    XStoreName(g_gfx.display, g_gfx.window, "gpngr " GPNGR_VERSION);
    g_gfx.gc     = XCreateGC(g_gfx.display, g_gfx.window, 0, NULL);
    g_gfx.buffer = XCreatePixmap(g_gfx.display, g_gfx.window,
                                 g_gfx.width, g_gfx.height,
                                 DefaultDepth(g_gfx.display, g_gfx.screen));

#if HAS_XFT
    g_gfx.xft_draw = XftDrawCreate(g_gfx.display, g_gfx.buffer,
                                    g_gfx.visual, g_gfx.colormap);

    g_gfx.xft_font = NULL;
    const char *font_patterns[] = {
        "monospace:size=9:style=Bold",
        "Courier New:size=9:style=Bold",
        "fixed:size=9",
        NULL
    };
    for (int fi = 0; font_patterns[fi] && !g_gfx.xft_font; fi++)
        g_gfx.xft_font = XftFontOpenName(g_gfx.display, g_gfx.screen,
                                          font_patterns[fi]);

    g_gfx.xft_font_small = NULL;
    const char *small_patterns[] = {
        "monospace:size=7:style=Bold",
        "Courier New:size=7:style=Bold",
        "fixed:size=7",
        NULL
    };
    for (int fi = 0; small_patterns[fi] && !g_gfx.xft_font_small; fi++)
        g_gfx.xft_font_small = XftFontOpenName(g_gfx.display, g_gfx.screen,
                                                small_patterns[fi]);

    if (!g_gfx.xft_font) {
        XftDrawDestroy(g_gfx.xft_draw);
        g_gfx.xft_draw = NULL;
    }
    if (!g_gfx.xft_font_small && g_gfx.xft_font)
        g_gfx.xft_font_small = g_gfx.xft_font;
#endif

    g_gfx.font = XLoadQueryFont(g_gfx.display,
        "-*-courier-bold-r-*-*-13-*-*-*-*-*-iso8859-1");
    if (!g_gfx.font)
        g_gfx.font = XLoadQueryFont(g_gfx.display, "9x15bold");
    if (!g_gfx.font)
        g_gfx.font = XLoadQueryFont(g_gfx.display, "fixed");

    g_gfx.font_small = XLoadQueryFont(g_gfx.display,
        "-*-courier-bold-r-*-*-10-*-*-*-*-*-iso8859-1");
    if (!g_gfx.font_small)
        g_gfx.font_small = XLoadQueryFont(g_gfx.display, "6x13");
    if (!g_gfx.font_small)
        g_gfx.font_small = g_gfx.font;

    g_gfx.wm_delete_window = XInternAtom(g_gfx.display, "WM_DELETE_WINDOW", False);
    XSetWMProtocols(g_gfx.display, g_gfx.window, &g_gfx.wm_delete_window, 1);
    XMapWindow(g_gfx.display, g_gfx.window);

    if (g_start_fullscreen) linux_toggle_fullscreen();

    XEvent event;
    int running = 1;

    while (running) {
        int fd = ConnectionNumber(g_gfx.display);
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        struct timeval tv = { 0, 50000 };
        select(fd + 1, &fds, NULL, NULL, &tv);

        while (XPending(g_gfx.display)) {
            XNextEvent(g_gfx.display, &event);
            switch (event.type) {
            case Expose:
                mark_dirty();
                break;

            case ConfigureNotify:
                if (event.xconfigure.width  != g_gfx.width ||
                    event.xconfigure.height != g_gfx.height) {
                    g_gfx.width  = event.xconfigure.width;
                    g_gfx.height = event.xconfigure.height;
                    XFreePixmap(g_gfx.display, g_gfx.buffer);
                    g_gfx.buffer = XCreatePixmap(g_gfx.display, g_gfx.window,
                                                 g_gfx.width, g_gfx.height,
                                                 DefaultDepth(g_gfx.display, g_gfx.screen));
#if HAS_XFT
                    if (g_gfx.xft_draw) {
                        XftDrawDestroy(g_gfx.xft_draw);
                        g_gfx.xft_draw = XftDrawCreate(g_gfx.display, g_gfx.buffer,
                                                        g_gfx.visual, g_gfx.colormap);
                    }
#endif
                    g_pending_resize = 1;
                    g_resize_time_ms = get_tick_us() / 1000UL;
                    mark_dirty();
                }
                break;

            case KeyPress: {
                char buf[32];
                KeySym keysym;
                XLookupString(&event.xkey, buf, sizeof(buf), &keysym, NULL);
                if (keysym == XK_Escape) {
                    if (g_focused >= 0) {
                        g_focused = -1;
                        update_ring_sizes_linux(g_gfx.width, g_gfx.height);
                        mark_dirty();
                    } else if (g_gfx.fullscreen) {
                        linux_toggle_fullscreen();
                    } else {
                        running = 0;
                    }
                } else if (keysym == XK_F11 || keysym == XK_f || keysym == XK_F) {
                    linux_toggle_fullscreen();
                } else if (keysym == XK_q || keysym == XK_Q) {
                    running = 0;
                }
                break;
            }

            case ButtonPress: {
                if (event.xbutton.button != Button1) break;
                unsigned long now_ms = get_tick_us() / 1000UL;
                int mx = event.xbutton.x;
                int my = event.xbutton.y;
                int dx = abs(mx - g_last_click_x);
                int dy = abs(my - g_last_click_y);
                unsigned long dt = now_ms - g_last_click_time;

                if (dt < 400 && dx < 20 && dy < 20) {
                    if (g_focused >= 0) {
                        g_focused = -1;
                    } else {
                        int rows, cols;
                        auto_layout(g_num_workers, g_rows, g_cols, &rows, &cols);
                        int cw = g_gfx.width  / cols;
                        int ch = g_gfx.height / rows;
                        int idx = (my / ch) * cols + (mx / cw);
                        if (idx >= 0 && idx < g_num_workers) g_focused = idx;
                    }
                    g_last_click_time = 0;
                    update_ring_sizes_linux(g_gfx.width, g_gfx.height);
                    mark_dirty();
                } else {
                    g_last_click_time = now_ms;
                    g_last_click_x    = mx;
                    g_last_click_y    = my;
                }
                break;
            }

            case ClientMessage:
                if ((Atom)event.xclient.data.l[0] == g_gfx.wm_delete_window)
                    running = 0;
                break;
            }
        }

        if (g_pending_resize) {
            unsigned long now_ms = get_tick_us() / 1000UL;
            if (now_ms - g_resize_time_ms >= 150UL) {
                g_pending_resize = 0;
                update_ring_sizes_linux(g_gfx.width, g_gfx.height);
                mark_dirty();
            }
        }
        if (g_dirty) {
            g_dirty = 0;
            linux_repaint();
        }
    }

    for (int i = 0; i < g_num_workers; i++) stop_worker(g_workers[i]);

#if HAS_XFT
    if (g_gfx.xft_draw)       XftDrawDestroy(g_gfx.xft_draw);
    if (g_gfx.xft_font)       XftFontClose(g_gfx.display, g_gfx.xft_font);
    if (g_gfx.xft_font_small && g_gfx.xft_font_small != g_gfx.xft_font)
                               XftFontClose(g_gfx.display, g_gfx.xft_font_small);
#endif
    XFreePixmap(g_gfx.display, g_gfx.buffer);
    XFreeGC(g_gfx.display, g_gfx.gc);
    XDestroyWindow(g_gfx.display, g_gfx.window);
    XCloseDisplay(g_gfx.display);

    return 0;
}
#endif
