"""
Discord Data Package Viewer — v3

Usage:
  GUI mode:  python generate_discord_viewer.py        (opens file-picker window)
  CLI mode:  python generate_discord_viewer.py <path>  (headless, for power users)

Δημιουργεί: discord_viewer.html  (standalone, ανοίγει στον browser)
"""

import json, sys, base64, hashlib, re, logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter

log = logging.getLogger("discord_viewer")
logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

# Fix Windows console encoding for Greek text
try:
    if sys.stdout and sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if sys.stderr and sys.stderr.encoding and sys.stderr.encoding.lower() not in ('utf-8', 'utf8'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

PACKAGE_PATH = None   # Set dynamically by CLI arg or GUI selection
OUTPUT_FILE  = None   # Derived: package_parent / "discord_viewer.html"

# ─── HELPERS ──────────────────────────────────────────────
def b64_file(path):
    if not path or not path.exists(): return None
    ext  = path.suffix.lower().lstrip(".")
    mime = {"gif":"image/gif","png":"image/png","jpg":"image/jpeg","jpeg":"image/jpeg","webp":"image/webp"}.get(ext,"application/octet-stream")
    return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode()}"

# Embed browser-icon.ico as base64 favicon
def _load_ico():
    for name in ("browser-icon.ico", "icon.ico"):
        ico = Path(__file__).parent / name
        if ico.exists():
            return f"data:image/x-icon;base64,{base64.b64encode(ico.read_bytes()).decode()}"
    return ""
ICO_B64 = _load_ico()

def name_to_color(name):
    """Generate a consistent HSL color from a name string."""
    h = int(hashlib.md5(name.encode()).hexdigest()[:4], 16) % 360
    return h

# ─── GUI STDOUT / LOG HELPERS ────────────────────────────

# Status keywords: map print output → friendly status string
_STATUS_PATTERNS = [
    ("Extracting",       "Extracting ZIP…"),
    ("Extraction complete", "Extraction complete"),
    ("Φορτώνω",          "Loading messages…"),
    ("Fetching",         "Fetching Tenor thumbnails…"),
    ("Δημιουργώ HTML",   "Generating HTML…"),
    ("DONE!",            "Complete!"),
    ("User:",            "Loaded user profile"),
    ("Servers:",         "Loaded servers"),
    ("Activity events:", "Loaded activity"),
    ("Quests:",          "Loading extras…"),
    ("User map:",        "Resolving @mentions…"),
]


import re as _re
_PCT_RE = _re.compile(r'(\d+)/(\d+)\s+files\s+\((\d+)%\)')

class TextRedirector:
    """Intercepts stdout/stderr writes → Text widget + optional status label."""
    def __init__(self, text_widget, original, tag="stdout", status_var=None, progress_ref=None):
        self.text_widget = text_widget
        self.original = original
        self.tag = tag
        self.status_var = status_var
        self.progress_ref = progress_ref   # (CTkProgressBar, tk_root) or None
        self.encoding = "utf-8"
        self.errors = "replace"

    def write(self, s):
        if self.original:
            try: self.original.write(s)
            except Exception: pass
        if self.text_widget and s:
            self.text_widget.after(0, self._append, s)

    def _append(self, s):
        try:
            self.text_widget.configure(state="normal")
            self.text_widget.insert("end", s, (self.tag,))
            self.text_widget.see("end")
            self.text_widget.configure(state="disabled")
        except Exception:
            pass
        # Update status label from key phrases
        if self.status_var and s.strip():
            for keyword, status in _STATUS_PATTERNS:
                if keyword in s:
                    try: self.status_var.set(status)
                    except Exception: pass
                    break
        # Update progress bar with extraction percentage
        if self.progress_ref and s.strip():
            m = _PCT_RE.search(s)
            if m:
                done, total, pct = int(m.group(1)), int(m.group(2)), int(m.group(3))
                bar, root = self.progress_ref
                try:
                    bar.configure(mode="determinate")
                    bar.set(pct / 100)
                    if self.status_var:
                        self.status_var.set(f"Extracting…  {done:,} / {total:,}  ({pct}%)")
                except Exception:
                    pass

    def flush(self):
        if self.original:
            try: self.original.flush()
            except Exception: pass

    def reconfigure(self, **kwargs):
        pass  # no-op: prevents crash from module-level encoding fix


class TextWidgetLogHandler(logging.Handler):
    """Routes logging.warning() etc. into the GUI text widget."""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record) + "\n"
        if self.text_widget:
            self.text_widget.after(0, self._append, msg)

    def _append(self, msg):
        try:
            self.text_widget.configure(state="normal")
            self.text_widget.insert("end", msg, ("warning",))
            self.text_widget.see("end")
            self.text_widget.configure(state="disabled")
        except Exception:
            pass

# ─── LOAD DATA ────────────────────────────────────────────
def load_user():
    p = PACKAGE_PATH / "Account" / "user.json"
    with open(p, encoding="utf-8") as f:
        d = json.load(f)
    # Decode account creation date from Discord snowflake ID
    uid = d.get("id", "0")
    try:
        from datetime import timezone
        created_ms = (int(uid) >> 22) + 1420070400000
        created_iso = datetime.fromtimestamp(created_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        created_iso = ""
    
    # Parse flags for badges (flags are strings in newer exports)
    flags_raw = d.get("flags", [])
    badge_names = []
    flag_map_str = {
        "STAFF":                    "Staff",
        "PARTNER":                  "Partner",
        "HYPESQUAD":                "HypeSquad Events",
        "HYPESQUAD_ONLINE_HOUSE_1": "HypeSquad Bravery",
        "HYPESQUAD_ONLINE_HOUSE_2": "HypeSquad Brilliance",
        "HYPESQUAD_ONLINE_HOUSE_3": "HypeSquad Balance",
        "BUG_HUNTER_LEVEL_1":       "Bug Hunter Level 1",
        "BUG_HUNTER_LEVEL_2":       "Bug Hunter Level 2",
        "PREMIUM_EARLY_SUPPORTER":  "Early Supporter",
        "VERIFIED_DEVELOPER":       "Verified Bot Developer",
        "ACTIVE_DEVELOPER":         "Active Developer",
        "PREMIUM_DISCRIMINATOR":    "Premium Discriminator",
        "USED_DESKTOP_CLIENT":      "Desktop User",
        "USED_WEB_CLIENT":          "Web User",
        "USED_MOBILE_CLIENT":       "Mobile User",
        "CERTIFIED_MODERATOR":      "Certified Moderator",
        "SPAMMER":                  "Spammer",
        "BOT_HTTP_INTERACTIONS":    "HTTP Interaction Bot",
        "QUARANTINED":              "Quarantined",
    }
    # Bitmask → badge for integer flag decoding
    flag_map_int = {
        1:       "Staff",
        2:       "Partner",
        4:       "HypeSquad Events",
        8:       "Bug Hunter Level 1",
        64:      "HypeSquad Bravery",
        128:     "HypeSquad Brilliance",
        256:     "HypeSquad Balance",
        512:     "Early Supporter",
        16384:   "Bug Hunter Level 2",
        65536:   "Verified Bot",
        131072:  "Verified Bot Developer",
        262144:  "Certified Moderator",
        4194304: "Active Developer",
    }
    # Normalise flags_raw into a list regardless of input type
    if isinstance(flags_raw, dict):
        # Some exports use {"public_flags": 123, ...} — extract values
        flags = []
        for v in flags_raw.values():
            if isinstance(v, int):
                flags.append(v)
            elif isinstance(v, str):
                flags.append(v)
    elif isinstance(flags_raw, (str, int)):
        flags = [flags_raw]
    elif isinstance(flags_raw, list):
        flags = flags_raw
    else:
        flags = []
    for flag in flags:
        if isinstance(flag, str) and flag in flag_map_str:
            badge_names.append(flag_map_str[flag])
        elif isinstance(flag, str):
            log.debug("Unknown string flag: %s", flag)
        elif isinstance(flag, int):
            # Decode bitmask: test each known bit
            decoded = False
            for bit, name in flag_map_int.items():
                if flag & bit:
                    badge_names.append(name)
                    decoded = True
            if not decoded and flag != 0:
                log.debug("Unknown integer flag value: %d", flag)
    
    return {
        "id":            uid,
        "username":      d.get("username","unknown"),
        "global_name":   d.get("global_name") or d.get("username",""),
        "email":         d.get("email",""),
        "avatar_hash":   d.get("avatar_hash",""),
        "has_mobile":    bool(d.get("has_mobile")),
        "has_phone":     bool(d.get("phone")),
        "premium_until": d.get("premium_until",""),
        "phone":         d.get("phone",""),
        "flags":         flags,
        "badges":        badge_names,
        "created_at":    created_iso,
    }

def load_servers():
    p = PACKAGE_PATH / "Servers" / "index.json"
    if not p.exists(): return {}
    with open(p, encoding="utf-8") as f:
        return json.load(f)

def load_activity():
    stats = defaultdict(int)
    rep_dir = PACKAGE_PATH / "Activity" / "reporting"
    if not rep_dir.exists(): return stats
    for fp in rep_dir.glob("*.json"):
        try:
            with open(fp, encoding="utf-8") as f:
                for line_no, line in enumerate(f, 1):
                    line = line.strip()
                    if not line: continue
                    try:
                        stats[json.loads(line).get("event_type","?")] += 1
                    except (json.JSONDecodeError, ValueError) as e:
                        log.warning("Malformed JSON in %s line %d: %s", fp.name, line_no, e)
        except OSError as e:
            log.warning("Could not read activity file %s: %s", fp.name, e)
    return stats

def load_connections(user_data):
    """Extract linked accounts (Spotify, PSN, Epic etc.) from user.json"""
    conn_icons = {
        "spotify":     "🎵", "epicgames":  "🎮", "playstation": "🎮",
        "xbox":        "🎮", "steam":      "🎮", "twitch":      "📺",
        "youtube":     "📺", "twitter":    "🐦", "reddit":      "👾",
        "github":      "💻", "instagram":  "📸", "tiktok":      "🎵",
        "leagueoflegends": "🎮", "battlenet": "🎮", "contacts":  "📱",
    }
    out = []
    for c in user_data.get("connections", []):
        if c.get("revoked"): continue
        ctype = c.get("type","")
        out.append({
            "type":     ctype,
            "name":     c.get("name",""),
            "verified": c.get("verified", False),
            "icon":     conn_icons.get(ctype, "🔗"),
        })
    return out

def load_top_games(user_data):
    """Extract top games by playtime from user_activity_application_statistics"""
    games = []
    for g in user_data.get("user_activity_application_statistics", []):
        dur = g.get("total_duration", 0)
        if dur < 60: continue  # skip < 1 min
        games.append({
            "app_id":     g["application_id"],
            "hours":      round(dur / 3600, 1),
            "last_played": (g.get("last_played_at") or "")[:10],
        })
    games.sort(key=lambda x: x["hours"], reverse=True)
    return games[:15]

def load_friends(user_data):
    """Extract friends list from relationships"""
    friends, blocked = [], []
    for r in user_data.get("relationships", []):
        u = r.get("user", {})
        name = u.get("global_name") or u.get("username","?")
        entry = {"name": name, "username": u.get("username",""), "type": r.get("type","")}
        if r["type"] == "FRIEND":
            friends.append(entry)
        elif r["type"] == "BLOCKED":
            blocked.append(entry)
    return {"friends": friends, "blocked_count": len(blocked)}

def load_notes(user_data):
    """Extract notes written about other users"""
    return [{"uid": uid, "text": text}
            for uid, text in user_data.get("notes", {}).items()
            if text and text.strip()]

def load_sessions(user_data):
    """Extract login sessions"""
    out = []
    for s in user_data.get("user_sessions", []):
        ud = s.get("user_data", {})
        ci = ud.get("client_info", {})
        out.append({
            "created":  (ud.get("creation_time") or "")[:10],
            "last_used":(ud.get("approx_last_used_time") or "")[:10],
            "os":       ci.get("os","?"),
            "platform": ci.get("platform","?"),
            "ip":       ci.get("ip",""),
            "mfa":      ud.get("is_mfa", False),
        })
    out.sort(key=lambda x: x["created"], reverse=True)
    return out

def load_quests(pkg_path):
    """Load quest completion data"""
    p = pkg_path / "Ads" / "quests_user_status.json"
    if not p.exists(): return []
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for q in data:
        out.append({
            "quest_id":    q.get("quest_id",""),
            "enrolled":    (q.get("enrolled_at") or "")[:10],
            "completed":   (q.get("completed_at") or "")[:10],
            "claimed":     (q.get("claimed_at") or "")[:10],
            "done":        bool(q.get("completed_at")),
        })
    out.sort(key=lambda x: x["enrolled"], reverse=True)
    return out

def load_poker(pkg_path):
    """Load poker stats"""
    act_dir = pkg_path / "Activities"
    data = None
    if act_dir.exists():
        for sub in sorted(act_dir.iterdir()):
            if not sub.is_dir(): continue
            p = sub / "poker" / "poker.json"
            if p.exists():
                try:
                    with open(p, encoding="utf-8") as f:
                        data = json.load(f)
                    break
                except Exception as exc:
                    print(f"    [warn] poker parse error in {sub.name}: {exc}")
    if not data: return {}
    gs = data.get("global_stats", {})
    return {
        "games_played":    gs.get("games_played", 0),
        "games_won":       gs.get("games_won", 0),
        "pvp_games":       gs.get("pvp_games_played", 0),
        "bot_games":       gs.get("bot_games_played", 0),
        "biggest_pot":     gs.get("biggest_pot", 0),
        "most_chips":      gs.get("most_chips", 0),
        "chip_reserve":    gs.get("chip_reserve", 0),
        "all_ins":         gs.get("all_ins", 0),
        "folds":           gs.get("folds", 0),
        "play_time_min":   round(gs.get("play_time", 0) / 60, 1),
        "emoted":          gs.get("emoted", 0),
    }

def load_nitro_history(pkg_path):
    """Load Nitro subscription history from entitlements"""
    p = pkg_path / "Account" / "user_data_exports" / "discord_billing" / "entitlements.json"
    if not p.exists(): return []
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    
    NITRO_SKUS = {
        "521847234246082599": "Nitro",
        "521846918637420545": "Nitro Classic",
        "628379670982688768": "Nitro Basic",
        "743225458687041556": "Nitro Basic",
        "1086939278932725811": "Nitro",
        "1096263500899344394": "Nitro Basic",
        "590663762298667008": "Server Boost",
        "521847876940505088": "Server Boost",
    }
    PLAN_NAMES = {
        "511651880837840896": "Monthly",
        "642251038925127690": "Monthly",
        "978380684370378762": "Monthly",
        "511651885459963904": "Yearly",
        "641446808627216404": "Yearly",
        "521846935048470528": "Yearly (Classic)",
    }
    
    entries = []
    for r in data.get("records", []):
        sku = str(r.get("sku_id",""))
        if sku not in NITRO_SKUS: continue
        started  = (r.get("starts_at") or r.get("created_at") or "")[:10]
        ended    = (r.get("ends_at") or r.get("deleted_at") or "")[:10]
        plan     = PLAN_NAMES.get(str(r.get("subscription_plan_id","")), "")
        gifter   = r.get("gifter_user_id")
        entries.append({
            "tier":    NITRO_SKUS[sku],
            "plan":    plan,
            "started": started,
            "ended":   ended,
            "gifted":  bool(gifter),
            "gifter":  gifter or "",
        })
    # deduplicate by started date
    seen = set()
    unique = []
    for e in sorted(entries, key=lambda x: x["started"]):
        key = e["started"]
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique

def load_payments_summary(pkg_path):
    """Load payment history"""
    p = pkg_path / "Account" / "user_data_exports" / "discord_billing" / "payments.json"
    if not p.exists(): return {"total_real": 0, "total_orbs": 0, "items": []}
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    
    total_real, total_orbs = 0, 0
    items = []
    for r in data.get("records", []):
        curr   = r.get("currency","")
        amt    = r.get("amount", 0)
        desc   = r.get("description","")
        date   = r.get("created_at","")[:10]
        status = r.get("status", 0)
        if status != 1: continue  # only succeeded
        if curr == "discord_orb":
            total_orbs += amt
        else:
            total_real += amt
        items.append({"desc": desc, "date": date, "currency": curr,
                      "amount": amt, "orbs": curr=="discord_orb"})
    items.sort(key=lambda x: x["date"], reverse=True)
    return {"total_real": total_real, "total_orbs": total_orbs, "items": items}


import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

def fetch_tenor_thumb(tenor_id):
    """Fetch Tenor thumbnail URL server-side during HTML generation."""
    try:
        url = f"https://tenor.com/oembed?url=https://tenor.com/view/{tenor_id}&format=json"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read())
            return d.get("thumbnail_url") or d.get("url") or ""
    except Exception as e:
        log.debug("Tenor fetch failed for %s: %s", tenor_id, e)
        return ""

_TENOR_THUMB_CACHE = {}

def get_tenor_thumb(tenor_id):
    if tenor_id not in _TENOR_THUMB_CACHE:
        _TENOR_THUMB_CACHE[tenor_id] = fetch_tenor_thumb(tenor_id)
    return _TENOR_THUMB_CACHE[tenor_id]

def load_messages(channel_index):
    msgs_dir = PACKAGE_PATH / "Messages"
    channels, total = [], 0
    dirs = sorted([d for d in msgs_dir.iterdir() if d.is_dir()])
    print(f"  Φορτώνω {len(dirs)} φακέλους...")

    # ── Single-pass stats accumulators (avoids re-iterating all messages) ──
    st_monthly   = defaultdict(int)
    st_daily     = defaultdict(int)
    st_hourly    = defaultdict(int)
    st_word_freq = Counter()
    st_emoji_freq = Counter()
    st_att_images = 0
    st_att_videos = 0
    st_att_files  = 0
    st_att_ext    = Counter()
    st_first_ts   = None
    st_last_ts    = None

    for i, ch_dir in enumerate(dirs):
        ch_id    = ch_dir.name.lstrip("c")
        ch_label = channel_index.get(ch_id, "")
        is_dm    = "Direct Message" in ch_label

        display_name, server_name = ch_label, ""
        if is_dm:
            display_name = ch_label.replace("Direct Message with ", "").strip()
            server_name  = "DM"
        elif " in " in ch_label:
            parts = ch_label.split(" in ", 1)
            display_name, server_name = parts[0].strip(), parts[1].strip()

        msgs_path = ch_dir / "messages.json"
        if not msgs_path.exists(): continue
        try:
            with open(msgs_path, encoding="utf-8") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, ValueError) as e:
            log.warning("Corrupted messages.json in %s: %s — channel skipped", ch_dir.name, e)
            continue
        except OSError as e:
            log.warning("Could not read %s: %s", msgs_path, e)
            continue

        messages = []
        for m in raw:
            # Support both old (Contents/Attachments) and new (content/attachments) key casing
            c = (m.get("content") or m.get("Contents") or "").strip()
            # Attachments: newer exports → list of dicts; older → space-separated string
            att_raw = m.get("attachments") if "attachments" in m else m.get("Attachments") or ""
            if isinstance(att_raw, list):
                urls = []
                for att in att_raw:
                    if isinstance(att, dict):
                        u = att.get("url") or att.get("proxy_url") or ""
                    else:
                        u = str(att)
                    if u: urls.append(u)
                a = " ".join(urls)
            else:
                a = str(att_raw).strip() if att_raw else ""
            ts      = m.get("Timestamp") or m.get("timestamp") or ""
            msg_id  = str(m.get("ID") or m.get("id") or "")
            # Author (present in newer package exports)
            author_obj  = m.get("author") or {}
            author_name = (author_obj.get("global_name") or author_obj.get("username") or "").strip()
            author_id   = str(author_obj.get("id") or "")
            if not c and not a: continue
            messages.append({
                "id": msg_id, "ts": ts, "c": c, "a": a,
                "author": author_name, "author_id": author_id,
            })

            # ── Accumulate stats inline (single pass) ──
            if ts:
                try:
                    st_monthly[ts[:7]] += 1
                    st_daily[ts[:10]] += 1
                    st_hourly[int(ts[11:13])] += 1
                except (ValueError, IndexError):
                    pass
                if st_first_ts is None or ts < st_first_ts: st_first_ts = ts
                if st_last_ts  is None or ts > st_last_ts:  st_last_ts  = ts
            if c:
                st_emoji_freq.update(_EMOJI_RE.findall(c))
                tokens = _WORD_SPLIT_RE.sub(" ", c.lower()).split()
                st_word_freq.update(
                    t for t in tokens
                    if len(t) >= 3 and t not in _STOP and not t.isdigit()
                )
            if a:
                for url in a.split():
                    ext = url.split("?")[0].rsplit(".", 1)[-1].lower() if "." in url else ""
                    st_att_ext[ext] += 1
                    if ext in _IMG_EXT:
                        st_att_images += 1
                    elif ext in _VID_EXT:
                        st_att_videos += 1
                    else:
                        st_att_files += 1

        if not messages: continue
        messages.reverse()
        total += len(messages)

        channels.append({
            "id":       ch_id,
            "name":     display_name,
            "server":   server_name,
            "type":     "DM" if is_dm else "SERVER",
            "count":    len(messages),
            "last_ts":  messages[0]["ts"],
            "first_ts": messages[-1]["ts"],
            "messages": messages,
        })
        if (i+1) % 100 == 0:
            print(f"  ... {i+1}/{len(dirs)}")

    # DEFAULT SORT: by message count descending
    channels.sort(key=lambda x: x["count"], reverse=True)
    print(f"  OK: {len(channels)} κανάλια | {total:,} msgs")

    stats_accum = {
        "monthly": st_monthly, "daily": st_daily, "hourly": st_hourly,
        "word_freq": st_word_freq, "emoji_freq": st_emoji_freq,
        "att_images": st_att_images, "att_videos": st_att_videos,
        "att_files": st_att_files, "att_ext_cnt": st_att_ext,
        "first_ts": st_first_ts, "last_ts": st_last_ts,
    }
    return channels, total, stats_accum

# Greek + English stop words for word cloud
_STOP = set("""
α αι αλλά αν και κι αν αντί από αρα αρά αυτά αυτές αυτοί αυτό αυτός αφού γι για
γιατί γιατι γύρω δε δεν δηλαδή διότι εαν εγώ ειμαι εiμαι εκεί εκτός εκτος
ελπίζω εναν ενώ εξ εξαιτίας εξαιτιας επί επε επι εστω εφόσον εφοσον εως
ή ήδη ημας ήταν θα θέλω θελω ι ιδία ιι ιίι ιν ιναι ια ιία
και καθ καθε κατά κατω κει κεινος κιόλας κιολας κοντά κοντα
μα μαζί μαζι με μεν μεντα μέσα μέσω μετά μη μην μπρος μπρoς
να ναι ντε ντα παρά παρα περί περι πια πλαι ποιος που πρίν
πριν πριτο προ πρός προς σαν σε στα στη στην στης στο στον
σύμφωνα τα τελικά τελικα τες τηλ τι τιποτα τιποτε τον τος
τότε τοτε του τους τύπου τωρα τώρα υπαρχω υπο ύστερα υστερα
φυσικά φυσικα χωρίς χωρις ω ως
a an and are as at be been being but by can did do does for from
had has have i if in is it its me my no not of on or so that the
their them they this to up was we with you your
""".lower().split())

# Emoji regex pattern (covers most Unicode emoji)
_EMOJI_RE = re.compile(
    r'[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF'
    r'\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF'
    r'\U00002600-\U000027BF\U0001F900-\U0001F9FF'
    r'\U0001FA00-\U0001FA6F\U0001FA70-\U0001FAFF'
    r'\U00002702-\U000027B0\U0000200D\U0000FE0F'
    r'\U0001F004\U0001F0CF]+'
)

# Image / video extensions for attachment categorisation
_IMG_EXT  = {"jpg","jpeg","png","gif","webp","bmp","svg","avif","heic"}
_VID_EXT  = {"mp4","mov","webm","mkv","avi","m4v","flv","wmv"}

_TENOR_RE = re.compile(r'https?://tenor\.com/view/[\w-]+')
_WORD_SPLIT_RE = re.compile(r"[^\w\s]")

def prefetch_tenor_thumbs(channels):
    """Pre-fetch all tenor thumbnail URLs in parallel."""
    tenor_ids = set()
    for ch in channels:
        for m in ch.get("messages", []):
            for txt in [m.get("c",""), m.get("a","")]:
                for url in re.findall(r'https?://tenor\.com/view/[\S]+', txt):
                    tid = url.rstrip('/').split('/')[-1].split('-')[-1]
                    if tid.isdigit() or len(tid) > 8:
                        tenor_ids.add(tid)
    if not tenor_ids:
        return
    tenor_ids = list(tenor_ids)
    print(f"  Fetching {len(tenor_ids)} Tenor thumbnails (parallel)...")
    done = [0]
    failed = [0]
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(fetch_tenor_thumb, tid): tid for tid in tenor_ids}
        for f in as_completed(futures):
            tid = futures[f]
            result = f.result()
            _TENOR_THUMB_CACHE[tid] = result
            done[0] += 1
            if not result:
                failed[0] += 1
            if done[0] % 50 == 0 or done[0] == len(tenor_ids):
                print(f"    {done[0]}/{len(tenor_ids)}")
    found = sum(1 for v in _TENOR_THUMB_CACHE.values() if v)
    print(f"  Tenor thumbs OK ({found} found)")
    if failed[0] == len(tenor_ids) and len(tenor_ids) > 0:
        log.warning("All %d Tenor fetches failed — you may be offline or rate-limited. "
                     "GIF previews will be broken in the HTML output.", len(tenor_ids))
    elif failed[0] > 0:
        log.warning("%d/%d Tenor fetches failed — some GIF previews may be missing.",
                     failed[0], len(tenor_ids))

def calc_stats(channels, total, accum):
    """Finalize statistics from pre-computed accumulators (single-pass, no re-iteration)."""
    dms   = [c for c in channels if c["type"]=="DM"]
    srvs  = [c for c in channels if c["type"]=="SERVER"]

    # top DM contacts
    top_dms = sorted(dms, key=lambda x: -x["count"])[:10]

    # messages per server
    srv_cnt = defaultdict(int)
    for c in channels:
        if c["server"] and c["server"] != "DM":
            srv_cnt[c["server"]] += c["count"]
    top_servers = sorted(srv_cnt.items(), key=lambda x: -x[1])[:8]

    # Use pre-computed accumulators from load_messages (no second pass)
    monthly    = accum["monthly"]
    daily      = accum["daily"]
    hourly     = accum["hourly"]
    word_freq  = accum["word_freq"]
    emoji_freq = accum["emoji_freq"]
    att_ext_cnt = accum["att_ext_cnt"]

    dom_ext = att_ext_cnt.most_common(1)[0][0] if att_ext_cnt else ""

    return {
        "total":      total,
        "dms":        len(dms),
        "servers":    len(srvs),
        "top_dms":    top_dms,
        "top_servers":top_servers,
        "monthly":   sorted(monthly.items()),
        "daily":     sorted(daily.items()),
        "hourly":    [hourly[i] for i in range(24)],
        "words":     word_freq.most_common(40),
        "emoji":     emoji_freq.most_common(15),
        "att_images":accum["att_images"],
        "att_videos":accum["att_videos"],
        "att_files": accum["att_files"],
        "dom_ext":   dom_ext,
        "first_ts":  accum["first_ts"] or "",
        "last_ts":   accum["last_ts"]  or "",
    }

# ─── GENERATE HTML ────────────────────────────────────────
def generate_html(user, servers_idx, channels, stats, activity, avatar_b64, extra, av_static=None):
    print("  Δημιουργώ HTML...")

    channels_meta = []
    all_msgs      = {}
    for ch in channels:
        # pop messages to avoid holding two copies in memory (Issue: 1M+ msg RAM usage)
        msgs = ch.pop("messages")
        channels_meta.append(ch)
        all_msgs[ch["id"]] = msgs

    av_css        = f'background-image:url("{avatar_b64}")' if avatar_b64 else "background:var(--bg3)"
    av_static_css = f'background-image:url("{av_static or avatar_b64}")' if (av_static or avatar_b64) else "background:var(--bg3)"
    has_av_js     = "true" if avatar_b64 else "false"

    # Pre-compute server colors for JS
    srv_colors = {}
    for sid, sname in servers_idx.items():
        h = name_to_color(sname)
        srv_colors[sname] = h

    nitro_until = ""
    if user.get("premium_until"):
        try:
            dt = datetime.fromisoformat(user["premium_until"].replace("Z","+00:00"))
            nitro_until = dt.strftime("%d/%m/%Y")
        except: pass

    # Serialize
    JS = {
        "USER":     user,
        "SERVERS":  servers_idx,
        "CHANNELS": channels_meta,
        "ALL_MSGS": all_msgs,
        "STATS":    {
            "total":       stats["total"],
            "dms":         stats["dms"],
            "servers":     stats["servers"],
            "top_dms":     [[c["name"], c["count"], c["id"]] for c in stats["top_dms"]],
            "top_servers": stats["top_servers"],
            "monthly":     stats["monthly"],
            "daily":       stats["daily"],
            "hourly":      stats["hourly"],
            "words":       stats["words"],
            "emoji":       stats["emoji"],
            "att_images":  stats["att_images"],
            "att_videos":  stats["att_videos"],
            "att_files":   stats["att_files"],
            "dom_ext":     stats["dom_ext"],
            "first_ts":    stats["first_ts"],
            "last_ts":     stats["last_ts"],
            "voice":       activity.get("voice_connection_success", 0),
        },
        "SRV_COLORS": srv_colors,
        "NITRO_UNTIL":   nitro_until,
        "CONNECTIONS":   extra["connections"],
        "FRIENDS":       extra["friends"],
        "NOTES":         extra["notes"],
        "QUESTS":        extra["quests"],
        "NITRO_HISTORY": extra["nitro_history"],
        "PAYMENTS":      extra["payments"],
        "ORBS_BALANCE":  extra["orbs_balance"],
        "USER_MAP":        extra.get("user_map", {}),
        "SERVER_ICONS":    extra.get("server_icons", {}),
        "SERVER_CHANNELS": extra.get("server_channels", {}),
        "SERVER_WEBHOOKS": extra.get("server_webhooks", {}),
        "HARVEST_HISTORY": extra.get("harvest_history", []),
        "AD_TRAITS":       extra.get("ad_traits", {}),
        "SUPPORT_TICKETS": extra.get("support_tickets", {}),
        "DEV_APPS":        extra.get("dev_apps", []),
    }

    def jd(v):
            return (json.dumps(v, ensure_ascii=False)
                    .replace("<", "\\u003c")
                    .replace(">", "\\u003e")
                    .replace("\u2028", "\\u2028")
                    .replace("\u2029", "\\u2029"))

    # ── HTML ──────────────────────────────────────────────
    MENTION_JS = r"""      let raw = esc(m.c);
raw = parseDiscordMarkdown(raw);
let contentHtml = linkify(raw);
      contentHtml = contentHtml.replace(/&lt;@!?(\d+)&gt;/g, function(_, uid) {
        var uname = (USER_MAP && USER_MAP[uid]) ? USER_MAP[uid] : uid;
        return '<span class="mention">@' + uname + '</span>';
      });
      contentHtml = contentHtml.replace(/&lt;@&amp;(\d+)&gt;/g, function(_, rid) {
        return '<span class="mention mention-role">@' + rid + '</span>';
      });
      contentHtml = contentHtml.replace(/&lt;#(\d+)&gt;/g, function(_, cid) {
        var dch = CHANNELS.find(function(x) { return x.id === cid; });
        var dchName = dch ? dch.name : cid;
        return '<span class="mention mention-ch">#' + dchName + '</span>';
      });
      contentHtml = contentHtml.replace(/&lt;(a?):(\w+):(\d+)&gt;/g, function(_, anim, ename, eid) {
        var eext = anim ? 'gif' : 'webp';
        var eurl = 'https://cdn.discordapp.com/emojis/' + eid + '.' + eext + '?size=32&quality=lossless';
        return '<img class="custom-emoji" src="' + eurl + '" alt=":' + ename + ':" title=":' + ename + ':" loading="lazy">';
      });
"""

    return f"""<!DOCTYPE html>
<html lang="el">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Discord Archive · {user.get('global_name','')}</title>
<link rel="icon" type="image/x-icon" href="{ICO_B64}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
:root{{
  /* ── Base: extremely dark for glass contrast ── */
  --bg0:#03040c; --bg1:#060812; --bg2:#080c1a; --bg3:#0b101f; --bg4:#0f1428;
  --accent:#5865f2; --accent2:#4752c4; --accent3:#818cf8;
  --green:#23a559; --gold:#f0b232; --red:#ed4245; --blurple:#818cf8;
  --pink:#ff73fa; --cyan:#00d4ff;

  /* ── High-contrast text (glass surfaces demand it) ── */
  --text:#edf0ff; --text2:#bfc6e8; --muted:#6872a0; --faint:#2e3560;
  --border:rgba(255,255,255,0.08); --border2:rgba(255,255,255,0.05);
  --hover1:rgba(255,255,255,0.05); --hover2:rgba(255,255,255,0.09); --sel:rgba(88,101,242,0.22);

  /* ── Glass surface tokens ── */
  --glass:rgba(255,255,255,0.04);
  --glass2:rgba(255,255,255,0.07);
  --glass3:rgba(255,255,255,0.12);
  --glass4:rgba(255,255,255,0.18);
  --glass-border:rgba(255,255,255,0.10);
  --glass-border2:rgba(255,255,255,0.17);
  --glass-blur:blur(28px);
  --glass-blur2:blur(16px);

  /* ── Bevel / highlight edges ── */
  --bevel-t:1px solid rgba(255,255,255,0.15);
  --bevel-l:1px solid rgba(255,255,255,0.09);
  --bevel-b:1px solid rgba(0,0,0,0.55);
  --bevel-r:1px solid rgba(0,0,0,0.35);

  /* ── Shadows ── */
  --shadow-sm:0 2px 14px rgba(0,0,0,0.55);
  --shadow:0 8px 36px rgba(0,0,0,0.65);
  --shadow-lg:0 18px 64px rgba(0,0,0,0.75);
  --shadow-accent:0 4px 28px rgba(88,101,242,0.35);

  --font:'Noto Sans',sans-serif; --mono:'JetBrains Mono',monospace;
  --r:8px; --r2:14px; --r3:20px; --r4:28px;
}}

*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html,body{{
  height:100%;overflow:hidden;
  font-family:var(--font);
  background:var(--bg0);
  color:var(--text);font-size:17px;line-height:1.4;
  user-select:none;-webkit-user-select:none;
}}

/* Global deep-space mesh background */
body::before{{
  content:'';
  position:fixed;inset:0;z-index:0;pointer-events:none;
  background:
    radial-gradient(ellipse 90% 70% at 5% -10%, rgba(88,101,242,0.22) 0%, transparent 55%),
    radial-gradient(ellipse 70% 60% at 95% 110%, rgba(114,137,218,0.16) 0%, transparent 50%),
    radial-gradient(ellipse 60% 50% at 50% 50%, rgba(255,115,250,0.06) 0%, transparent 65%),
    radial-gradient(ellipse 40% 40% at 80% 20%, rgba(0,212,255,0.05) 0%, transparent 50%);
}}
/* Subtle noise grain overlay */
body::after{{
  content:'';
  position:fixed;inset:0;z-index:0;pointer-events:none;
  opacity:0.018;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
  background-size:200px 200px;
}}

#app{{position:relative;z-index:1}}
button{{cursor:pointer;font-family:var(--font)}}
a{{color:#88b4ff;text-decoration:none}}
a:hover{{text-decoration:underline;color:#b0ceff}}
::-webkit-scrollbar{{width:5px;height:5px}}
::-webkit-scrollbar-thumb{{
  background:rgba(255,255,255,0.09);
  border-radius:8px;
}}
::-webkit-scrollbar-track{{background:transparent}}
/* ── DISCORD MARKDOWN + COLORED CODE BLOCKS ── */
.spoiler {{
  background:#202225; color:#202225; padding:0 4px 1px; border-radius:3px;
  cursor:pointer; user-select:none; transition:all .2s;
}}
.spoiler.revealed, .spoiler:hover {{
  background:transparent; color:inherit;
}}
code {{
  font-family:var(--mono); background:rgba(88,101,242,0.15);
  padding:2px 6px; border-radius:3px; font-size:0.93em; color:#c9d1d9;
}}
pre {{
  background:rgba(0,0,0,0.45) !important; padding:12px 14px;
  border-radius:6px; overflow-x:auto; margin:8px 0;
  border-left:4px solid var(--accent); font-family:var(--mono);
  font-size:14.5px; line-height:1.45; color:#e6e9ef;
  max-width: 1000px;
}}

/* Colored Discord "languages" */
.code-fix   {{ color:#f04747 !important; }}
.code-diff  {{ color:#43b581 !important; }}
.code-diff .plus  {{ color:#43b581 !important; }}
.code-diff .minus {{ color:#f04747 !important; }}
.code-yaml, .code-yml  {{ color:#00b0a8 !important; }}
.code-http  {{ color:#faa61a !important; }}
.code-ini   {{ color:#f0b232 !important; }}
.code-css   {{ color:#7289da !important; }}
/* ── LAYOUT ───────────────────────────────── */
#app{{display:flex;height:100vh;overflow:hidden}}

/* ── RAIL ─────────────────────────────────── */
#rail{{
  width:84px;min-width:84px;
  /* background & backdrop-filter moved to ::before so child animations
     do NOT invalidate the blur composite layer → fixes gradient shadow flicker */
  background:transparent;
  border-right:1px solid rgba(255,255,255,0.06);
  display:flex;flex-direction:column;align-items:center;
  padding:12px 0;gap:4px;overflow-y:auto;overflow-x:hidden;scrollbar-width:none;
  box-shadow:2px 0 40px rgba(0,0,0,0.6);
  position:relative;z-index:10;
  isolation:isolate;
}}
#rail::before{{
  content:'';
  position:fixed;
  top:0;left:0;
  width:84px;height:100vh;
  background:rgba(4,5,16,0.75);
  backdrop-filter:blur(48px) saturate(1.4);
  -webkit-backdrop-filter:blur(48px) saturate(1.4);
  z-index:-1;
  pointer-events:none;
}}
#rail::-webkit-scrollbar{{display:none}}

/* rail-wrap: positioning context for the pill OUTSIDE overflow:hidden */
.rail-wrap{{
  position:relative;
  flex-shrink:0;
  margin-bottom:4px;
  display:flex;
  align-items:center;
}}
.rail-icon{{
  position:relative;width:54px;height:54px;
  border-radius:50%;cursor:pointer;
  display:flex;align-items:center;justify-content:center;
  background:rgba(255,255,255,0.05);
  color:var(--text2);
  font-size:20px;font-weight:800;letter-spacing:-1px;
  transition:border-radius .18s cubic-bezier(.55,0,.1,1),
             background .18s ease,
             box-shadow .18s ease,
             transform .12s ease;
  flex-shrink:0;
  overflow:hidden;
  user-select:none;
  border-top:1px solid rgba(255,255,255,0.13);
  border-left:1px solid rgba(255,255,255,0.08);
  border-bottom:1px solid rgba(0,0,0,0.5);
  border-right:1px solid rgba(0,0,0,0.3);
  box-shadow:0 4px 20px rgba(0,0,0,0.5),
             inset 0 1px 0 rgba(255,255,255,0.10),
             inset 0 -1px 0 rgba(0,0,0,0.2);
  /* translateZ(0): forces own GPU composite layer from the start
     → eliminates layer-promotion flicker on hover/active transitions */
  transform:translateZ(0);
  will-change:border-radius, box-shadow;
  /* backdrop-filter REMOVED: it forces a new stacking context on every
     transition frame in Chrome/Windows → the gradient shadow flicker.
     The icons have solid bg when active so it's not needed visually. */
}}
.rail-icon:hover,.rail-icon.active{{border-radius:35%;transform:translateZ(0) scale(1.04)}}
.rail-icon.active{{
  background:var(--srv-color,hsl(230,60%,42%)) !important;
  color:#fff;
  border-top-color:rgba(255,255,255,0.28);
  border-left-color:rgba(255,255,255,0.16);
  box-shadow:0 6px 28px var(--srv-glow,rgba(88,101,242,0.55)),
             inset 0 1px 0 rgba(255,255,255,0.28),
             inset 0 -1px 0 rgba(0,0,0,0.18);
}}
.rail-icon:hover:not(.active){{
  background:rgba(255,255,255,0.10) !important;
  color:#fff;
  border-top-color:rgba(255,255,255,0.18);
  box-shadow:0 6px 24px rgba(88,101,242,0.28),
             inset 0 1px 0 rgba(255,255,255,0.15);
}}

/* pill lives in .rail-wrap (sibling of .rail-icon, outside overflow:hidden)
   so its gradient shadow never interacts with the icon's clip region */
.rail-pill{{
  position:absolute;left:-4px;top:50%;transform:translateY(-50%);
  width:4px;
  background:linear-gradient(to bottom, rgba(255,255,255,0.95), rgba(180,200,255,0.6));
  border-radius:0 4px 4px 0;
  box-shadow:0 0 14px rgba(255,255,255,0.6),2px 0 10px rgba(180,200,255,0.5);
  height:0;
  transition:height .22s cubic-bezier(.55,0,.1,1);
  pointer-events:none;
  z-index:10;
}}
.rail-wrap.active .rail-pill{{height:40px}}
.rail-wrap:hover .rail-pill{{height:20px}}
.rail-sep{{width:30px;height:1px;background:rgba(255,255,255,0.07);border-radius:1px;margin:4px 0;flex-shrink:0}}

/* rail tooltip */
.rail-icon[data-tip]::after{{
  content:attr(data-tip);
  position:absolute;left:72px;top:50%;transform:translateY(-50%);
  background:rgba(8,10,22,0.95);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  color:#fff;font-size:12px;font-weight:600;
  padding:8px 14px;border-radius:var(--r2);white-space:nowrap;
  z-index:300;pointer-events:none;opacity:0;
  border:1px solid rgba(255,255,255,0.12);
  box-shadow:0 8px 36px rgba(0,0,0,0.65),
             inset 0 1px 0 rgba(255,255,255,0.08);
  transition:opacity .12s;
}}
.rail-icon[data-tip]:hover::after{{opacity:1}}

/* ── SIDEBAR ──────────────────────────────── */
#sidebar{{
  width:280px;min-width:248px;
  background:rgba(8,10,22,0.72);
  backdrop-filter:blur(36px) saturate(1.3);
  -webkit-backdrop-filter:blur(36px) saturate(1.3);
  display:flex;flex-direction:column;overflow:hidden;
  border-right:1px solid rgba(255,255,255,0.07);
  box-shadow:inset -1px 0 0 rgba(0,0,0,0.3);
}}

/* search */
#sb-search{{padding:10px 8px 4px;flex-shrink:0}}
#sb-search input{{
  width:100%;height:36px;padding:0 14px;
  background:rgba(255,255,255,0.06);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border-radius:var(--r2);
  color:var(--text);font-family:var(--font);font-size:13px;outline:none;
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.4);
  border-right:1px solid rgba(0,0,0,0.25);
  transition:border-color .15s, background .15s;
}}
#sb-search input:focus{{
  border-top-color:rgba(88,101,242,0.7);
  background:rgba(255,255,255,0.09);
}}
#sb-search input::placeholder{{color:var(--muted)}}

/* ── FILTER BAR ──────────────────────────────── */
#sb-controls{{
  display:flex;align-items:center;gap:4px;
  padding:5px 8px 9px;flex-shrink:0;
  /* sunken trough */
  background:rgba(0,0,0,0.18);
  border-bottom:1px solid rgba(0,0,0,0.32);
  box-shadow:inset 0 2px 10px rgba(0,0,0,0.28),
             inset 0 -1px 0 rgba(255,255,255,0.03);
}}
.filt-btn{{
  flex:1;height:30px;font-size:10px;font-weight:800;
  font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;
  cursor:pointer;color:var(--muted);
  /* glass body with slight top-to-bottom gradient */
  background:linear-gradient(170deg,
    rgba(255,255,255,0.085) 0%,
    rgba(255,255,255,0.030) 100%);
  backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);
  border-radius:10px;
  /* bevel: bright top-left, dark bottom-right */
  border-top:1.5px solid rgba(255,255,255,0.16);
  border-left:1px   solid rgba(255,255,255,0.09);
  border-bottom:1.5px solid rgba(0,0,0,0.55);
  border-right:1px   solid rgba(0,0,0,0.35);
  /* outer lift + inner gloss */
  box-shadow:
    0 5px 18px rgba(0,0,0,0.52),
    0 1px  5px rgba(0,0,0,0.28),
    inset 0  1px 0 rgba(255,255,255,0.14),
    inset 0 -1px 0 rgba(0,0,0,0.18);
  transition:all .15s cubic-bezier(.4,0,.2,1);
  position:relative;
}}
.filt-btn:hover:not(.on){{
  color:var(--text2);
  background:linear-gradient(170deg,
    rgba(255,255,255,0.13) 0%,
    rgba(255,255,255,0.06) 100%);
  border-top-color:rgba(255,255,255,0.26);
  box-shadow:
    0 7px 24px rgba(0,0,0,0.58),
    0 2px  8px rgba(0,0,0,0.34),
    inset 0  1px 0 rgba(255,255,255,0.22),
    inset 0 -1px 0 rgba(0,0,0,0.14);
  transform:translateY(-1px);
}}
.filt-btn:active:not(.on){{
  transform:translateY(1px);
  box-shadow:
    0 2px  8px rgba(0,0,0,0.40),
    inset 0 2px 5px rgba(0,0,0,0.32),
    inset 0 1px 0 rgba(255,255,255,0.08);
}}
.filt-btn.on{{
  color:#fff;
  background:linear-gradient(158deg,
    rgba(112,126,255,1) 0%,
    rgba(88,101,242,1)  35%,
    rgba(72, 85,226,1)  65%,
    rgba(58, 70,208,1)  100%);
  border-top-color:rgba(255,255,255,0.38);
  border-left-color:rgba(255,255,255,0.22);
  border-bottom-color:rgba(0,0,0,0.62);
  border-right-color:rgba(0,0,0,0.42);
  box-shadow:
    0 8px 32px rgba(88,101,242,0.72),
    0 3px 12px rgba(0,0,0,0.55),
    0 0   0 1px rgba(88,101,242,0.32),
    inset 0  1.5px 0 rgba(255,255,255,0.42),
    inset 0 -2px   0 rgba(0,0,0,0.24);
  text-shadow:0 1px 6px rgba(0,0,0,0.45);
  transform:translateY(0);
  z-index:2;
}}

/* channel list */
#ch-list{{flex:1;overflow-y:auto;padding:6px 0}}
.ch-section{{
  padding:18px 8px 6px 12px;
  font-size:10px;font-weight:700;font-family:var(--mono);
  text-transform:uppercase;letter-spacing:.07em;color:var(--muted);
  display:flex;align-items:center;gap:4px;
}}
.ch-item{{
  display:flex;align-items:center;gap:10px;
  padding:7px 10px;cursor:pointer;
  border-radius:var(--r2);margin:2px 6px;
  transition:background .10s,border-color .10s;
  border:1px solid transparent;
  position:relative;
}}
.ch-item:hover{{
  background:rgba(255,255,255,0.07);
  border-color:rgba(255,255,255,0.07);
}}
.ch-item.sel{{
  background:rgba(255,255,255,0.09);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border-top:1px solid rgba(255,255,255,0.14);
  border-left:2px solid var(--accent);
  border-bottom:1px solid rgba(0,0,0,0.3);
  border-right:1px solid rgba(0,0,0,0.15);
  box-shadow:0 2px 16px rgba(0,0,0,0.3),
             inset 0 1px 0 rgba(255,255,255,0.08);
}}
.ch-item.sel .ch-name{{color:#fff;font-weight:600}}

.ch-av{{
  width:40px;height:40px;border-radius:50%;
  display:flex;align-items:center;justify-content:center;
  font-size:14px;flex-shrink:0;font-weight:800;
  color:#fff;position:relative;overflow:hidden;
  border-top:1px solid rgba(255,255,255,0.18);
  border-left:1px solid rgba(255,255,255,0.10);
  border-bottom:1px solid rgba(0,0,0,0.45);
  border-right:1px solid rgba(0,0,0,0.28);
  box-shadow:0 2px 10px rgba(0,0,0,0.4);
}}
.ch-av img{{width:100%;height:100%;object-fit:cover;position:absolute;inset:0}}

.ch-body{{flex:1;min-width:0}}
.ch-name{{
  font-size:14px;color:var(--text2);font-weight:500;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}}
.ch-sub{{
  font-size:11px;color:var(--muted);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  font-family:var(--mono);
}}
.ch-badge{{
  font-size:11px;font-family:var(--mono);font-weight:700;
  background:rgba(255,255,255,0.06);
  color:var(--muted);padding:3px 9px;
  border-radius:var(--r4);flex-shrink:0;
  border-top:1px solid rgba(255,255,255,0.10);
  border-left:1px solid rgba(255,255,255,0.06);
  border-bottom:1px solid rgba(0,0,0,0.4);
  border-right:1px solid rgba(0,0,0,0.25);
}}

/* ── USER PANEL ──────────────────────────── */
#user-panel{{
  padding:10px 10px;
  background:rgba(4,5,14,0.7);
  backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px);
  display:flex;align-items:center;gap:10px;
  border-top:1px solid rgba(255,255,255,0.07);
  flex-shrink:0;
}}
#u-av{{
  width:34px;height:34px;border-radius:50%;
  {av_css};background-size:cover;background-position:center;
  background-color:var(--accent);
  display:flex;align-items:center;justify-content:center;
  font-size:14px;font-weight:700;color:#fff;
  flex-shrink:0;position:relative;
  border-top:1px solid rgba(255,255,255,0.18);
  border-bottom:1px solid rgba(0,0,0,0.45);
  box-shadow:0 2px 10px rgba(0,0,0,0.4);
}}
#u-av::after{{
  content:'';position:absolute;bottom:-1px;right:-1px;
  width:11px;height:11px;border-radius:50%;
  background:var(--green);border:3px solid var(--bg0);
  box-shadow:0 0 6px rgba(35,165,89,0.5);
}}
#u-info{{flex:1;min-width:0}}
.u-name{{font-size:13px;font-weight:700;color:#fff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.u-tag {{font-size:11px;color:var(--muted);font-family:var(--mono)}}
#u-icons{{display:flex;gap:6px;flex-shrink:0}}
.u-ico{{font-size:16px;color:var(--muted);cursor:pointer;transition:color .1s;width:20px;text-align:center}}
.u-ico:hover{{color:var(--text)}}

/* ── MAIN ─────────────────────────────────── */
#main{{flex:1;display:flex;flex-direction:column;overflow:hidden;background:var(--bg3);position:relative;}}

/* ── HOME ─────────────────────────────────── */
#home{{flex:1;overflow-y:auto;display:flex;flex-direction:column;gap:0;
  /* prevent flex from squishing children — all content must be flex-shrink:0 */
  min-height:0;
}}

/* ── HERO ─────────────────────────────────── */
.hero{{
  padding:28px 28px 24px;
  background:linear-gradient(145deg,
    rgba(88,101,242,0.14) 0%,
    rgba(10,12,28,0.88) 60%,
    rgba(5,7,18,0.97) 100%);
  backdrop-filter:blur(32px) saturate(1.3);
  -webkit-backdrop-filter:blur(32px) saturate(1.3);
  border-bottom:1px solid rgba(255,255,255,0.08);
  border-radius:0 0 var(--r4) var(--r4);
  display:flex;gap:0;align-items:flex-start;
  box-shadow:0 12px 48px rgba(0,0,0,0.7),
             inset 0 1px 0 rgba(255,255,255,0.12);
  position:relative;overflow:visible;
  flex-shrink:0;
  min-height:170px;
}}
.hero::before{{
  content:'';position:absolute;inset:0;pointer-events:none;
  border-radius:0 0 var(--r4) var(--r4);
  overflow:hidden;
  background:
    radial-gradient(ellipse 70% 90% at 0% 0%, rgba(88,101,242,0.16) 0%, transparent 65%),
    radial-gradient(ellipse 50% 70% at 100% 100%, rgba(114,137,218,0.08) 0%, transparent 60%);
}}
.hero::after{{
  content:'';position:absolute;
  top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent 0%,rgba(255,255,255,0.18) 30%,rgba(255,255,255,0.22) 50%,rgba(255,255,255,0.18) 70%,transparent 100%);
}}
.hero-main{{
  display:flex;gap:18px;align-items:center;
  width:100%;position:relative;z-index:1;
}}
.hero-av{{
  width:108px;height:108px;border-radius:50%;
  {av_css};background-size:cover;background-position:center;
  background-color:var(--accent);
  display:flex;align-items:center;justify-content:center;
  font-size:36px;font-weight:800;color:#fff;
  flex-shrink:0;position:relative;
  border:3px solid rgba(255,255,255,0.12);
  outline:3px solid rgba(88,101,242,0.5);
  box-shadow:0 8px 40px rgba(88,101,242,0.4),
             0 4px 20px rgba(0,0,0,0.6),
             inset 0 1px 0 rgba(255,255,255,0.2);
}}
.hero-av::after{{
  content:'';position:absolute;bottom:3px;right:3px;
  width:18px;height:18px;border-radius:50%;
  background:var(--green);border:4px solid var(--bg0);
  box-shadow:0 0 10px rgba(35,165,89,0.6);
}}
.hero-info{{flex:1;min-width:0;padding-top:2px}}
.hero-name{{font-size:30px;font-weight:800;color:#fff;line-height:1;
  text-shadow:0 2px 20px rgba(88,101,242,0.3);}}
.hero-username{{font-size:14px;color:var(--muted);font-family:var(--mono);margin-top:4px}}

/* hero badges */
.hero-badges{{display:flex;flex-wrap:wrap;gap:5px;margin-top:10px;}}
.hbadge{{
  font-size:11px;font-weight:700;padding:4px 10px;
  border-radius:var(--r4);
  background:rgba(255,255,255,0.07);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  color:var(--text2);display:inline-flex;align-items:center;gap:5px;
  border-top:1px solid rgba(255,255,255,0.16);
  border-left:1px solid rgba(255,255,255,0.09);
  border-bottom:1px solid rgba(0,0,0,0.4);
  border-right:1px solid rgba(0,0,0,0.25);
  box-shadow:0 2px 12px rgba(0,0,0,0.4),
             inset 0 1px 0 rgba(255,255,255,0.10);
  cursor:default;
  letter-spacing:.01em;height:26px;
}}
.hbadge .badge-icon{{font-size:12px;flex-shrink:0;line-height:1}}
.hbadge .badge-text{{display:flex;flex-direction:row;align-items:center;gap:4px;line-height:1}}
.hbadge .badge-label{{font-size:11px;font-weight:600;opacity:0.75}}
.hbadge .badge-value{{font-size:11px;font-weight:700;font-family:var(--mono)}}

.hb-nitro{{
  background:rgba(88,101,242,0.20);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border-top-color:rgba(130,145,255,0.35);
  border-left-color:rgba(130,145,255,0.18);
  color:#c5caff;
  box-shadow:0 2px 16px rgba(88,101,242,0.25),inset 0 1px 0 rgba(255,255,255,0.12);
}}
.hb-mobile,.hb-phone{{
  background:rgba(35,165,89,0.18);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border-top-color:rgba(87,242,135,0.30);
  color:#7ee8a2;
  box-shadow:0 2px 14px rgba(35,165,89,0.2),inset 0 1px 0 rgba(255,255,255,0.10);
}}
.hb-discord{{
  background:rgba(114,137,218,0.18);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border-top-color:rgba(160,180,255,0.28);
  color:#aab4e8;
  box-shadow:0 2px 14px rgba(114,137,218,0.18),inset 0 1px 0 rgba(255,255,255,0.10);
}}
.hb-date{{
  background:rgba(255,255,255,0.06);
  border-top-color:rgba(255,255,255,0.14);
  color:var(--text2);
}}
.hb-hype{{
  background:rgba(240,178,50,0.18);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border-top-color:rgba(240,200,100,0.30);
  color:#f9d87e;
  box-shadow:0 2px 14px rgba(240,178,50,0.2),inset 0 1px 0 rgba(255,255,255,0.10);
}}

/* stat cards row */
.stats-row {{
  display:flex;flex-wrap:wrap;justify-content:center;
  align-items:center;gap:8px;padding:18px 20px 0;
  flex-shrink:0;
}}
.stats-row2 {{
  padding:10px 20px 0;
  display:flex;flex-wrap:wrap;gap:8px;justify-content:center;
  flex-shrink:0;
}}
.sec-title2 {{
  font-size:12px;font-weight:700;font-family:var(--mono);
  text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
  margin-bottom:10px;display:flex;align-items:center;gap:8px;width:100%;
}}
.sec-title2::after{{content:'';flex:1;height:1px;background:rgba(255,255,255,0.05)}}

/* top-tabs */
.top-tabs {{
  display:flex;gap:0;
  background:rgba(0,0,0,0.45);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  border-radius:100px;padding:3px;
  border:1px solid rgba(255,255,255,0.07);
}}
.top-tab {{
  font-size:11px;font-weight:700;font-family:var(--mono);
  letter-spacing:.03em;text-transform:uppercase;
  padding:6px 18px;border-radius:100px;
  color:var(--muted);background:transparent;border:none;
  cursor:pointer;transition:all .18s ease;
}}
.top-tab:hover:not(.on){{color:var(--text2);background:rgba(255,255,255,0.07);}}
.top-tab.on{{
  background:linear-gradient(135deg,rgba(88,101,242,0.9) 0%,rgba(71,82,196,0.95) 100%);
  color:#fff;
  box-shadow:0 2px 14px rgba(88,101,242,0.55),inset 0 1px 0 rgba(255,255,255,0.20);
}}

/* STAT CARD — full glassmorphism */
.stat-card {{
  background:rgba(255,255,255,0.06);
  backdrop-filter:blur(24px) saturate(1.2);
  -webkit-backdrop-filter:blur(24px) saturate(1.2);
  border-top:1px solid rgba(255,255,255,0.16);
  border-left:1px solid rgba(255,255,255,0.09);
  border-bottom:1px solid rgba(0,0,0,0.50);
  border-right:1px solid rgba(0,0,0,0.32);
  border-radius:var(--r2);
  padding:10px 17px;
  display:inline-flex;align-items:center;justify-content:center;gap:10px;
  transition:all .18s ease;
  width:fit-content;min-width:fit-content;flex-shrink:0;
  box-shadow:0 4px 20px rgba(0,0,0,0.45),
             inset 0 1px 0 rgba(255,255,255,0.10);
}}
.stat-card:hover {{
  background:rgba(255,255,255,0.10);
  border-top-color:rgba(255,255,255,0.22);
  box-shadow:0 8px 32px rgba(0,0,0,0.55),
             0 0 0 1px rgba(88,101,242,0.22),
             inset 0 1px 0 rgba(255,255,255,0.14);
  transform:translateY(-1px);
}}
.stat-card-ico {{font-size:22px;flex-shrink:0;line-height:1}}
.stat-card-body {{display:flex;flex-direction:column;align-items:center;gap:1px}}
.stat-card-num {{
  font-size:22px;font-weight:800;color:#fff;line-height:1.2;white-space:nowrap;
  text-shadow:0 1px 8px rgba(88,101,242,0.2);
}}
.stat-card-lbl {{
  font-size:12px;font-family:var(--mono);text-transform:uppercase;
  letter-spacing:.03em;color:var(--muted);white-space:nowrap;
}}

/* section */
.sec{{padding:16px 20px 0;flex-shrink:0;}}
.sec-title{{
  font-size:12px;font-weight:700;font-family:var(--mono);
  text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
  margin-bottom:14px;display:flex;align-items:center;gap:8px;
}}
.sec-title::after{{content:'';flex:1;height:1px;background:rgba(255,255,255,0.05)}}

/* SERVER CARD — glass */
.srv-grid{{display:flex;gap:10px}}
.srv-col{{flex:1;display:flex;flex-direction:column;gap:10px}}
.srv-card{{
  border-radius:var(--r3);
  padding:14px 16px;display:flex;align-items:center;gap:14px;
  background:rgba(255,255,255,0.06);
  backdrop-filter:blur(24px) saturate(1.2);
  -webkit-backdrop-filter:blur(24px) saturate(1.2);
  border-top:1px solid rgba(255,255,255,0.15);
  border-left:1px solid rgba(255,255,255,0.08);
  border-bottom:1px solid rgba(0,0,0,0.50);
  border-right:1px solid rgba(0,0,0,0.32);
  box-shadow:0 4px 24px rgba(0,0,0,0.50),
             inset 0 1px 0 rgba(255,255,255,0.10);
  transition:all .20s ease;cursor:pointer;
}}
.srv-card:hover{{
  background:rgba(255,255,255,0.10);
  border-top-color:rgba(255,255,255,0.22);
  box-shadow:0 8px 36px rgba(0,0,0,0.60),
             inset 0 1px 0 rgba(255,255,255,0.14);
  transform:translateY(-2px);
}}
.srv-card-ico{{
  width:46px;height:46px;border-radius:var(--r2);flex-shrink:0;
  display:flex;align-items:center;justify-content:center;
  font-size:18px;font-weight:800;color:#fff;
  border-top:1px solid rgba(255,255,255,0.22);
  border-bottom:1px solid rgba(0,0,0,0.4);
  box-shadow:0 3px 12px rgba(0,0,0,0.4),inset 0 1px 0 rgba(255,255,255,0.15);
}}
.srv-card-info{{flex:1;min-width:0}}
.srv-card-name{{font-size:14px;font-weight:700;color:#fff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.srv-card-msgs{{font-size:13px;color:var(--muted);font-family:var(--mono);margin-top:2px}}
.srv-card-bar{{height:3px;background:rgba(255,255,255,0.08);border-radius:4px;margin-top:8px;overflow:hidden}}
.srv-card-bar-fill{{height:100%;border-radius:4px;background:var(--accent);
  box-shadow:0 0 8px rgba(88,101,242,0.5);}}

/* top DMs — glass */
.dm-list{{display:flex;gap:10px}}
.dm-col{{flex:1;display:flex;flex-direction:column;gap:10px}}
.dm-row{{
  display:flex;align-items:center;gap:14px;
  padding:14px 16px;
  background:rgba(255,255,255,0.05);
  backdrop-filter:blur(20px) saturate(1.2);
  -webkit-backdrop-filter:blur(20px) saturate(1.2);
  border-top:1px solid rgba(255,255,255,0.14);
  border-left:1px solid rgba(255,255,255,0.08);
  border-bottom:1px solid rgba(0,0,0,0.48);
  border-right:1px solid rgba(0,0,0,0.30);
  border-radius:var(--r3);
  box-shadow:0 4px 20px rgba(0,0,0,0.45),
             inset 0 1px 0 rgba(255,255,255,0.09);
  transition:all .18s;cursor:pointer;min-width:0;
}}
.dm-row:hover{{
  background:rgba(255,255,255,0.09);
  border-top-color:rgba(255,255,255,0.20);
  border-left-color:rgba(88,101,242,0.45);
  box-shadow:0 8px 32px rgba(0,0,0,0.55),
             inset 0 1px 0 rgba(255,255,255,0.12);
  transform:translateY(-1px);
}}
.dm-rank{{width:22px;text-align:center;font-size:15px;flex-shrink:0}}
.dm-av{{
  width:46px;height:46px;border-radius:var(--r2);flex-shrink:0;
  display:flex;align-items:center;justify-content:center;
  font-size:18px;font-weight:800;color:#fff;
  border-top:1px solid rgba(255,255,255,0.22);
  border-bottom:1px solid rgba(0,0,0,0.45);
  box-shadow:0 3px 12px rgba(0,0,0,0.45);
}}
.dm-info{{flex:1;min-width:0}}
.dm-name{{font-size:14px;font-weight:700;color:#fff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.dm-msgs{{font-size:13px;color:var(--muted);font-family:var(--mono);margin-top:2px}}
.dm-bar-wrap{{width:100%;height:3px;background:rgba(255,255,255,0.08);border-radius:4px;overflow:hidden;margin-top:7px}}
.dm-bar{{height:100%;border-radius:4px;box-shadow:0 0 6px rgba(88,101,242,0.4);}}

/* chart canvas */
canvas {{
  display:block;width:100% !important;height:140px !important;
  border-radius:var(--r2);
}}

/* Emoji row — glass chips */
.emoji-row{{display:flex;flex-wrap:wrap;gap:8px}}
.emoji-item{{
  display:flex;flex-direction:column;align-items:center;gap:4px;
  background:rgba(255,255,255,0.06);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border-top:1px solid rgba(255,255,255,0.15);
  border-left:1px solid rgba(255,255,255,0.08);
  border-bottom:1px solid rgba(0,0,0,0.42);
  border-right:1px solid rgba(0,0,0,0.26);
  border-radius:var(--r2);padding:10px 14px;
  min-width:54px;
  box-shadow:0 3px 14px rgba(0,0,0,0.45),
             inset 0 1px 0 rgba(255,255,255,0.09);
  transition:all .16s;cursor:default;
}}
.emoji-item:hover{{
  background:rgba(255,255,255,0.11);
  border-top-color:rgba(88,101,242,0.5);
  box-shadow:0 6px 24px rgba(88,101,242,0.18),
             inset 0 1px 0 rgba(255,255,255,0.12);
  transform:translateY(-2px) scale(1.04);
}}
.emoji-glyph{{font-size:28px;line-height:1}}
.emoji-cnt{{font-size:10px;font-family:var(--mono);color:var(--muted)}}

/* Word Cloud — deep glass panel */
.wordcloud{{
  position:relative;
  background:rgba(255,255,255,0.04);
  backdrop-filter:blur(32px) saturate(1.2);
  -webkit-backdrop-filter:blur(32px) saturate(1.2);
  border-top:1px solid rgba(255,255,255,0.14);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.50);
  border-right:1px solid rgba(0,0,0,0.30);
  border-radius:var(--r3);padding:28px 28px 24px;
  display:flex;flex-wrap:wrap;align-items:center;justify-content:center;
  gap:6px 10px;overflow:hidden;
  box-shadow:0 8px 48px rgba(0,0,0,0.60),
             inset 0 1px 0 rgba(255,255,255,0.10);
}}
.wordcloud::before{{
  content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse at 50% 50%,rgba(88,101,242,0.07) 0%,transparent 75%);
  pointer-events:none;
}}
.wc-word{{
  cursor:default;line-height:1.3;font-weight:700;
  transition:opacity .15s,transform .18s,color .15s,text-shadow .18s;
  white-space:nowrap;padding:2px 4px;border-radius:4px;
}}
.wc-word:hover{{
  opacity:1!important;transform:scale(1.14);
  background:rgba(255,255,255,0.07);
  text-shadow:0 0 24px currentColor,0 0 40px currentColor;
}}

/* ── MESSAGE SEARCH BAR ───────────────────── */
#msg-search-bar{{
  position:absolute;top:0;bottom:0;right:0;
  display:flex;align-items:center;gap:6px;padding:0 10px;
  background:rgba(8,10,22,0.85);
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  border-left:1px solid rgba(255,255,255,0.07);
  border-radius:0 0 0 var(--r2);z-index:10;
  width:0;overflow:hidden;opacity:0;
  transition:width .22s cubic-bezier(.4,0,.2,1),opacity .18s ease;
  pointer-events:none;
}}
#msg-search-bar.visible{{
  width:min(420px,62%);opacity:1;pointer-events:all;
}}
#msg-srch{{
  flex:1;min-width:0;height:30px;padding:0 10px;
  background:rgba(255,255,255,0.08);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border-radius:var(--r);color:var(--text);
  font-family:var(--font);font-size:13px;outline:none;
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.40);
  border-right:1px solid rgba(0,0,0,0.25);
  transition:border-color .15s,background .15s;
  white-space:nowrap;
}}
#msg-srch:focus{{border-top-color:rgba(88,101,242,0.8);background:rgba(255,255,255,0.11)}}
#msg-srch::placeholder{{color:var(--muted)}}
#msg-srch-count{{font-size:10px;font-family:var(--mono);color:var(--muted);white-space:nowrap;flex-shrink:0;min-width:44px;text-align:right}}
#msg-srch-nav{{display:flex;gap:2px;flex-shrink:0}}
.srch-nav-btn{{
  width:24px;height:24px;border-radius:var(--r);
  background:rgba(255,255,255,0.07);
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.40);
  border-right:1px solid rgba(0,0,0,0.25);
  color:var(--muted);font-size:12px;display:flex;align-items:center;justify-content:center;
  transition:all .12s;
}}
.srch-nav-btn:hover{{background:rgba(88,101,242,0.8);color:#fff;border-color:transparent;
  box-shadow:0 2px 10px rgba(88,101,242,0.4);}}
.srch-close-btn{{
  width:24px;height:24px;border-radius:50%;
  background:transparent;border:none;color:var(--muted);font-size:14px;
  display:flex;align-items:center;justify-content:center;
  flex-shrink:0;transition:color .1s,background .1s;
}}
.srch-close-btn:hover{{color:#fff;background:rgba(255,255,255,0.10)}}
mark.hl{{
  background:rgba(88,101,242,0.25);color:#d0d5ff;
  border-radius:3px;padding:1px 3px;font-style:normal;
  box-shadow:0 0 0 1px rgba(88,101,242,0.32);
  transition:background .15s,box-shadow .15s;
}}
mark.hl.cur{{
  background:linear-gradient(135deg,rgba(88,101,242,0.95) 0%,rgba(114,137,218,0.9) 100%);
  color:#fff;
  box-shadow:0 0 0 1.5px rgba(140,155,255,0.8),0 2px 10px rgba(88,101,242,0.55);
}}

/* ── CHANNEL HEADER ──────────────────────── */
#ch-hdr{{
  height:56px;min-height:56px;padding:0 18px;
  display:flex;align-items:center;gap:10px;position:relative;overflow:hidden;
  border-bottom:1px solid rgba(0,0,0,0.40);
  background:rgba(10,12,26,0.65);
  backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px);
  flex-shrink:0;
  box-shadow:0 1px 0 rgba(255,255,255,0.05),
             0 4px 20px rgba(0,0,0,0.3);
}}
.hdr-ico{{font-size:20px;color:var(--muted);flex-shrink:0}}
.hdr-name{{font-size:17px;font-weight:700;color:#fff}}
.hdr-sep{{color:var(--faint);font-size:13px;margin:0 4px}}
.hdr-srv{{font-size:13px;color:var(--muted)}}
.hdr-cnt{{
  font-size:12px;font-family:var(--mono);
  color:var(--text2);
  background:rgba(255,255,255,0.07);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  padding:4px 12px;border-radius:var(--r4);
  border-top:1px solid rgba(255,255,255,0.13);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.42);
  border-right:1px solid rgba(0,0,0,0.26);
  box-shadow:0 2px 8px rgba(0,0,0,0.3);
  cursor:default;
}}
#hdr-srch-btn{{margin-left:auto}}

/* ── CUSTOM DATE RANGE PICKER ────────────── */
#date-range-picker{{
  display:none;
  position:absolute;
  top:60px;
  left:50%;
  transform:translateX(-50%);
  z-index:200;
  background:rgba(10,12,26,0.97);
  backdrop-filter:blur(40px) saturate(1.4);
  -webkit-backdrop-filter:blur(40px) saturate(1.4);
  border-top:1px solid rgba(255,255,255,0.14);
  border-left:1px solid rgba(255,255,255,0.09);
  border-bottom:1px solid rgba(0,0,0,0.60);
  border-right:1px solid rgba(0,0,0,0.40);
  border-radius:var(--r3);
  box-shadow:0 24px 64px rgba(0,0,0,0.80),
             inset 0 1px 0 rgba(255,255,255,0.10);
  padding:0;
  width:640px;
  max-width:96vw;
  overflow:hidden;
  user-select:none;
}}
#date-range-picker.visible{{display:block}}
/* top bar */
.drp-bar{{
  display:flex;align-items:center;gap:8px;
  padding:10px 16px;
  background:rgba(255,255,255,0.04);
  border-bottom:1px solid rgba(255,255,255,0.07);
}}
.drp-field{{
  flex:1;display:flex;align-items:center;gap:8px;
  background:rgba(255,255,255,0.07);
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.40);
  border-right:1px solid rgba(0,0,0,0.25);
  border-radius:var(--r2);
  padding:6px 12px;
  cursor:pointer;
  transition:border-color .15s,background .15s;
}}
.drp-field.focus{{
  border-top-color:rgba(88,101,242,0.8);
  background:rgba(88,101,242,0.10);
}}
.drp-field-ico{{font-size:13px;color:var(--muted)}}
.drp-field-val{{
  font-size:12px;font-family:var(--mono);color:var(--text);
  min-width:80px;
}}
.drp-field-val.empty{{color:var(--muted)}}
.drp-sep{{font-size:14px;color:var(--faint);flex-shrink:0}}
.drp-bar-actions{{display:flex;gap:6px;margin-left:4px;flex-shrink:0}}
.drp-apply{{
  height:32px;padding:0 16px;
  background:linear-gradient(145deg,rgba(88,101,242,0.92) 0%,rgba(71,82,196,0.97) 100%);
  border-top:1px solid rgba(255,255,255,0.22);
  border-left:1px solid rgba(255,255,255,0.12);
  border-bottom:1px solid rgba(0,0,0,0.40);
  border-right:1px solid rgba(0,0,0,0.28);
  border-radius:var(--r4);
  font-size:12px;font-weight:700;font-family:var(--mono);
  color:#fff;cursor:pointer;
  box-shadow:0 2px 14px rgba(88,101,242,0.45),inset 0 1px 0 rgba(255,255,255,0.20);
  transition:all .15s;
}}
.drp-apply:hover{{
  box-shadow:0 4px 20px rgba(88,101,242,0.65),inset 0 1px 0 rgba(255,255,255,0.25);
  transform:translateY(-1px);
}}
.drp-clear{{
  height:32px;padding:0 14px;
  background:rgba(255,255,255,0.06);
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.40);
  border-right:1px solid rgba(0,0,0,0.25);
  border-radius:var(--r4);
  font-size:12px;font-weight:600;font-family:var(--mono);
  color:var(--muted);cursor:pointer;transition:all .15s;
}}
.drp-clear:hover{{background:rgba(255,255,255,0.12);color:var(--text)}}
/* calendars row */
.drp-cals{{
  display:flex;gap:0;
}}
.drp-cal{{
  flex:1;padding:16px;
}}
.drp-cal+.drp-cal{{
  border-left:1px solid rgba(255,255,255,0.06);
}}
.drp-cal-head{{
  display:flex;align-items:center;justify-content:space-between;
  margin-bottom:14px;
}}
.drp-cal-title{{
  font-size:13px;font-weight:700;color:#fff;
  cursor:pointer;
  transition:color .12s;
}}
.drp-cal-title:hover{{color:var(--accent3)}}
.drp-nav{{
  width:28px;height:28px;border-radius:50%;
  background:rgba(255,255,255,0.06);
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.40);
  border-right:1px solid rgba(0,0,0,0.25);
  color:var(--muted);font-size:13px;
  display:flex;align-items:center;justify-content:center;
  cursor:pointer;transition:all .12s;
  line-height:1;
}}
.drp-nav:hover{{
  background:rgba(88,101,242,0.80);color:#fff;
  border-top-color:rgba(255,255,255,0.22);
  box-shadow:0 2px 10px rgba(88,101,242,0.4);
}}
.drp-nav.ghost{{visibility:hidden}}
/* weekday header */
.drp-weekdays{{
  display:grid;grid-template-columns:repeat(7,1fr);
  margin-bottom:6px;
}}
.drp-wd{{
  text-align:center;font-size:10px;font-weight:700;
  font-family:var(--mono);color:var(--muted);
  letter-spacing:.05em;padding:4px 0;
}}
/* day grid */
.drp-days{{
  display:grid;grid-template-columns:repeat(7,1fr);
  gap:2px;
}}
.drp-day{{
  position:relative;
  aspect-ratio:1;
  display:flex;align-items:center;justify-content:center;
  font-size:12px;font-weight:500;color:var(--text2);
  border-radius:50%;
  cursor:pointer;
  transition:background .10s,color .10s;
  z-index:1;
}}
.drp-day:hover:not(.empty):not(.other-month){{
  background:rgba(88,101,242,0.35);color:#fff;
}}
.drp-day.other-month{{color:var(--faint);cursor:default}}
.drp-day.empty{{pointer-events:none}}
.drp-day.today{{
  color:var(--accent3);font-weight:700;
}}
.drp-day.today::after{{
  content:'';position:absolute;bottom:3px;left:50%;
  transform:translateX(-50%);
  width:4px;height:4px;border-radius:50%;
  background:var(--accent3);
}}
.drp-day.sel-start,.drp-day.sel-end{{
  background:linear-gradient(135deg,rgba(88,101,242,0.95) 0%,rgba(71,82,196,1) 100%) !important;
  color:#fff !important;font-weight:700;
  box-shadow:0 2px 14px rgba(88,101,242,0.55);
  border-radius:50%;
  z-index:2;
}}
.drp-day.in-range{{
  background:rgba(88,101,242,0.15);
  border-radius:0;
  color:var(--text);
}}
.drp-day.in-range.range-row-start{{border-radius:50% 0 0 50%}}
.drp-day.in-range.range-row-end{{border-radius:0 50% 50% 0}}
.drp-day.sel-start.has-end{{border-radius:50% 0 0 50%}}
.drp-day.sel-end.has-start{{border-radius:0 50% 50% 0}}
/* footer */
.drp-footer{{
  display:flex;align-items:center;justify-content:space-between;
  padding:10px 16px;
  border-top:1px solid rgba(255,255,255,0.06);
  background:rgba(0,0,0,0.18);
}}
.drp-hint{{
  font-size:11px;font-family:var(--mono);color:var(--faint);
}}
.drp-shortcut-row{{
  display:flex;gap:6px;
}}
.drp-shortcut{{
  font-size:10px;font-family:var(--mono);font-weight:600;
  padding:4px 10px;border-radius:100px;
  background:rgba(255,255,255,0.06);
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.38);
  border-right:1px solid rgba(0,0,0,0.22);
  color:var(--muted);cursor:pointer;transition:all .12s;
}}
.drp-shortcut:hover{{background:rgba(88,101,242,0.22);color:var(--accent3);border-top-color:rgba(88,101,242,0.45);}}

/* ── MESSAGES ─────────────────────────────── */
#msgs{{
  flex:1;overflow-y:auto;display:flex;flex-direction:column;
  padding:8px 0 4px;
}}
#msgs::-webkit-scrollbar{{width:6px}}

.date-sep{{
  display:flex;align-items:center;gap:12px;
  padding:12px 16px;font-size:12px;font-weight:600;
  color:var(--muted);font-family:var(--mono);user-select:none;
}}
.date-sep::before,.date-sep::after{{
  content:'';flex:1;height:1px;
  background:linear-gradient(90deg,rgba(255,255,255,0.04),rgba(255,255,255,0.08),rgba(255,255,255,0.04));
}}

/* message group */
.msg-group{{padding:2px 0;position:relative}}
.msg{{
  display:flex;gap:16px;padding:2px 16px;
  transition:background .08s;position:relative;
}}
.msg:hover{{background:rgba(255,255,255,0.026)}}

/* glass accent stripe on hover for continuation messages */
.msg.cont:hover{{background:rgba(255,255,255,0.026)}}
.msg.cont:hover::before{{
  content:'';
  position:absolute;left:0;top:0;bottom:0;
  width:2px;
  background:linear-gradient(180deg,transparent 0%,rgba(88,101,242,0.55) 50%,transparent 100%);
  border-radius:0 2px 2px 0;
  pointer-events:none;
}}

/* Opening message — glass bubble treatment */
.msg:not(.cont):hover .msg-body::before{{
  content:'';
  position:absolute;inset:-2px -2px -2px 44px;
  background:rgba(255,255,255,0.025);
  backdrop-filter:blur(4px);
  border-radius:var(--r2);
  border-top:1px solid rgba(255,255,255,0.07);
  pointer-events:none;
  z-index:-1;
}}
.msg:not(.cont) .msg-body{{position:relative}}

.msg-av-col{{width:48px;flex-shrink:0}}
.msg-av{{
  width:44px;height:44px;border-radius:50%;
  {av_static_css};background-size:cover;background-position:center;
  background-color:var(--accent);
  display:flex;align-items:center;justify-content:center;
  font-size:16px;font-weight:700;color:#fff;
  flex-shrink:0;margin-top:1px;
  border-top:1px solid rgba(255,255,255,0.18);
  border-bottom:1px solid rgba(0,0,0,0.45);
  box-shadow:0 3px 14px rgba(0,0,0,0.45);
  transition:transform .18s ease,box-shadow .18s ease;
}}
.msg:hover .msg-av.has-gif{{
  background-image:url("{avatar_b64}") !important;
  transform:scale(1.06);
  box-shadow:0 4px 18px rgba(88,101,242,0.3);
}}
.msg.cont{{padding-top:1px}}
.msg.cont .msg-av{{visibility:hidden;height:0;margin:0}}
.msg.cont .msg-av-col{{padding-top:0}}

.msg-ts-hover{{
  position:absolute;left:0;top:50%;transform:translateY(-50%);
  width:56px;text-align:right;padding-right:8px;
  font-size:10px;font-family:var(--mono);color:var(--muted);
  opacity:0;transition:opacity .1s;pointer-events:none;user-select:none;
}}

.msg-body{{flex:1;min-width:0}}
.msg-header{{display:flex;align-items:baseline;gap:8px;margin-bottom:3px}}
.msg-author{{font-size:16px;font-weight:600;color:var(--blurple);line-height:1}}
.msg-ts{{font-size:13px;color:var(--muted);font-family:var(--mono)}}

/* Message content — high contrast */
.msg-content{{
  font-size:16px;line-height:1.48;color:var(--text);
  word-break:break-word;white-space:pre-wrap;
  user-select:text;-webkit-user-select:text;
}}
/* custom selection — blurple glow, matches Discord aesthetic */
.msg-content ::selection,
.msg-content::selection{{
  background:rgba(88,101,242,0.45);
  color:#fff;
  text-shadow:0 0 12px rgba(88,101,242,0.7);
}}

/* ── ATTACHMENTS ─────────────────────────── */
.att-img{{
  display:inline-block;margin-top:8px;
  max-width:560px;border-radius:var(--r3);overflow:hidden;
  background:rgba(0,0,0,0.3);cursor:zoom-in;
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.5);
  border-right:1px solid rgba(0,0,0,0.3);
  box-shadow:0 4px 20px rgba(0,0,0,0.5);
  transition:box-shadow .15s,transform .15s;
}}
.att-img:hover{{
  box-shadow:0 8px 32px rgba(0,0,0,0.65);
  transform:scale(1.005);
}}
.att-img img{{display:block;max-width:100%;max-height:400px;object-fit:contain}}

/* ── EXPIRED / 404 ATTACHMENT PLACEHOLDER ── */
.att-expired-ph{{
  display:inline-flex;flex-direction:column;
  align-items:center;justify-content:center;gap:5px;
  padding:18px 28px;min-width:150px;
  border-radius:var(--r2);
  background:rgba(255,255,255,0.03);
  border:1px dashed rgba(255,255,255,0.14);
  color:var(--muted);text-decoration:none;
  cursor:pointer;transition:background .14s,border-color .14s,color .14s;
  text-align:center;
}}
.att-expired-ph:hover{{
  background:rgba(255,255,255,0.07);
  border-color:rgba(255,255,255,0.26);
  color:var(--text2);
  text-decoration:none;
}}
.att-exp-ico{{font-size:26px;line-height:1;opacity:.55}}
.att-exp-name{{
  font-size:11px;font-family:var(--mono);color:var(--text2);
  max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}}
.att-exp-lbl{{
  font-size:10px;font-family:var(--mono);
  color:var(--muted);letter-spacing:.04em;
}}

.att-file{{
  display:inline-flex;align-items:center;gap:10px;margin-top:6px;
  padding:10px 16px;
  background:rgba(255,255,255,0.06);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  border-top:1px solid rgba(255,255,255,0.13);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.45);
  border-right:1px solid rgba(0,0,0,0.28);
  border-radius:var(--r2);
  font-size:13px;font-family:var(--mono);color:var(--accent3);max-width:420px;
  text-decoration:none;
  box-shadow:0 3px 14px rgba(0,0,0,0.4);
  transition:all .15s;
}}
.att-file:hover{{
  background:rgba(255,255,255,0.10);
  border-top-color:rgba(88,101,242,0.5);
  color:var(--accent3);
  box-shadow:0 5px 20px rgba(0,0,0,0.5);
}}

/* ── CUSTOM AUDIO PLAYER ──────────────────── */
.att-voice{{
  display:inline-flex;align-items:center;gap:10px;margin-top:8px;
  padding:10px 14px;
  background:rgba(255,255,255,0.06);
  backdrop-filter:blur(24px) saturate(1.2);
  -webkit-backdrop-filter:blur(24px) saturate(1.2);
  border-top:1px solid rgba(255,255,255,0.15);
  border-left:1px solid rgba(255,255,255,0.09);
  border-bottom:1px solid rgba(0,0,0,0.48);
  border-right:1px solid rgba(0,0,0,0.30);
  border-radius:30px;
  max-width:420px;width:100%;
  box-shadow:0 4px 20px rgba(0,0,0,0.45),
             inset 0 1px 0 rgba(255,255,255,0.09);
  transition:all .18s;
}}
.att-voice:hover{{
  background:rgba(255,255,255,0.09);
  border-top-color:rgba(88,101,242,0.45);
  box-shadow:0 6px 28px rgba(88,101,242,0.20),
             inset 0 1px 0 rgba(255,255,255,0.12);
}}
.att-voice-ico{{font-size:22px;flex-shrink:0;line-height:1;color:var(--accent3);
  filter:drop-shadow(0 2px 6px rgba(88,101,242,0.4));}}
.aud-play-btn{{
  width:34px;height:34px;border-radius:50%;flex-shrink:0;
  background:linear-gradient(145deg,rgba(88,101,242,0.90) 0%,rgba(71,82,196,0.95) 100%);
  border-top:1px solid rgba(255,255,255,0.22);
  border-left:1px solid rgba(255,255,255,0.12);
  border-bottom:1px solid rgba(0,0,0,0.35);
  border-right:1px solid rgba(0,0,0,0.22);
  color:#fff;font-size:13px;
  display:flex;align-items:center;justify-content:center;
  cursor:pointer;padding-left:2px;
  box-shadow:0 3px 14px rgba(88,101,242,0.50),
             inset 0 1px 0 rgba(255,255,255,0.22);
  transition:all .14s;
}}
.aud-play-btn:hover{{transform:scale(1.08);
  box-shadow:0 5px 20px rgba(88,101,242,0.65),inset 0 1px 0 rgba(255,255,255,0.25);}}
.aud-play-btn:active{{transform:scale(0.93)}}
.aud-progress-wrap{{
  flex:1;min-width:0;height:4px;
  background:rgba(255,255,255,0.10);
  border-radius:4px;position:relative;cursor:pointer;overflow:visible;
}}
.aud-progress-fill{{
  position:absolute;left:0;top:0;bottom:0;width:0%;
  background:linear-gradient(90deg,var(--accent),var(--pink));
  border-radius:4px;
  box-shadow:0 0 8px rgba(88,101,242,0.4);
  transition:width .1s linear;pointer-events:none;
}}
.aud-progress-thumb{{
  position:absolute;top:50%;left:0%;
  transform:translate(-50%,-50%) scale(0);
  width:13px;height:13px;border-radius:50%;
  background:#fff;box-shadow:0 0 6px rgba(0,0,0,0.5);
  pointer-events:none;transition:transform .12s;
}}
.att-voice:hover .aud-progress-thumb{{transform:translate(-50%,-50%) scale(1)}}
.aud-time{{
  font-size:11px;font-family:var(--mono);color:var(--muted);
  flex-shrink:0;min-width:36px;text-align:right;
}}
.aud-vol-wrap{{
  display:flex;align-items:center;gap:5px;
  overflow:hidden;max-width:0;opacity:0;
  transition:max-width .22s ease,opacity .18s ease;flex-shrink:0;
}}
.att-voice:hover .aud-vol-wrap{{max-width:90px;opacity:1}}
.aud-vol-btn{{
  background:none;border:none;color:var(--muted);font-size:14px;
  cursor:pointer;padding:0;flex-shrink:0;line-height:1;
  transition:color .12s;width:18px;text-align:center;
}}
.aud-vol-btn:hover{{color:var(--text)}}
.aud-vol-slider{{
  -webkit-appearance:none;
  width:60px;height:3px;border-radius:3px;
  background:linear-gradient(to right,var(--accent) 0%,var(--accent) var(--avol,100%),rgba(255,255,255,0.18) var(--avol,100%),rgba(255,255,255,0.18) 100%);
  outline:none;cursor:pointer;flex-shrink:0;
}}
.aud-vol-slider::-webkit-slider-thumb{{
  -webkit-appearance:none;width:11px;height:11px;border-radius:50%;
  background:#fff;cursor:pointer;box-shadow:0 0 4px rgba(0,0,0,0.5);
}}
.aud-vol-slider::-moz-range-thumb{{
  width:11px;height:11px;border-radius:50%;border:none;
  background:#fff;cursor:pointer;
}}
.aud-vol-slider::-moz-range-progress{{
  background:var(--accent);height:3px;border-radius:3px;
}}

/* Video volume slider fill */
.vid-slider{{
  background:linear-gradient(to right,rgba(255,255,255,.85) 0%,rgba(255,255,255,.85) var(--vol-pct,100%),rgba(255,255,255,.20) var(--vol-pct,100%),rgba(255,255,255,.20) 100%);
}}

/* tenor GIF embed */
.att-tenor{{
  display:inline-block;margin-top:8px;
  max-width:420px;border-radius:var(--r3);overflow:hidden;
  background:rgba(0,0,0,0.4);
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.5);
  border-right:1px solid rgba(0,0,0,0.32);
  cursor:default;position:relative;
  box-shadow:0 4px 20px rgba(0,0,0,0.5);
  user-select:none;-webkit-user-select:none;
}}
.att-tenor iframe{{display:block;width:420px;max-width:100%;height:280px;border:0;pointer-events:none}}
.att-tenor-thumb{{
  position:absolute;inset:0;
  background-size:cover;background-position:center;
  transition:opacity .3s ease;pointer-events:none;z-index:2;
}}
.att-tenor.loaded .att-tenor-thumb{{opacity:0}}
.att-tenor-overlay{{
  position:absolute;inset:0;
  display:flex;align-items:center;justify-content:center;
  background:rgba(0,0,0,0.25);
  opacity:1;transition:opacity .2s;pointer-events:none;z-index:3;
}}
.att-tenor:hover .att-tenor-overlay{{opacity:0}}
.att-tenor.loaded .att-tenor-overlay{{display:none}}
.att-tenor-play-icon{{
  display:flex;align-items:center;justify-content:center;
  width:56px;height:28px;
  filter:drop-shadow(0 2px 12px rgba(0,0,0,0.85));
  transition:transform .18s ease;
  border-radius:6px;
}}
.att-tenor:hover .att-tenor-play-icon{{transform:scale(1.12)}}
.att-tenor-lbl{{
  font-size:10px;font-family:var(--mono);font-weight:700;
  text-transform:uppercase;letter-spacing:.06em;
  color:rgba(255,255,255,.7);
  background:rgba(0,0,0,.45);padding:2px 7px;border-radius:4px;
}}

/* ── NAV AREA ─────────────────────────────── */
#nav-area {{
  display:flex;flex-direction:column;align-items:stretch;padding:0;
  background:rgba(6,8,20,0.85);
  backdrop-filter:blur(28px) saturate(1.2);
  -webkit-backdrop-filter:blur(28px) saturate(1.2);
  border-top:1px solid rgba(255,255,255,0.07);
  position:sticky;bottom:0;z-index:100;
  box-shadow:0 -4px 32px rgba(0,0,0,0.5),
             inset 0 1px 0 rgba(255,255,255,0.05);
}}
#nav-progress{{display:none;flex-direction:column;gap:2px;padding:5px 16px 3px}}
#nav-progress.active{{display:flex}}
#nav-progress-bar{{height:2px;background:rgba(255,255,255,0.07);border-radius:2px;overflow:hidden}}
#nav-progress-fill{{
  height:100%;border-radius:2px;
  background:linear-gradient(90deg,var(--accent),var(--accent3));
  box-shadow:0 0 6px rgba(88,101,242,0.6);
  transition:width .1s linear;width:0%;
}}
#nav-progress-lbl{{font-size:9px;font-family:var(--mono);letter-spacing:.05em;color:var(--faint);text-align:right;line-height:1}}
#nav-buttons {{
  display:flex;align-items:center;justify-content:space-between;
  padding:11px 14px;gap:8px;
}}
#btm-load-all-btn {{
  display:none;align-items:center;gap:6px;
  background:rgba(88,101,242,0.14) !important;
  color:#aab4e8 !important;
  border-top:1px solid rgba(130,145,255,0.28) !important;
  border-left:1px solid rgba(130,145,255,0.16) !important;
  border-bottom:1px solid rgba(0,0,0,0.35) !important;
  border-right:1px solid rgba(0,0,0,0.22) !important;
  font-family:var(--mono) !important;font-size:11px !important;
  font-weight:700 !important;letter-spacing:.04em !important;
  text-transform:uppercase !important;
  padding:6px 18px !important;border-radius:100px !important;
  cursor:pointer;transition:all .18s ease !important;
  box-shadow:none !important;white-space:nowrap;
  backdrop-filter:blur(12px) !important;
}}
#btm-load-all-btn:hover {{
  background:rgba(88,101,242,0.35) !important;color:#fff !important;
  border-top-color:rgba(130,145,255,0.55) !important;
  box-shadow:0 0 18px rgba(88,101,242,0.3) !important;
}}
.btn-nav {{
  display:inline-flex;align-items:center;justify-content:center;gap:5px;
  height:30px;padding:0 12px !important;border-radius:8px;
  background:rgba(255,255,255,0.06) !important;
  border-top:1px solid rgba(255,255,255,0.12) !important;
  border-left:1px solid rgba(255,255,255,0.07) !important;
  border-bottom:1px solid rgba(0,0,0,0.42) !important;
  border-right:1px solid rgba(0,0,0,0.26) !important;
  color:var(--muted) !important;font-size:12px !important;
  font-family:var(--mono);font-weight:600;letter-spacing:.02em;
  cursor:pointer;transition:all .14s !important;
  flex-shrink:0;white-space:nowrap;user-select:none;
  backdrop-filter:blur(8px) !important;
}}
.btn-nav .nav-arrow{{font-size:14px;line-height:1;flex-shrink:0}}
.btn-nav:hover {{
  background:rgba(88,101,242,0.22) !important;
  border-top-color:rgba(130,145,255,0.45) !important;
  color:#c5caff !important;
  box-shadow:none !important;
}}
.btn-nav:active {{background:rgba(88,101,242,0.40) !important;transform:scale(0.96) !important;}}
.btn-nav:disabled {{opacity:0.3 !important;cursor:not-allowed !important;}}
.nav-group {{display:flex;gap:6px}}
.nav-lbl {{font-size:11px;font-weight:600;letter-spacing:.02em;font-family:var(--mono)}}
#load-area {{display:none !important}}
.load-main-btn {{display:none}}

/* context menu */
#ctx-menu{{
  position:fixed;z-index:9998;
  background:rgba(10,12,26,0.96);
  backdrop-filter:blur(32px) saturate(1.4);
  -webkit-backdrop-filter:blur(32px) saturate(1.4);
  border-top:1px solid rgba(255,255,255,0.14);
  border-left:1px solid rgba(255,255,255,0.09);
  border-bottom:1px solid rgba(0,0,0,0.55);
  border-right:1px solid rgba(0,0,0,0.35);
  border-radius:12px;padding:6px;min-width:210px;
  box-shadow:0 20px 60px rgba(0,0,0,0.75),
             0 4px 16px rgba(0,0,0,0.5),
             inset 0 1px 0 rgba(255,255,255,0.10);
  display:none;user-select:none;
}}
#ctx-menu.open{{display:block}}
.ctx-item{{
  padding:10px 14px;font-size:13px;font-weight:500;color:var(--text2);
  cursor:pointer;display:flex;align-items:center;gap:12px;
  position:relative;overflow:hidden;
  border-radius:8px;
  transition:color .15s ease;
}}
/* sliding gradient fill on hover */
.ctx-item::before{{
  content:'';
  position:absolute;inset:0;
  background:linear-gradient(90deg,
    rgba(88,101,242,0.0) 0%,
    rgba(88,101,242,0.22) 50%,
    rgba(114,137,218,0.14) 100%);
  transform:translateX(-100%);
  transition:transform .20s cubic-bezier(.4,0,.2,1);
  border-radius:inherit;
}}
/* left accent bar */
.ctx-item::after{{
  content:'';
  position:absolute;left:0;top:18%;height:64%;
  width:3px;
  background:linear-gradient(to bottom, #a5b4fc, #5865f2);
  border-radius:0 3px 3px 0;
  box-shadow:0 0 10px rgba(88,101,242,0.9);
  transform:scaleY(0);
  transition:transform .16s cubic-bezier(.4,0,.2,1);
  transform-origin:center;
}}
.ctx-item:hover{{
  color:#fff;
}}
.ctx-item:hover::before{{
  transform:translateX(0);
}}
.ctx-item:hover::after{{
  transform:scaleY(1);
}}
.ctx-item:hover .ctx-ico{{
  transform:scale(1.18) rotate(-4deg);
  filter:drop-shadow(0 0 5px rgba(140,150,255,0.75));
}}
.ctx-item .ctx-ico{{
  font-size:15px;flex-shrink:0;width:20px;text-align:center;
  transition:transform .18s cubic-bezier(.4,0,.2,1), filter .18s ease;
}}
.ctx-sep{{
  height:1px;
  background:linear-gradient(90deg, transparent, rgba(255,255,255,0.08), transparent);
  margin:4px 6px;
}}

/* ── LIGHTBOX ──────────────────────────────── */
#lb{{
  display:none;position:fixed;inset:0;
  background:rgba(0,0,0,0.92);z-index:999;
  align-items:center;justify-content:center;cursor:zoom-out;
  backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);
}}
#lb.open{{display:flex}}
#lb img{{
  max-width:90vw;max-height:90vh;object-fit:contain;
  border-radius:var(--r3);
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.5);
  box-shadow:0 24px 80px rgba(0,0,0,0.8);
}}
#lb-close{{
  position:fixed;top:20px;right:20px;
  width:38px;height:38px;border-radius:50%;
  background:rgba(255,255,255,0.10);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  color:#fff;
  border-top:1px solid rgba(255,255,255,0.18);
  border-bottom:1px solid rgba(0,0,0,0.45);
  font-size:20px;
  display:flex;align-items:center;justify-content:center;
  cursor:pointer;transition:background .12s;
}}
#lb-close:hover{{background:rgba(255,255,255,0.22)}}

/* ── GIF WRAPPER WITH PLAY OVERLAY ────────── */
.att-gif-wrap {{
  position:relative;display:inline-block;
  max-width:560px;width:100%;margin-top:8px;
  border-radius:14px;overflow:hidden;
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.52);
  border-right:1px solid rgba(0,0,0,0.32);
  box-shadow:0 6px 28px rgba(0,0,0,0.6);
}}
.att-gif-wrap img {{display:block;width:100%;max-height:380px;object-fit:contain;cursor:pointer;}}
.gif-play-btn {{
  position:absolute;top:50%;left:50%;
  transform:translate(-50%,-50%) scale(0.9);
  width:48px;height:48px;
  display:flex;align-items:center;justify-content:center;
  cursor:pointer;opacity:0;
  transition:opacity .18s ease,transform .18s ease;
  pointer-events:none;z-index:4;user-select:none;
}}
.att-gif-wrap:hover .gif-play-btn {{
  opacity:1;transform:translate(-50%,-50%) scale(1);pointer-events:auto;
}}
.gif-play-btn:hover {{
  filter:brightness(1.2);
}}
.gif-play-btn:active {{transform:translate(-50%,-50%) scale(0.88)}}

/* ── CUSTOM VIDEO PLAYER ──────────────────── */
.att-video-wrap {{
  position:relative;display:inline-block;
  max-width:560px;width:100%;margin-top:8px;
  border-radius:14px;overflow:hidden;background:#000;
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.52);
  border-right:1px solid rgba(0,0,0,0.32);
  box-shadow:0 6px 28px rgba(0,0,0,0.6);
}}
.att-video-wrap video {{
  display:block;width:100%;max-height:380px;object-fit:contain;cursor:pointer;
}}
.vid-play-btn {{
  position:absolute;top:50%;left:50%;
  transform:translate(-50%,-50%) scale(0.85);
  width:52px;height:52px;border-radius:50%;
  background:rgba(0,0,0,0.60);
  backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);
  border:1.5px solid rgba(255,255,255,0.28);
  color:#fff;font-size:20px;
  display:flex;align-items:center;justify-content:center;
  cursor:pointer;opacity:0;
  transition:opacity .18s ease,transform .18s ease,background .15s;
  pointer-events:none;z-index:4;user-select:none;
}}
.att-video-wrap:hover .vid-play-btn,
.att-video-wrap.paused .vid-play-btn {{
  opacity:1;transform:translate(-50%,-50%) scale(1);pointer-events:auto;
}}
.vid-play-btn:hover {{
  background:rgba(88,101,242,0.70) !important;
  border-color:rgba(255,255,255,0.45) !important;
}}
.vid-play-btn:active {{transform:translate(-50%,-50%) scale(0.92) !important}}
.vid-progress-wrap {{
  position:absolute;bottom:44px;left:0;right:0;
  height:4px;cursor:pointer;z-index:6;
  opacity:0;transition:opacity .18s ease,height .15s ease,bottom .15s ease;
}}
.att-video-wrap:hover .vid-progress-wrap{{opacity:1}}
.att-video-wrap:hover .vid-progress-wrap:hover{{height:6px;bottom:43px}}
.vid-progress-bg {{
  position:absolute;inset:0;
  background:rgba(255,255,255,0.18);border-radius:4px;overflow:hidden;
}}
.vid-progress-fill {{
  height:100%;width:0%;
  background:linear-gradient(90deg,var(--accent),var(--accent3));
  border-radius:4px;
  box-shadow:0 0 6px rgba(88,101,242,0.5);
  transition:width .1s linear;pointer-events:none;
}}
.vid-progress-thumb {{
  position:absolute;top:50%;left:0%;
  transform:translate(-50%,-50%) scale(0);
  width:13px;height:13px;border-radius:50%;
  background:#fff;box-shadow:0 0 6px rgba(0,0,0,0.6);
  pointer-events:none;transition:transform .12s;z-index:7;
}}
.vid-progress-wrap:hover .vid-progress-thumb{{transform:translate(-50%,-50%) scale(1)}}
:fullscreen .vid-progress-wrap,
:-webkit-full-screen .vid-progress-wrap {{display:none}}
.att-video-wrap:fullscreen,
.att-video-wrap:-webkit-full-screen {{
  width:100vw !important;max-width:100vw !important;height:100vh !important;
  border-radius:0 !important;background:#000 !important;
  display:flex !important;flex-direction:column !important;
  align-items:center !important;justify-content:center !important;
}}
.att-video-wrap:fullscreen video,
.att-video-wrap:-webkit-full-screen video {{
  width:100% !important;height:100% !important;
  max-height:100vh !important;object-fit:contain !important;
}}
.vid-controls {{
  position:absolute;bottom:0;left:0;right:0;
  display:flex;align-items:center;gap:8px;
  padding:6px 12px 8px;
  background:linear-gradient(0deg,rgba(0,0,0,0.85) 0%,transparent 100%);
  opacity:0;transition:opacity .18s ease;z-index:5;
}}
.att-video-wrap:hover .vid-controls{{opacity:1}}
.vid-vol-btn {{
  background:none;border:none;color:#fff;font-size:16px;
  cursor:pointer;padding:0;flex-shrink:0;line-height:1;
  opacity:.80;transition:opacity .12s;
}}
.vid-vol-btn:hover{{opacity:1}}
.vid-slider {{
  -webkit-appearance:none;width:72px;height:3px;border-radius:3px;
  background:linear-gradient(to right,
    rgba(255,255,255,.88) 0%,rgba(255,255,255,.88) var(--vol-pct,100%),
    rgba(255,255,255,.20) var(--vol-pct,100%),rgba(255,255,255,.20) 100%);
  outline:none;cursor:pointer;flex-shrink:0;transition:height .12s;
}}
.vid-slider:hover{{height:5px}}
.vid-slider::-webkit-slider-thumb {{
  -webkit-appearance:none;width:13px;height:13px;border-radius:50%;
  background:#fff;cursor:pointer;box-shadow:0 0 5px rgba(0,0,0,0.6);
  transition:transform .12s;
}}
.vid-slider:hover::-webkit-slider-thumb{{transform:scale(1.2)}}
.vid-slider::-moz-range-thumb {{
  width:13px;height:13px;border-radius:50%;border:none;background:#fff;cursor:pointer;
}}
.vid-slider::-moz-range-progress {{
  background:rgba(255,255,255,.88);height:3px;border-radius:3px;
}}
.vid-time {{
  font-size:11px;font-family:var(--mono);color:rgba(255,255,255,.75);
  flex-shrink:0;margin-left:auto;white-space:nowrap;user-select:none;
}}
.vid-action-btn {{
  background:none;border:none;color:rgba(255,255,255,.75);font-size:15px;
  cursor:pointer;padding:0 2px;flex-shrink:0;line-height:1;
  transition:color .12s,transform .12s;opacity:.80;
}}
.vid-action-btn:hover{{color:#fff;opacity:1;transform:scale(1.15)}}

/* ── ACTIVITY BOX ─────────────────────────── */
.activity-box {{
  background:rgba(255,255,255,0.05);
  backdrop-filter:blur(32px) saturate(1.2);
  -webkit-backdrop-filter:blur(32px) saturate(1.2);
  border-top:1px solid rgba(255,255,255,0.14);
  border-left:1px solid rgba(255,255,255,0.08);
  border-bottom:1px solid rgba(0,0,0,0.50);
  border-right:1px solid rgba(0,0,0,0.30);
  border-radius:var(--r3);
  padding:20px 20px 16px;
  box-shadow:0 8px 48px rgba(0,0,0,0.55),
             inset 0 1px 0 rgba(255,255,255,0.09);
  transition:box-shadow .2s,border-color .2s;
}}
.activity-box:hover {{
  border-top-color:rgba(88,101,242,0.35);
  box-shadow:0 12px 56px rgba(0,0,0,0.65),
             0 0 0 1px rgba(88,101,242,0.12),
             inset 0 1px 0 rgba(255,255,255,0.10);
}}
.activity-header {{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}}
.activity-title {{font-size:11px;font-weight:700;font-family:var(--mono);text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}}
.activity-tabs {{
  display:flex;gap:0;
  background:rgba(0,0,0,0.45);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  border-radius:100px;padding:3px;
  border:1px solid rgba(255,255,255,0.06);
}}
.activity-tab {{
  font-size:11px;font-weight:600;font-family:var(--mono);
  letter-spacing:.02em;padding:5px 15px;border-radius:100px;
  color:var(--muted);background:transparent;border:none;
  cursor:pointer;transition:all .18s ease;
}}
.activity-tab:hover:not(.on){{color:var(--text2);background:rgba(255,255,255,0.07)}}
.activity-tab.on {{
  background:linear-gradient(135deg,rgba(88,101,242,0.90) 0%,rgba(71,82,196,0.95) 100%);
  color:#fff;
  box-shadow:0 2px 14px rgba(88,101,242,0.55),inset 0 1px 0 rgba(255,255,255,0.20);
}}
.activity-canvas-wrap{{position:relative;z-index:1}}

/* ── DATE STRIP ───────────────────────────── */
.date-strip{{display:flex;align-items:center;gap:18px}}
.date-pill{{
  display:inline-flex;align-items:center;gap:8px;
  background:rgba(255,255,255,0.07);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  border-top:1px solid rgba(255,255,255,0.14);
  border-left:1px solid rgba(255,255,255,0.08);
  border-bottom:1px solid rgba(0,0,0,0.42);
  border-right:1px solid rgba(0,0,0,0.26);
  border-radius:var(--r4);padding:8px 18px;
  font-size:12px;font-family:var(--mono);color:var(--text2);
  box-shadow:0 3px 14px rgba(0,0,0,0.4),inset 0 1px 0 rgba(255,255,255,0.08);
}}
.date-pill-lbl{{color:var(--muted);margin-right:2px}}
.date-pill-val{{color:#fff;font-weight:600}}

/* ── SETTINGS MODAL ────────────────────────── */
#settings-modal{{
  display:none;position:fixed;inset:0;z-index:9999;
  background:rgba(0,0,0,0.70);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);
  align-items:center;justify-content:center;
}}
#settings-modal.open{{display:flex}}
.settings-panel{{
  background:rgba(10,12,26,0.92);
  backdrop-filter:blur(40px) saturate(1.3);
  -webkit-backdrop-filter:blur(40px) saturate(1.3);
  border-top:1px solid rgba(255,255,255,0.16);
  border-left:1px solid rgba(255,255,255,0.10);
  border-bottom:1px solid rgba(0,0,0,0.55);
  border-right:1px solid rgba(0,0,0,0.35);
  border-radius:var(--r3);padding:0;min-width:320px;max-width:420px;width:90%;
  box-shadow:0 24px 80px rgba(0,0,0,0.70),
             inset 0 1px 0 rgba(255,255,255,0.10);
  overflow:hidden;
}}
.settings-header{{
  display:flex;align-items:center;justify-content:space-between;
  padding:16px 20px;border-bottom:1px solid rgba(255,255,255,0.08);
  font-size:15px;font-weight:700;color:#fff;
}}
.settings-close{{
  background:none;border:none;color:var(--muted);font-size:18px;
  cursor:pointer;padding:2px 6px;border-radius:4px;line-height:1;
  transition:color .1s,background .1s;
}}
.settings-close:hover{{color:#fff;background:rgba(255,255,255,0.10)}}
.settings-body{{padding:20px}}
.settings-row{{display:flex;align-items:center;justify-content:space-between;gap:16px}}
.settings-label{{font-size:13px;font-weight:600;color:var(--text)}}
.lang-options{{display:flex;gap:8px}}
.lang-opt{{
  padding:7px 14px;border-radius:var(--r2);font-size:13px;font-weight:600;
  cursor:pointer;transition:all .15s;
  background:rgba(255,255,255,0.06);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border-top:1px solid rgba(255,255,255,0.13);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.42);
  border-right:1px solid rgba(0,0,0,0.26);
  color:var(--muted);
}}
.lang-opt:hover{{background:rgba(255,255,255,0.10);color:var(--text)}}
.lang-opt.active{{
  background:linear-gradient(145deg,rgba(88,101,242,0.88) 0%,rgba(71,82,196,0.95) 100%);
  border-top-color:rgba(255,255,255,0.22);color:#fff;
  box-shadow:0 2px 14px rgba(88,101,242,0.45),inset 0 1px 0 rgba(255,255,255,0.18);
}}

/* ── CONNECTIONS ────────────────────────────── */
.conn-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px}}
.conn-card{{
  background:rgba(255,255,255,0.06);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border-top:1px solid rgba(255,255,255,0.14);
  border-left:1px solid rgba(255,255,255,0.08);
  border-bottom:1px solid rgba(0,0,0,0.45);
  border-right:1px solid rgba(0,0,0,0.28);
  border-radius:var(--r2);padding:10px 14px;
  display:flex;align-items:center;gap:10px;
  box-shadow:0 3px 14px rgba(0,0,0,0.4),inset 0 1px 0 rgba(255,255,255,0.08);
  transition:all .16s;
}}
.conn-card:hover{{
  background:rgba(255,255,255,0.10);
  border-top-color:rgba(88,101,242,0.45);
  transform:translateY(-1px);
  box-shadow:0 6px 24px rgba(0,0,0,0.5),inset 0 1px 0 rgba(255,255,255,0.11);
}}
.conn-icon{{font-size:20px;flex-shrink:0}}
.conn-info{{min-width:0}}
.conn-type{{font-size:10px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}}
.conn-name{{font-size:13px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.conn-verified{{display:inline-block;font-size:10px;color:#23a559;margin-left:4px}}


/* ── FRIEND STAT PILL (reused by quests) ───── */
.friend-stat-pill{{
  background:rgba(88,101,242,0.14);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border:1px solid rgba(88,101,242,0.28);
  border-radius:20px;padding:4px 14px;font-size:12px;font-weight:600;color:#b5bcf0;
  box-shadow:0 2px 10px rgba(88,101,242,0.15);
}}

/* ── NOTES ──────────────────────────────────── */
.notes-list{{display:flex;flex-direction:column;gap:6px}}
.note-card{{
  background:rgba(255,255,255,0.04);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border-left:3px solid var(--accent);
  border-top:1px solid rgba(255,255,255,0.10);
  border-bottom:1px solid rgba(0,0,0,0.40);
  border-right:1px solid rgba(0,0,0,0.22);
  border-radius:0 var(--r2) var(--r2) 0;padding:8px 12px;
  box-shadow:0 2px 12px rgba(0,0,0,0.36);
}}
.note-uid{{font-size:10px;font-family:var(--mono);color:var(--muted);margin-bottom:3px}}
.note-text{{font-size:13px;color:var(--text2);word-break:break-word}}

/* ── SESSION MFA badge (reused by quests) ──── */
.session-mfa{{
  font-size:10px;
  background:rgba(35,165,89,0.18);
  backdrop-filter:blur(8px);
  color:#7ee8a2;border-radius:4px;padding:1px 6px;flex-shrink:0;
  border:1px solid rgba(35,165,89,0.25);
}}

/* ── QUESTS ──────────────────────────────────── */
.quests-summary{{display:flex;gap:10px;margin-bottom:10px;align-items:center;flex-wrap:wrap}}
.quest-progress-bar{{flex:1;min-width:120px;height:6px;background:rgba(255,255,255,0.07);border-radius:4px;overflow:hidden}}
.quest-progress-fill{{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent3));border-radius:4px;
  box-shadow:0 0 8px rgba(88,101,242,0.5);transition:width .5s}}
.quest-pct{{font-size:12px;font-family:var(--mono);color:var(--muted);flex-shrink:0}}
.quests-list{{display:flex;flex-direction:column;gap:4px;max-height:200px;overflow-y:auto}}
.quest-row{{
  display:flex;align-items:center;gap:8px;
  padding:5px 10px;border-radius:var(--r);
  background:rgba(255,255,255,0.03);
  border:1px solid rgba(255,255,255,0.05);
}}
.quest-dot{{width:8px;height:8px;border-radius:50%;flex-shrink:0}}
.quest-dot.done{{background:#23a559;box-shadow:0 0 6px rgba(35,165,89,0.5);}}
.quest-dot.pend{{background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15)}}
.quest-date{{font-size:11px;font-family:var(--mono);color:var(--muted);flex-shrink:0}}
.quest-id{{font-size:11px;color:var(--faint);font-family:var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}}


/* ── COLLAPSIBLE ─────────────────────────────── */
.collapse-btn{{
  background:none;border:none;color:var(--muted);
  font-size:10px;padding:0 2px;cursor:pointer;
  transition:transform .25s ease,color .15s;
  margin-left:4px;line-height:1;flex-shrink:0;transform:rotate(0deg);
}}
.collapse-btn:hover{{color:var(--text2)}}
.collapse-btn.open{{transform:rotate(180deg)}}
.collapsible-body{{
  overflow:hidden;max-height:0;opacity:0;
  transition:max-height .35s cubic-bezier(.4,0,.2,1),opacity .25s ease;
}}
.collapsible-body.open{{max-height:2000px;opacity:1}}

/* ── NITRO HISTORY ────────────────────────────── */
.nitro-timeline{{position:relative;padding-left:20px}}
.nitro-timeline::before{{
  content:'';position:absolute;left:6px;top:0;bottom:0;width:2px;
  background:linear-gradient(180deg,var(--accent),transparent);
  border-radius:2px;
}}
.nitro-entry{{
  position:relative;margin-bottom:14px;
  background:rgba(255,255,255,0.06);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border-top:1px solid rgba(255,255,255,0.14);
  border-left:1px solid rgba(255,255,255,0.08);
  border-bottom:1px solid rgba(0,0,0,0.46);
  border-right:1px solid rgba(0,0,0,0.28);
  border-radius:var(--r2);padding:10px 14px;
  box-shadow:0 3px 16px rgba(0,0,0,0.42),inset 0 1px 0 rgba(255,255,255,0.08);
}}
.nitro-entry::before{{
  content:'';position:absolute;left:-17px;top:14px;
  width:10px;height:10px;border-radius:50%;
  background:var(--accent);border:2px solid var(--bg0);
  box-shadow:0 0 8px rgba(88,101,242,0.7);
}}
.nitro-entry.gifted{{border-left:3px solid #f0b232}}
.nitro-entry.gifted::before{{background:#f0b232;box-shadow:0 0 8px rgba(240,178,50,0.7)}}
.nitro-tier{{font-size:13px;font-weight:700;color:#c5caff;display:flex;align-items:center;gap:6px}}
.nitro-plan{{font-size:11px;font-family:var(--mono);color:var(--muted)}}
.nitro-dates{{font-size:11px;color:var(--faint);margin-top:4px;font-family:var(--mono)}}
.nitro-gifted-badge{{
  font-size:10px;
  background:rgba(240,178,50,0.18);
  color:#f0b232;border-radius:4px;padding:1px 7px;font-family:var(--mono);
  border:1px solid rgba(240,178,50,0.28);
}}

/* ── PAYMENTS ─────────────────────────────────── */
.payments-summary{{display:flex;gap:10px;margin-bottom:10px;flex-wrap:wrap}}
.pay-total-card{{
  background:rgba(255,255,255,0.06);
  backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);
  border-top:1px solid rgba(255,255,255,0.14);
  border-left:1px solid rgba(255,255,255,0.08);
  border-bottom:1px solid rgba(0,0,0,0.45);
  border-right:1px solid rgba(0,0,0,0.28);
  border-radius:var(--r2);padding:10px 16px;flex:1;min-width:130px;
  box-shadow:0 3px 14px rgba(0,0,0,0.40),inset 0 1px 0 rgba(255,255,255,0.08);
}}
.pay-total-num{{font-size:18px;font-weight:800;color:#fff}}
.pay-total-lbl{{font-size:10px;font-family:var(--mono);text-transform:uppercase;color:var(--muted)}}
.payments-list{{display:flex;flex-direction:column;gap:5px;max-height:220px;overflow-y:auto}}
.pay-row{{
  display:flex;align-items:center;gap:10px;
  padding:7px 12px;border-radius:var(--r);
  background:rgba(255,255,255,0.03);
  border:1px solid rgba(255,255,255,0.06);
  font-size:12px;
  transition:background .10s;
}}
.pay-row:hover{{background:rgba(255,255,255,0.06)}}
.pay-date{{font-family:var(--mono);color:var(--muted);width:80px;flex-shrink:0}}
.pay-desc{{flex:1;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.pay-amt{{font-family:var(--mono);font-size:11px;flex-shrink:0}}
.pay-amt.orb{{color:#b4a8ff}}
.pay-amt.real{{color:#7ee8a2}}

/* ── ORBS ──────────────────────────────────────── */
.orbs-badge{{
  font-size:11px;font-weight:700;padding:4px 10px;
  border-radius:var(--r4);
  background:rgba(155,140,255,0.20);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  color:#dcd4ff;display:inline-flex;align-items:center;gap:5px;
  border-top:1px solid rgba(180,168,255,0.24);
  border-left:1px solid rgba(155,140,255,0.14);
  border-bottom:1px solid rgba(0,0,0,0.4);
  border-right:1px solid rgba(0,0,0,0.25);
  box-shadow:0 2px 12px rgba(155,140,255,0.28),
             inset 0 1px 0 rgba(255,255,255,0.10);
  cursor:default;
  letter-spacing:.01em;height:26px;
}}

/* ── Discord mentions & custom emoji ── */
.mention {{
  display:inline;
  background:rgba(88,101,242,0.25);
  backdrop-filter:blur(8px);
  color:#d0d5ff;
  border-radius:4px;padding:0 4px;font-weight:600;font-size:0.92em;
  border:1px solid rgba(88,101,242,0.25);
  cursor:default;
}}
.mention-ch {{background:rgba(0,212,255,0.14);color:#7ed9f7;border-color:rgba(0,212,255,0.20);}}
.mention-role {{background:rgba(88,101,242,0.18);color:#c0c4f8;border:1px solid rgba(88,101,242,0.32);}}
.custom-emoji {{
  display:inline;width:22px;height:22px;
  vertical-align:-5px;object-fit:contain;margin:0 1px;
}}
/* ── Discord Markdown ── */
.md-h1{{font-size:1.55em;font-weight:800;color:#fff;display:block;margin:6px 0 2px;
  border-bottom:1px solid rgba(255,255,255,0.10);padding-bottom:4px;line-height:1.2}}
.md-h2{{font-size:1.25em;font-weight:700;color:#e3e5ff;display:block;margin:4px 0 2px;line-height:1.2}}
.md-h3{{font-size:1.08em;font-weight:700;color:#b5bcf0;display:block;margin:3px 0 1px;line-height:1.2}}
.md-hr{{display:block;height:2px;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.18),transparent);
  border:none;margin:8px 0;border-radius:2px;}}
.md-blockquote{{
  display:block;border-left:3px solid var(--accent);
  margin:4px 0;padding:3px 10px;
  background:rgba(88,101,242,0.07);border-radius:0 4px 4px 0;
  color:var(--text2);font-style:italic;
}}
.md-code-block{{
  display:block;margin:8px 0;
  background:rgba(0,0,0,0.55);
  backdrop-filter:blur(12px);
  border-top:1px solid rgba(255,255,255,0.10);
  border-left:1px solid rgba(255,255,255,0.06);
  border-bottom:1px solid rgba(0,0,0,0.55);
  border-right:1px solid rgba(0,0,0,0.35);
  border-radius:var(--r2);
  overflow:hidden;
  box-shadow:0 4px 20px rgba(0,0,0,0.45);
}}
.md-code-lang{{
  display:block;
  padding:5px 14px 4px;
  font-size:10px;font-family:var(--mono);font-weight:700;
  letter-spacing:.08em;text-transform:uppercase;
  color:var(--muted);
  background:rgba(255,255,255,0.04);
  border-bottom:1px solid rgba(255,255,255,0.07);
}}
.md-code-block pre{{
  margin:0;padding:12px 16px;
  font-family:var(--mono);font-size:13px;line-height:1.55;
  color:#d4d4d4;overflow-x:auto;white-space:pre;
}}
/* syntax highlight colours (basic) */
.md-code-block pre .tok-kw{{color:#c792ea}}
.md-code-block pre .tok-str{{color:#c3e88d}}
.md-code-block pre .tok-num{{color:#f78c6c}}
.md-code-block pre .tok-cmt{{color:#546e7a;font-style:italic}}
.md-code-block pre .tok-fn{{color:#82aaff}}
.md-inline-code{{
  font-family:var(--mono);font-size:0.88em;
  background:rgba(0,0,0,0.45);
  color:#e8e8e8;
  border:1px solid rgba(255,255,255,0.10);
  border-radius:4px;padding:1px 6px;
}}
.md-bold{{font-weight:800;color:#fff}}
.md-italic{{font-style:italic;color:var(--text2)}}
.md-under{{text-decoration:underline}}
.md-strike{{text-decoration:line-through;color:var(--muted)}}
.md-spoiler{{
  background:rgba(255,255,255,0.08);
  color:transparent;border-radius:4px;padding:0 4px;
  cursor:pointer;transition:all .2s;
  user-select:none;
}}
.md-spoiler.revealed{{
  background:rgba(255,255,255,0.12);
  color:var(--text);
}}

/* last section padding */
.sec.last{{padding-bottom:32px}}

/* ── SERVER ICONS (rail + detail modal) ─────── */
.srv-icon-img{{width:40px;height:40px;border-radius:50%;object-fit:cover;flex-shrink:0;border:1px solid rgba(255,255,255,0.12)}}
.srv-icon-placeholder{{
  width:40px;height:40px;border-radius:50%;flex-shrink:0;
  display:flex;align-items:center;justify-content:center;
  font-size:16px;font-weight:800;color:#fff;
}}

/* ── SERVER DETAIL MODAL ──────────────────── */
#srv-detail-modal{{
  position:fixed;inset:0;z-index:500;
  background:rgba(0,0,0,0.72);
  backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);
  display:flex;align-items:center;justify-content:center;
  padding:24px;
}}
.srvd-panel{{
  width:100%;max-width:600px;max-height:80vh;
  background:rgba(10,12,28,0.96);
  backdrop-filter:blur(40px);-webkit-backdrop-filter:blur(40px);
  border-top:1px solid rgba(255,255,255,0.14);
  border-left:1px solid rgba(255,255,255,0.09);
  border-bottom:1px solid rgba(0,0,0,0.6);
  border-right:1px solid rgba(0,0,0,0.4);
  border-radius:var(--r3);
  box-shadow:0 24px 80px rgba(0,0,0,0.8),0 0 0 1px rgba(255,255,255,0.06),inset 0 1px 0 rgba(255,255,255,0.10);
  display:flex;flex-direction:column;overflow:hidden;
}}
.srvd-header{{
  display:flex;align-items:center;gap:14px;padding:18px 20px 14px;
  border-bottom:1px solid rgba(255,255,255,0.07);flex-shrink:0;
}}
.srvd-icon-wrap{{flex-shrink:0}}
.srvd-info{{flex:1;min-width:0}}
.srvd-name{{font-size:17px;font-weight:800;color:#fff}}
.srvd-meta{{font-size:12px;color:var(--muted);margin-top:2px;font-family:var(--mono)}}
.srvd-close{{
  background:none;border:none;color:var(--muted);font-size:18px;
  padding:4px 8px;border-radius:var(--r);cursor:pointer;
  transition:color .12s,background .12s;
}}
.srvd-close:hover{{color:#fff;background:rgba(255,255,255,0.08)}}
.srvd-body{{overflow-y:auto;padding:14px 20px 20px;flex:1}}
.srvd-sub-title{{
  font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;
  color:var(--muted);display:flex;align-items:center;gap:6px;
  padding:6px 0 8px;border-bottom:1px solid rgba(255,255,255,0.06);margin-bottom:8px;
}}

/* channels list in srv-detail */
.srvd-cat{{
  font-size:10px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;
  color:var(--muted);padding:10px 0 4px;
}}
.srvd-ch-row{{
  display:flex;align-items:center;gap:6px;padding:4px 6px 4px 18px;
  border-radius:var(--r);font-size:13px;color:var(--text2);
  transition:background .10s;
}}
.srvd-ch-row:hover{{background:rgba(255,255,255,0.05)}}
.srvd-ch-ico{{font-size:14px;flex-shrink:0;width:18px;text-align:center}}
.srvd-ch-name{{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.srvd-ch-badge{{
  font-size:10px;font-family:var(--mono);
  background:rgba(88,101,242,0.18);color:var(--blurple);
  border:1px solid rgba(88,101,242,0.25);
  border-radius:10px;padding:0 6px;flex-shrink:0;
}}

/* webhooks list in srv-detail */
.srvd-wh-row{{
  display:flex;align-items:center;gap:10px;
  padding:8px 10px;border-radius:var(--r2);margin-bottom:6px;
  background:rgba(255,255,255,0.04);
  border:1px solid rgba(255,255,255,0.06);
  transition:background .10s;
}}
.srvd-wh-row:hover{{background:rgba(255,255,255,0.07)}}
.srvd-wh-av{{width:32px;height:32px;border-radius:50%;object-fit:cover;flex-shrink:0;background:rgba(255,255,255,0.1)}}
.srvd-wh-av-ph{{width:32px;height:32px;border-radius:50%;flex-shrink:0;background:rgba(88,101,242,0.25);display:flex;align-items:center;justify-content:center;font-size:14px}}
.srvd-wh-info{{flex:1;min-width:0}}
.srvd-wh-name{{font-size:13px;font-weight:600;color:var(--text)}}
.srvd-wh-type{{font-size:10px;font-family:var(--mono);color:var(--muted)}}
.srvd-wh-ch{{font-size:11px;color:var(--faint)}}
/* allow taller channel lists in the server detail */
.srvd-body .collapsible-body.open{{max-height:600px;overflow-y:auto}}

/* ── HARVEST HISTORY ──────────────────────── */
.harvest-summary{{
  font-size:13px;color:var(--text2);margin-bottom:12px;
  background:rgba(88,101,242,0.10);border-left:3px solid var(--accent);
  border-radius:0 var(--r) var(--r) 0;padding:8px 12px;
}}
.harvest-timeline{{position:relative;padding-left:22px}}
.harvest-timeline::before{{
  content:'';position:absolute;left:8px;top:0;bottom:0;width:2px;
  background:linear-gradient(180deg,var(--accent),transparent);border-radius:2px;
}}
.harvest-entry{{
  position:relative;margin-bottom:10px;
  display:flex;align-items:center;gap:12px;
  background:rgba(255,255,255,0.04);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border-top:1px solid rgba(255,255,255,0.10);
  border-left:1px solid rgba(255,255,255,0.06);
  border-bottom:1px solid rgba(0,0,0,0.40);
  border-right:1px solid rgba(0,0,0,0.22);
  border-radius:var(--r2);padding:8px 14px;
  box-shadow:0 2px 12px rgba(0,0,0,0.36);
}}
.harvest-entry::before{{
  content:'';position:absolute;left:-17px;top:50%;transform:translateY(-50%);
  width:10px;height:10px;border-radius:50%;
  background:var(--accent);border:2px solid var(--bg0);
  box-shadow:0 0 8px rgba(88,101,242,0.6);
}}
.harvest-date{{font-size:12px;font-family:var(--mono);color:var(--text2);font-weight:600}}
.harvest-email{{font-size:11px;font-family:var(--mono);color:var(--muted)}}

/* ── AD PROFILE ───────────────────────────── */
.adprofile-banner{{
  font-size:12px;color:#c9a227;
  background:rgba(240,178,50,0.08);
  border-left:3px solid #f0b232;
  border-radius:0 var(--r) var(--r) 0;
  padding:8px 12px;margin-bottom:14px;line-height:1.5;
}}
.adprofile-card{{
  background:rgba(255,255,255,0.05);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border-top:1px solid rgba(255,255,255,0.12);
  border-left:1px solid rgba(255,255,255,0.07);
  border-bottom:1px solid rgba(0,0,0,0.44);
  border-right:1px solid rgba(0,0,0,0.26);
  border-radius:var(--r2);padding:14px 18px;
  box-shadow:0 3px 16px rgba(0,0,0,0.42),inset 0 1px 0 rgba(255,255,255,0.07);
}}
.adp-row{{display:flex;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,0.05);align-items:flex-start;flex-wrap:wrap}}
.adp-row:last-child{{border-bottom:none}}
.adp-key{{font-size:11px;font-family:var(--mono);color:var(--muted);flex-shrink:0;width:160px;padding-top:2px}}
.adp-val{{font-size:13px;font-weight:600;color:var(--text);flex:1}}
.adp-theme-wrap{{display:flex;flex-wrap:wrap;gap:5px;margin-top:4px}}
.adp-theme{{
  font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;
  background:rgba(88,101,242,0.16);color:#b5bcf0;
  border:1px solid rgba(88,101,242,0.28);border-radius:20px;
  padding:2px 10px;
}}

/* ── SUPPORT TICKETS ──────────────────────── */
.tickets-summary{{
  font-size:13px;color:var(--text2);
  background:rgba(255,255,255,0.04);border-left:3px solid var(--accent);
  border-radius:0 var(--r) var(--r) 0;padding:8px 12px;
}}
.ticket-card{{margin-bottom:8px;border-radius:var(--r2);overflow:hidden;border:1px solid rgba(255,255,255,0.07)}}
.ticket-hdr{{
  display:flex;align-items:center;gap:10px;padding:10px 14px;
  background:rgba(255,255,255,0.05);cursor:pointer;
  transition:background .12s;
}}
.ticket-hdr:hover{{background:rgba(255,255,255,0.09)}}
.ticket-date{{font-size:11px;font-family:var(--mono);color:var(--muted);flex-shrink:0}}
.ticket-status{{
  font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
  border-radius:10px;padding:1px 8px;flex-shrink:0;font-family:var(--mono);
}}
.ticket-status.closed{{background:rgba(35,165,89,0.18);color:#7ee8a2;border:1px solid rgba(35,165,89,0.28)}}
.ticket-status.deleted{{background:rgba(255,255,255,0.08);color:var(--muted);border:1px solid rgba(255,255,255,0.12)}}
.ticket-status.open{{background:rgba(240,178,50,0.18);color:#f0b232;border:1px solid rgba(240,178,50,0.28)}}
.ticket-subject{{flex:1;font-size:13px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.ticket-body{{
  background:rgba(0,0,0,0.25);padding:12px 14px;
  display:none;flex-direction:column;gap:8px;
}}
.ticket-body.open{{display:flex}}
.ticket-bubble{{
  max-width:80%;border-radius:var(--r2);padding:8px 12px;
  font-size:13px;line-height:1.45;word-break:break-word;
}}
.ticket-bubble.user{{
  align-self:flex-end;
  background:rgba(88,101,242,0.35);
  border-top:1px solid rgba(88,101,242,0.5);
  border-left:1px solid rgba(88,101,242,0.3);
  border-bottom:1px solid rgba(0,0,0,0.4);
  border-right:1px solid rgba(0,0,0,0.25);
  color:#d0d5ff;
}}
.ticket-bubble.agent{{
  align-self:flex-start;
  background:rgba(255,255,255,0.07);
  border:1px solid rgba(255,255,255,0.08);
  color:var(--text2);
}}
.ticket-bubble-meta{{font-size:10px;color:var(--muted);margin-bottom:3px;font-family:var(--mono)}}

/* ── DEVELOPER APPS BADGE ─────────────────── */
.hbadge.hb-devapp{{
  background:rgba(99,102,241,0.18);
  border-top:1px solid rgba(129,140,248,0.30);
  border-left:1px solid rgba(99,102,241,0.18);
  border-bottom:1px solid rgba(0,0,0,0.4);
  border-right:1px solid rgba(0,0,0,0.25);
  position:relative;
  overflow:visible;
}}
.hbadge.hb-devapp .badge-label{{color:#c7d2fe}}
.hbadge.hb-devapp .badge-value{{color:#818cf8}}
.devapp-tooltip{{
  display:none;position:absolute;top:calc(100% + 8px);left:50%;transform:translateX(-50%);
  background:rgba(8,10,22,0.97);
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  border:1px solid rgba(255,255,255,0.12);border-radius:var(--r2);
  padding:8px 12px;z-index:400;min-width:200px;
  box-shadow:0 12px 40px rgba(0,0,0,0.7);
  font-size:11px;line-height:1.6;color:var(--text2);
  white-space:nowrap;
}}
.hbadge.hb-devapp:hover .devapp-tooltip{{display:block}}
.devapp-tip-row{{display:flex;align-items:center;gap:6px}}
.devapp-tip-bot{{
  font-size:9px;font-family:var(--mono);
  background:rgba(88,101,242,0.20);color:#9ca3f5;
  border-radius:4px;padding:0 5px;
}}
/* ── LOADING SCREEN ──────────────────────────────────────────── */
#loading-screen{{
  position:fixed;inset:0;z-index:99999;
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  background:radial-gradient(ellipse 80% 80% at 50% 40%,
    rgba(88,101,242,0.13) 0%,
    rgba(4,5,16,1) 65%),
    #04050F;
  transition:opacity .5s ease, visibility .5s ease;
  gap:28px;
}}
#loading-screen.done{{
  opacity:0;visibility:hidden;pointer-events:none;
}}
/* orbiting rings */
.ld-rings{{
  position:relative;width:90px;height:90px;
}}
.ld-ring{{
  position:absolute;inset:0;border-radius:50%;
  border:2px solid transparent;
}}
.ld-ring-1{{
  border-top-color:rgba(88,101,242,0.9);
  border-right-color:rgba(88,101,242,0.3);
  animation:ld-spin1 1.1s linear infinite;
}}
.ld-ring-2{{
  inset:10px;
  border-top-color:transparent;
  border-bottom-color:rgba(114,137,218,0.7);
  border-left-color:rgba(114,137,218,0.2);
  animation:ld-spin2 .8s linear infinite;
}}
.ld-ring-3{{
  inset:22px;
  border-right-color:rgba(160,170,255,0.6);
  border-top-color:transparent;
  animation:ld-spin1 .6s linear infinite reverse;
}}
.ld-dot{{
  position:absolute;inset:38px;border-radius:50%;
  background:radial-gradient(circle, rgba(140,150,255,1) 0%, rgba(88,101,242,0.6) 60%, transparent 100%);
  box-shadow:0 0 18px rgba(88,101,242,0.9), 0 0 40px rgba(88,101,242,0.4);
  animation:ld-pulse .9s ease-in-out infinite alternate;
}}
@keyframes ld-spin1{{ to{{transform:rotate(360deg)}} }}
@keyframes ld-spin2{{ to{{transform:rotate(-360deg)}} }}
@keyframes ld-pulse{{
  from{{transform:scale(.85);opacity:.7}}
  to{{transform:scale(1.1);opacity:1}}
}}
/* text */
.ld-title{{
  font-size:18px;font-weight:700;color:#fff;letter-spacing:.04em;
  text-shadow:0 0 24px rgba(88,101,242,0.7);
}}
.ld-sub{{
  font-size:12px;font-weight:500;color:rgba(160,170,255,0.7);
  letter-spacing:.12em;text-transform:uppercase;
  margin-top:-20px;
}}
/* animated progress bar */
.ld-bar-wrap{{
  width:200px;height:2px;
  background:rgba(255,255,255,0.07);
  border-radius:2px;overflow:hidden;
}}
.ld-bar{{
  height:100%;width:0%;
  background:linear-gradient(90deg, #5865f2, #a5b4fc);
  box-shadow:0 0 8px rgba(88,101,242,0.8);
  border-radius:2px;
  transition:width .3s ease;
  animation:ld-bar-fill 1.6s cubic-bezier(.4,0,.2,1) forwards;
}}
@keyframes ld-bar-fill{{
  0%{{width:0%}}
  60%{{width:75%}}
  85%{{width:90%}}
  100%{{width:100%}}
}}
</style>
</head>
<body>
<!-- LOADING SCREEN -->
<div id="loading-screen">
  <div class="ld-rings">
    <div class="ld-ring ld-ring-1"></div>
    <div class="ld-ring ld-ring-2"></div>
    <div class="ld-ring ld-ring-3"></div>
    <div class="ld-dot"></div>
  </div>
  <div class="ld-title">Discord Viewer</div>
  <div class="ld-sub">Loading your data...</div>
  <div class="ld-bar-wrap"><div class="ld-bar"></div></div>
</div>
<div id="app">

<!-- RAIL -->
<div id="rail">
  <div class="rail-wrap active" id="rail-home-wrap">
    <div class="rail-pill"></div>
    <div class="rail-icon active" id="rail-home" data-tip="Home" onclick="showHome(this)">
      🏠
    </div>
  </div>
  <div class="rail-sep"></div>
  <div id="rail-srvs"></div>
</div>

<!-- SIDEBAR -->
<div id="sidebar">
  <div id="sb-search">
    <input id="srch" placeholder="🔍 Αναζήτηση..." data-i18n-ph="search-sidebar" />
  </div>
  <div id="sb-controls">
    <button class="filt-btn" onclick="setFilt(this,'DM')">DM</button>
    <button class="filt-btn" onclick="setFilt(this,'FRIENDS')">Friends</button>
    <button class="filt-btn" onclick="setFilt(this,'SERVER')">Server</button>
  </div>
  <div id="ch-list"></div>
  <div id="user-panel">
    <div id="u-av"></div>
    <div id="u-info">
      <div class="u-name" id="u-name-el"></div>
      <div class="u-tag"  id="u-tag-el"></div>
    </div>
    <div id="u-icons">
      <span class="u-ico" title="Ρυθμίσεις / Settings" onclick="openSettings()" id="settings-btn" style="font-size:18px;width:24px">⚙️</span>
    </div>
  </div>
</div>

<!-- MAIN -->
<div id="main">

  <!-- HOME SCREEN -->
  <div id="home" style="display:flex">
    <!-- Hero -->
    <div class="hero">
      <div class="hero-main">
        <div class="hero-av" id="hero-av-el"></div>
        <div class="hero-info">
          <div class="hero-name" id="hero-name-el"></div>
          <div class="hero-username" id="hero-user-el"></div>
          <div class="hero-badges" id="hero-badges-el"></div>
        </div>
      </div>
    </div>

    <!-- Stat cards (single row) -->
    <div class="stats-row" id="stats-row-el"></div>

    <!-- Top Emoji (stats-row2 — immediately under stat cards) -->
    <div class="stats-row2" id="stats-row2-el">
      <div class="emoji-row" id="emoji-row-el"></div>
    </div>

    <!-- Top Servers + Top DMs combined toggle box -->
    <div class="sec">
      <div class="sec-title" style="margin-bottom:10px">
        <div class="top-tabs">
          <button class="top-tab on" id="tab-servers" onclick="switchTopTab('servers')">🏆 Top Servers</button>
          <button class="top-tab" id="tab-dms" onclick="switchTopTab('dms')">👥 Top DMs</button>
        </div>
      </div>
      <div id="panel-servers">
        <div class="srv-grid" id="srv-grid-el"></div>
      </div>
      <div id="panel-dms" style="display:none">
        <div class="dm-list" id="dm-list-el"></div>
      </div>
    </div>

    <!-- Word Cloud -->
    <div class="sec">
      <div class="sec-title" data-i18n="sec-wc">💬 Word Cloud</div>
      <div class="wordcloud" id="wordcloud-el"></div>
    </div>

    <!-- Activity Chart (single box, with tabs) -->
    <div class="sec last">
      <div class="activity-box">
        <div class="activity-header">
          <div class="activity-title-wrap">
            <div class="activity-title" data-i18n="activity-title">Δραστηριότητα</div>
            <div class="activity-subtitle" id="activity-subtitle-el" data-i18n="act-sub-month">ΜΗΝΙΑΙΑ ΑΝΑΛΥΣΗ</div>
          </div>
          <div class="activity-tabs">
            <button class="activity-tab on" onclick="setActivityTab(this,'month')">All Time</button>
            <button class="activity-tab" onclick="setActivityTab(this,'90d')">90 Days</button>
            <button class="activity-tab" onclick="setActivityTab(this,'30d')">Month</button>
            <button class="activity-tab" onclick="setActivityTab(this,'7d')">Week</button>
            <button class="activity-tab" onclick="setActivityTab(this,'hour')">Hour</button>
          </div>
        </div>
        <div class="activity-canvas-wrap">
          <canvas id="c-activity" height="150"></canvas>
        </div>
      </div>
    </div>
    <!-- ── LINKED ACCOUNTS ─────────────────── -->
    <div class="sec" id="sec-connections" style="display:none">
      <div class="sec-title" data-gr="🔗 Σύνδεσμοι Λογαριασμών" data-en="🔗 Linked Accounts">🔗 Linked Accounts</div>
      <div class="conn-grid" id="connections-el"></div>
    </div>

    <!-- ── TOP GAMES ────────────────────────── -->


    <!-- ── NOTES (collapsible) ────────────── -->
    <div class="sec" id="sec-notes" style="display:none">
      <div class="sec-title" style="cursor:pointer" onclick="toggleCollapse('notes-body','notes-chevron')">📝 Notes on Users<button class="collapse-btn" id="notes-chevron">▼</button></div>
      <div class="collapsible-body" id="notes-body">
        <div class="notes-list" id="notes-el"></div>
      </div>
    </div>


    <!-- ── QUESTS ───────────────────────────── -->
    <div class="sec" id="sec-quests" style="display:none">
      <div class="sec-title" style="cursor:pointer" onclick="toggleCollapse('quests-body','quests-chevron')">🏆 Discord Quests<button class="collapse-btn" id="quests-chevron">▼</button></div>
      <div class="collapsible-body" id="quests-body">
        <div class="quests-summary" id="quests-summary-el"></div>
        <div class="quests-list" id="quests-el"></div>
      </div>
    </div>


    <!-- ── NITRO HISTORY ─────────────────────── -->
    <div class="sec" id="sec-nitro" style="display:none">
      <div class="sec-title" style="cursor:pointer" onclick="toggleCollapse('nitro-body','nitro-chevron')">💎 Nitro History<button class="collapse-btn" id="nitro-chevron">▼</button></div>
      <div class="collapsible-body" id="nitro-body">
        <div class="nitro-timeline" id="nitro-el"></div>
      </div>
    </div>

    <!-- ── DATA REQUEST HISTORY ──────────────── -->
    <div class="sec" id="sec-harvest" style="display:none">
      <div class="sec-title" style="cursor:pointer" onclick="toggleCollapse('harvest-body','harvest-chevron')">📋 Data Request History<button class="collapse-btn" id="harvest-chevron">▼</button></div>
      <div class="collapsible-body" id="harvest-body">
        <div id="harvest-summary-el" style="margin-bottom:10px"></div>
        <div class="harvest-timeline" id="harvest-el"></div>
      </div>
    </div>

    <!-- ── AD PROFILE ───────────────────────── -->
    <div class="sec" id="sec-adprofile" style="display:none">
      <div class="sec-title" style="cursor:pointer" onclick="toggleCollapse('adprofile-body','adprofile-chevron')">🎯 Ad Profile<button class="collapse-btn" id="adprofile-chevron">▼</button></div>
      <div class="collapsible-body" id="adprofile-body">
        <div id="adprofile-el"></div>
      </div>
    </div>

    <!-- ── SUPPORT TICKETS ──────────────────── -->
    <div class="sec" id="sec-tickets" style="display:none">
      <div class="sec-title" style="cursor:pointer" onclick="toggleCollapse('tickets-body','tickets-chevron')">🎫 Support Tickets<button class="collapse-btn" id="tickets-chevron">▼</button></div>
      <div class="collapsible-body" id="tickets-body">
        <div id="tickets-summary-el" style="margin-bottom:10px"></div>
        <div id="tickets-el"></div>
      </div>
    </div>

  </div>

  <!-- SERVER DETAIL MODAL -->
  <div id="srv-detail-modal" style="display:none">
    <div class="srvd-panel">
      <div class="srvd-header">
        <div class="srvd-icon-wrap" id="srvd-icon-el"></div>
        <div class="srvd-info">
          <div class="srvd-name" id="srvd-name-el"></div>
          <div class="srvd-meta" id="srvd-meta-el"></div>
        </div>
        <button class="srvd-close" onclick="closeSrvDetail()">✕</button>
      </div>
      <div class="srvd-body">
        <!-- Channels subsection -->
        <div id="srvd-ch-wrap">
          <div class="srvd-sub-title" style="cursor:pointer" onclick="toggleCollapse('srvd-ch-body','srvd-ch-chev')"># Channels<button class="collapse-btn open" id="srvd-ch-chev">▼</button></div>
          <div class="collapsible-body open" id="srvd-ch-body">
            <div id="srvd-ch-el"></div>
          </div>
        </div>
        <!-- Webhooks subsection -->
        <div id="srvd-wh-wrap" style="display:none;margin-top:14px">
          <div class="srvd-sub-title" style="cursor:pointer" onclick="toggleCollapse('srvd-wh-body','srvd-wh-chev')">🔗 Webhooks<button class="collapse-btn open" id="srvd-wh-chev">▼</button></div>
          <div class="collapsible-body open" id="srvd-wh-body">
            <div id="srvd-wh-el"></div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- CHANNEL HEADER -->
  <div id="ch-hdr" style="display:none">
    <span class="hdr-ico" id="hdr-ico-el"></span>
    <span class="hdr-name" id="hdr-name-el"></span>
    <span class="hdr-sep"  id="hdr-sep-el"></span>
    <span class="hdr-srv"  id="hdr-srv-el"></span>
    
    <!-- Central Group -->
    <div id="hdr-center-group" style="position:absolute; left:50%; transform:translateX(-50%); display:flex; align-items:center; gap:8px">
      <span class="hdr-cnt"  id="hdr-cnt-el"></span>
      <button class="hdr-cnt" id="hdr-dr-btn" title="Επιλογή χρονικής περιόδου" data-i18n-title="datepicker-btn" onclick="toggleDateRangePicker()" tabindex="0" style="cursor:pointer">📅</button>
    </div>

    <button class="hdr-cnt" id="hdr-srch-btn" title="Αναζήτηση στα μηνύματα (S)" data-i18n-title="search-btn" onclick="openMsgSearch()" tabindex="0" style="cursor:pointer">🔍</button>

    <!-- SEARCH BAR — expands horizontally inside header -->
    <div id="msg-search-bar">
      <input id="msg-srch" placeholder="Αναζήτηση..." data-i18n-ph="search-msgs" autocomplete="off" tabindex="0">
      <span id="msg-srch-count"></span>
      <div id="msg-srch-nav">
        <button class="srch-nav-btn" onclick="srchNav(-1)" title="Προηγούμενο" tabindex="0">↑</button>
        <button class="srch-nav-btn" onclick="srchNav(+1)" title="Επόμενο" tabindex="0">↓</button>
      </div>
      <button class="srch-close-btn" onclick="closeMsgSearch()" title="Esc" tabindex="0">✕</button>
    </div>
  </div>

  <!-- DATE RANGE PICKER (CUSTOM) -->
  <div id="date-range-picker">
    <!-- Top bar: field displays + actions -->
    <div class="drp-bar">
      <div class="drp-field" id="drp-field-start" onclick="drpFocusField('start')">
        <span class="drp-field-ico">📅</span>
        <span class="drp-field-val empty" id="drp-val-start" data-i18n-ph-el="Από..." data-i18n-ph-en="From...">From...</span>
      </div>
      <span class="drp-sep">→</span>
      <div class="drp-field" id="drp-field-end" onclick="drpFocusField('end')">
        <span class="drp-field-ico">📅</span>
        <span class="drp-field-val empty" id="drp-val-end" data-i18n-ph-el="Έως..." data-i18n-ph-en="To...">To...</span>
      </div>
      <div class="drp-bar-actions">
        <button class="drp-clear" onclick="clearDateRange()" data-i18n="dr-clear">Clear</button>
        <button class="drp-apply" onclick="applyDateRange()" data-i18n="dr-apply">✓ Apply</button>
      </div>
    </div>
    <!-- Two calendars side by side -->
    <div class="drp-cals">
      <div class="drp-cal" id="drp-cal-left"></div>
      <div class="drp-cal" id="drp-cal-right"></div>
    </div>
    <!-- Footer: shortcuts -->
    <div class="drp-footer">
      <span class="drp-hint" id="drp-hint" data-i18n-el="Επιλέξτε αρχική ημερομηνία" data-i18n-en="Select start date">Select start date</span>
      <div class="drp-shortcut-row">
        <button class="drp-shortcut" onclick="drpShortcut(7)"  data-i18n-el="Τελ. 7 μέρες"  data-i18n-en="Last 7 days">Last 7 days</button>
        <button class="drp-shortcut" onclick="drpShortcut(30)" data-i18n-el="Τελ. 30 μέρες" data-i18n-en="Last 30 days">Last 30 days</button>
        <button class="drp-shortcut" onclick="drpShortcut(90)" data-i18n-el="Τελ. 90 μέρες" data-i18n-en="Last 90 days">Last 90 days</button>
        <button class="drp-shortcut" onclick="drpShortcutYear()" data-i18n-el="5τος έτος" data-i18n-en="This year">This year</button>
      </div>
    </div>
  </div>

  <!-- MESSAGES -->
  <div id="msgs" style="display:none"></div>
  <div id="load-area" style="display:none"></div>

  <!-- NAV AREA with progress strip -->
  <div id="nav-area" style="display:none">
    <div id="nav-progress">
      <div id="nav-progress-bar"><div id="nav-progress-fill"></div></div>
      <div id="nav-progress-lbl"></div>
    </div>
    <div id="nav-buttons"></div>
  </div>
</div>

<!-- CUSTOM CONTEXT MENU -->
<div id="ctx-menu">
  <div class="ctx-item" id="ctx-copy-id" onclick="ctxCopyId()"><span class="ctx-ico">🔑</span>Copy ID</div>
  <div class="ctx-item" id="ctx-copy-name" onclick="ctxCopyName()"><span class="ctx-ico">📋</span>Copy Name</div>
</div>

<!-- LIGHTBOX -->
<div id="lb" onclick="closeLB()">
  <button id="lb-close" onclick="closeLB()">✕</button>
  <img id="lb-img" src="" alt="">
</div>

</div>
<script>
// ── DATA ───────────────────────────────────────────────────
const USER      = {jd(JS["USER"])};
const SERVERS   = {jd(JS["SERVERS"])};
const CHANNELS  = {jd(JS["CHANNELS"])};
const ALL_MSGS  = {jd(JS["ALL_MSGS"])};
const STATS     = {jd(JS["STATS"])};
const SRV_COLORS= {jd(JS["SRV_COLORS"])};
const HAS_AV    = {has_av_js};
const CONNECTIONS  = {jd(JS["CONNECTIONS"])};
const FRIENDS      = {jd(JS["FRIENDS"])};
const NOTES        = {jd(JS["NOTES"])};
const QUESTS       = {jd(JS["QUESTS"])};
const NITRO_HISTORY= {jd(JS["NITRO_HISTORY"])};
const PAYMENTS     = {jd(JS["PAYMENTS"])};
const ORBS_BALANCE = {jd(JS["ORBS_BALANCE"])};
const USER_MAP      = {jd(JS["USER_MAP"])};
const SERVER_ICONS    = {jd(JS["SERVER_ICONS"])};
const SERVER_CHANNELS = {jd(JS["SERVER_CHANNELS"])};
const SERVER_WEBHOOKS = {jd(JS["SERVER_WEBHOOKS"])};
const HARVEST_HISTORY = {jd(JS["HARVEST_HISTORY"])};
const AD_TRAITS       = {jd(JS["AD_TRAITS"])};
const SUPPORT_TICKETS = {jd(JS["SUPPORT_TICKETS"])};
const DEV_APPS        = {jd(JS["DEV_APPS"])};
let PER_PAGE  = 250;

// ── SVG ICONS ──────────────────────────────────────────────
const SVG_PLAY = `<svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6.5 4.2L16.5 10L6.5 15.8V4.2Z" fill="white" stroke="white" stroke-width="0.5" stroke-linejoin="round"/></svg>`;
const SVG_PAUSE = `<svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="4.5" y="3" width="4" height="14" rx="1.5" fill="white"/><rect x="11.5" y="3" width="4" height="14" rx="1.5" fill="white"/></svg>`;
const SVG_TENOR_PLAY = `<svg width="56" height="28" viewBox="0 0 56 28" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="56" height="28" rx="6" fill="rgba(0,0,0,0.70)"/><rect x="0.5" y="0.5" width="55" height="27" rx="5.5" stroke="rgba(255,255,255,0.28)"/><text x="28" y="20" font-size="15" font-weight="800" fill="white" text-anchor="middle" font-family="Arial,sans-serif" letter-spacing="1">GIF</text></svg>`;
const SVG_GIF_PLAY = `<svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="24" cy="24" r="23" fill="rgba(0,0,0,0.45)" stroke="rgba(255,255,255,0.25)" stroke-width="1.2"/><path d="M18 14L36 24L18 34V14Z" fill="white" stroke="white" stroke-width="0.3" stroke-linejoin="round"/><text x="24" y="40" font-size="10" font-weight="bold" fill="rgba(255,255,255,0.8)" text-anchor="middle">GIF</text></svg>`;

let curCh=null, curPage=1, filt='ALL', railSrv=null, isLoadingMsgs=false, allMsgsLoaded=false;
let dateRange = {{ start: null, end: null }};

// ── COLORS ─────────────────────────────────────────────────
function hslGrad(h, a=0.9) {{
  return `linear-gradient(135deg,hsl(${{h}},70%,${{a>0.5?38:28}}%) 0%,hsl(${{(h+40)%360}},65%,${{a>0.5?48:38}}%) 100%)`;
}}
function hslSolid(h) {{ return `hsl(${{h}},60%,42%)`; }}

function srvColor(name) {{
  const h = SRV_COLORS[name];
  if (h !== undefined) return h;
  let v=0; for(let c of name) v=(v*31+c.charCodeAt(0))&0xffff;
  return v%360;
}}

// ── INIT ───────────────────────────────────────────────────
function init() {{
  const gname = USER.global_name || USER.username || 'Unknown';

  // User panel
  document.getElementById('u-name-el').textContent = gname;
  document.getElementById('u-tag-el').textContent  = '@'+USER.username;

  // Hero
  document.getElementById('hero-name-el').textContent = gname;
  document.getElementById('hero-user-el').textContent  = '@'+USER.username + (USER.email ? '  ·  '+USER.email : '');
  if (!HAS_AV) {{
    document.getElementById('hero-av-el').textContent = ini(gname);
    document.getElementById('u-av').textContent       = ini(gname);
  }}

  // ── Hero badges ──
  buildHeroBadges();

  // ── Stat cards (single row) ──
  const sr = document.getElementById('stats-row-el');
  const voice = STATS.voice || 0;
  const totalWords = STATS.words.reduce((s,[,c])=>s+c,0);
  const statDefs = [
    ['💬', fmt(STATS.total),       'Μηνύματα',  'Messages'],
    ['🗂️', fmt(CHANNELS.length),   'Κανάλια',   'Channels'],
    ['🏰', fmt(STATS.servers),     'Servers',   'Servers'],
    ['🎙️', fmt(voice),             'Voice',     'Voice'],
    ['📝', fmt(totalWords),        'Λέξεις',    'Words'],
    ['🖼️', fmt(STATS.att_images),  'Εικόνες',   'Images'],
    ['🎥', fmt(STATS.att_videos),  'Βίντεο',    'Videos'],
    ['📎', fmt(STATS.att_files),   'Αρχεία',    'Files'],
  ];
  statDefs.forEach(([ico,num,grLbl,enLbl]) => {{
    const d=document.createElement('div');
    d.className='stat-card';
    d.innerHTML=`<div class="stat-card-ico">${{ico}}</div><div class="stat-card-body"><div class="stat-card-num">${{num}}</div><div class="stat-card-lbl" data-gr="${{grLbl}}" data-en="${{enLbl}}">${{grLbl}}</div></div>`;
    sr.appendChild(d);
  }});

  // ── First message date — injected as badge into hero-badges ──
  if (STATS.first_ts) {{
    const el = document.getElementById('hero-badges-el');
    const fmt2 = ts => ts ? fmtDate(ts.slice(0,10)) : '—';
    const b = document.createElement('div');
    b.className = 'hbadge hb-date';
    b.innerHTML = `<span class="badge-icon">🌱</span><span class="badge-text"><span class="badge-label" data-i18n="badge-firstmsg">Πρώτο μήνυμα</span><span class="badge-value">${{fmt2(STATS.first_ts)}}</span></span>`;
    el.appendChild(b);
  }}

  // Top servers / DMs
  buildTopServers();
  buildTopDMs();
  buildRail();
  renderChs(CHANNELS);

  // Search
  document.getElementById('srch').addEventListener('input', e => applyFilters(e.target.value));

  // Build emoji + word cloud immediately (DOM-based, no canvas needed)
  buildEmojiRow();
  buildWordCloud();

  // Chart
  setTimeout(() => {{ drawActivity(); }}, 50);

  // Κάνε το DM button default κατά το άνοιγμα
  setTimeout(() => {{
    const dmBtn = document.querySelectorAll('.filt-btn')[0];
    if (dmBtn && !railSrv) {{
      setFilt(dmBtn, 'DM');
    }}
  }}, 100);

  // ── Extra sections (new data) ──
  buildExtraSections();
}}

// ── HERO BADGES ────────────────────────────────────────────
function buildHeroBadges() {{
  const el = document.getElementById('hero-badges-el');
  
  function makeBadge(cls, icon, label, i18nKey, value) {{
    const b = document.createElement('div');
    b.className = 'hbadge ' + cls;
    if (value !== undefined) {{
      b.innerHTML = `<span class="badge-icon">${{icon}}</span><span class="badge-text"><span class="badge-label"${{i18nKey?' data-i18n="'+i18nKey+'"':''}}>${{label}}</span><span class="badge-value">${{value}}</span></span>`;
    }} else {{
      b.innerHTML = `<span class="badge-icon">${{icon}}</span><span class="badge-label" style="opacity:1"${{i18nKey?' data-i18n="'+i18nKey+'"':''}}>${{label}}</span>`;
    }}
    return b;
  }}

  // Nitro
  if (USER.premium_until && USER.premium_until !== '') {{
    const until = USER.premium_until.split('T')[0];
    const [y,m,d] = until.split('-');
    el.appendChild(makeBadge('hb-nitro hb-i18n','⚡','Nitro λήγει','nitro-lbl',`${{d}}/${{m}}/${{y}}`));
  }}
  
  // Mobile
  if (USER.has_mobile) {{
    el.appendChild(makeBadge('hb-mobile hb-i18n','📱','Mobile','mobile-lbl'));
  }}
  
  // Phone Verified
  if (USER.has_phone) {{
    el.appendChild(makeBadge('hb-phone hb-i18n','✅','Phone Verified','phone-lbl'));
  }}
  
  // Discord join date
  if (USER.created_at) {{
    const created = USER.created_at.split('T')[0];
    const [y,m,d] = created.split('-');
    const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    el.appendChild(makeBadge('hb-discord hb-i18n','🎂','Μέλος από','discord-lbl',`${{d}} ${{MONTHS[parseInt(m)-1]}} ${{y}}`));
  }}
  
  // HypeSquad
  USER.badges.forEach(badgeName => {{
    if (badgeName.includes('HypeSquad')) {{
      el.appendChild(makeBadge('hb-hype hb-i18n','💡','HypeSquad Brilliance','hype-lbl'));
    }}
  }});
}}

// ── TOP SERVERS ────────────────────────────────────────────
// Build a server-name → guild_id lookup (used by both buildTopServers and buildRail)
function _srvNameToSid() {{
  const m = {{}};
  Object.entries(SERVERS).forEach(([sid, name]) => {{ m[name] = sid; }});
  return m;
}}

function buildTopServers() {{
  const g = document.getElementById('srv-grid-el');
  const maxV = STATS.top_servers[0]?.[1] || 1;
  const left  = document.createElement('div');
  const right = document.createElement('div');
  left.className = right.className = 'srv-col';

  const nameToSid = _srvNameToSid();

  STATS.top_servers.forEach(([name,cnt], i) => {{
    const h       = srvColor(name);
    const abbr    = name.replace(/[^a-zA-ZΑ-Ωα-ω0-9 ]/g,'').trim();
    const ini2    = abbr.split(' ').map(w=>w[0]||'').join('').toUpperCase().slice(0,2) || '?';
    const sid     = nameToSid[name] || '';
    const iconUrl = sid ? SERVER_ICONS[sid] : null;

    const d = document.createElement('div');
    d.className = 'srv-card';

    // Icon: real image if available, else colored letter abbreviation
    const icoHtml = iconUrl
      ? `<div class="srv-card-ico" style="background:${{hslGrad(h,1)}};padding:0;overflow:hidden">
           <img src="${{iconUrl}}" style="width:46px;height:46px;object-fit:cover;border-radius:var(--r2);display:block" loading="lazy">
         </div>`
      : `<div class="srv-card-ico" style="background:${{hslGrad(h,1)}}">${{ini2}}</div>`;

    d.innerHTML = `
      ${{icoHtml}}
      <div class="srv-card-info">
        <div class="srv-card-name">${{esc(name)}}</div>
        <div class="srv-card-msgs" data-cnt="${{cnt}}">${{fmt(cnt)}} ${{LANG==='el'?'μηνύματα':'messages'}}</div>
        <div class="srv-card-bar"><div class="srv-card-bar-fill" style="width:${{Math.round(cnt/maxV*100)}}%;background:${{hslSolid(h)}}"></div></div>
      </div>`;
    d.onclick = () => filterSrv(name);
    (i < 4 ? left : right).appendChild(d);
  }});
  g.appendChild(left);
  g.appendChild(right);
}}

// ── TOP DMs ────────────────────────────────────────────────
function buildTopDMs() {{
  const dl   = document.getElementById('dm-list-el');
  const maxV = STATS.top_dms[0]?.[1] || 1;
  const ranks= ['🥇','🥈','🥉','4','5','6','7','8','9','10'];
  const left  = document.createElement('div');
  const right = document.createElement('div');
  left.className = right.className = 'dm-col';

  STATS.top_dms.forEach(([name,cnt,id], i) => {{
    const d = document.createElement('div');
    d.className='dm-row';
    if (id) d.dataset.id = id;
    d.innerHTML=`
      <div class="dm-rank">${{ranks[i]||i+1}}</div>
      <div class="dm-av" style="background:hsl(${{_authorHue(name)}},55%,38%)">${{ini(name)}}</div>
      <div class="dm-info">
        <div class="dm-name">${{esc(name)}}</div>
        <div class="dm-msgs" data-cnt="${{cnt}}">${{fmt(cnt)}} ${{LANG==='el'?'μηνύματα':'messages'}}</div>
        <div class="dm-bar-wrap"><div class="dm-bar" style="width:${{Math.round(cnt/maxV*100)}}%;background:var(--accent)"></div></div>
      </div>`;
    d.onclick = () => {{
      const ch = CHANNELS.find(c=>c.id===id);
      if (ch) openCh(ch);
    }};
    (i < 5 ? left : right).appendChild(d);
  }});
  dl.appendChild(left);
  dl.appendChild(right);
}}

// ── EMOJI ROW ──────────────────────────────────────────────
function buildEmojiRow() {{
  const el = document.getElementById('emoji-row-el');
  if (!el || !STATS.emoji || !STATS.emoji.length) {{
    el && (el.parentElement.style.display='none'); return;
  }}
  STATS.emoji.forEach(([em, cnt]) => {{
    const d = document.createElement('div');
    d.className = 'emoji-item';
    d.title = `${{em}} — ${{cnt.toLocaleString('el-GR')}} φορές`;
    d.innerHTML = `<div class="emoji-glyph">${{em}}</div><div class="emoji-cnt">${{fmt(cnt)}}</div>`;
    el.appendChild(d);
  }});
}}

// ── WORD CLOUD ─────────────────────────────────────────────
function buildWordCloud() {{
  const el = document.getElementById('wordcloud-el');
  if (!el || !STATS.words || !STATS.words.length) {{
    el && (el.parentElement.style.display='none'); return;
  }}
  const maxCnt = STATS.words[0][1] || 1;
  const hues = [220, 260, 200, 160, 280, 180, 300];
  STATS.words.forEach(([word, cnt], i) => {{
    const ratio = cnt / maxCnt;
    const size  = Math.round(11 + ratio * 22);   // 11px – 33px
    const op    = 0.45 + ratio * 0.55;
    const h     = hues[i % hues.length];
    const span  = document.createElement('span');
    span.className = 'wc-word';
    span.textContent = word;
    span.title = `${{word}}: ${{cnt.toLocaleString('el-GR')}} φορές`;
    span.style.cssText = `font-size:${{size}}px;color:hsl(${{h}},65%,65%);opacity:${{op.toFixed(2)}}`;
    el.appendChild(span);
  }});
}}

// ── TOP TAB SWITCH (Servers / DMs) ─────────────────────────
function switchTopTab(tab) {{
  const isServers = tab === 'servers';
  document.getElementById('panel-servers').style.display = isServers ? '' : 'none';
  document.getElementById('panel-dms').style.display     = isServers ? 'none' : '';
  document.getElementById('tab-servers').classList.toggle('on', isServers);
  document.getElementById('tab-dms').classList.toggle('on', !isServers);
}}

// ── RAIL ───────────────────────────────────────────────────
function buildRail() {{
  const rail = document.getElementById('rail-srvs');
  
  // Υπολογισμός μηνυμάτων ανά server
  const srvMsgCount = new Map();
  CHANNELS.forEach(ch => {{
    if (ch.server && ch.server !== 'DM') {{
      srvMsgCount.set(ch.server, (srvMsgCount.get(ch.server) || 0) + ch.count);
    }}
  }});
  
  // Δημιουργία λίστας servers που έχουν μηνύματα, ταξινομημένη φθίνουσα
  const serversWithMsgs = [];
  Object.entries(SERVERS).forEach(([sid, name]) => {{
    const count = srvMsgCount.get(name) || 0;
    if (count > 0) {{
      serversWithMsgs.push({{ sid, name, count }});
    }}
  }});

  // Ταξινόμηση βάσει μηνυμάτων (φθίνουσα)
  serversWithMsgs.sort((a, b) => b.count - a.count);

  // Δημιουργία rail icons
  serversWithMsgs.forEach(({{ sid, name, count }}) => {{
    const h    = srvColor(name);
    const abbr = name.replace(/[^a-zA-ZΑ-Ωα-ω0-9 ]/g,'').trim();
    const ini2 = abbr.split(' ').map(w=>w[0]||'').join('').toUpperCase().slice(0,2)||'?';

    // wrap: pill lives here (outside overflow:hidden) to prevent shadow flicker
    const wrap = document.createElement('div');
    wrap.className = 'rail-wrap';

    const pill = document.createElement('div');
    pill.className = 'rail-pill';
    wrap.appendChild(pill);

    const el   = document.createElement('div');
    el.className = 'rail-icon';
    el.setAttribute('data-tip', `${{name}} (${{fmt(count)}} ${{LANG==='el'?'μηνύματα':'messages'}})`);
    el.setAttribute('data-cnt', count);
    el.setAttribute('data-name', name);
    el.setAttribute('data-sid', sid);
    el.style.cssText = `--srv-color:hsl(${{h}},60%,42%);--srv-glow:hsla(${{h}},65%,52%,0.52);background:#111214;color:#fff;font-size:14px`;
    // Show server icon if available, else text abbreviation
    if (SERVER_ICONS[sid]) {{
      el.innerHTML = `<img src="${{SERVER_ICONS[sid]}}" style="width:40px;height:40px;border-radius:50%;object-fit:cover;position:absolute;left:50%;top:50%;transform:translate(-50%,-50%)" alt="">`;
    }} else {{
      el.innerHTML = ini2;
    }}
    el.onclick = (e) => {{
      if (e.ctrlKey || e.metaKey) {{
        // Ctrl+click → open server detail modal
        openSrvDetail(sid, name);
      }} else {{
        filterSrv(name); activateRail(el);
      }}
    }};
    el.addEventListener('contextmenu', (e) => {{
      e.preventDefault();
      openSrvDetail(sid, name);
    }});
    wrap.appendChild(el);
    rail.appendChild(wrap);
  }});
}}

function activateRail(el) {{
  // active class goes on rail-wrap (controls pill height) AND rail-icon (controls styles)
  document.querySelectorAll('.rail-icon').forEach(r => {{
    r.classList.remove('active');
    if (r.parentElement && r.parentElement.classList.contains('rail-wrap')) {{
      r.parentElement.classList.remove('active');
    }}
  }});
  document.querySelectorAll('#rail-home-wrap').forEach(r=>r.classList.remove('active'));
  if (el) {{
    el.classList.add('active');
    if (el.parentElement && el.parentElement.classList.contains('rail-wrap')) {{
      el.parentElement.classList.add('active');
    }}
  }}
}}

// ── FILTERS ────────────────────────────────────────────────
function setFilt(btn, mode) {{
  filt=mode;
  document.querySelectorAll('.filt-btn').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  applyFilters(document.getElementById('srch').value);
}}

function filterSrv(name) {{
  railSrv=name;

  // Κάνε το Server button active (index 2: DM=0, Friends=1, Server=2)
  const serverBtn = document.querySelectorAll('.filt-btn')[2];
  setFilt(serverBtn, 'SERVER');
  
  // Sync rail icon
  const railIcon = document.querySelector(`.rail-icon[data-name="${{name}}"]`);
  activateRail(railIcon);

  applyFilters(document.getElementById('srch').value);
}}

function showHome(el) {{
  // Κάνε το DM button default πατημένο
  const dmBtn = document.querySelectorAll('.filt-btn')[0];
  setFilt(dmBtn, 'DM');

  // Prevent flicker: skip re-activation if already active
  if (!el || !el.classList.contains('active')) {{
    activateRail(el);
    // also activate the wrap for pill
    const homeWrap = document.getElementById('rail-home-wrap');
    if (homeWrap) homeWrap.classList.add('active');
  }}
  railSrv=null;
  applyFilters(document.getElementById('srch').value);
  document.getElementById('home').style.display   ='flex';
  document.getElementById('ch-hdr').style.display ='none';
  document.getElementById('msgs').style.display   ='none';
  document.getElementById('load-area').style.display='none';
  // Close date range picker if open
  document.getElementById('date-range-picker').classList.remove('visible');
  // hide nav buttons on home screen
  const _nb = document.getElementById('nav-buttons');
  if (_nb) _nb.style.visibility = 'hidden';
  const _bla = document.getElementById('btm-load-all-btn');
  if (_bla) _bla.style.display = 'none';
  curCh=null;
  document.querySelectorAll('.ch-item').forEach(c=>c.classList.remove('sel'));
}}

function applyFilters(q) {{
  q=q.toLowerCase().trim();

  if (filt === 'FRIENDS') {{
    renderFriendsChs(q);
    return;
  }}

  let list=CHANNELS;
  if (filt!=='ALL')  list=list.filter(c=>c.type===filt);
  if (railSrv)       list=list.filter(c=>c.server===railSrv);
  if (q) list=list.filter(c=>c.name.toLowerCase().includes(q)||c.server.toLowerCase().includes(q));
  renderChs(list);
}}

// Match friends to DM channels, sorted by message count
function renderFriendsChs(q) {{
  const el = document.getElementById('ch-list');
  el.innerHTML = '';
  if (!FRIENDS || !FRIENDS.friends || !FRIENDS.friends.length) {{
    el.innerHTML = '<div class="ch-section" style="color:var(--muted);padding:12px">No friends data</div>';
    return;
  }}
  // Build DM channel lookup: clean name (no #discriminator) → channel obj
  const dmLookup = {{}};
  CHANNELS.filter(c => c.type === 'DM').forEach(ch => {{
    const clean = ch.name.replace(/#\\d+$/, '').toLowerCase().trim();
    dmLookup[clean] = ch;
  }});

  // Match each friend to their DM channel
  let matched = [];
  FRIENDS.friends.forEach(f => {{
    const uname = (f.username || '').toLowerCase();
    const gname = (f.name || '').toLowerCase();
    const ch = dmLookup[uname] || dmLookup[gname];
    if (ch) {{
      matched.push({{ friend: f, ch: ch }});
    }}
  }});

  // Sort by message count descending
  matched.sort((a, b) => b.ch.count - a.ch.count);

  // Apply search filter
  if (q) {{
    matched = matched.filter(m =>
      m.friend.name.toLowerCase().includes(q) ||
      m.friend.username.toLowerCase().includes(q) ||
      m.ch.name.toLowerCase().includes(q)
    );
  }}

  el.innerHTML = `<div class="ch-section">👥 ${{LANG==='el'?'Φίλοι':'Friends'}} (${{matched.length}})</div>`;
  matched.forEach(m => el.appendChild(makeChItem(m.ch)));
}}

// ── CHANNEL LIST ───────────────────────────────────────────
function renderChs(list) {{
  const el = document.getElementById('ch-list');
  el.innerHTML = '';
  // Section headers
  const dms  = list.filter(c=>c.type==='DM');
  const srvs = list.filter(c=>c.type==='SERVER');

  if ((filt==='ALL'||filt==='DM') && dms.length) {{
    el.innerHTML += `<div class="ch-section">👤 DMs (${{dms.length}})</div>`;
    dms.forEach(ch => el.appendChild(makeChItem(ch)));
  }}
  if ((filt==='ALL'||filt==='SERVER') && srvs.length) {{
    el.innerHTML += `<div class="ch-section"># Servers (${{srvs.length}})</div>`;
    srvs.forEach(ch => el.appendChild(makeChItem(ch)));
  }}
}}

function makeChItem(ch) {{
  const row = document.createElement('div');
  row.className = 'ch-item'+(curCh?.id===ch.id?' sel':'');
  row.dataset.id = ch.id;

  const isDM = ch.type==='DM';
  let avHtml, subHtml;
  if (isDM) {{
    const h=(ch.name.split('').reduce((a,c)=>a+c.charCodeAt(0),0)*37)%360;
    avHtml=`<div class="ch-av" style="background:${{hslGrad(h,1)}}">${{ini(ch.name)}}</div>`;
    subHtml = '';
  }} else {{
    const h=srvColor(ch.server||ch.name);
    avHtml=`<div class="ch-av" style="background:${{hslGrad(h,1)}}">#</div>`;
    subHtml = `<div class="ch-sub">${{esc(ch.server||'')}}</div>`;
  }}

  row.innerHTML = `
    ${{avHtml}}
    <div class="ch-body">
      <div class="ch-name">${{esc(ch.name)}}</div>
      ${{subHtml}}
    </div>
    <div class="ch-badge">${{fmt(ch.count)}}</div>`;
  row.onclick = () => openCh(ch);
  return row;
}}

// ── OPEN CHANNEL ───────────────────────────────────────────
function openCh(ch) {{
  curCh=ch; curPage=1; allMsgsLoaded=false;
  dateRange = {{ start: null, end: null }};
  _drp.selStart = null; _drp.selEnd = null; _drp.focus = 'start';
  // Close date picker if open
  document.getElementById('date-range-picker').classList.remove('visible');
  document.querySelectorAll('.ch-item').forEach(r=>r.classList.toggle('sel',r.dataset.id===ch.id));
  document.getElementById('home').style.display    ='none';
  document.getElementById('ch-hdr').style.display  ='flex';
  document.getElementById('msgs').style.display    ='flex';
  document.getElementById('load-area').style.display='block';

  document.getElementById('hdr-ico-el').textContent  = ch.type==='DM' ? '👤' : '#';
  document.getElementById('hdr-name-el').textContent = ch.name;
  document.getElementById('hdr-sep-el').textContent  = ch.server ? ' · ' : '';
  document.getElementById('hdr-srv-el').textContent  = ch.server||'';
  document.getElementById('hdr-cnt-el').textContent  = ch.count.toLocaleString('el-GR')+(LANG==='el'?' μηνύματα':' messages');
  
  // Deactivate Home icon if navigating to a channel
  if (ch.type === 'DM') {{
    activateRail(null);
  }} else if (ch.server) {{
    const railIcon = document.querySelector(`.rail-icon[data-name="${{ch.server}}"]`);
    activateRail(railIcon);
  }}
  
  // Ορισμός min/max για custom date picker
  if (ch.messages && ch.messages.length) {{
    _drp.minDate = ch.messages[ch.messages.length-1].ts.slice(0,10);
    _drp.maxDate = ch.messages[0].ts.slice(0,10);
  }}
  
  document.getElementById('msgs').innerHTML = '';
  const area = document.getElementById('msgs');
  delete area.dataset.prevDate;
  delete area.dataset.prevTsMs;
  renderMsgs();

  // Set initial scroll position to bottom
  requestAnimationFrame(() => {{
    area.scrollTop = area.scrollHeight;
  }});
}} // ─────────────────────────────────
// ── CUSTOM DATE RANGE PICKER ────────────────────────────────
const MONTHS_GR = ['Ιανουάριος','Φεβρουάριος','Μάρτιος','Απρίλιος','Μάιος','Ιούνιος',
                   'Ιούλιος','Αύγουστος','Σεπτέμβριος','Οκτώβριος','Νοέμβριος','Δεκέμβριος'];
const MONTHS_EN = ['January','February','March','April','May','June',
                   'July','August','September','October','November','December'];
const WD_GR = ['Κυ','Δε','Τρ','Τε','Πε','Πα','Σα'];
const WD_EN = ['Su','Mo','Tu','We','Th','Fr','Sa'];

let _drp = {{
  selStart: null,   // 'YYYY-MM-DD' | null
  selEnd:   null,
  focus:    'start',  // which field is being filled
  leftYear: 0, leftMonth: 0,   // calendars' current view
  rightYear: 0, rightMonth: 0,
  hoverDay: null,
  minDate:  null,
  maxDate:  null,
}};

function _drpFmt(dateStr) {{
  if (!dateStr) return null;
  const [y,m,d] = dateStr.split('-');
  return `${{parseInt(d).toString().padStart(2,'0')}}/${{parseInt(m).toString().padStart(2,'0')}}/${{y}}`;
}}

function toggleDateRangePicker() {{
  const el = document.getElementById('date-range-picker');
  const isVis = el.classList.contains('visible');
  if (isVis) {{ el.classList.remove('visible'); return; }}
  // Init view to span the current channel's date range
  const now = new Date();
  let ry = now.getFullYear(), rm = now.getMonth();
  let ly = ry, lm = rm - 1;
  if (lm < 0) {{ lm = 11; ly--; }}
  // If channel has messages, seed from its range
  if (curCh) {{
    const msgs = ALL_MSGS[curCh.id] || [];
    if (msgs.length) {{
      const first = msgs[msgs.length-1].ts.slice(0,7);
      const last  = msgs[0].ts.slice(0,7);
      _drp.minDate = msgs[msgs.length-1].ts.slice(0,10);
      _drp.maxDate = msgs[0].ts.slice(0,10);
      const [fy,fm] = last.split('-').map(Number);
      ry = fy; rm = fm-1;
      ly = rm-1 < 0 ? ry-1 : ry;
      lm = rm-1 < 0 ? 11 : rm-1;
    }}
  }}
  _drp.leftYear=ly; _drp.leftMonth=lm;
  _drp.rightYear=ry; _drp.rightMonth=rm;
  _drp.focus = _drp.selStart ? 'end' : 'start';
  _drpRender();
  el.classList.add('visible');
  _drpUpdateFocusUI();
}}

function drpFocusField(which) {{
  _drp.focus = which;
  _drpUpdateFocusUI();
}}

function _drpUpdateFocusUI() {{
  document.getElementById('drp-field-start').classList.toggle('focus', _drp.focus==='start');
  document.getElementById('drp-field-end').classList.toggle('focus', _drp.focus==='end');
  const hint = document.getElementById('drp-hint');
  if (hint) hint.textContent = _drp.focus==='start' ? 'Επιλέξτε αρχική ημερομηνία' : 'Επιλέξτε τελική ημερομηνία';
}}

function _drpRender() {{
  _drpRenderCal('left',  _drp.leftYear,  _drp.leftMonth);
  _drpRenderCal('right', _drp.rightYear, _drp.rightMonth);
  // update field labels
  const sv = document.getElementById('drp-val-start');
  const ev = document.getElementById('drp-val-end');
  if (_drp.selStart) {{ sv.textContent = _drpFmt(_drp.selStart); sv.classList.remove('empty'); }}
  else {{ sv.textContent = 'Από...'; sv.classList.add('empty'); }}
  if (_drp.selEnd) {{ ev.textContent = _drpFmt(_drp.selEnd); ev.classList.remove('empty'); }}
  else {{ ev.textContent = 'Έως...'; ev.classList.add('empty'); }}
}}

function _drpRenderCal(side, year, month) {{
  const el = document.getElementById('drp-cal-'+side);
  if (!el) return;
  const isLeft = side === 'left';
  const WD = LANG==='el' ? WD_GR : WD_EN;
  const MN = LANG==='el' ? MONTHS_GR : MONTHS_EN;
  const today = new Date(); today.setHours(0,0,0,0);
  const todayStr = today.toISOString().slice(0,10);
  // Nav arrows: left cal has prev, right cal has next; between them, shared nav
  const showPrev = isLeft;
  const showNext = !isLeft;
  let html = `<div class="drp-cal-head">`;
  html += `<button class="drp-nav${{showPrev?'':' ghost'}}" onclick="_drpNav(-1)" title="Προηγούμενος">‹</button>`;
  html += `<span class="drp-cal-title">${{MN[month]}} ${{year}}</span>`;
  html += `<button class="drp-nav${{showNext?'':' ghost'}}" onclick="_drpNav(1)" title="Επόμενος">›</button>`;
  html += `</div>`;
  // Weekdays
  html += '<div class="drp-weekdays">';
  WD.forEach(w => html += `<div class="drp-wd">${{w}}</div>`);
  html += '</div>';
  // Days
  html += '<div class="drp-days">';
  const firstDay = new Date(year, month, 1).getDay();
  const daysInMonth = new Date(year, month+1, 0).getDate();
  const daysInPrev  = new Date(year, month, 0).getDate();
  // leading other-month
  for (let i=0;i<firstDay;i++) {{
    const d = daysInPrev - firstDay + 1 + i;
    html += `<div class="drp-day other-month">${{d}}</div>`;
  }}
  for (let d=1;d<=daysInMonth;d++) {{
    const dateStr = `${{year}}-${{String(month+1).padStart(2,'0')}}-${{String(d).padStart(2,'0')}}`;
    let cls = 'drp-day';
    if (dateStr === todayStr) cls += ' today';
    const isSS = dateStr === _drp.selStart;
    const isSE = dateStr === _drp.selEnd;
    const inRange = _drp.selStart && _drp.selEnd && dateStr > _drp.selStart && dateStr < _drp.selEnd;
    if (isSS) cls += ' sel-start' + (_drp.selEnd?' has-end':'');
    if (isSE) cls += ' sel-end' + (_drp.selStart?' has-start':'');
    if (inRange) {{
      cls += ' in-range';
      // Check row boundary
      const col = (new Date(year, month, d).getDay());
      if (col === 0) cls += ' range-row-start';
      if (col === 6) cls += ' range-row-end';
    }}
    // disabled?
    if (_drp.minDate && dateStr < _drp.minDate) cls += ' other-month';
    if (_drp.maxDate && dateStr > _drp.maxDate) cls += ' other-month';
    html += `<div class="${{cls}}" onclick="_drpSelectDay('${{dateStr}}')" title="${{dateStr}}">${{d}}</div>`;
  }}
  // trailing
  const total = firstDay + daysInMonth;
  const trailing = total % 7 === 0 ? 0 : 7 - (total % 7);
  for (let i=1;i<=trailing;i++) html += `<div class="drp-day other-month">${{i}}</div>`;
  html += '</div>';
  el.innerHTML = html;
}}

function _drpNav(dir) {{
  // Move both calendars together
  let lm = _drp.leftMonth + dir;
  let ly = _drp.leftYear;
  if (lm < 0)  {{ lm = 11; ly--; }}
  if (lm > 11) {{ lm = 0;  ly++; }}
  let rm = lm + 1, ry = ly;
  if (rm > 11) {{ rm = 0; ry++; }}
  _drp.leftYear=ly; _drp.leftMonth=lm;
  _drp.rightYear=ry; _drp.rightMonth=rm;
  _drpRender();
}}

function _drpSelectDay(dateStr) {{
  if (_drp.focus === 'start') {{
    _drp.selStart = dateStr;
    // If end is before new start, clear it
    if (_drp.selEnd && _drp.selEnd < dateStr) _drp.selEnd = null;
    _drp.focus = 'end';
  }} else {{
    if (_drp.selStart && dateStr < _drp.selStart) {{
      // Swap: clicked before start
      _drp.selEnd = _drp.selStart;
      _drp.selStart = dateStr;
      _drp.focus = 'start';
    }} else {{
      _drp.selEnd = dateStr;
      _drp.focus = 'start';
    }}
  }}
  _drpRender();
  _drpUpdateFocusUI();
}}

function drpShortcut(days) {{
  const end = new Date(); end.setHours(0,0,0,0);
  const start = new Date(end); start.setDate(start.getDate() - days + 1);
  _drp.selStart = start.toISOString().slice(0,10);
  _drp.selEnd   = end.toISOString().slice(0,10);
  // Snap calendar to show the range end
  const rm = end.getMonth(), ry = end.getFullYear();
  let lm = rm-1, ly = ry;
  if (lm<0) {{ lm=11; ly--; }}
  _drp.leftYear=ly; _drp.leftMonth=lm;
  _drp.rightYear=ry; _drp.rightMonth=rm;
  _drpRender();
  _drpUpdateFocusUI();
}}

function drpShortcutYear() {{
  // This year
  const now = new Date();
  const y = now.getFullYear();
  _drp.selStart = `${{y}}-01-01`;
  _drp.selEnd   = `${{y}}-12-31`;
  const ly=y, lm=0, rm=6, ry=y;
  _drp.leftYear=ly; _drp.leftMonth=lm;
  _drp.rightYear=ry; _drp.rightMonth=rm;
  _drpRender();
  _drpUpdateFocusUI();
}}

function applyDateRange() {{
  const start = _drp.selStart;
  const end   = _drp.selEnd;
  if (!start && !end) {{
    dateRange = {{ start: null, end: null }};
  }} else {{
    dateRange = {{
      start: start ? start + 'T00:00:00' : null,
      end:   end   ? end   + 'T23:59:59' : null,
    }};
  }}
  curPage = 1;
  const _a1 = document.getElementById('msgs');
  _a1.innerHTML = ''; delete _a1.dataset.prevDate; delete _a1.dataset.prevTsMs;
  renderMsgs();
  document.getElementById('date-range-picker').classList.remove('visible');
}}

function clearDateRange() {{
  _drp.selStart = null; _drp.selEnd = null;
  _drp.focus = 'start';
  _drpRender();
  _drpUpdateFocusUI();
  dateRange = {{ start: null, end: null }};
  curPage = 1;
  const _a2 = document.getElementById('msgs');
  _a2.innerHTML = ''; delete _a2.dataset.prevDate; delete _a2.dataset.prevTsMs;
  renderMsgs();
}}

// Close DRP on outside click
document.addEventListener('click', function(e) {{
  const drp = document.getElementById('date-range-picker');
  const btn = document.getElementById('hdr-dr-btn');
  if (drp && drp.classList.contains('visible')) {{
    if (!drp.contains(e.target) && e.target !== btn && !btn.contains(e.target)) {{
      drp.classList.remove('visible');
    }}
  }}
}}, true);

function filterMessagesByDate(messages) {{
  if (!dateRange.start && !dateRange.end) return messages;
  
  return messages.filter(m => {{
    const ts = m.ts;
    if (dateRange.start && ts < dateRange.start) return false;
    if (dateRange.end && ts > dateRange.end) return false;
    return true;
  }});
}}

// ── AUTHOR COLOR HELPER ────────────────────────────────────
function _authorHue(name) {{
  let h = 0;
  for (let c of String(name||'?')) h = (h * 31 + c.charCodeAt(0)) & 0xffff;
  return h % 360;
}}

// ── RENDER MESSAGES ────────────────────────────────────────
// ── MESSAGE ANNOTATION ────────────────────────────────────
// Pass 1: pure JS, no DOM — computes date-sep and continuation flags for the
// entire slice in one O(n) sweep.  Fast even for 10 000 messages.
function _annotateSlice(slice, initDate, initTsMs, initAuthor) {{
  const myName = USER.global_name || USER.username || '';
  let pDate   = initDate   || '';
  let pTsMs   = initTsMs   || 0;
  let pAuthor = initAuthor || '';
  return slice.map(m => {{
    const date       = m.ts.slice(0, 10);
    const tsMs       = Date.parse(m.ts) || 0;
    const authorName = (m.author && m.author.trim()) ? m.author : myName;
    const isOwn      = !m.author || m.author.trim() === myName;
    const needDateSep = date !== pDate;
    const isCont      = !needDateSep
                      && pTsMs > 0
                      && (tsMs - pTsMs) < 5 * 60 * 1000
                      && pAuthor === authorName;
    if (needDateSep) {{ pDate = date; pTsMs = 0; pAuthor = ''; }}
    pTsMs   = tsMs;
    pAuthor = authorName;
    return {{ m, date, authorName, isOwn, needDateSep, isCont }};
  }});
}}

// Pass 2: DOM build — converts pre-annotated items into a DocumentFragment.
// No state tracking needed here; all decisions are already made.
function _buildAnnotatedFragment(items) {{
  const frag = document.createDocumentFragment();
  items.forEach(({{ m, date, authorName, isOwn, needDateSep, isCont }}) => {{
    if (needDateSep) {{
      const sep = document.createElement('div');
      sep.className = 'date-sep';
      sep.setAttribute('data-date', date);
      sep.textContent = fmtDate(date);
      frag.appendChild(sep);
    }}

    const avHtml = (isOwn && HAS_AV)
      ? '<div class="msg-av has-gif"></div>'
      : `<div class="msg-av" style="background:hsl(${{_authorHue(authorName)}},58%,40%)">${{ini(authorName)}}</div>`;

    const authorColor = isOwn
      ? 'var(--blurple)'
      : `hsl(${{_authorHue(authorName)}},75%,68%)`;

    let body = '';
    if (!isCont) {{
      body += '<div class="msg-header">'
        + `<span class="msg-author" style="color:${{authorColor}}">${{esc(authorName)}}</span>`
        + '<span class="msg-ts">' + fmtTime(m.ts) + '</span>'
        + '</div>';
    }}
    if (m.c) {{
      // Tenor GIFs in message content — render as embed instead of plain link
      {MENTION_JS}
            // Replace linkified tenor URLs with iframe embeds
      contentHtml = contentHtml.replace(
        /<a href="(https?:[/][/]tenor[.]com[/]view[/][^"]+)"[^>]*>[^<]+<[/]a>/g,
        (match, url) => {{
          const tenorId = url.split('/').pop().split('-').pop();
          const _tmap = {jd(_TENOR_THUMB_CACHE)};
          const _tthumb = _tmap[tenorId] || '';
          const _tStyle = _tthumb ? ` style="background-image:url('${{_tthumb}}')"` : '';
          return `<div class="att-tenor" data-tenor-id="${{tenorId}}"><iframe data-src="https://tenor.com/embed/${{tenorId}}" src="" allowfullscreen frameborder="0"></iframe><div class="att-tenor-thumb"${{_tStyle}}></div><div class="att-tenor-overlay"><span class="att-tenor-play-icon">${{SVG_TENOR_PLAY}}</span></div></div>`;
        }}
      );
      if (contentHtml.trim()) body += '<div class="msg-content">' + contentHtml + '</div>';
    }}
    if (m.a) {{
      m.a.split(' ').filter(Boolean).forEach(url => {{
        const cl  = url.split('?')[0].toLowerCase();
        const fn  = (url.split('/').pop() || 'file').split('?')[0];
        const fnl = fn.toLowerCase();
        // Tenor link stored as attachment
        if (/tenor[.]com[/]view[/]/.test(url)) {{
          const tenorId = url.split('/').pop().split('-').pop();
          const tenorThumb = {jd(_TENOR_THUMB_CACHE)}[tenorId] || '';
          const thumbStyle = tenorThumb ? ` style="background-image:url('${{tenorThumb}}')"` : '';
          body += `<div class="att-tenor" data-tenor-id="${{tenorId}}">
  <iframe data-src="https://tenor.com/embed/${{tenorId}}" src="" allowfullscreen frameborder="0"></iframe>
  <div class="att-tenor-thumb"${{thumbStyle}}></div>
  <div class="att-tenor-overlay"><span class="att-tenor-play-icon">${{SVG_TENOR_PLAY}}</span></div>
</div>`;
        }} else if (/[.](jpg|jpeg|png|gif|webp)$/.test(cl)) {{
          const isGif = /[.]gif$/.test(cl);
          if (isGif) {{
            body += '<div class="att-gif-wrap" onclick="openLB(\\\'' + esc(url) + '\\\')" title="Click to enlarge">'
                  + '<img src="' + esc(url) + '" loading="lazy" onerror="_imgExpired(this)">'
                  + '<div class="gif-play-btn">${{SVG_GIF_PLAY}}</div>'
                  + '</div>';
          }} else {{
            body += '<div class="att-img" onclick="openLB(\\\'' + esc(url) + '\\\')" title="Click to enlarge">'
                  + '<img src="' + esc(url) + '" loading="lazy" onerror="_imgExpired(this)">'
                  + '</div>';
          }}
        }} else if (/[.](mp4|mov|webm|mkv|m4v|avi)$/.test(cl)) {{
          const vidId = 'vid_' + Math.random().toString(36).slice(2, 8);
          body += `<div class="att-video-wrap paused" id="wrap_${{vidId}}">
  <video id="${{vidId}}" preload="metadata"
    onclick="vidTogglePlay('${{vidId}}')"
    onplay="vidOnPlay('${{vidId}}')"
    onpause="vidOnPause('${{vidId}}')"
    ontimeupdate="vidOnTime('${{vidId}}')"
    onloadedmetadata="vidOnMeta('${{vidId}}')"
    onerror="_vidExpired('${{vidId}}','${{esc(url)}}')"
  ><source src="${{esc(url)}}" onerror="_vidExpired('${{vidId}}','${{esc(url)}}')" ></video>
  <button class="vid-play-btn" id="pbtn_${{vidId}}" onclick="vidTogglePlay('${{vidId}}')">${{SVG_PLAY}}</button>
  <!-- progress bar — hidden when fullscreen -->
  <div class="vid-progress-wrap" id="vprog_${{vidId}}"
    onmousedown="vidSeekStart(event,'${{vidId}}')"
    ontouchstart="vidSeekStart(event,'${{vidId}}')">
    <div class="vid-progress-bg">
      <div class="vid-progress-fill" id="vpfill_${{vidId}}"></div>
    </div>
    <div class="vid-progress-thumb" id="vpthumb_${{vidId}}"></div>
  </div>
  <div class="vid-controls">
    <button class="vid-vol-btn" id="vico_${{vidId}}" onclick="toggleVidMute('${{vidId}}',this)">🔊</button>
    <input type="range" class="vid-slider" id="vslider_${{vidId}}" min="0" max="1" step="0.05" value="1" style="--vol-pct:100%" oninput="setVidVol('${{vidId}}',this)">
    <span class="vid-time" id="vtime_${{vidId}}">0:00</span>
    <button class="vid-action-btn" title="Picture in Picture" onclick="vidPiP('${{vidId}}')">⧉</button>
    <button class="vid-action-btn" title="Fullscreen" onclick="vidFullscreen('${{vidId}}')">⛶</button>
  </div>
</div>`;
        }} else if (/[.](ogg|mp3|m4a|wav|opus|flac|aac)$/.test(cl) || /voice-message/.test(fnl)) {{
          const isVoice = /voice.?message/.test(fnl) || /[.]ogg$/.test(cl);
          const audId = 'aud_' + Math.random().toString(36).slice(2,9);
          body += `<div class="att-voice" id="wrap_${{audId}}">
  <span class="att-voice-ico">${{isVoice ? '🎙️' : '🎵'}}</span>
  <button class="aud-play-btn" id="pbtn_${{audId}}" onclick="audToggle('${{audId}}')" aria-label="Play">▶</button>
  <div class="aud-progress-wrap" id="pbar_${{audId}}" onmousedown="audStartDrag(event,'${{audId}}')" ontouchstart="audStartDrag(event,'${{audId}}')">
    <div class="aud-progress-fill" id="pfill_${{audId}}"></div>
    <div class="aud-progress-thumb" id="pthumb_${{audId}}"></div>
  </div>
  <span class="aud-time" id="ptime_${{audId}}">0:00</span>
  <div class="aud-vol-wrap">
    <button class="aud-vol-btn" id="vbtn_${{audId}}" onclick="audToggleMute('${{audId}}',this)">🔊</button>
    <input class="aud-vol-slider" id="vslider_${{audId}}" type="range" min="0" max="1" step="0.05" value="1"
      oninput="audSetVol('${{audId}}',this)" style="--avol:100%">
  </div>
  <audio id="${{audId}}" preload="metadata" src="${{esc(url)}}"
    ontimeupdate="audUpdate('${{audId}}')" onended="audEnded('${{audId}}')" onloadedmetadata="audMeta('${{audId}}')"></audio>
</div>`;
        }} else {{
          body += '<a class="att-file" href="' + esc(url) + '" target="_blank" rel="noopener">📎 ' + esc(fn) + '</a>';
        }}
      }});
    }}

    const row = document.createElement('div');
    row.className = 'msg' + (isCont ? ' cont' : '');
    row.innerHTML =
      '<div class="msg-av-col">' +
        (isCont ? '<div class="msg-ts-hover">' + fmtTimeShort(m.ts) + '</div>' : avHtml) +
      '</div>' +
      '<div class="msg-body">' + body + '</div>';
    frag.appendChild(row);
  }});
  return frag;
}}

// ── APPEND (initial load) — uses dataset state for continuity across pages ──
function _buildMsgRows(slice, method) {{
  const area = document.getElementById('msgs');
  const initDate   = method === 'append' ? (area.dataset.prevDate   || '') : '';
  const initTsMs   = method === 'append' ? parseInt(area.dataset.prevTsMs || '0') : 0;
  const initAuthor = method === 'append' ? (area.dataset.prevAuthor || '') : '';

  const annotated = _annotateSlice(slice, initDate, initTsMs, initAuthor);
  const frag      = _buildAnnotatedFragment(annotated);

  if (method === 'prepend') {{
    area.prepend(frag);
  }} else {{
    area.appendChild(frag);
    // Save state for next append call
    if (annotated.length) {{
      const last = annotated[annotated.length - 1];
      area.dataset.prevDate   = last.date;
      area.dataset.prevTsMs   = String(Date.parse(last.m.ts) || 0);
      area.dataset.prevAuthor = last.authorName;
    }}
  }}
}}

function updateNav(rem = 0) {{
  const na = document.getElementById('nav-area');
  const nb = document.getElementById('nav-buttons');
  if (!nb) return;
  const isEl = LANG === 'el';
  const loadTxt = isEl ? 'Φόρτωση παλαιότερων' : 'Load older';
  nb.innerHTML =
    '<div class="nav-group">' +
      '<button class="btn-nav" onclick="goToFirst()" title="' + (isEl?'Πρώτο μήνυμα':'First message') + '">' +
        '<span class="nav-arrow">↑</span>' +
        '<span class="nav-lbl">' + (isEl?'Πρώτο':'Top') + '</span>' +
      '</button>' +
      '<button class="btn-nav" onclick="goToLast()" title="' + (isEl?'Τελευταίο μήνυμα':'Last message') + '">' +
        '<span class="nav-arrow">↓</span>' +
        '<span class="nav-lbl">' + (isEl?'Τελευταίο':'Bottom') + '</span>' +
      '</button>' +
    '</div>' +
    '<button id="btm-load-all-btn" onclick="loadMore(true)" style="display:' + (rem > 0 ? 'inline-flex' : 'none') + '">' +
      loadTxt +
    '</button>' +
    '<div style="width:80px"></div>';
  na.style.display = 'flex';
}}

function renderMsgs() {{
  if (!curCh) return;
  // restore nav buttons visibility
  const _nb = document.getElementById('nav-buttons');
  if (_nb) _nb.style.visibility = 'visible';
  const all   = filterMessagesByDate(ALL_MSGS[curCh.id] || []);
  const area  = document.getElementById('msgs');
  const lm    = document.getElementById('load-area');
  
  const start = Math.max(0, all.length - curPage * PER_PAGE);
  const end   = all.length - (curPage - 1) * PER_PAGE;
  const slice = all.slice(start, end);

  _buildMsgRows(slice, 'append');

  lm.innerHTML = '';
  lm.style.display = 'none';
  const btmAllBtn = document.getElementById('btm-load-all-btn');
  if (btmAllBtn) {{
    btmAllBtn.style.display = start > 0 ? 'block' : 'none';
  }}
  updateNav(start);

  if (curPage === 1) area.scrollTop = area.scrollHeight;
}}

function loadMore(loadAll = false) {{
  if (!curCh || isLoadingMsgs) return;
  const all  = filterMessagesByDate(ALL_MSGS[curCh.id] || []);
  const lm   = document.getElementById('load-area');
  const area = document.getElementById('msgs');

  isLoadingMsgs = true;
  if (loadAll) allMsgsLoaded = true;
  curPage++;

  const start = Math.max(0, all.length - curPage * PER_PAGE);
  const end   = all.length - (curPage - 1) * PER_PAGE;
  const slice = loadAll ? all.slice(0, end) : all.slice(start, end);
  const total = slice.length;

  if (!total) {{ isLoadingMsgs = false; return; }}

  _lockNav(true);

  // Show slim progress strip in nav-area
  function _setProgress(pct, done, total) {{
    const np  = document.getElementById('nav-progress');
    const npf = document.getElementById('nav-progress-fill');
    const npl = document.getElementById('nav-progress-lbl');
    if (!np) return;
    if (pct < 0) {{ np.classList.remove('active'); return; }}
    np.classList.add('active');
    if (npf) npf.style.width = pct + '%';
    if (npl) npl.textContent = done + ' / ' + total;
  }}

  _setProgress(0, 0, total);

  const oldScrollTop = area.scrollTop;
  const oldHeight    = area.scrollHeight;

  // Phase 1: Annotate entire slice in one sync JS pass
  const annotated = _annotateSlice(slice);

  // Phase 2: Split into chunks
  const CHUNK = 200;
  const chunks = [];
  for (let i = 0; i < annotated.length; i += CHUNK) {{
    chunks.push(annotated.slice(i, i + CHUNK));
  }}

  // Phase 3: Build DocumentFragments per rAF
  const frags = [];
  let bIdx = 0;

  function buildPhase() {{
    if (bIdx >= chunks.length) {{
      // Phase 4: Prepend frags in reverse order
      let pIdx = frags.length - 1;
      function prependPhase() {{
        if (pIdx < 0) {{
          const newHeight   = area.scrollHeight;
          const addedHeight = newHeight - oldHeight;
          isLoadingMsgs = false;
          _setProgress(-1, 0, 0);
          const rem = loadAll ? 0 : Math.max(0, all.length - curPage * PER_PAGE);
          const btn = document.getElementById('btm-load-all-btn');
          if (btn) btn.style.display = rem > 0 ? 'inline-flex' : 'none';
          updateNav(rem);
          area.scrollTop = loadAll ? area.scrollHeight : oldScrollTop + addedHeight;
          _lockNav(false);
          return;
        }}
        area.prepend(frags[pIdx]);
        pIdx--;
        const done = frags.length - 1 - pIdx;
        const pct  = Math.round((done / frags.length) * 100);
        _setProgress(pct, Math.min(done * CHUNK, total), total);
        requestAnimationFrame(prependPhase);
      }}
      requestAnimationFrame(prependPhase);
      return;
    }}
    frags.push(_buildAnnotatedFragment(chunks[bIdx]));
    bIdx++;
    const pct = Math.round((bIdx / chunks.length) * 50);
    _setProgress(pct, Math.min(bIdx * CHUNK, total), total);
    requestAnimationFrame(buildPhase);
  }}

  requestAnimationFrame(buildPhase);
}}

// ── DEFERRED TASK RUNNER ─────────────────────────────────────
// Yields control to the browser before running heavy work,
// preventing long tasks on the main thread (INP fix).
function _defer(fn) {{
  if (typeof scheduler !== 'undefined' && scheduler.postTask) {{
    scheduler.postTask(fn, {{ priority: 'user-blocking' }});
  }} else {{
    setTimeout(fn, 0);
  }}
}}

// Disable btn-nav during heavy operations (visual feedback + prevents re-entry)
function _lockNav(lock) {{
  document.querySelectorAll('.btn-nav, #btm-load-all-btn').forEach(b => {{
    b.disabled = lock;
    b.style.opacity = lock ? '0.45' : '';
    b.style.cursor  = lock ? 'wait' : '';
  }});
}}

function goToFirst() {{
  if (!curCh || isLoadingMsgs) return;
  const area = document.getElementById('msgs');
  if (allMsgsLoaded) {{ area.scrollTop = 0; return; }}
  _lockNav(true);
  _defer(() => {{
    const all = filterMessagesByDate(ALL_MSGS[curCh.id] || []);
    const totalPages = Math.ceil(all.length / PER_PAGE);
    curPage = totalPages;
    area.innerHTML = '';
    delete area.dataset.prevDate;
    delete area.dataset.prevTsMs;
    delete area.dataset.prevAuthor;
    renderMsgs();
    area.scrollTop = 0;
    _lockNav(false);
  }});
}}

function goToLast() {{
  if (!curCh || isLoadingMsgs) return;
  const area = document.getElementById('msgs');
  if (allMsgsLoaded) {{ area.scrollTop = area.scrollHeight; return; }}
  _lockNav(true);
  _defer(() => {{
    curPage = 1;
    area.innerHTML = '';
    delete area.dataset.prevDate;
    delete area.dataset.prevTsMs;
    delete area.dataset.prevAuthor;
    renderMsgs();
    requestAnimationFrame(() => {{
      area.scrollTop = area.scrollHeight;
      _lockNav(false);
    }});
  }});
}}

// ── CHART DEFAULTS ─────────────────────────────────────────
const _CHART_DEFAULTS = {{
  responsive: true,
  maintainAspectRatio: false,
  interaction: {{ mode: 'index', intersect: false }},
  animation: {{ duration: 700, easing: 'easeOutQuart' }},
  plugins: {{
    legend: {{ display: false }},
    tooltip: {{
      backgroundColor: 'rgba(14,16,21,0.97)',
      borderColor: 'rgba(88,101,242,0.45)',
      borderWidth: 1,
      titleColor: '#e3e5e8',
      bodyColor: '#8b909a',
      padding: {{ top:10, bottom:10, left:14, right:14 }},
      cornerRadius: 10,
      displayColors: false,
      callbacks: {{
        title: (ctx) => ctx[0].label,
        label: (ctx) => `  ${{Number(ctx.raw).toLocaleString('el-GR')}} ${{LANG==='el'?'μηνύματα':'messages'}}`
      }}
    }},
  }},
  scales: {{
    x: {{
      grid: {{ display: false, drawBorder: false }},
      ticks: {{
        color: '#4e5058',
        font: {{ family: "'JetBrains Mono',monospace", size: 9 }},
        maxRotation: 0,
        autoSkip: true,
        maxTicksLimit: 8
      }},
      border: {{ display: false }}
    }},
    y: {{
      grid: {{
        color: 'rgba(255,255,255,0.035)',
        drawBorder: false,
      }},
      ticks: {{
        color: '#4e5058',
        font: {{ family: "'JetBrains Mono',monospace", size: 9 }},
        callback: v => fmt(v),
        maxTicksLimit: 4
      }},
      border: {{ display: false }},
      beginAtZero: true
    }},
  }},
}};

let _charts = {{}};
let _activityTab = 'month';

// ── ACTIVITY CHART FUNCTIONS ──────────────────────────────
function getActivityDataset(tab) {{
  const monthNames = ['Ιαν','Φεβ','Μαρ','Απρ','Μαϊ','Ιουν','Ιουλ','Αυγ','Σεπ','Οκτ','Νοε','Δεκ'];

  if (tab === 'month') {{
    return {{
      labels: STATS.monthly.map(([ym]) => {{ const [,m]=ym.split('-'); return monthNames[parseInt(m)-1]; }}),
      data:   STATS.monthly.map(m => m[1]),
      skip:   1
    }};
  }}

  if (tab === '90d' || tab === '30d' || tab === '7d') {{
    const limit = tab === '90d' ? 90 : (tab === '30d' ? 30 : 7);
    const skip  = tab === '90d' ? 7 : (tab === '30d' ? 3 : 1);
    
    // Get last N days from daily stats
    const keys = STATS.daily.map(d => d[0]).slice(-limit);
    const dataMap = Object.fromEntries(STATS.daily);
    
    return {{
      labels: keys.map(k => {{
        const [,m,d] = k.split('-');
        return `${{parseInt(d)}}/${{parseInt(m)}}`;
      }}),
      data: keys.map(k => dataMap[k] || 0),
      skip: skip
    }};
  }}

  if (tab === 'hour') {{
    return {{
      labels: STATS.hourly.map((_,i)=>`${{String(i).padStart(2,'0')}}:00`),
      data:   STATS.hourly,
      skip:   3
    }};
  }}

  return {{ labels:[], data:[], skip:1 }};
}}

const _tabLabels = {{
  el: {{
    month: 'ΣΥΝΟΛΙΚΗ ΑΝΑΛΥΣΗ (ALL TIME)',
    '90d': 'ΑΝΑΛΥΣΗ ΤΕΛΕΥΤΑΙΩΝ 90 ΗΜΕΡΩΝ',
    '30d': 'ΗΜΕΡΗΣΙΑ ΤΟΥ ΜΗΝΑ (30 ΜΕΡΕΣ)',
    '7d':  'ΑΝΑΛΥΣΗ ΤΕΛΕΥΤΑΙΑΣ ΕΒΔΟΜΑΔΑΣ',
    hour:  'ΑΝΑΛΥΣΗ ΑΝΑ ΩΡΑ',
  }},
  en: {{
    month: 'OVERALL ANALYSIS (ALL TIME)',
    '90d': 'LAST 90 DAYS ANALYSIS',
    '30d': 'DAILY OF THE MONTH (30 DAYS)',
    '7d':  'LAST WEEK ANALYSIS',
    hour:  'HOURLY ANALYSIS',
  }},
}};

function setActivityTab(btn, tab) {{
  _activityTab = tab;
  document.querySelectorAll('.activity-tab').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  const sub = document.getElementById('activity-subtitle-el');
  if (sub) sub.textContent = (_tabLabels[LANG]||_tabLabels.el)[tab] || '';
  drawActivity();
}}

function drawActivity() {{
  const cv = document.getElementById('c-activity');
  if (!cv) return;
  if (_charts['activity']) _charts['activity'].destroy();

  const {{ labels, data, skip }} = getActivityDataset(_activityTab);

  const ctx2d = cv.getContext('2d');
  const h = cv.offsetHeight || 150;
  const grad = ctx2d.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0,   'rgba(88,101,242,0.42)');
  grad.addColorStop(0.5, 'rgba(88,101,242,0.10)');
  grad.addColorStop(1,   'rgba(88,101,242,0.00)');

  _charts['activity'] = new Chart(cv, {{
    type: 'line',
    data: {{
      labels,
      datasets: [{{
        data,
        tension: 0.4,
        borderWidth: 2.5,
        borderColor: '#5865f2',
        backgroundColor: grad,
        fill: true,
        pointRadius: 0,
        pointHoverRadius: 5,
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: '#5865f2',
        pointHoverBorderWidth: 2,
        pointHitRadius: 12,
      }}]
    }},
    options: {{
      ..._CHART_DEFAULTS,
      interaction: {{
        mode: 'index',
        intersect: false,
      }},
      scales: {{
        ..._CHART_DEFAULTS.scales,
        x: {{
          ..._CHART_DEFAULTS.scales.x,
          ticks: {{
            ..._CHART_DEFAULTS.scales.x.ticks,
            callback: (v, i) => i % skip === 0 ? labels[i] : ''
          }}
        }}
      }}
    }}
  }});
}}

function openMsgSearch() {{
  document.getElementById('msg-search-bar').classList.add('visible');
  document.getElementById('msg-srch').focus();
}}

function closeMsgSearch() {{
  document.getElementById('msg-search-bar').classList.remove('visible');
  // Clear input and all highlights
  const inp = document.getElementById('msg-srch');
  if (inp) inp.value = '';
  document.querySelectorAll('#msgs mark.hl').forEach(el => {{
    el.outerHTML = el.textContent;
  }});
  _srchMatches = [];
  _srchIdx = -1;
  updateSrchCount();
}}

let _srchMatches = [];
let _srchIdx     = -1;

function _runMsgSearch() {{
  const q = document.getElementById('msg-srch').value.trim().toLowerCase();
  _srchMatches = [];
  _srchIdx = -1;
  // Clear old highlights
  document.querySelectorAll('#msgs mark.hl').forEach(el => {{
    el.outerHTML = el.textContent;
  }});
  if (!q) {{ updateSrchCount(); return; }}
  // Find and highlight
  document.querySelectorAll('#msgs .msg-content').forEach(el => {{
    const txt = el.innerHTML;
    const _SRCH_SPEC = '.+*?^$|()[]{{}}\\\\';  // special regex chars
    const safeQ = q.split('').map(c => _SRCH_SPEC.includes(c) ? '\\\\' + c : c).join('');
    const rex = new RegExp(safeQ, 'gi');
    if (!rex.test(el.textContent)) return;
    el.innerHTML = el.innerHTML.replace(rex, m => `<mark class="hl">${{m}}</mark>`);
    const marks = el.querySelectorAll('mark.hl');
    marks.forEach(m => _srchMatches.push(m));
  }});
  if (_srchMatches.length) {{
    _srchIdx = _srchMatches.length - 1;
    _highlightSrch();
  }}
  updateSrchCount();
}}

function _highlightSrch() {{
  document.querySelectorAll('#msgs mark.hl.cur').forEach(el => el.classList.remove('cur'));
  if (_srchIdx < 0 || _srchIdx >= _srchMatches.length) return;
  const cur = _srchMatches[_srchIdx];
  cur.classList.add('cur');
  cur.scrollIntoView({{ behavior:'smooth', block:'center' }});
}}

function updateSrchCount() {{
  const cnt = document.getElementById('msg-srch-count');
  if (!cnt) return;
  const q = document.getElementById('msg-srch').value.trim();
  if (!q) {{ cnt.textContent = ''; return; }}
  if (!_srchMatches.length) {{ cnt.textContent = LANG==='el'?'Δεν βρέθηκε':'No results'; return; }}
  cnt.textContent = `${{_srchIdx+1}} / ${{_srchMatches.length}}`;
}}

function srchNav(dir) {{
  if (!_srchMatches.length) return;
  _srchIdx = (_srchIdx - dir + _srchMatches.length) % _srchMatches.length;
  _highlightSrch();
  updateSrchCount();
}}

// Wire up live search on input
document.getElementById('msg-srch').addEventListener('input', _runMsgSearch);
document.getElementById('msg-srch').addEventListener('keydown', e => {{
  if (e.key === 'Enter') {{ e.preventDefault(); srchNav(e.shiftKey ? -1 : 1); }}
  if (e.key === 'Escape') closeMsgSearch();
}});

// ── LIGHTBOX ────────────────────────────────────────────────
function openLB(src) {{
  document.getElementById('lb-img').src=src;
  document.getElementById('lb').classList.add('open');
}}
function closeLB() {{
  document.getElementById('lb').classList.remove('open');
  document.getElementById('lb-img').src='';
}}
document.addEventListener('keydown', e => {{ if(e.key==='Escape') {{ closeLB(); closeCtxMenu(); }} }});

// ── CONTEXT MENU ────────────────────────────────────────────
let _ctxTarget = null;

function closeCtxMenu() {{
  const m = document.getElementById('ctx-menu');
  if (m) m.classList.remove('open');
  _ctxTarget = null;
}}

function showCtxMenu(e, id, name) {{
  e.preventDefault();
  e.stopPropagation();
  closeCtxMenu();
  _ctxTarget = {{ id, name }};
  const m = document.getElementById('ctx-menu');
  if (!m) return;
  // Position
  const x = Math.min(e.clientX, window.innerWidth  - 200);
  const y = Math.min(e.clientY, window.innerHeight - 80);
  m.style.left = x + 'px';
  m.style.top  = y + 'px';
  // Show/hide copy-id row
  document.getElementById('ctx-copy-id').style.display = id ? '' : 'none';
  m.classList.add('open');
}}

function ctxCopyId() {{
  if (_ctxTarget?.id) navigator.clipboard.writeText(_ctxTarget.id).then(() => showToast('ID copied: ' + _ctxTarget.id));
  closeCtxMenu();
}}

function ctxCopyName() {{
  if (_ctxTarget?.name) navigator.clipboard.writeText(_ctxTarget.name).then(() => showToast('Name copied: ' + _ctxTarget.name));
  closeCtxMenu();
}}

// Toast notification
function showToast(msg) {{
  let t = document.getElementById('_toast');
  if (!t) {{
    t = document.createElement('div');
    t.id = '_toast';
    t.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(10px);background:rgba(30,32,36,.97);color:#fff;font-size:13px;font-family:var(--mono);padding:9px 20px;border-radius:100px;z-index:9999;opacity:0;transition:opacity .2s,transform .2s;pointer-events:none;border:1px solid rgba(255,255,255,.1);box-shadow:0 4px 20px rgba(0,0,0,.5)';
    document.body.appendChild(t);
  }}
  t.textContent = msg;
  t.style.opacity = '1'; t.style.transform = 'translateX(-50%) translateY(0)';
  clearTimeout(t._tmr);
  t._tmr = setTimeout(() => {{ t.style.opacity='0'; t.style.transform='translateX(-50%) translateY(10px)'; }}, 2200);
}}

// Disable native right-click everywhere, show custom menu on targets
document.addEventListener('contextmenu', e => {{
  // Check if right-clicked on a ch-item
  const chItem = e.target.closest('.ch-item');
  if (chItem) {{
    const id   = chItem.dataset.id || '';
    const name = chItem.querySelector('.ch-name')?.textContent || '';
    showCtxMenu(e, id, name);
    return;
  }}
  // Check srv-card
  const srvCard = e.target.closest('.srv-card');
  if (srvCard) {{
    const name = srvCard.querySelector('.srv-card-name')?.textContent || '';
    showCtxMenu(e, '', name);
    return;
  }}
  // Check dm-row
  const dmRow = e.target.closest('.dm-row');
  if (dmRow) {{
    const id   = dmRow.dataset.id || '';
    const name = dmRow.querySelector('.dm-name')?.textContent || '';
    showCtxMenu(e, id, name);
    return;
  }}
  // Everywhere else — block native menu
  e.preventDefault();
}});

// Close context menu on click elsewhere
document.addEventListener('click', e => {{
  if (!e.target.closest('#ctx-menu')) closeCtxMenu();
}});
// ── DISCORD MARKDOWN PARSER v2 (FULL) ────────────────────────────────
function parseDiscordMarkdown(text) {{
  if (!text) return '';

  // 1. Spoiler
  text = text.replace(/\\|\\|([\\s\\S]+?)\\|\\|/g, 
    '<span class="spoiler" onclick="this.classList.toggle(\\'revealed\\')">$1</span>');

  // 2. Code blocks με γλώσσα (```fix, ```diff κλπ.)
  text = text.replace(/```(\\w*)\\n?([\\s\\S]*?)```/g, (match, lang, code) => {{
    lang = (lang || '').toLowerCase().trim();
    code = esc(code.trim());

    let cls = '';
    if (lang === 'fix') cls = 'code-fix';
    else if (lang === 'diff') {{
      cls = 'code-diff';
      code = code
        .replace(/^(\\+.*)$/gm, '<span class="plus">$1</span>')
        .replace(/^(-.*)$/gm,  '<span class="minus">$1</span>');
    }}
    else if (lang === 'yaml' || lang === 'yml') cls = 'code-yaml';
    else if (lang === 'http') cls = 'code-http';
    else if (lang === 'ini') cls = 'code-ini';
    else if (lang === 'css') cls = 'code-css';
    else if (lang) cls = `language-${{lang}}`;

    return `<pre><code class="${{cls}}">${{code}}</code></pre>`;
  }});

  // 3. Inline code
  text = text.replace(/`([^`\\n]+)`/g, '<code>$1</code>');

  // 4. Bold / Italic / Underline / Strikethrough
  text = text.replace(/\\*\\*\\*([^*]+)\\*\\*\\*/g, '<strong><em>$1</em></strong>');
  text = text.replace(/___([^_]+)___/g, '<strong><em>$1</em></strong>');
  text = text.replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>');
  text = text.replace(/__([^_]+)__/g, '<strong>$1</strong>');
  text = text.replace(/\\*([^*]+)\\*/g, '<em>$1</em>');
  text = text.replace(/_([^_]+)_/g, '<em>$1</em>');
  text = text.replace(/~~(.+?)~~/g, '<del>$1</del>');

  // 5. Blockquote
  text = text.replace(/^> (.+)$/gm, '<blockquote style="border-left:4px solid #5865f2;padding-left:12px;color:#b9bbbe;margin:6px 0;">$1</blockquote>');

  return text;
}}
// ── UTILS ───────────────────────────────────────────────────
function esc(s)  {{ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;') }}
function ini(s)  {{ return String(s||'?')[0].toUpperCase() }}
function linkify(h) {{
  const re = /(https?:[/][/][^ <>\"&]+)/g;
  return h.replace(re, '<a href="$1" target="_blank" rel="noopener">$1</a>');
}}
function fmt(n) {{
  if (n>=1e6)  return (n/1e6).toFixed(1)+'M';
  if (n>=1000) return (n/1000).toFixed(1)+'k';
  return String(n);
}}
function fmtDate(d) {{
  const MGR=['Ιανουαρίου','Φεβρουαρίου','Μαρτίου','Απριλίου','Μαΐου','Ιουνίου','Ιουλίου','Αυγούστου','Σεπτεμβρίου','Οκτωβρίου','Νοεμβρίου','Δεκεμβρίου'];
  const MEN=['January','February','March','April','May','June','July','August','September','October','November','December'];
  const M = LANG === 'el' ? MGR : MEN;
  const [y,m,day]=d.split('-');
  return `${{parseInt(day)}} ${{M[parseInt(m)-1]}} ${{y}}`;
}}
function fmtTime(ts)      {{ return ts.slice(0,16).replace('T',' ') }}
function fmtTimeShort(ts) {{ return ts.slice(11,16) }}



// ── COLLAPSIBLE TOGGLE ──────────────────────────────────────
function toggleCollapse(bodyId, btnId) {{
  const body = document.getElementById(bodyId);
  const btn  = document.getElementById(btnId);
  if (!body) return;
  const isOpen = body.classList.contains('open');
  body.classList.toggle('open', !isOpen);
  if (btn) btn.classList.toggle('open', !isOpen);
}}

// ── EXTRA SECTIONS ───────────────────────────────────────────
function buildExtraSections() {{
  buildConnections();
  buildNotes();
  buildQuests();
  buildNitroHistory();
  buildOrbs();
  buildDevAppsBadge();
  buildHarvestHistory();
  buildAdProfile();
  buildSupportTickets();
}}

function showSec(id) {{
  const el = document.getElementById(id);
  if (el) el.style.display = '';
}}

// ── LINKED ACCOUNTS ──────────────────────────────────────────
function buildConnections() {{
  if (!CONNECTIONS || !CONNECTIONS.length) return;
  showSec('sec-connections');
  const el = document.getElementById('connections-el');
  CONNECTIONS.forEach(conn => {{
    const card = document.createElement('div');
    card.className = 'conn-card';
    const verified = conn.verified ? '<span class="conn-verified">✓</span>' : '';
    card.innerHTML = `
      <div class="conn-icon">${{conn.icon}}</div>
      <div class="conn-info">
        <div class="conn-type">${{conn.type}}${{verified}}</div>
        <div class="conn-name" title="${{conn.name}}">${{conn.name}}</div>
      </div>`;
    el.appendChild(card);
  }});
}}



// ── NOTES ─────────────────────────────────────────────────────
function buildNotes() {{
  if (!NOTES || !NOTES.length) return;
  showSec('sec-notes');
  const el = document.getElementById('notes-el');
  NOTES.forEach(n => {{
    const card = document.createElement('div');
    card.className = 'note-card';
    card.innerHTML = `<div class="note-uid">User ${{n.uid}}</div><div class="note-text">${{esc(n.text)}}</div>`;
    el.appendChild(card);
  }});
}}


// ── QUESTS ────────────────────────────────────────────────────
function buildQuests() {{
  if (!QUESTS || !QUESTS.length) return;
  showSec('sec-quests');
  const done  = QUESTS.filter(q => q.done).length;
  const total = QUESTS.length;
  const pct   = Math.round((done / total) * 100);

  const sumEl = document.getElementById('quests-summary-el');
  sumEl.innerHTML = `
    <div class="friend-stat-pill" data-key="quests" data-val="${{done}}/${{total}}">✅ ${{done}} / ${{total}} ${{LANG==='el'?'Ολοκληρωμένα':'Completed'}}</div>
    <div class="quest-progress-bar" style="flex:1;min-width:120px">
      <div class="quest-progress-fill" style="width:${{pct}}%"></div>
    </div>
    <div class="quest-pct">${{pct}}%</div>`;

  const el = document.getElementById('quests-el');
  QUESTS.slice(0, 30).forEach(q => {{
    const row = document.createElement('div');
    row.className = 'quest-row';
    row.innerHTML = `
      <div class="quest-dot ${{q.done ? 'done' : 'pend'}}"></div>
      <div class="quest-date">${{q.enrolled}}</div>
      <div class="quest-id">Quest ${{q.quest_id}}</div>
      ${{q.done ? `<div class="session-mfa" style="background:rgba(35,165,89,.2);color:#7ee8a2">✓ ${{q.completed.slice(0,10)}}</div>` : '<div class="quest-pct">pending</div>'}}`;
    el.appendChild(row);
  }});
}}


// ── NITRO HISTORY ─────────────────────────────────────────────
function buildNitroHistory() {{
  if (!NITRO_HISTORY || !NITRO_HISTORY.length) return;
  showSec('sec-nitro');
  const el = document.getElementById('nitro-el');
  NITRO_HISTORY.slice().reverse().forEach(n => {{
    const entry = document.createElement('div');
    entry.className = 'nitro-entry' + (n.gifted ? ' gifted' : '');
    entry.setAttribute('data-started', n.started || '');
    entry.setAttribute('data-ended',   n.ended   || '');
    const giftBadge = n.gifted ? `<span class="nitro-gifted-badge">🎁 ${{LANG==='el'?'Δώρο':'Gifted'}}</span>` : '';
    const endStr = n.ended ? ` → ${{n.ended}}` : (LANG==='el' ? ' → ενεργό' : ' → active');
    entry.innerHTML = `
      <div class="nitro-tier">⚡ ${{n.tier}} ${{giftBadge}}</div>
      <div class="nitro-plan">${{n.plan || 'subscription'}}</div>
      <div class="nitro-dates">${{n.started}}${{endStr}}</div>`;
    el.appendChild(entry);
  }});
}}

// ── ORBS (injected into hero-badges) ─────────────────────────
function buildOrbs() {{
  if (!ORBS_BALANCE) return;
  const el = document.getElementById('hero-badges-el');
  if (!el) return;
  const badge = document.createElement('span');
  badge.className = 'orbs-badge';
  badge.innerHTML = `🔮 ${{ORBS_BALANCE.toLocaleString()}} Orbs`;
  el.appendChild(badge);
}}

// ── DEVELOPER APPS BADGE ──────────────────────────────────────
function buildDevAppsBadge() {{
  if (!DEV_APPS || !DEV_APPS.length) return;
  const el = document.getElementById('hero-badges-el');
  if (!el) return;
  const badge = document.createElement('div');
  badge.className = 'hbadge hb-devapp';
  // Build tooltip rows
  const rows = DEV_APPS.map(a => {{
    const botTag = a.has_bot ? `<span class="devapp-tip-bot">Bot</span>` : '';
    return `<div class="devapp-tip-row">${{esc(a.name)}} ${{botTag}}</div>`;
  }}).join('');
  badge.innerHTML = `
    <span class="badge-icon">⚙️</span>
    <span class="badge-text">
      <span class="badge-label">Developer Apps</span>
      <span class="badge-value">${{DEV_APPS.length}}</span>
    </span>
    <div class="devapp-tooltip">${{rows}}</div>`;
  el.appendChild(badge);
}}


// ── HARVEST HISTORY ────────────────────────────────────────────
function buildHarvestHistory() {{
  if (!HARVEST_HISTORY || !HARVEST_HISTORY.length) return;
  showSec('sec-harvest');
  const sumEl = document.getElementById('harvest-summary-el');
  const n = HARVEST_HISTORY.length;
  sumEl.innerHTML = `<div class="harvest-summary">You have requested your Discord data <strong>${{n}}</strong> time${{n!==1?'s':''}}.</div>`;
  const el = document.getElementById('harvest-el');
  HARVEST_HISTORY.forEach(r => {{
    const entry = document.createElement('div');
    entry.className = 'harvest-entry';
    const date = (r.created_at || '').slice(0, 10);
    const email = r.email || '';
    let maskedEmail = '';
    if (email) {{
      const [local, domain] = email.split('@');
      maskedEmail = (local.slice(0, 3) || '???') + '***@' + (domain || '?');
    }}
    entry.innerHTML = `
      <div>
        <div class="harvest-date">${{date}}</div>
        ${{maskedEmail ? `<div class="harvest-email">${{maskedEmail}}</div>` : ''}}
      </div>`;
    el.appendChild(entry);
  }});
}}


// ── AD PROFILE ────────────────────────────────────────────────
function buildAdProfile() {{
  if (!AD_TRAITS || !Object.keys(AD_TRAITS).length) return;
  showSec('sec-adprofile');
  const el = document.getElementById('adprofile-el');
  const T = AD_TRAITS;
  const nitroMap = {{1:'Nitro Classic', 2:'Nitro', 3:'Nitro Basic'}};

  const gameL30  = (T.game_ids_l30  || []).length;
  const gameL90  = (T.game_ids_l90  || []).length;
  const gameL365 = (T.game_ids_l365 || []).length;
  const themes   = T.theme_names_l90 || [];
  const qEnrolled = (T.quest_history_enrolled || []).length;
  const qClaimed  = (T.quest_history_reward_claimed || []).length;
  const platMap = {{ desktop:'Desktop', mobile:'Mobile', web:'Web' }};

  const rows = [
    ['Age group',        T.age_group || '—'],
    ['Primary platform', platMap[T.primary_platform_l30] || T.primary_platform_l30 || '—'],
    ['Region',           (T.reg_region || '—') + (T.reg_country_code ? ` (${{T.reg_country_code}})` : '')],
    ['Nitro type',       nitroMap[T.subscription_premium_type] || '—'],
    ['Game activity',    `Discord tracked ${{gameL30}} games in the last 30 days, ${{gameL90}} in 90 days, ${{gameL365}} in 365 days`],
    ['Quests',           `Enrolled in ${{qEnrolled}} quests / ${{qClaimed}} rewards claimed`],
  ];

  const themeHtml = themes.length
    ? `<div class="adp-theme-wrap">${{themes.map(t=>`<span class="adp-theme">${{t}}</span>`).join('')}}</div>`
    : '—';

  el.innerHTML = `
    <div class="adprofile-banner">This is the ad targeting profile Discord builds about you.<br>Most users are unaware this data exists.</div>
    <div class="adprofile-card">
      ${{rows.map(([k,v])=>`<div class="adp-row"><div class="adp-key">${{k}}</div><div class="adp-val">${{esc(String(v))}}</div></div>`).join('')}}
      ${{themes.length ? `<div class="adp-row"><div class="adp-key">Gaming themes</div><div class="adp-val">${{themeHtml}}</div></div>` : ''}}
    </div>`;
}}


// ── SUPPORT TICKETS ────────────────────────────────────────────
function buildSupportTickets() {{
  if (!SUPPORT_TICKETS || !Object.keys(SUPPORT_TICKETS).length) return;
  showSec('sec-tickets');

  const tickets = Object.values(SUPPORT_TICKETS);
  tickets.sort((a, b) => (b.created_at || '') > (a.created_at || '') ? 1 : -1);

  const closed  = tickets.filter(t => t.status === 'closed').length;
  const deleted = tickets.filter(t => t.status === 'deleted').length;
  const open    = tickets.filter(t => t.status !== 'closed' && t.status !== 'deleted').length;
  const total   = tickets.length;

  const sumEl = document.getElementById('tickets-summary-el');
  sumEl.innerHTML = `<div class="tickets-summary">${{total}} ticket${{total!==1?'s':''}} total — ${{closed}} closed, ${{deleted}} deleted${{open?' , '+open+' open':''}}</div>`;

  const el = document.getElementById('tickets-el');
  tickets.forEach((t, idx) => {{
    const card = document.createElement('div');
    card.className = 'ticket-card';
    const date    = (t.created_at || '').slice(0, 10);
    const status  = t.status || 'open';
    const subject = t.subject === 'SCRUBBED' ? 'Content removed by Discord' : (t.subject || '(no subject)');
    const bodyId  = 'tc-body-' + idx;

    card.innerHTML = `
      <div class="ticket-hdr" onclick="toggleTicket('${{bodyId}}')">
        <div class="ticket-date">${{date}}</div>
        <div class="ticket-status ${{status}}">${{status}}</div>
        <div class="ticket-subject">${{esc(subject)}}</div>
      </div>
      <div class="ticket-body" id="${{bodyId}}"></div>`;
    el.appendChild(card);

    // Sort comments ASC and populate lazily on first open
    const bodyEl = document.getElementById(bodyId);
    const comments = (t.comments || []).slice().sort((a, b) =>
      (a.created_at || '') > (b.created_at || '') ? 1 : -1
    );
    bodyEl._rendered = false;
    bodyEl._comments = comments;
  }});
}}

function toggleTicket(bodyId) {{
  const body = document.getElementById(bodyId);
  if (!body) return;
  const isOpen = body.classList.contains('open');
  if (!isOpen && !body._rendered) {{
    // Render comments on first expand
    body._rendered = true;
    body._comments.forEach(c => {{
      const isUser = (c.author || '').toLowerCase() === 'user';
      const bub = document.createElement('div');
      bub.className = 'ticket-bubble ' + (isUser ? 'user' : 'agent');
      const ts = (c.created_at || '').slice(0, 16).replace('T', ' ');
      bub.innerHTML = `<div class="ticket-bubble-meta">${{esc(c.author || '?')}} · ${{ts}}</div>${{esc(c.comment || '')}}`;
      body.appendChild(bub);
    }});
  }}
  body.classList.toggle('open', !isOpen);
}}


// ── SERVER DETAIL ──────────────────────────────────────────────
function openSrvDetail(sid, name) {{
  const modal = document.getElementById('srv-detail-modal');
  const iconEl = document.getElementById('srvd-icon-el');
  const nameEl = document.getElementById('srvd-name-el');
  const metaEl = document.getElementById('srvd-meta-el');
  const chEl   = document.getElementById('srvd-ch-el');
  const whEl   = document.getElementById('srvd-wh-el');
  const whWrap = document.getElementById('srvd-wh-wrap');

  // Server icon
  iconEl.innerHTML = '';
  if (SERVER_ICONS[sid]) {{
    const img = document.createElement('img');
    img.src = SERVER_ICONS[sid];
    img.className = 'srv-icon-img';
    img.style.cssText = 'width:48px;height:48px';
    iconEl.appendChild(img);
  }} else {{
    const ph = document.createElement('div');
    ph.className = 'srv-icon-placeholder';
    ph.style.cssText = `width:48px;height:48px;background:hsl(${{srvColor(name)}},60%,38%)`;
    ph.textContent = (name.replace(/[^a-zA-ZΑ-Ωα-ω0-9 ]/g,'').trim().split(' ').map(w=>w[0]||'').join('').toUpperCase().slice(0,2)||'?');
    iconEl.appendChild(ph);
  }}
  nameEl.textContent = name;

  // Channels
  chEl.innerHTML = '';
  const rawChs = SERVER_CHANNELS[sid] || [];

  // Build channel name → message count lookup from our parsed messages
  const chNameCount = {{}};
  CHANNELS.filter(c => c.server === name).forEach(c => {{ chNameCount[c.name] = (chNameCount[c.name]||0) + c.count; }});

  const cats = rawChs.filter(c => c.type === 4);
  const nonCats = rawChs.filter(c => c.type !== 4);
  const typeIco = {{ 0:'#', 2:'🔊', 5:'📢' }};

  // Group by parent
  const byParent = {{}};
  nonCats.forEach(c => {{
    const pid = c.parent_id || '__none__';
    if (!byParent[pid]) byParent[pid] = [];
    byParent[pid].push(c);
  }});
  // Sort within groups
  Object.values(byParent).forEach(arr => arr.sort((a,b) => (a.position||0)-(b.position||0)));

  function renderGroup(catId, catName) {{
    if (catName) {{
      const h = document.createElement('div');
      h.className = 'srvd-cat';
      h.textContent = catName;
      chEl.appendChild(h);
    }}
    const group = byParent[catId] || [];
    group.forEach(ch => {{
      const row = document.createElement('div');
      row.className = 'srvd-ch-row';
      const ico = typeIco[ch.type] || '#';
      const msgCnt = chNameCount[ch.name];
      const badge = msgCnt ? `<span class="srvd-ch-badge">${{fmt(msgCnt)}}</span>` : '';
      row.innerHTML = `<span class="srvd-ch-ico">${{ico}}</span><span class="srvd-ch-name">${{esc(ch.name||'')}}</span>${{badge}}`;
      chEl.appendChild(row);
    }});
  }}

  // Render top-level first, then each category
  renderGroup('__none__', null);
  cats.sort((a,b)=>(a.position||0)-(b.position||0)).forEach(cat => {{
    renderGroup(String(cat.id), cat.name);
  }});

  const chCount = nonCats.length;
  metaEl.textContent = `${{chCount}} channel${{chCount!==1?'s':''}}`;

  // Webhooks
  whEl.innerHTML = '';
  const rawWHs = SERVER_WEBHOOKS[sid] || [];
  if (rawWHs.length) {{
    whWrap.style.display = '';
    // Build channel id → name lookup from rawChs
    const chIdName = {{}};
    rawChs.forEach(c => {{ if (c.id) chIdName[String(c.id)] = c.name; }});
    const typeLabel = {{ 1:'Incoming', 2:'Channel Follower' }};
    rawWHs.forEach(wh => {{
      const row = document.createElement('div');
      row.className = 'srvd-wh-row';
      const chName = chIdName[String(wh.channel_id)] || wh.channel_id || '—';
      let avHtml;
      if (wh.avatar) {{
        avHtml = `<img class="srvd-wh-av" src="https://cdn.discordapp.com/avatars/${{wh.id}}/${{wh.avatar}}.png" alt="" loading="lazy">`;
      }} else {{
        avHtml = `<div class="srvd-wh-av-ph">🔗</div>`;
      }}
      row.innerHTML = `
        ${{avHtml}}
        <div class="srvd-wh-info">
          <div class="srvd-wh-name">${{esc(wh.name||'')}}</div>
          <div class="srvd-wh-type">${{typeLabel[wh.type]||'Webhook'}} · #${{esc(chName)}}</div>
        </div>`;
      whEl.appendChild(row);
    }});
  }} else {{
    whWrap.style.display = 'none';
  }}

  modal.style.display = 'flex';
  document.body.style.overflow = 'hidden';
}}

function closeSrvDetail() {{
  const modal = document.getElementById('srv-detail-modal');
  modal.style.display = 'none';
  document.body.style.overflow = '';
}}

// Close server detail on backdrop click
document.addEventListener('click', function(e) {{
  const modal = document.getElementById('srv-detail-modal');
  if (e.target === modal) closeSrvDetail();
}});


// ─────────────────────────────────────────────────────────────

// ── SETTINGS MODAL ──────────────────────────────────────────

var LANG = 'en';

const I18N = {{
  el: {{
    // section titles
    'sec-servers':     '🏆 Top Servers',
    'sec-dms':         '👥 Top DM Contacts',
    'sec-emoji':       '😄 Top Emoji',
    'sec-wc':          '💬 Word Cloud',
    'activity-title':  'Δραστηριότητα',
    'act-sub-month':   'ΜΗΝΙΑΙΑ ΑΝΑΛΥΣΗ',
    // date range
    'dr-from':    '📅 Από:',
    'dr-to':      'έως:',
    'dr-apply':   'Εφαρμογή',
    'dr-clear':   'Καθαρισμός',
    // search
    'search-sidebar': '🔍 Αναζήτηση...',
    'search-msgs':    '🔍 Αναζήτηση μηνύματος...',
    'search-btn':     'Αναζήτηση στα μηνύματα (S)',
    'datepicker-btn': 'Επιλογή χρονικής περιόδου',
    'srch-prev':      'Προηγούμενο (Shift+Enter)',
    'srch-next':      'Επόμενο (Enter)',
    'srch-close':     'Κλείσιμο (Esc)',
    // badges
    'badge-firstmsg': 'Πρώτο μήνυμα',
    'nitro-lbl':      'Nitro λήγει',
    'mobile-lbl':     'Mobile',
    'phone-lbl':      'Επαλ. τηλεφώνου',
    'discord-lbl':    'Μέλος από',
    'hype-lbl':       'HypeSquad Brilliance',
    // settings modal
    'settings-title': 'Ρυθμίσεις',
    'settings-lang':  'Γλώσσα',
  }},
  en: {{
    'sec-servers':     '🏆 Top Servers',
    'sec-dms':         '👥 Top DM Contacts',
    'sec-emoji':       '😄 Top Emoji',
    'sec-wc':          '💬 Word Cloud',
    'activity-title':  'Activity',
    'act-sub-month':   'MONTHLY ANALYSIS',
    'dr-from':    '📅 From:',
    'dr-to':      'to:',
    'dr-apply':   'Apply',
    'dr-clear':   'Clear',
    'search-sidebar': '🔍 Search...',
    'search-msgs':    '🔍 Search messages...',
    'search-btn':     'Search messages (S)',
    'datepicker-btn': 'Select date range',
    'srch-prev':      'Previous (Shift+Enter)',
    'srch-next':      'Next (Enter)',
    'srch-close':     'Close (Esc)',
    'badge-firstmsg': 'First message',
    'nitro-lbl':      'Nitro expires',
    'mobile-lbl':     'Mobile',
    'phone-lbl':      'Phone Verified',
    'discord-lbl':    'Discord Member since',
    'hype-lbl':       'HypeSquad Brilliance',
    'settings-title': 'Settings',
    'settings-lang':  'Language',
  }}
}};

function applyI18n() {{
  const L = I18N[LANG];
  document.documentElement.lang = LANG;
  // text content
  document.querySelectorAll('[data-i18n]').forEach(el => {{
    const k = el.getAttribute('data-i18n');
    if (L[k] !== undefined) el.textContent = L[k];
  }});
  // placeholders
  document.querySelectorAll('[data-i18n-ph]').forEach(el => {{
    const k = el.getAttribute('data-i18n-ph');
    if (L[k] !== undefined) el.placeholder = L[k];
  }});
  // title attributes
  document.querySelectorAll('[data-i18n-title]').forEach(el => {{
    const k = el.getAttribute('data-i18n-title');
    if (L[k] !== undefined) el.title = L[k];
  }});
  // direct el/en text on element (drp-bar, drp-footer etc.)
  document.querySelectorAll('[data-i18n-el][data-i18n-en]').forEach(el => {{
    el.textContent = LANG === 'el' ? el.getAttribute('data-i18n-el') : el.getAttribute('data-i18n-en');
  }});
  // stat card labels (data-gr / data-en)
  document.querySelectorAll('[data-gr][data-en]').forEach(el => {{
    el.textContent = LANG === 'el' ? el.getAttribute('data-gr') : el.getAttribute('data-en');
  }});
  // update activity subtitle to match current tab
  const sub = document.getElementById('activity-subtitle-el');
  if (sub) sub.textContent = (_tabLabels[LANG]||_tabLabels.el)[_activityTab] || '';
  // update hdr-cnt-el if a channel is open
  if (curCh) {{
    document.getElementById('hdr-cnt-el').textContent =
      curCh.count.toLocaleString('el-GR') + (LANG === 'el' ? ' μηνύματα' : ' messages');
  }}
  // update server rail data-tips
  document.querySelectorAll('[data-cnt][data-name]').forEach(el => {{
    const name = el.getAttribute('data-name');
    const cnt  = el.getAttribute('data-cnt');
    el.setAttribute('data-tip', `${{name}} (${{Number(cnt).toLocaleString('el-GR')}} ${{LANG==='el'?'μηνύματα':'messages'}})`);
  }});

  // ── Re-translate dynamically built content ──────────────────
  const isEl = LANG === 'el';
  const msgWord = isEl ? 'μηνύματα' : 'messages';

  // date separators in message area — re-render from data-date attr
  document.querySelectorAll('.date-sep[data-date]').forEach(el => {{
    el.textContent = fmtDate(el.getAttribute('data-date'));
  }});

  // srv-card-msgs: data-cnt attribute
  document.querySelectorAll('.srv-card-msgs[data-cnt]').forEach(el => {{
    el.textContent = fmt(Number(el.getAttribute('data-cnt'))) + ' ' + msgWord;
  }});

  // dm-msgs: data-cnt attribute
  document.querySelectorAll('.dm-msgs[data-cnt]').forEach(el => {{
    el.textContent = fmt(Number(el.getAttribute('data-cnt'))) + ' ' + msgWord;
  }});

  // friend-stat-pill: data-key + data-val
  document.querySelectorAll('.friend-stat-pill[data-key]').forEach(el => {{
    const key = el.getAttribute('data-key');
    const val = el.getAttribute('data-val') || '';
    if (key === 'friends')  el.textContent = `👥 ${{val}} ${{isEl?'Φίλοι':'Friends'}}`;
    else if (key === 'blocked') el.textContent = `🚫 ${{val}} ${{isEl?'Αποκλεισμένοι':'Blocked'}}`;
    else if (key === 'quests')  el.textContent = `✅ ${{val.replace('/', ' / ')}} ${{isEl?'Ολοκληρωμένα':'Completed'}}`;
  }});

  // nitro-entry dates: data-started, data-ended
  document.querySelectorAll('.nitro-entry[data-started]').forEach(el => {{
    const started = el.getAttribute('data-started');
    const ended   = el.getAttribute('data-ended');
    const dateEl  = el.querySelector('.nitro-dates');
    if (dateEl) {{
      const endStr = ended ? ` → ${{ended}}` : (isEl ? ' → ενεργό' : ' → active');
      dateEl.textContent = started + endStr;
    }}
    // also update gift badge inside
    const giftBadge = el.querySelector('.nitro-gifted-badge');
    if (giftBadge) giftBadge.textContent = '🎁 ' + (isEl ? 'Δώρο' : 'Gifted');
  }});
}}

function openSettings() {{
  document.getElementById('settings-modal').classList.add('open');
}}
function closeSettings() {{
  document.getElementById('settings-modal').classList.remove('open');
}}
function setLang(lang) {{
  LANG = lang;
  document.querySelectorAll('.lang-opt').forEach(b => {{
    b.classList.toggle('active', b.getAttribute('data-lang') === lang);
  }});
  applyI18n();
}}

// ── EXPIRED / 404 ATTACHMENT HANDLER ───────────────────────
function _imgExpired(img) {{
  try {{
    const url  = img.src || '';
    const raw  = url.split('/').pop() || 'image';
    const fn   = decodeURIComponent(raw.split('?')[0]) || 'attachment';
    const wrap = img.parentElement;
    if (!wrap) return;

    // Determine the display icon based on extension
    const ext = fn.split('.').pop().toLowerCase();
    const ico = ext === 'gif' ? '🎞️'
              : /^(mp4|mov|webm|mkv)$/.test(ext) ? '🎥'
              : /^(mp3|ogg|wav|opus|flac)$/.test(ext) ? '🎵'
              : '🖼️';

    img.style.display = 'none';
    // Remove zoom/lightbox cursor so the placeholder link works cleanly
    wrap.style.cursor = 'default';
    wrap.style.background = 'none';
    wrap.style.border = 'none';
    wrap.style.boxShadow = 'none';
    wrap.style.transform = 'none';
    try {{ wrap.removeAttribute('onclick'); }} catch(e) {{}}
    // Hide any sibling play buttons (GIF overlay, etc.)
    wrap.querySelectorAll('.gif-play-btn,.att-tenor-overlay').forEach(el => el.style.display='none');

    const ph = document.createElement('a');
    ph.className = 'att-expired-ph';
    ph.href = url;
    ph.target = '_blank';
    ph.rel = 'noopener noreferrer';
    ph.title = 'Expired CDN link — click to try in browser';
    ph.onclick = e => e.stopPropagation();
    ph.innerHTML = `<span class="att-exp-ico">${{ico}}</span>`
                 + `<span class="att-exp-name">${{fn}}</span>`
                 + `<span class="att-exp-lbl">🚫 Unavailable · tap to try</span>`;
    wrap.appendChild(ph);
  }} catch(e) {{}}
}}

function _vidExpired(vidId, url) {{
  try {{
    const wrap = document.getElementById('wrap_' + vidId);
    if (!wrap || wrap.dataset.expiredShown) return;
    wrap.dataset.expiredShown = '1';
    const raw = url.split('/').pop() || 'video';
    const fn  = decodeURIComponent(raw.split('?')[0]) || 'video';
    wrap.style.cssText = 'background:none;border:none;box-shadow:none';
    wrap.innerHTML = '';
    const ph = document.createElement('a');
    ph.className = 'att-expired-ph';
    ph.href = url;
    ph.target = '_blank';
    ph.rel = 'noopener noreferrer';
    ph.title = 'Expired CDN link — click to try in browser';
    ph.innerHTML = `<span class="att-exp-ico">🎥</span>`
                 + `<span class="att-exp-name">${{fn}}</span>`
                 + `<span class="att-exp-lbl">⏱ Expired · tap to retry</span>`;
    wrap.appendChild(ph);
  }} catch(e) {{}}
}}

// ── CUSTOM AUDIO PLAYER CONTROLS ───────────────────────────
function _audFmt(s) {{
  const m = Math.floor((s||0)/60);
  const sec = Math.floor((s||0)%60);
  return m+':'+String(sec).padStart(2,'0');
}}
function _audSetProgress(id, pct) {{
  const fill  = document.getElementById('pfill_'+id);
  const thumb = document.getElementById('pthumb_'+id);
  if (fill)  fill.style.width  = pct+'%';
  if (thumb) thumb.style.left  = pct+'%';
}}
function audToggle(id) {{
  const a = document.getElementById(id);
  const b = document.getElementById('pbtn_'+id);
  if (!a) return;
  if (a.paused) {{
    // Pause all other players first
    document.querySelectorAll('.att-voice audio').forEach(el => {{
      if (el.id !== id && !el.paused) {{ el.pause(); }}
    }});
    a.play();
    if (b) b.textContent = '⏸';
  }} else {{
    a.pause();
    if (b) b.textContent = '▶';
  }}
}}
function audUpdate(id) {{
  const a = document.getElementById(id);
  if (!a || !a.duration) return;
  const pct = (a.currentTime / a.duration) * 100;
  _audSetProgress(id, pct);
  const t = document.getElementById('ptime_'+id);
  if (t) t.textContent = _audFmt(a.currentTime) + ' / ' + _audFmt(a.duration);
}}
function audEnded(id) {{
  _audSetProgress(id, 0);
  const b = document.getElementById('pbtn_'+id);
  if (b) b.textContent = '▶';
  const t = document.getElementById('ptime_'+id);
  const a = document.getElementById(id);
  if (t && a) t.textContent = '0:00 / ' + _audFmt(a.duration);
}}
function audMeta(id) {{
  const a = document.getElementById(id);
  const t = document.getElementById('ptime_'+id);
  if (t && a) t.textContent = '0:00 / ' + _audFmt(a.duration);
}}
function audToggleMute(id, btn) {{
  const a = document.getElementById(id);
  if (!a) return;
  a.muted = !a.muted;
  btn.textContent = a.muted ? '🔇' : (a.volume < 0.5 ? '🔉' : '🔊');
  const s = document.getElementById('vslider_'+id);
  if (s) {{ const v = a.muted ? 0 : a.volume; s.value = v; s.style.setProperty('--avol', Math.round(v*100)+'%'); }}
}}
function audSetVol(id, slider) {{
  const a = document.getElementById(id);
  if (!a) return;
  const v = parseFloat(slider.value);
  a.volume = v;
  a.muted  = (v === 0);
  slider.style.setProperty('--avol', Math.round(v*100)+'%');
  const b = document.getElementById('vbtn_'+id);
  if (b) b.textContent = v === 0 ? '🔇' : v < 0.5 ? '🔉' : '🔊';
}}
function audStartDrag(e, id) {{
  e.preventDefault();
  function _seek(ev) {{
    const bar = document.getElementById('pbar_'+id);
    const a   = document.getElementById(id);
    if (!bar || !a || !a.duration) return;
    const rect = bar.getBoundingClientRect();
    const clientX = ev.touches ? ev.touches[0].clientX : ev.clientX;
    const pct = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
    a.currentTime = pct * a.duration;
    _audSetProgress(id, pct*100);
  }}
  _seek(e);
  function onMove(ev) {{ _seek(ev); }}
  function onUp()   {{
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup',   onUp);
    document.removeEventListener('touchmove', onMove);
    document.removeEventListener('touchend',  onUp);
  }}
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup',   onUp);
  document.addEventListener('touchmove', onMove, {{passive:false}});
  document.addEventListener('touchend',  onUp);
}}

// ── VIDEO CONTROLS ──────────────────────────────────────────
function _vidFmt(s) {{
  const m = Math.floor((s||0)/60);
  const sec = Math.floor((s||0)%60);
  return m+':'+String(sec).padStart(2,'0');
}}
function _vidSetProgress(id, pct) {{
  const fill  = document.getElementById('vpfill_'+id);
  const thumb = document.getElementById('vpthumb_'+id);
  if (fill)  fill.style.width = pct+'%';
  if (thumb) thumb.style.left = pct+'%';
}}
function vidTogglePlay(id) {{
  const vid = document.getElementById(id);
  if (!vid) return;
  vid.paused ? vid.play() : vid.pause();
}}
function vidOnPlay(id) {{
  const wrap = document.getElementById('wrap_'+id);
  const btn  = document.getElementById('pbtn_'+id);
  if (wrap) wrap.classList.remove('paused');
  if (btn)  btn.innerHTML = SVG_PAUSE;
}}
function vidOnPause(id) {{
  const wrap = document.getElementById('wrap_'+id);
  const btn  = document.getElementById('pbtn_'+id);
  if (wrap) wrap.classList.add('paused');
  if (btn)  btn.innerHTML = SVG_PLAY;
}}
function vidOnTime(id) {{
  const vid = document.getElementById(id);
  if (!vid || !vid.duration) return;
  const pct = (vid.currentTime / vid.duration) * 100;
  _vidSetProgress(id, pct);
  const t = document.getElementById('vtime_'+id);
  if (t) t.textContent = _vidFmt(vid.currentTime) + ' / ' + _vidFmt(vid.duration);
}}
function vidOnMeta(id) {{
  const vid = document.getElementById(id);
  const t   = document.getElementById('vtime_'+id);
  if (t && vid) t.textContent = '0:00 / ' + _vidFmt(vid.duration);
}}
function vidSeekStart(e, id) {{
  e.preventDefault();
  function _seek(ev) {{
    const bar = document.getElementById('vprog_'+id);
    const vid = document.getElementById(id);
    if (!bar || !vid || !vid.duration) return;
    const rect = bar.getBoundingClientRect();
    const clientX = ev.touches ? ev.touches[0].clientX : ev.clientX;
    const pct = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
    vid.currentTime = pct * vid.duration;
    _vidSetProgress(id, pct * 100);
  }}
  _seek(e);
  const onMove = ev => _seek(ev);
  const onUp   = () => {{
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup',   onUp);
    document.removeEventListener('touchmove', onMove);
    document.removeEventListener('touchend',  onUp);
  }};
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup',   onUp);
  document.addEventListener('touchmove', onMove, {{passive:false}});
  document.addEventListener('touchend',  onUp);
}}
function vidPiP(id) {{
  const vid = document.getElementById(id);
  if (!vid) return;
  if (document.pictureInPictureElement === vid) {{
    document.exitPictureInPicture();
  }} else {{
    vid.requestPictureInPicture && vid.requestPictureInPicture().catch(()=>{{}});
  }}
}}
function vidFullscreen(id) {{
  const wrap = document.getElementById('wrap_'+id);
  const vid  = document.getElementById(id);
  if (!wrap) return;
  const fsEl = document.fullscreenElement || document.webkitFullscreenElement;
  if (fsEl) {{
    (document.exitFullscreen || document.webkitExitFullscreen || (()=>{{}})).call(document);
  }} else {{
    // Prefer fullscreen on the wrap so our CSS controls stay visible
    const req = wrap.requestFullscreen || wrap.webkitRequestFullscreen;
    if (req) {{
      req.call(wrap).catch(()=>{{
        // fallback: native video fullscreen
        const vreq = vid && (vid.requestFullscreen || vid.webkitRequestFullscreen || vid.mozRequestFullScreen);
        if (vreq) vreq.call(vid);
      }});
    }} else if (vid) {{
      const vreq = vid.requestFullscreen || vid.webkitRequestFullscreen || vid.mozRequestFullScreen;
      if (vreq) vreq.call(vid);
    }}
  }}
}}
function setVidVol(id, slider) {{
  const vid = document.getElementById(id);
  if (!vid) return;
  const v = parseFloat(slider.value);
  vid.volume = v;
  vid.muted  = (v === 0);
  slider.style.setProperty('--vol-pct', Math.round(v*100)+'%');
  const ico = document.getElementById('vico_' + id);
  if (ico) ico.textContent = v === 0 ? '🔇' : v < 0.5 ? '🔉' : '🔊';
}}
function toggleVidMute(id, btn) {{
  const vid = document.getElementById(id);
  if (!vid) return;
  vid.muted = !vid.muted;
  btn.textContent = vid.muted ? '🔇' : vid.volume < 0.5 ? '🔉' : '🔊';
  const s = document.getElementById('vslider_' + id);
  if (s) {{ s.value = vid.muted ? 0 : vid.volume; s.style.setProperty('--vol-pct', vid.muted ? '0%' : Math.round(vid.volume*100)+'%'); }}
}}

// ── TENOR GIF: hover-to-play (thumbnails baked in by Python) ───
document.addEventListener('mouseover', e => {{
  const tenor = e.target.closest('.att-tenor');
  if (!tenor) return;
  const iframe = tenor.querySelector('iframe[data-src]');
  if (!iframe || tenor.dataset.tenorLoading) return;
  tenor.dataset.tenorLoading = '1';
  // Wait for iframe to actually load before hiding thumbnail (prevents black flash)
  iframe.addEventListener('load', () => {{
    tenor.classList.add('loaded');
  }}, {{ once: true }});
  iframe.src = iframe.dataset.src;
  // Safety fallback: if load event never fires (CSP block etc), hide thumb after 3s
  setTimeout(() => tenor.classList.add('loaded'), 3000);
}});

init();

// Dismiss loading screen — small delay so browser paints the full UI first
requestAnimationFrame(() => {{
  requestAnimationFrame(() => {{
    setTimeout(() => {{
      const ls = document.getElementById('loading-screen');
      if (ls) ls.classList.add('done');
    }}, 120);
  }});
}});

// close modal backdrop — after DOM is fully loaded
window.addEventListener('load', function() {{
  const _sm = document.getElementById('settings-modal');
  if (_sm) _sm.addEventListener('click', function(e) {{ if (e.target === this) closeSettings(); }});
}});
</script>

<!-- SETTINGS MODAL -->
<div id="settings-modal">
  <div class="settings-panel">
    <div class="settings-header">
      <span data-i18n="settings-title">Ρυθμίσεις</span>
      <button class="settings-close" onclick="closeSettings()">✕</button>
    </div>
    <div class="settings-body">
      <div class="settings-row">
        <div class="settings-label" data-i18n="settings-lang">Γλώσσα</div>
        <div class="lang-options">
          <button class="lang-opt" data-lang="el" onclick="setLang('el')">🇬🇷 Ελληνικά</button>
          <button class="lang-opt active" data-lang="en" onclick="setLang('en')">🇬🇧 English</button>
        </div>
      </div>
    </div>
  </div>
</div>
</body>
</html>"""


# ─── NEW FEATURE LOADERS ──────────────────────────────────────

def load_server_icons(pkg_path, servers_idx, raw_user=None):
    """Load server icon images as base64 data URIs, with CDN URL fallback.

    Priority:
      1. Local icon file in Servers/<guild_id>/icon.{jpeg,gif,png,webp}
      2. Icon hash in guild_memberships → Discord CDN URL
         (animated icons start with "a_" and get .gif extension)
    """
    icons = {}

    # ── 1. Local icon files (base64 data URI) ──────────────────
    for guild_id in servers_idx:
        for ext, mime in [
            ("jpeg", "image/jpeg"),
            ("gif",  "image/gif"),
            ("png",  "image/png"),
            ("webp", "image/webp"),
        ]:
            p = pkg_path / "Servers" / str(guild_id) / f"icon.{ext}"
            try:
                if p.exists():
                    b64 = base64.b64encode(p.read_bytes()).decode()
                    icons[str(guild_id)] = f"data:{mime};base64,{b64}"
                    break
            except Exception:
                pass

    # ── 2. CDN fallback from guild_memberships in user.json ─────
    if raw_user:
        for gm in raw_user.get("guild_memberships", []):
            g   = gm.get("guild", {})
            gid = str(g.get("id") or gm.get("guild_id") or "")
            icon_hash = g.get("icon") or ""
            if gid and icon_hash and gid not in icons:
                # Animated icons start with "a_" → .gif, else .png
                ext = "gif" if icon_hash.startswith("a_") else "png"
                icons[gid] = (
                    f"https://cdn.discordapp.com/icons/{gid}/{icon_hash}.{ext}?size=64"
                )

    return icons


def load_server_channels(pkg_path, servers_idx):
    """Load channels.json for each server."""
    result = {}
    for guild_id in servers_idx:
        p = pkg_path / "Servers" / str(guild_id) / "channels.json"
        try:
            if p.exists():
                with open(p, encoding="utf-8") as f:
                    result[str(guild_id)] = json.load(f)
        except Exception:
            pass
    return result


def load_server_webhooks(pkg_path, servers_idx):
    """Load webhooks.json for each server (skip empty arrays)."""
    result = {}
    for guild_id in servers_idx:
        p = pkg_path / "Servers" / str(guild_id) / "webhooks.json"
        try:
            if p.exists():
                with open(p, encoding="utf-8") as f:
                    data = json.load(f)
                if data:
                    result[str(guild_id)] = data
        except Exception:
            pass
    return result


def load_harvest_history(pkg_path):
    """Load data subject access request history, newest first."""
    p = (pkg_path / "Account" / "user_data_exports"
         / "discord_harvests" / "data_subject_access_requests.json")
    try:
        if p.exists():
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            records = data.get("records", [])
            records.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            return records
    except Exception:
        pass
    return []


def load_ad_traits(pkg_path):
    """Load ad targeting traits from Ads/traits.json."""
    p = pkg_path / "Ads" / "traits.json"
    try:
        if p.exists():
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def load_support_tickets(pkg_path):
    """Load support tickets dict."""
    p = pkg_path / "Support_Tickets" / "tickets.json"
    try:
        if p.exists():
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def load_dev_apps(pkg_path):
    """Load developer apps from Account/applications/*/application.json."""
    apps = []
    apps_dir = pkg_path / "Account" / "applications"
    if not apps_dir.exists():
        return apps
    for app_dir in apps_dir.iterdir():
        if not app_dir.is_dir():
            continue
        p = app_dir / "application.json"
        try:
            if p.exists():
                with open(p, encoding="utf-8") as f:
                    d = json.load(f)
                app_id   = d.get("id", app_dir.name)
                icon_hash = d.get("icon")
                icon_url  = (f"https://cdn.discordapp.com/app-icons/{app_id}/{icon_hash}.png"
                             if icon_hash else "")
                apps.append({
                    "id":       str(app_id),
                    "name":     d.get("name", ""),
                    "has_bot":  "bot" in d,
                    "icon_url": icon_url,
                })
        except Exception:
            pass
    return apps


# ─── CORE GENERATION ─────────────────────────────────────────
def run_generation(package_path_str, output_path_str=None):
    """Run the full generation pipeline.  Called by both CLI and GUI modes."""
    global PACKAGE_PATH, OUTPUT_FILE
    import zipfile as _zf

    input_path = Path(package_path_str)
    if not input_path.exists():
        raise FileNotFoundError(f"Not found: {input_path}")

    # ── ZIP handling: extract automatically ──
    if input_path.suffix.lower() == ".zip":
        if not _zf.is_zipfile(input_path):
            raise ValueError(f"Not a valid ZIP file: {input_path.name}")
        extract_dir = input_path.with_suffix("")          # package.zip → package/
        with _zf.ZipFile(input_path, "r") as zf:
            members = zf.namelist()
            total = len(members)
            step = max(1, total // 20)   # ~5% increments
            print(f"Extracting {input_path.name} ({total:,} files) …")
            for i, member in enumerate(members, 1):
                zf.extract(member, extract_dir)
                if i % step == 0 or i == total:
                    pct = i * 100 // total
                    print(f"  {i:,}/{total:,} files ({pct}%)")
        print(f"Extraction complete → {extract_dir.name}/")
        # Some ZIPs have a single top-level folder; detect and unwrap
        if not (extract_dir / "Account" / "user.json").exists():
            subs = [d for d in extract_dir.iterdir() if d.is_dir()]
            if len(subs) == 1 and (subs[0] / "Account" / "user.json").exists():
                extract_dir = subs[0]
        PACKAGE_PATH = extract_dir
        _default_out = input_path.parent / "discord_viewer.html"
    else:
        PACKAGE_PATH = input_path
        _default_out = PACKAGE_PATH.parent / "discord_viewer.html"

    OUTPUT_FILE = Path(output_path_str) if output_path_str else _default_out

    # ── Validate ──
    if not (PACKAGE_PATH / "Account" / "user.json").exists():
        raise FileNotFoundError("Not a valid Discord data package: missing Account/user.json")
    if not (PACKAGE_PATH / "Messages" / "index.json").exists():
        raise FileNotFoundError("Not a valid Discord data package: missing Messages/index.json")

    print("Discord Archive Viewer v3"); print("="*50)

    # Load raw user.json for functions that need the full data
    with open(PACKAGE_PATH / "Account" / "user.json", encoding="utf-8") as f:
        raw_user = json.load(f)

    user = load_user()
    print(f"User: {user['global_name']} (@{user['username']})")
    servers = load_servers()
    print(f"Servers: {len(servers)}")
    activity = load_activity()
    print(f"Activity events: {sum(activity.values())}")
    idx = json.load(open(PACKAGE_PATH/"Messages"/"index.json", encoding="utf-8"))
    channels, total, stats_accum = load_messages(idx)
    av = None
    av_static = None  # non-animated version for msg-av

    gif_path = PACKAGE_PATH / "Account" / "avatar.gif"
    if gif_path.exists():
        av = b64_file(gif_path)
        print("Avatar: OK (gif)")
        try:
            from PIL import Image
            import io
            with Image.open(gif_path) as im:
                im.seek(0)
                frame = im.convert("RGBA")
                buf = io.BytesIO()
                frame.save(buf, format="PNG")
                av_static = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
            print("Avatar static: OK (first frame extracted)")
        except Exception as e:
            print(f"Avatar static: fallback to gif ({e})")
            av_static = av
    else:
        for _ext in ("png", "webp", "jpg", "jpeg"):
            data = b64_file(PACKAGE_PATH / "Account" / f"avatar.{_ext}")
            if data:
                av = data
                av_static = data
                print(f"Avatar: OK ({_ext})")
                break

    if not av:
        print("Avatar: not found")
    print("  Prefetching Tenor thumbnails...")
    prefetch_tenor_thumbs(channels)
    stats = calc_stats(channels, total, stats_accum)

    quests       = load_quests(PACKAGE_PATH)
    nitro_hist   = load_nitro_history(PACKAGE_PATH)
    payments     = load_payments_summary(PACKAGE_PATH)
    connections  = load_connections(raw_user)
    friends_data = load_friends(raw_user)
    notes        = load_notes(raw_user)
    orbs         = raw_user.get("current_orbs_balance", 0)
    print(f"Quests: {len(quests)} | Nitro history: {len(nitro_hist)}")

    # Build user ID → display name map for resolving @mentions
    user_map = {}
    user_map[user["id"]] = user["global_name"] or user["username"]
    for r in raw_user.get("relationships", []):
        u = r.get("user", {})
        uid = str(u.get("id", ""))
        name = u.get("global_name") or u.get("username") or ""
        if uid and name:
            user_map[uid] = name
    for ch in channels:
        for m in ch.get("messages", []):
            aid = m.get("author_id", "")
            aname = m.get("author", "")
            if aid and aname and aid not in user_map:
                user_map[aid] = aname
    print(f"User map: {len(user_map)} known users for @mention resolution")

    server_icons    = load_server_icons(PACKAGE_PATH, servers, raw_user=raw_user)
    server_channels = load_server_channels(PACKAGE_PATH, servers)
    server_webhooks = load_server_webhooks(PACKAGE_PATH, servers)
    harvest_history = load_harvest_history(PACKAGE_PATH)
    ad_traits       = load_ad_traits(PACKAGE_PATH)
    support_tickets = load_support_tickets(PACKAGE_PATH)
    dev_apps        = load_dev_apps(PACKAGE_PATH)
    print(f"Server icons: {len(server_icons)} | Channels: {len(server_channels)} | "
          f"Webhooks: {len(server_webhooks)} | Harvest: {len(harvest_history)} | "
          f"Dev apps: {len(dev_apps)}")

    extra = {
        "connections":     connections,
        "friends":         friends_data,
        "notes":           notes,
        "quests":          quests,
        "nitro_history":   nitro_hist,
        "payments":        payments,
        "orbs_balance":    orbs,
        "user_map":        user_map,
        "server_icons":    server_icons,
        "server_channels": server_channels,
        "server_webhooks": server_webhooks,
        "harvest_history": harvest_history,
        "ad_traits":       ad_traits,
        "support_tickets": support_tickets,
        "dev_apps":        dev_apps,
    }
    html = generate_html(user, servers, channels, stats, activity, av, extra, av_static=av_static)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(html)
    sz = OUTPUT_FILE.stat().st_size / 1024 / 1024
    print(f"\nDONE! {sz:.1f}MB → {OUTPUT_FILE}")


# ─── GUI (CustomTkinter) ─────────────────────────────────────
_BLURPLE       = "#5865F2"
_BLURPLE_HOVER = "#4752C4"
_DARK_BG       = "#1a1a2e"
_ICON_PATH     = Path(__file__).with_name("icon.ico")


class DiscordViewerGUI:
    """Modern dark GUI using CustomTkinter — ZIP-only workflow."""

    def __init__(self, ctk_mod):
        self.ctk = ctk_mod
        self.root = ctk_mod.CTk()
        self.root.title("Discord Archive Viewer v3")
        self.root.resizable(True, True)
        self.root.minsize(560, 460)
        _mw, _mh = 720, 560
        self.root.geometry(f"{_mw}x{_mh}")
        # ── icon (window + taskbar) ──
        if _ICON_PATH.exists():
            _ico = str(_ICON_PATH)
            def _set_icon():
                try: self.root.iconbitmap(default=_ico)
                except Exception: pass
                try: self.root.iconbitmap(_ico)
                except Exception: pass
                try: self.root.wm_iconbitmap(_ico)
                except Exception: pass
            _set_icon()
            self.root.after(100, _set_icon)
            self.root.after(300, _set_icon)
        elif not _ICON_PATH.exists():
            # icon.ico not found — show custom warning once at startup
            def _warn_icon():
                self._show_error(
                    "Icon Not Found",
                    f"icon.ico not found next to the script.\n"
                    f"Expected: {_ICON_PATH}\n\n"
                    f"Place icon.ico in the same folder as\n"
                    f"generate_discord_viewer.py to enable the icon."
                )
            self.root.after(400, _warn_icon)

        self.selected_path = None
        self.output_path   = None
        self._old_stdout   = None
        self._old_stderr   = None
        self._log_handler  = None

        self._build_ui()
        # Show the English warning modal after the window is drawn
        self.root.after(120, self._show_english_warning)

    def _setup_popup(self, dlg, dw: int, dh: int) -> None:
        import sys as _sys
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.transient(self.root)
        dlg.attributes("-topmost", True)
        dlg.protocol("WM_DELETE_WINDOW", lambda: None)
        scale = self.root._get_window_scaling()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = int(((sw / 2) - (dw / 2)) * scale)
        y = int(((sh / 2) - (dh / 2)) * scale)
        dlg.geometry(f"{dw}x{dh}+{x}+{y}")
        if _ICON_PATH.exists():
            _ico = str(_ICON_PATH)
            def _set_dlg_icon():
                try: dlg.iconbitmap(default=_ico)
                except Exception: pass
                try: dlg.iconbitmap(_ico)
                except Exception: pass
                try: dlg.wm_iconbitmap(_ico)
                except Exception: pass
            dlg.after(50,  _set_dlg_icon)
            dlg.after(150, _set_dlg_icon)
            dlg.after(350, _set_dlg_icon)
        def _harden():
            if _sys.platform != "win32": return
            try:
                import ctypes as _ct
                hwnd = _ct.windll.user32.GetParent(dlg.winfo_id())
                if not hwnd: return
                GWL_STYLE = -16
                sty = _ct.windll.user32.GetWindowLongW(hwnd, GWL_STYLE)
                sty &= ~(0x00020000 | 0x00010000)  # no WS_MINIMIZEBOX / WS_MAXIMIZEBOX
                _ct.windll.user32.SetWindowLongW(hwnd, GWL_STYLE, sty)
                _ct.windll.user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x0027)
                hmenu = _ct.windll.user32.GetSystemMenu(hwnd, False)
                if hmenu:
                    _ct.windll.user32.EnableMenuItem(hmenu, 0xF060, 0x0001)  # SC_CLOSE | MF_GRAYED
            except Exception: pass
        dlg.after(130, _harden)

    @staticmethod
    def _close_popup(dlg) -> None:
        try: dlg.attributes("-topmost", False)
        except Exception: pass
        try: dlg.grab_release()
        except Exception: pass
        try: dlg.destroy()
        except Exception: pass

    # English warning modal ─────────────────────────
    def _show_english_warning(self):
        ctk = self.ctk
        dlg = ctk.CTkToplevel(self.root)
        dlg.title("Important — Read Before Continuing")
        self._setup_popup(dlg, 640, 480)

        # orange accent bar at top
        ctk.CTkFrame(dlg, fg_color="#ff9900", height=7, corner_radius=0).pack(fill="x")

        # ── icon + bold title — fully centered ──
        ctk.CTkLabel(
            dlg, text="⚠️",
            font=ctk.CTkFont(size=52),
            anchor="center"
        ).pack(pady=(28, 6))

        ctk.CTkLabel(
            dlg,
            text="Discord Language Must Be English",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#ffcc44",
            justify="center",
            anchor="center"
        ).pack(padx=30, pady=(0, 6))

        # divider
        ctk.CTkFrame(dlg, fg_color="#444466", height=2, corner_radius=0).pack(fill="x", padx=40, pady=(8, 18))

        # body text — centered
        body = (
            "This tool only works with Discord data packages requested\n"
            "while Discord's interface language was set to  English.\n\n"
            "If your Discord is set to another language  (Greek, French,\n"
            "German, Spanish …)  the folder structure will differ and the\n"
            "viewer will fail or display incorrect data.\n\n"
            "Before requesting your data package, go to:\n"
            "Discord Settings  →  Language  →  Select  English"
        )
        ctk.CTkLabel(
            dlg,
            text=body,
            font=ctk.CTkFont(size=14),
            text_color="#d0d0d0",
            justify="center",
            anchor="center"
        ).pack(padx=40, pady=(0, 24), fill="x")

        # confirm button — centered
        ctk.CTkButton(
            dlg,
            text="✓  I Understand, Continue",
            width=260, height=46,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color="#ff9900",
            hover_color="#cc7700",
            text_color="#000000",
            corner_radius=12,
            command=lambda: self._close_popup(dlg)
        ).pack(pady=(0, 30))

        dlg.bind("<Return>", lambda e: self._close_popup(dlg))
        dlg.after(80, dlg.focus_force)

    # ── custom error dialog (replaces messagebox) ─────────
    def _show_error(self, title, message):
        ctk = self.ctk
        dlg = ctk.CTkToplevel(self.root)
        dlg.title(title)
        self._setup_popup(dlg, 440, 240)

        ctk.CTkLabel(dlg, text=title,
                     font=ctk.CTkFont(size=16, weight="bold"),
                     text_color="#ff5555").pack(pady=(20, 6))
        ctk.CTkLabel(dlg, text=message,
                     font=ctk.CTkFont(size=12), text_color="gray",
                     wraplength=360, justify="center").pack(padx=20, pady=(0, 16))
        ctk.CTkButton(dlg, text="OK", width=100, fg_color=_BLURPLE,
                      hover_color=_BLURPLE_HOVER,
                      command=lambda: self._close_popup(dlg)).pack(pady=(0, 16))
        dlg.bind("<Return>", lambda e: self._close_popup(dlg))
        dlg.after(50, dlg.focus_force)

    # ── layout ─────────────────────────────────────────────
    def _build_ui(self):
        ctk = self.ctk
        import tkinter as _tk

        # ═══════════════════════════════════════════════════
        # HEADER
        # ═══════════════════════════════════════════════════
        hdr = ctk.CTkFrame(self.root, fg_color="#12122a", corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="Discord Archive Viewer",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color="#ffffff").pack(side="left", padx=20, pady=14)
        ctk.CTkLabel(hdr, text="v3",
                     font=ctk.CTkFont(size=11),
                     text_color="#5865F2").pack(side="left", pady=14)

        # ═══════════════════════════════════════════════════
        # ZIP DROP ZONE CARD
        # ═══════════════════════════════════════════════════
        self._zip_card = ctk.CTkFrame(
            self.root,
            fg_color="#14142b",
            corner_radius=12,
            border_width=2,
            border_color="#2a2a55"
        )
        self._zip_card.pack(fill="x", padx=20, pady=(14, 6))

        # col 0 = icon (fixed), col 1 = text (expands), col 2 = button (fixed)
        self._zip_card.columnconfigure(0, weight=0)
        self._zip_card.columnconfigure(1, weight=1)
        self._zip_card.columnconfigure(2, weight=0)

        self._zip_ico_lbl = ctk.CTkLabel(
            self._zip_card,
            text="📦",
            font=ctk.CTkFont(size=28)
        )
        self._zip_ico_lbl.grid(row=0, column=0, rowspan=2,
                               padx=(18, 10), pady=(14, 14), sticky="w")

        self._zip_name_lbl = ctk.CTkLabel(
            self._zip_card,
            text="No file selected",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#888888",
            anchor="w"
        )
        self._zip_name_lbl.grid(row=0, column=1, padx=(0, 8), pady=(16, 2), sticky="ew")

        self._zip_sub_lbl = ctk.CTkLabel(
            self._zip_card,
            text="Click  Browse ZIP  to select your Discord data package",
            font=ctk.CTkFont(size=11),
            text_color="#555577",
            anchor="w"
        )
        self._zip_sub_lbl.grid(row=1, column=1, padx=(0, 8), pady=(0, 16), sticky="ew")

        self.browse_btn = ctk.CTkButton(
            self._zip_card,
            text="Browse ZIP…",
            command=self._browse_zip,
            width=130, height=36,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=_BLURPLE, hover_color=_BLURPLE_HOVER,
            corner_radius=8
        )
        self.browse_btn.grid(row=0, column=2, rowspan=2,
                             padx=(12, 18), pady=14, sticky="e")

        # ═══════════════════════════════════════════════════
        # PROGRESS BAR  (hidden until generation starts)
        # ═══════════════════════════════════════════════════
        self.prog_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.prog_frame.pack(fill="x", padx=20, pady=(2, 0))

        self.progress = ctk.CTkProgressBar(
            self.prog_frame, height=8,
            progress_color=_BLURPLE,
            fg_color="#2a2a40",
            mode="determinate"
        )
        self.progress.set(0)
        self._progress_visible = False

        self.status_var = _tk.StringVar(value="")
        self.status_label = ctk.CTkLabel(
            self.prog_frame, textvariable=self.status_var,
            font=ctk.CTkFont(size=11),
            text_color="gray", anchor="w"
        )
        self.status_label.pack(fill="x", pady=(2, 0))

        # ═══════════════════════════════════════════════════
        # LOG TEXTBOX
        # ═══════════════════════════════════════════════════
        self.log_text = ctk.CTkTextbox(
            self.root,
            font=("Consolas", 12),
            fg_color=_DARK_BG,
            text_color="#cccccc",
            state="disabled",
            wrap="word",
            corner_radius=8
        )
        self.log_text.pack(fill="both", expand=True, padx=20, pady=(8, 8))
        self.log_text.tag_config("warning", foreground="#ffaa00")
        self.log_text.tag_config("error",   foreground="#ff5555")
        self.log_text.tag_config("success", foreground="#55ff55")
        self.log_text.tag_config("stdout",  foreground="#cccccc")

        # ═══════════════════════════════════════════════════
        # BOTTOM ACTION BUTTONS
        # ═══════════════════════════════════════════════════
        btn_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=(0, 16))

        self.gen_btn = ctk.CTkButton(
            btn_frame, text="⚡  Generate HTML",
            command=self._start_generation,
            state="disabled", width=180, height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=_BLURPLE, hover_color=_BLURPLE_HOVER,
            corner_radius=10
        )
        self.gen_btn.pack(side="left")

        self.open_btn = ctk.CTkButton(
            btn_frame, text="🌐  Open in Browser",
            command=self._open_html,
            state="disabled", width=180, height=40,
            font=ctk.CTkFont(size=13),
            fg_color="#1e1e3a", hover_color="#2a2a4a",
            border_width=1, border_color="#3a3a6a",
            corner_radius=10
        )
        self.open_btn.pack(side="right")

    # ── actions ────────────────────────────────────────────
    def _set_path(self, path):
        self.selected_path = path
        p = Path(path)
        # Update card labels
        self._zip_name_lbl.configure(
            text=p.name,
            text_color="#ffffff"
        )
        self._zip_sub_lbl.configure(
            text=f"✅  Ready to generate  —  {p.stat().st_size / 1024 / 1024:.1f} MB",
            text_color="#55bb77"
        )
        self._zip_card.configure(border_color="#5865F2")
        self.gen_btn.configure(state="normal")
        self.open_btn.configure(state="disabled")
        # reset progress bar appearance for a fresh run
        if self._progress_visible:
            self.progress.configure(mode="determinate",
                                    progress_color=_BLURPLE,
                                    fg_color="#2a2a40")
            self.progress.set(0)
        self.status_var.set("")
        self.output_path = None

    # ── Detect non-English Discord package ─────────────
    def _detect_package_language(self, zip_path: str):
        """Peek inside the ZIP without extracting.
        Returns (is_english: bool, detected_lang: str, non_english_folders: list)."""
        import zipfile as _zf
        # Expected top-level English folder names in a Discord data package
        ENGLISH_FOLDERS = {
            "Account", "Messages", "Servers", "Activity",
            "Ads", "Activities", "Programs"
        }
        # Known non-English translations of key folder names
        NON_ENGLISH_HINTS = {
            # Greek
            "Λογαριασμός": "Greek", "Μηνύματα": "Greek", "Διακομιστές": "Greek",
            "Δραστηριότητα": "Greek", "Σύνδεσμοι": "Greek",
            # French
            "Compte": "French", "Messages": None, "Serveurs": "French",
            "Activité": "French",
            # German
            "Konto": "German", "Nachrichten": "German", "Server": None,
            "Aktivität": "German",
            # Spanish
            "Cuenta": "Spanish", "Mensajes": "Spanish", "Servidores": "Spanish",
            "Actividad": "Spanish",
            # Portuguese
            "Conta": "Portuguese", "Mensagens": "Portuguese",
            # Italian
            "Account": None, "Messaggi": "Italian", "Attività": "Italian",
            # Dutch
            "Berichten": "Dutch", "Activiteit": "Dutch",
            # Russian
            "Аккаунт": "Russian", "Сообщения": "Russian", "Серверы": "Russian",
            # Turkish
            "Hesap": "Turkish", "Mesajlar": "Turkish", "Sunucular": "Turkish",
            # Polish
            "Konto": "Polish", "Wiadomości": "Polish", "Serwery": "Polish",
        }
        try:
            with _zf.ZipFile(zip_path, "r") as zf:
                names = zf.namelist()
            # Collect unique top-level folder names
            top_folders = set()
            for n in names:
                part = n.split("/")[0].strip()
                if part:
                    top_folders.add(part)
            # Also handle single-wrapper: zip → one_folder → Account, ...
            # If Account not directly present, check one level deeper
            sub_folders = set()
            for n in names:
                parts = n.split("/")
                if len(parts) >= 2 and parts[1].strip():
                    sub_folders.add(parts[1].strip())

            folders_to_check = top_folders | sub_folders

            non_english = []
            detected_lang = "Unknown"
            for folder in folders_to_check:
                lang = NON_ENGLISH_HINTS.get(folder)
                if lang and folder not in ENGLISH_FOLDERS:
                    non_english.append(folder)
                    detected_lang = lang

            # A key signal: if "Account" is absent but something else looks like it
            has_account = any("Account" in f or "account" in f.lower() for f in folders_to_check)
            is_english = has_account or len(non_english) == 0
            return is_english, detected_lang, non_english
        except Exception:
            return True, "", []   # can't detect → assume OK

    def _show_language_warning(self, detected_lang: str, non_english_folders: list):
        """Show a modal warning when a non-English package is detected."""
        ctk = self.ctk
        dlg = ctk.CTkToplevel(self.root)
        dlg.title("⚠️ Non-English Package Detected")
        self._setup_popup(dlg, 620, 480)

        # red accent bar
        ctk.CTkFrame(dlg, fg_color="#cc2222", height=7, corner_radius=0).pack(fill="x")

        ctk.CTkLabel(
            dlg, text="🌐",
            font=ctk.CTkFont(size=52),
            anchor="center"
        ).pack(pady=(24, 6))

        ctk.CTkLabel(
            dlg,
            text="Non-English Package Detected!",
            font=ctk.CTkFont(size=21, weight="bold"),
            text_color="#ff6666",
            justify="center", anchor="center"
        ).pack(padx=30)

        lang_str = f"  Detected language:  {detected_lang}  " if detected_lang and detected_lang != "Unknown" else ""
        if lang_str:
            ctk.CTkLabel(
                dlg, text=lang_str,
                font=ctk.CTkFont(size=13),
                text_color="#ffaa44",
                justify="center", anchor="center"
            ).pack(pady=(6, 0))

        ctk.CTkFrame(dlg, fg_color="#553333", height=2, corner_radius=0).pack(fill="x", padx=40, pady=(12, 16))

        folders_sample = ", ".join(f'"{f}"' for f in non_english_folders[:5])
        body = (
            f"The selected ZIP appears to be a Discord package\n"
            f"in a non-English language.\n\n"
            f"Non-English folder names found inside the ZIP:\n"
            f"  {folders_sample}\n\n"
            f"For example, instead of  \"Account\"  the package uses a\n"
            f"translated name. This tool requires English folder names.\n\n"
            f"To fix: change Discord's language to  English,  request\n"
            f"your data again, and open the new ZIP."
        )
        ctk.CTkLabel(
            dlg, text=body,
            font=ctk.CTkFont(size=13),
            text_color="#ccbbbb",
            justify="center", anchor="center"
        ).pack(padx=36, pady=(0, 20), fill="x")

        btn_row = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_row.pack(pady=(0, 28))

        _proceed = [False]
        def _on_proceed():
            _proceed[0] = True
            self._close_popup(dlg)

        ctk.CTkButton(
            btn_row, text="✕  Cancel — Choose Another File",
            width=230, height=42,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#cc2222", hover_color="#991111",
            text_color="#ffffff", corner_radius=10,
            command=lambda: self._close_popup(dlg)
        ).pack(side="left", padx=(0, 12))

        ctk.CTkButton(
            btn_row, text="⚠️  Proceed Anyway",
            width=180, height=42,
            font=ctk.CTkFont(size=13),
            fg_color="#555533", hover_color="#777744",
            text_color="#ffdd88", corner_radius=10,
            command=_on_proceed
        ).pack(side="left")

        dlg.bind("<Escape>", lambda e: self._close_popup(dlg))
        dlg.after(80, dlg.focus_force)
        dlg.wait_window()
        return _proceed[0]

    def _browse_zip(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            title="Select your Discord data package ZIP",
            filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")])
        if not path:
            return
        if not path.lower().endswith(".zip"):
            self._show_error(
                "Wrong File Type",
                f"The file you selected is not a ZIP archive:\n"
                f"  {Path(path).name}\n\n"
                f"Please select your Discord data package\n"
                f"which must be a  .zip  file.\n\n"
                f"Download it from Discord:\n"
                f"Settings → Privacy & Safety → Request Data"
            )
            return
        # ── Language detection ──
        is_english, detected_lang, non_english_folders = self._detect_package_language(path)
        if not is_english and non_english_folders:
            proceed = self._show_language_warning(detected_lang, non_english_folders)
            if not proceed:
                return   # user chose to cancel
        self._set_path(path)

    def _start_generation(self):
        import threading
        from tkinter import filedialog

        # ── Ask where to save the HTML ──
        save_path = filedialog.asksaveasfilename(
            title="Save discord_viewer.html",
            defaultextension=".html",
            initialfile=f"discord_viewer.html",
            filetypes=[("HTML file", "*.html"), ("All files", "*.*")],
            initialdir=str(Path(self.selected_path).parent)
        )
        if not save_path:   # user cancelled
            return

        self._save_path = save_path

        self.gen_btn.configure(state="disabled")
        self.browse_btn.configure(state="disabled")
        self.open_btn.configure(state="disabled")
        # clear log
        self.log_text.configure(state="normal")
        self.log_text.delete("0.0", "end")
        self.log_text.configure(state="disabled")
        # show progress bar now (hidden at startup)
        if not self._progress_visible:
            self.progress.pack(fill="x", pady=(0, 4), before=self.status_label)
            self._progress_visible = True
        # reset to blurple for fresh run
        self.progress.configure(mode="indeterminate",
                                progress_color=_BLURPLE, fg_color="#2a2a40")
        self.status_var.set("Starting…")
        self.progress.start()
        # redirect stdout / logging → text widget
        self._setup_redirects()
        threading.Thread(target=self._run_thread, daemon=True).start()


    def _run_thread(self):
        try:
            run_generation(self.selected_path, self._save_path)
            self.output_path = Path(self._save_path)
            self.root.after(0, self._on_success)
        except Exception as e:
            self.root.after(0, self._on_error, str(e))
        finally:
            self.root.after(0, self._restore_redirects)

    def _on_success(self):
        self.progress.stop()
        self.progress.configure(mode="determinate",
                                progress_color="#55ff99",
                                fg_color="#1a3a1a")
        self.progress.set(1.0)
        sz = self.output_path.stat().st_size / 1024 / 1024
        self.status_var.set(f"✔  Complete!  {sz:.1f} MB  →  {self.output_path.name}")
        self._zip_sub_lbl.configure(
            text=f"✅  HTML saved: {self.output_path.name}  ({sz:.1f} MB)",
            text_color="#55ff99"
        )
        self._zip_card.configure(border_color="#33aa66")
        self._log_tag(f"\n✔  Done!  {sz:.1f} MB → {self.output_path}\n", "success")
        self.gen_btn.configure(state="normal")
        self.browse_btn.configure(state="normal")
        self.open_btn.configure(state="normal")

    def _on_error(self, msg):
        self.progress.stop()
        self.progress.configure(mode="determinate",
                                progress_color="#ff5555",
                                fg_color="#3a1a1a")
        self.progress.set(1.0)
        self.status_var.set("✘  Error")
        self._log_tag(f"\n✘  ERROR: {msg}\n", "error")
        self.gen_btn.configure(state="normal")
        self.browse_btn.configure(state="normal")

    def _log_tag(self, text, tag):
        try:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", text, tag)
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        except Exception:
            pass

    def _open_html(self):
        if self.output_path and self.output_path.exists():
            import webbrowser
            webbrowser.open(str(self.output_path))

    # ── stdout / log redirect ─────────────────────────────
    def _setup_redirects(self):
        self._old_stdout = sys.stdout
        self._old_stderr = sys.stderr
        sys.stdout = TextRedirector(self.log_text, self._old_stdout, "stdout",
                                    status_var=self.status_var,
                                    progress_ref=(self.progress, self.root))
        sys.stderr = TextRedirector(self.log_text, self._old_stderr, "error")
        self._log_handler = TextWidgetLogHandler(self.log_text)
        self._log_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        log.addHandler(self._log_handler)

    def _restore_redirects(self):
        if self._old_stdout:
            sys.stdout = self._old_stdout
        if self._old_stderr:
            sys.stderr = self._old_stderr
        if self._log_handler:
            log.removeHandler(self._log_handler)

    # ── mainloop ──────────────────────────────────────────
    def run(self):
        # CustomTkinter uses DPI scaling — must account for it when positioning.
        # This is the official approach from the CTk author (_get_window_scaling).
        w, h = 720, 560
        scale = self.root._get_window_scaling()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = int(((sw / 2) - (w / 2)) * scale)
        y = int(((sh / 2) - (h / 2)) * scale)
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.mainloop()
        self._restore_redirects()


# ─── ENTRY POINT ─────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) > 1:
        # CLI mode:  python generate_discord_viewer.py /path/to/package
        try:
            run_generation(sys.argv[1])
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # GUI mode:  double-click or run without arguments
        try:
            import customtkinter as ctk
        except ImportError:
            print("Installing customtkinter…")
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "customtkinter"])
            import customtkinter as ctk
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        app = DiscordViewerGUI(ctk)
        app.run()

