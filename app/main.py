from fastapi import FastAPI
from fastapi import Request
from app.url_utils import validate_and_normalize
from app.fetcher import fetch_url_data
from fastapi import HTTPException
import os
from fastapi.responses import JSONResponse, HTMLResponse
from mimetypes import guess_type
from app.html_parser import extract_html_features
from app.risk_engine import compute_heuristic_score
import json, os, time, hashlib

app=FastAPI()

@app.get("/", response_class=HTMLResponse)
def read_root():
    static_file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "index.html")
    if not os.path.exists(static_file_path):
        static_file_path = "static/index.html"
    try:
        with open(static_file_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    except Exception as e:
        return HTMLResponse(content=f"<h1>SafeLink Scanner</h1><p>Error loading frontend: {str(e)}</p>", status_code=500)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/validate")
def validate(url: str):
    ok, result = validate_and_normalize(url)
    if ok:
        return {"status": "valid", "url": result}
    else:
        return {"status": "invalid", "reason": result}

@app.get("/fetch")
async def fetch(url: str):
    # Validate first
    ok, res = validate_and_normalize(url)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Invalid URL: {res}")

    # Use the normalized url returned by validator
    normalized = res
    data = await fetch_url_data(normalized)
    return data

@app.get("/testfile")
def testfile():
    path = "/mnt/data/Home.jpeg"   # your uploaded file
    if not os.path.exists(path):
        return JSONResponse({"exists": False, "path": path})
    size = os.path.getsize(path)
    mime, _ = guess_type(path)
    return {"exists": True, "path": path, "size": size, "mime": mime}

@app.get("/extract")
async def extract(url: str):
    # Step 1: Validate & normalize URL
    ok, res = validate_and_normalize(url)
    if not ok:
        return {"status": "invalid", "reason": res}

    clean_url = res

    # Step 2: Fetch HTML content
    data = await fetch_url_data(clean_url)

    # Step 3: If GET request failed
    if data["get"]["error"]:
        return {
            "status": "error",
            "reason": "Could not fetch site",
            "details": data["get"]["error"]
        }

    html = data["get"]["content"]

    # Step 4: Parse HTML
    extracted = extract_html_features(html)

    return {
        "status": "success",
        "url": clean_url,
        "fetch_info": {
            "status_code": data["get"]["status_code"],
            "final_url": data["get"]["final_url"],
            "filesize": data["get"]["filesize"]
        },
        "extracted": extracted
    }

@app.get("/risk")
async def risk(url: str):
    # 1) Validate
    ok, res = validate_and_normalize(url)
    if not ok:
        return {"status": "invalid", "reason": res}

    normalized = res

    # 2) Fetch + extract
    fetch_data = await fetch_url_data(normalized)
    if fetch_data.get("get", {}).get("error"):
        # still compute heuristics but mark fetch error
        extracted = {"title": None, "meta_description": None, "links": [], "forms": [], "scripts": [], "images": [], "iframes": [], "clean_text": ""}
    else:
        extracted = extract_html_features(fetch_data["get"].get("content", "") or "")

    # 3) Optional: check external services (if you have keys)
    vt = None
    gsb = None
    # If you have vt/gsb functions implemented, call them:
    # vt = await check_virus_total(normalized)
    # gsb = await check_google_safe_browsing(normalized)

    # 4) Compute heuristic score
    risk_report = compute_heuristic_score(fetch=fetch_data, extracted=extracted, normalized_url=normalized, vt=vt, gsb=gsb)

    # 5) Return aggregated report
    return {
        "status": "ok",
        "url": normalized,
        "fetch": fetch_data,
        "extracted": extracted,
        "risk": risk_report
    }


@app.get("/scan")
async def scan(url: str):
    # 1) Validate
    ok, res = validate_and_normalize(url)
    if not ok:
        return {"status": "invalid_url", "reason": res}

    normalized = res

    # 2) Fetch
    fetch_data = await fetch_url_data(normalized)

    # 3) Extract
    if fetch_data.get("get", {}).get("error"):
        extracted = {
            "title": None, "meta_description": None, "links": [],
            "forms": [], "scripts": [], "images": [], "iframes": [],
            "clean_text": ""
        }
    else:
        html = fetch_data["get"].get("content", "") or ""
        extracted = extract_html_features(html)

    # 4) Risk score
    risk = compute_heuristic_score(fetch_data, extracted, normalized)

    # 5) Build final summary (for Zoho)
    summary = {
        "status": "ok",
        "url": normalized,
        "verdict": risk["verdict"],
        "score": risk["score"],
        "title": extracted.get("title"),
        "final_url": fetch_data["get"].get("final_url"),
        "filesize": fetch_data["get"].get("filesize"),
        "explanations": risk["explanations"][:3],  # top 3 reasons only
    }

    return summary

CACHE_FILE = "cache/scans.json"
TTL = 60*60*12  # 12 hours

def _load():
    if not os.path.exists(CACHE_FILE):
        return {}
    return json.load(open(CACHE_FILE, "r"))

def _save(d):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    json.dump(d, open(CACHE_FILE, "w"))

def cache_get(url):
    d = _load()
    key = hashlib.sha256(url.encode()).hexdigest()
    item = d.get(key)
    if not item: return None
    if time.time() - item["ts"] > TTL:
        d.pop(key, None); _save(d); return None
    return item["result"]

def cache_set(url, result):
    d = _load()
    key = hashlib.sha256(url.encode()).hexdigest()
    d[key] = {"ts": time.time(), "result": result}
    _save(d)




