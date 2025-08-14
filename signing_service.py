import os, hashlib, hmac
from datetime import datetime
from io import BytesIO
from flask import Flask, request, send_file, abort, render_template_string
from pymongo import MongoClient
from gridfs import GridFS
import fitz  # PyMuPDF

# --- Env + debug -------------------------------------------------------------
MONGO_URI = (os.environ.get("MONGO_URI") or "").strip()
SIGN_SECRET = (os.environ.get("SIGN_SECRET") or "change-me").strip()
PORT = int(os.environ.get("PORT", "5001"))

# Debug: shows exactly what Render passed (look in Logs)
print("MONGO_URI repr:", repr(MONGO_URI))

if not (MONGO_URI.startswith("mongodb://") or MONGO_URI.startswith("mongodb+srv://")):
    raise ValueError("Invalid MONGO_URI: must start with 'mongodb://' or 'mongodb+srv://'. "
                     "Set Render env Key=MONGO_URI, Value=<your SRV URI> (no quotes)")

# --- DB ----------------------------------------------------------------------
client = MongoClient(MONGO_URI)
db = client["agr_cpq"]
fs = GridFS(db)
quotes = db["quotes"]

# --- App ---------------------------------------------------------------------
app = Flask(__name__)

def htok(t: str) -> str:
    return hmac.new(SIGN_SECRET.encode(), t.encode(), hashlib.sha256).hexdigest()

def find_by_token(tok: str):
    th = htok(tok)
    q = quotes.find_one({"$or": [{"buyer.token_hash": th}, {"seller.token_hash": th}]})
    if not q:
        return None, None
    role = "buyer" if q.get("buyer", {}).get("token_hash") == th else "seller"
    return q, role

def overlay_signature(pdf_bytes: bytes, sig_png: bytes, x: int, y: int, w: int = 180) -> bytes:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    page = doc[0]
    rect = page.rect
    y_top = rect.height - y
    img = fitz.open(stream=sig_png, filetype="png")
    iw, ih = img[0].rect.width, img[0].rect.height
    scale = w / max(iw, 1)
    h = ih * scale
    box = fitz.Rect(x, y_top - h, x + w, y_top)
    page.insert_image(box, stream=sig_png)
    out = BytesIO()
    doc.save(out); doc.close()
    return out.getvalue()

SIGN_FORM = """
<!doctype html><html><body style="font-family:Arial;max-width:620px;margin:auto">
  <h3>Sign Quote {{qid}} ({{role}})</h3>
  {% if msg %}<p style="color:green">{{msg}}</p>{% endif %}
  <form method="post" enctype="multipart/form-data">
    <label>Signature (PNG/JPG)</label><br/>
    <input name="signature" type="file" accept="image/*" required/><br/><br/>
    <button type="submit">Sign</button>
  </form>
</body></html>
"""

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/sign/<token>")
def sign_get(token):
    q, role = find_by_token(token)
    if not q:
        return abort(404)
    if q.get(role, {}).get("signed"):
        return render_template_string(SIGN_FORM, qid=q.get("quote_id",""), role=role, msg="Already signed.")
    return render_template_string(SIGN_FORM, qid=q.get("quote_id",""), role=role, msg=None)

@app.post("/sign/<token>")
def sign_post(token):
    q, role = find_by_token(token)
    if not q:
        return abort(404)
    file = request.files.get("signature")
    if not file:
        return abort(400, "signature required")

    orig = fs.find_one({"metadata.type":"quote_original","metadata.quote_id": q.get("quote_id","")})
    if not orig:
        return abort(400, "original pdf missing")
    signed_pdf = overlay_signature(orig.read(), file.read(), x=380 if role=="seller" else 120, y=120)

    fid = fs.put(signed_pdf, filename=f"{q.get('quote_id','')}-{role}-signed.pdf",
                 metadata={"type":"quote_signed","quote_id": q.get("quote_id",""), "role": role})
    quotes.update_one({"_id": q["_id"]}, {"$set":{
        f"{role}.signed": True, f"{role}.signed_at": datetime.utcnow(), f"{role}.file_id": fid,
        "status": ("fully_signed" if (role=="buyer" and q.get("seller",{}).get("signed")) or
                                 (role=="seller" and q.get("buyer",{}).get("signed")) else f"{role}_signed}")
    }})
    return send_file(BytesIO(signed_pdf), mimetype="application/pdf",
                     as_attachment=True, download_name=f"{q.get('quote_id','')}-{role}-signed.pdf")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)