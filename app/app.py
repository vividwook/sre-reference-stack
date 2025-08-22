from flask import Flask
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)
hits = Counter("hits_total", "Total hits")

@app.get("/healthz")
def healthz():
    return "ok", 200

@app.get("/")
def home():
    hits.inc()
    return "hello from sre-reference-stack", 200

@app.get("/metrics")
def metrics():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}
