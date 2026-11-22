"""
Local test harness for hx. Ground-truth endpoints:

  /reflect?q=...     reflected into HTML body, unescaped  -> SHOULD fire
  /dom?q=...         placed into a JS string sink via DOM  -> SHOULD fire
  /safe?q=...        escaped into HTML body                -> should NOT fire
  /attr?q=...        escaped into an attribute             -> should NOT fire
  /challenge         fake Cloudflare interstitial: sets a
                     cookie via JS after 1.5s, then redirects
                     to /reflect?q=test                     -> tests warm()
"""
from flask import Flask, request, redirect, make_response

app = Flask(__name__)

CHALLENGE_HTML = """
<!doctype html><html><head><title>Just a moment...</title></head>
<body>
<h1>Verifying you are human</h1>
<script>
  setTimeout(function () {
    document.cookie = "cf_clearance=fake-token-123; path=/";
    window.location.href = "/reflect?q=test";
  }, 1500);
</script>
</body></html>
"""

@app.route("/challenge")
def challenge():
    return CHALLENGE_HTML

@app.route("/reflect")
def reflect():
    q = request.args.get("q", "")
    # unescaped reflection into HTML body — classic reflected XSS
    return f"<html><body><div id='out'>{q}</div></body></html>"

@app.route("/dom")
def dom():
    q = request.args.get("q", "")
    # payload lands in a JS string, then flows to innerHTML via DOM sink
    return f"""<html><body>
<div id="out"></div>
<script>
  var input = "{q}";
  document.getElementById('out').innerHTML = input;
</script>
</body></html>"""

@app.route("/safe")
def safe():
    from markupsafe import escape
    q = request.args.get("q", "")
    return f"<html><body><div id='out'>{escape(q)}</div></body></html>"

@app.route("/attr")
def attr():
    from markupsafe import escape
    q = request.args.get("q", "")
    # escaped into an attribute value
    return f"<html><body><div data-x=\"{escape(q)}\">hi</div></body></html>"

@app.route("/jsstring")
def jsstring():
    q = request.args.get("q", "")
    return f"""<html><body><script>
var input = "{q}";
if (input) {{ document.title = input; }}
</script></body></html>"""

@app.route("/jsstring-single")
def jsstring_single():
    q = request.args.get("q", "")
    return f"""<html><body><script>
var input = '{q}';
</script></body></html>"""

@app.route("/attr-double")
def attr_double():
    q = request.args.get("q", "")
    return f'<html><body><div title="{q}">hi</div></body></html>'

@app.route("/attr-single")
def attr_single():
    q = request.args.get("q", "")
    return f"<html><body><div title='{q}'>hi</div></body></html>"

@app.route("/url-attr")
def url_attr():
    q = request.args.get("q", "")
    return f'<html><body><a href="{q}">click</a></body></html>'

@app.route("/script-block")
def script_block():
    q = request.args.get("q", "")
    return f"""<html><body><script>
var x = 1; {q}
</script></body></html>"""

@app.route("/post-reflect", methods=["POST"])
def post_reflect():
    q = request.form.get("q", "")
    return f"<html><body><div>{q}</div></body></html>"

@app.route("/post-json", methods=["POST"])
def post_json():
    q = (request.get_json(silent=True) or {}).get("q", "")
    return f"<html><body><div>{q}</div></body></html>"

@app.route("/post-safe", methods=["POST"])
def post_safe():
    from markupsafe import escape
    q = request.form.get("q", "")
    return f"<html><body><div>{escape(q)}</div></body></html>"

@app.route("/eval-sink")
def eval_sink():
    q = request.args.get("q", "")
    return f"<html><body><script>eval('{q}')</script></body></html>"

@app.route("/discovery")
def discovery_page():
    return """
<html><body>
<form action="/reflect" method="GET">
  <input type="text" name="q" value="hello">
  <input type="text" name="note" value="x">
  <input type="submit" value="go">
</form>
<form action="/post-csrf-check" method="POST">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="text" name="q" value="hello">
  <input type="submit" value="go">
</form>
<form action="/safe" method="GET">
  <input type="submit" value="no fields to inspect">
</form>
</body></html>
"""

@app.route("/post-csrf-check", methods=["POST"])
def post_csrf_check():
    if request.form.get("csrf_token") != "abc123":
        return "csrf failed", 403
    return "<html><body>ok</body></html>"

if __name__ == "__main__":
    app.run(port=5000, debug=False)