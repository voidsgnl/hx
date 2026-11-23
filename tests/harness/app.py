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
from flask import Flask, request, redirect, make_response, session

app = Flask(__name__)
app.secret_key = "hx-test-harness-session-secret"

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


@app.route("/hash-dom")
def hash_dom():
    return """<!doctype html><html><body>
<div id="out"></div>
<script>
  function renderRoute() {
    const query = location.hash.split("?", 2)[1] || "";
    const params = new URLSearchParams(query);
    document.getElementById("out").innerHTML = params.get("q") || "";
  }
  window.addEventListener("hashchange", renderRoute);
  renderRoute();
</script>
</body></html>"""

@app.route("/spa")
def spa():
    return """<!doctype html><html><body>
<script>
  fetch("/api/search?q=term");
  history.pushState({}, "", "/search?q=from-spa");
</script>
</body></html>"""


@app.route("/search")
def search_page():
    return "<html><body>search route</body></html>"


@app.route("/api/search")
def api_search():
    return {"results": [], "q": request.args.get("q", "")}


@app.route("/unrelated-alert")
def unrelated_alert():
    # A page-level script execution must not be mistaken for probe execution.
    return "<html><body><script>alert('unrelated-page-script')</script></body></html>"


@app.route("/cross-origin-redirect")
def cross_origin_redirect():
    # Redirect from localhost to 127.0.0.1: same harness, different origin.
    return redirect("http://127.0.0.1:5000/reflect?q=" + request.args.get("q", ""))


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

@app.route("/api-page")
def api_page():
    return """<!doctype html><html><body>
<script>
fetch("/api/xss", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Authorization": "Bearer hx-api-secret",
    "X-CSRF-Token": "hx-api-csrf"
  },
  body: JSON.stringify({message: "hello", token: "hx-api-csrf"})
});
</script>
API client
</body></html>"""


@app.route("/api/xss", methods=["POST"])
def api_xss():
    if request.headers.get("Authorization") != "Bearer hx-api-secret":
        return "authentication required", 401
    if request.headers.get("X-CSRF-Token") != "hx-api-csrf":
        return "csrf failed", 403
    body = request.get_json(silent=True) or {}
    return f"<html><body><div>{body.get('message', '')}</div></body></html>"


@app.route("/api-rotating-page")
def api_rotating_page():
    return """<!doctype html><html><body>
<script>
(async () => {
  const tokenResponse = await fetch("/api/rotate-token");
  const {token} = await tokenResponse.json();
  await fetch("/api/rotating-xss", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer hx-rotating-secret",
      "X-CSRF-Token": token
    },
    body: JSON.stringify({
      profile: {bio: "hello", csrf_token: "body-secret"},
      items: [{label: "first"}, {label: "second"}]
    })
  });
})();
</script>
Rotating API client
</body></html>"""


@app.route("/api/rotate-token")
def api_rotate_token():
    import secrets
    token = secrets.token_urlsafe(18)
    session["hx_csrf"] = token
    return {"token": token}


@app.route("/api/rotating-xss", methods=["POST"])
def api_rotating_xss():
    if request.headers.get("Authorization") != "Bearer hx-rotating-secret":
        return "authentication required", 401
    if request.headers.get("X-CSRF-Token") != session.get("hx_csrf"):
        return "stale CSRF token", 403
    body = request.get_json(silent=True) or {}
    bio = (body.get("profile") or {}).get("bio", "")
    return f"<html><body><div>{bio}</div></body></html>"


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

@app.route("/redirect")
def redirect_endpoint():
    return redirect(request.args.get("next", "/"))


@app.route("/internal-redirect")
def internal_redirect_endpoint():
    # This endpoint ignores the supplied destination and always redirects
    # to a fixed same-origin path.
    return redirect("/account")


@app.route("/post-form-page")
def post_form_page():
    return """<!doctype html><html><body>
<form action="/post-form-reflect" method="POST">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="text" name="q" value="initial">
  <button type="submit">Submit</button>
</form>
</body></html>"""


@app.route("/post-form-reflect", methods=["POST"])
def post_form_reflect():
    if request.form.get("csrf_token") != "abc123":
        return "csrf failed", 403
    return f"<html><body><div>{request.form.get('q', '')}</div></body></html>"


@app.route("/auth-form-page")
def auth_form_page():
    if request.cookies.get("hx_auth") != "valid":
        return "authentication required", 401
    return """<!doctype html><html><body>
<form action="/auth-post-reflect" method="POST">
  <input type="hidden" name="csrf_token" value="session-token">
  <input type="text" name="q" value="initial">
  <button type="submit">Submit</button>
</form>
</body></html>"""


@app.route("/auth-post-reflect", methods=["POST"])
def auth_post_reflect():
    if request.cookies.get("hx_auth") != "valid":
        return "authentication required", 401
    if request.form.get("csrf_token") != "session-token":
        return "csrf failed", 403
    return f"<html><body><div>{request.form.get('q', '')}</div></body></html>"


@app.route("/post-csrf-check", methods=["POST"])
def post_csrf_check():
    if request.form.get("csrf_token") != "abc123":
        return "csrf failed", 403
    return "<html><body>ok</body></html>"

@app.route("/interactive-api-page")
def interactive_api_page():
    session["hx_csrf"] = "hx-interactive-csrf"
    return """<!doctype html><html><body>
<button type="button" id="open-profile">Open profile</button>
<section id="profile-panel" hidden>
  <button type="button" id="load-profile">Load profile</button>
</section>
<script>
document.getElementById("open-profile").addEventListener("click", () => {
  document.getElementById("profile-panel").hidden = false;
});
document.getElementById("load-profile").addEventListener("click", async () => {
  await fetch("/api/interactive-xss", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer hx-interactive-secret",
      "X-CSRF-Token": "hx-interactive-csrf"
    },
    body: JSON.stringify({profile: {bio: "initial"}})
  });
});
</script>
</body></html>"""


@app.route("/api/interactive-xss", methods=["POST"])
def api_interactive_xss():
    if request.headers.get("Authorization") != "Bearer hx-interactive-secret":
        return "authentication required", 401
    if request.headers.get("X-CSRF-Token") != session.get("hx_csrf"):
        return "stale CSRF token", 403
    body = request.get_json(silent=True) or {}
    bio = (body.get("profile") or {}).get("bio", "")
    return f"<html><body><div>{bio}</div></body></html>"

if __name__ == "__main__":
    app.run(port=5000, debug=False)
