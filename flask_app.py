from flask import Flask, redirect, render_template, request, url_for
from dotenv import load_dotenv
import os
import git
import hmac
import hashlib
from db import db_read, db_write
from auth import login_manager, authenticate, register_user
from flask_login import login_user, logout_user, login_required, current_user
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# Load .env variables
load_dotenv()
W_SECRET = os.getenv("W_SECRET")

# Init flask app
app = Flask(__name__)
app.config["DEBUG"] = True
app.secret_key = "supersecret"

# Init auth
login_manager.init_app(app)
login_manager.login_view = "login"

# Valid component types (SQL injection prevention)
VALID_TYPES = [
    "cpu", "gpu", "ram", "psu", "ssd", "pc_case",
    "fans", "kuehler", "argb", "extensions", "mobo"
]

# DON'T CHANGE
def is_valid_signature(x_hub_signature, data, private_key):
    hash_algorithm, github_signature = x_hub_signature.split('=', 1)
    algorithm = hashlib.__dict__.get(hash_algorithm)
    encoded_key = bytes(private_key, 'latin-1')
    mac = hmac.new(encoded_key, msg=data, digestmod=algorithm)
    return hmac.compare_digest(mac.hexdigest(), github_signature)

# DON'T CHANGE
@app.post('/update_server')
def webhook():
    x_hub_signature = request.headers.get('X-Hub-Signature')
    if is_valid_signature(x_hub_signature, request.data, W_SECRET):
        repo = git.Repo('./mysite')
        origin = repo.remotes.origin
        origin.pull()
        return 'Updated PythonAnywhere successfully', 200
    return 'Unauthorized', 401


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        user = authenticate(
            request.form["username"],
            request.form["password"]
        )

        if user:
            login_user(user)
            return redirect(url_for("index"))

        error = "Benutzername oder Passwort ist falsch."

    return render_template(
        "auth.html",
        title="In dein Konto einloggen",
        action=url_for("login"),
        button_label="Einloggen",
        error=error,
        footer_text="Noch kein Konto?",
        footer_link_url=url_for("register"),
        footer_link_label="Registrieren"
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        ok = register_user(username, password)
        if ok:
            return redirect(url_for("login"))

        error = "Benutzername existiert bereits."

    return render_template(
        "auth.html",
        title="Neues Konto erstellen",
        action=url_for("register"),
        button_label="Registrieren",
        error=error,
        footer_text="Du hast bereits ein Konto?",
        footer_link_url=url_for("login"),
        footer_link_label="Einloggen"
    )


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))



@app.route("/", methods=["GET"])
@login_required
def index():
    pcs = db_read("SELECT id, name, status, gesamtpreis FROM pc ORDER BY id DESC")
    sales = db_read("""
        SELECT pc.name, sales.verkaufspreis, sales.verkauft_am,
               (sales.verkaufspreis - pc.gesamtpreis) AS profit
        FROM sales
        JOIN pc ON pc.id = sales.pc_id
        ORDER BY sales.verkauft_am DESC
    """)

    return render_template("dashboard.html", pcs=pcs, sales=sales)


@app.route("/pcs")
@login_required
def pc_list():
    pcs = db_read("SELECT id, name, status, gesamtpreis FROM pc ORDER BY id DESC")
    return render_template("pc_list.html", pcs=pcs)

@app.route("/components/new/<typ>", methods=["GET", "POST"])
@login_required
def component_new(typ):

    if typ not in VALID_TYPES:
        return "Ungültiger Komponententyp", 400

    if request.method == "POST":
        marke = request.form.get("marke")
        modell = request.form.get("modell")
        preis = request.form.get("preis")

        # In die richtige Tabelle einfügen
        db_write(
            f"INSERT INTO {typ} (marke, modell, preis) VALUES (%s, %s, %s)",
            (marke, modell, preis)
        )

        return redirect(url_for("component_new", typ=typ))

    return render_template("component_new.html", typ=typ)


@app.route("/pc/new", methods=["GET", "POST"])
@login_required
def pc_new():
    if request.method == "POST":
        name = request.form["name"]
        status = request.form.get("status", "gebaut")

        db_write("INSERT INTO pc (name, status) VALUES (%s, %s)", (name, status))
        return redirect(url_for("pc_list"))

    return render_template("pc_new.html")


@app.route("/pc/<int:pc_id>")
@login_required
def pc_detail(pc_id):
    pc = db_read("SELECT * FROM pc WHERE id=%s", (pc_id,))
    komponenten = db_read("SELECT * FROM pc_komponenten WHERE pc_id=%s", (pc_id,))
    return render_template("pc_detail.html", pc=pc, komponenten=komponenten)



@app.route("/pc/<int:pc_id>/add/<typ>")
@login_required
def add_component_list(pc_id, typ):

    if typ not in VALID_TYPES:
        return "Ungültiger Komponententyp", 400

    items = db_read(f"SELECT * FROM {typ}")
    return render_template("component_list.html", items=items, typ=typ, pc_id=pc_id)


@app.route("/pc/<int:pc_id>/add/<typ>/<int:item_id>")
@login_required
def add_component(pc_id, typ, item_id):

    if typ not in VALID_TYPES:
        return "Ungültiger Komponententyp", 400

    
    preis = db_read(f"SELECT preis FROM {typ} WHERE id=%s", (item_id,), single=True)

    if not preis:
        return "Komponente nicht gefunden", 404

    
    db_write("""
        INSERT INTO pc_komponenten (typ, pc_id, preis)
        VALUES (%s, %s, %s)
    """, (typ, pc_id, preis["preis"]))

    
    db_write("""
        UPDATE pc
        SET gesamtpreis = gesamtpreis + %s
        WHERE id = %s
    """, (preis["preis"], pc_id))

    return redirect(url_for("pc_detail", pc_id=pc_id))

@app.route("/components/new/<typ>", methods=["GET", "POST"])
@login_required
def component_new(typ):
    if typ not in VALID_TYPES:
        return "Ungültiger Komponententyp", 400

    if request.method == "POST":
        marke = request.form.get("marke")
        modell = request.form.get("modell")
        preis = request.form.get("preis")
        anzahl = request.form.get("anzahl", 1)

        # 1. In pc_komponenten einfügen (Inventar, noch keinem PC zugeordnet)
        komp_id = db_write(
            """
            INSERT INTO pc_komponenten (typ, marke, modell, preis, anzahl, pc_id)
            VALUES (%s, %s, %s, %s, %s, NULL)
            """,
            (typ, marke, modell, preis, anzahl),
            return_id=True
        )

        # 2. In die spezifische Tabelle einfügen
        if typ == "cpu":
            frequenz = request.form.get("frequenz_ghz")
            watt = request.form.get("watt")
            db_write(
                "INSERT INTO cpu (id, frequenz_ghz, watt) VALUES (%s, %s, %s)",
                (komp_id, frequenz, watt)
            )

        elif typ == "gpu":
            vram = request.form.get("vram")
            db_write(
                "INSERT INTO gpu (id, vram) VALUES (%s, %s)",
                (komp_id, vram)
            )

        elif typ == "ram":
            speicher = request.form.get("speichermenge_gb")
            cl = request.form.get("cl_rating")
            db_write(
                "INSERT INTO ram (id, speichermenge_gb, cl_rating) VALUES (%s, %s, %s)",
                (komp_id, speicher, cl)
            )

        elif typ == "psu":
            watt = request.form.get("watt")
            db_write(
                "INSERT INTO psu (id, watt) VALUES (%s, %s)",
                (komp_id, watt)
            )

        elif typ == "ssd":
            speicher = request.form.get("speichermenge_gb")
            db_write(
                "INSERT INTO ssd (id, speichermenge_gb) VALUES (%s, %s)",
                (komp_id, speicher)
            )

        elif typ in ["pc_case", "fans", "kuehler", "argb", "extensions", "mobo"]:
            # Haben aktuell nur die ID als FK
            table = typ
            db_write(f"INSERT INTO {table} (id) VALUES (%s)", (komp_id,))

        return redirect(url_for("component_new", typ=typ))

    return render_template("component_new.html", typ=typ)



@app.route("/pc/<int:pc_id>/sell", methods=["GET", "POST"])
@login_required
def sell_pc(pc_id):
    if request.method == "POST":
        preis = float(request.form["verkaufspreis"])

        db_write("INSERT INTO sales (pc_id, verkaufspreis) VALUES (%s, %s)", (pc_id, preis))
        db_write("UPDATE pc SET status='verkauft' WHERE id=%s", (pc_id,))

        return redirect(url_for("index"))

    pc = db_read("SELECT * FROM pc WHERE id=%s", (pc_id,), single=True)
    return render_template("sell_pc.html", pc=pc)
