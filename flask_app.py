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


VALID_TYPES = [
    "cpu", "gpu", "ram", "psu", "ssd", "pc_case",
    "fans", "kuehler", "argb", "extensions", "mobo"
]


# GITHUB WEBHOOK (DON'T TOUCH)


def is_valid_signature(x_hub_signature, data, private_key):
    hash_algorithm, github_signature = x_hub_signature.split('=', 1)
    algorithm = hashlib.__dict__.get(hash_algorithm)
    encoded_key = bytes(private_key, 'latin-1')
    mac = hmac.new(encoded_key, msg=data, digestmod=algorithm)
    return hmac.compare_digest(mac.hexdigest(), github_signature)


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

COMPONENT_ORDER = ["cpu", "gpu", "ram", "ssd", "psu", "pc_case", "fans", "kuehler", "argb", "extensions"]


@app.route("/")
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
    pcs = db_read(
        "SELECT id, name, status, gesamtpreis FROM pc WHERE user_id=%s ORDER BY id DESC",
        (current_user.id,)
    )
    return render_template("pc_list.html", pcs=pcs)



@app.route("/pc/new", methods=["GET", "POST"])
@login_required
def pc_new():
    if request.method == "POST":
        name = request.form["name"]
        status = request.form.get("status", "gebaut")

        # Neuer PC gehört dem aktuellen User
        pc_id = db_write(
            "INSERT INTO pc (name, status, user_id) VALUES (%s, %s, %s)",
            (name, status, current_user.id)
        )

        return redirect(url_for("add_component_list", pc_id=pc_id, typ="cpu"))

    return render_template("pc_new.html")



@app.route("/pc/<int:pc_id>")
@login_required
def pc_detail(pc_id):
    pc = db_read(
        "SELECT * FROM pc WHERE id=%s AND user_id=%s",
        (pc_id, current_user.id)
    )
    komponenten = db_read(
        "SELECT * FROM pc_komponenten WHERE pc_id=%s AND user_id=%s",
        (pc_id, current_user.id)
    )
    return render_template("pc_detail.html", pc=pc, komponenten=komponenten)



@app.route("/components/new/<typ>", methods=["GET", "POST"])
@login_required
def component_new(typ):
    if typ not in VALID_TYPES:
        return "Ungültiger Komponententyp", 400

    if request.method == "POST":
        marke = request.form.get("marke")
        modell = request.form.get("modell")
        preis = float(request.form.get("preis") or 0)
        anzahl = request.form.get("anzahl", 1)

        # user_id speichern
        komp_id = db_write("""
            INSERT INTO pc_komponenten (typ, marke, modell, preis, anzahl, pc_id, user_id)
            VALUES (%s, %s, %s, %s, %s, NULL, %s)
        """, (typ, marke, modell, preis, anzahl, current_user.id))

        if typ == "gpu":
            db_write(
                "INSERT INTO gpu (id, vram) VALUES (%s, %s)",
                (komp_id, request.form.get("vram"))
            )
        elif typ == "ram":
            db_write(
                "INSERT INTO ram (id, speichermenge_gb, cl_rating) VALUES (%s, %s, %s)",
                (komp_id, request.form.get("speichermenge_gb"), request.form.get("cl_rating"))
            )
        elif typ == "psu":
            db_write(
                "INSERT INTO psu (id, watt) VALUES (%s, %s)",
                (komp_id, request.form.get("watt"))
            )
        elif typ == "ssd":
            db_write(
                "INSERT INTO ssd (id, speichermenge_gb) VALUES (%s, %s)",
                (komp_id, request.form.get("speichermenge_gb"))
            )
        else:
            db_write(f"INSERT INTO {typ} (id) VALUES (%s)", (komp_id,))

        return redirect(url_for("component_new", typ=typ))

    return render_template("component_new.html", typ=typ)


@app.route("/pc/<int:pc_id>/add/<typ>")
@login_required
def add_component_list(pc_id, typ):
    if typ not in VALID_TYPES:
        return "Ungültiger Komponententyp", 400

    select_extra = ""
    join_sql = ""

    if typ == "gpu":
        select_extra = ", g.vram"
        join_sql = "LEFT JOIN gpu g ON g.id = k.id"
    elif typ == "ram":
        select_extra = ", r.speichermenge_gb, r.cl_rating"
        join_sql = "LEFT JOIN ram r ON r.id = k.id"
    elif typ == "psu":
        select_extra = ", p.watt"
        join_sql = "LEFT JOIN psu p ON p.id = k.id"
    elif typ == "ssd":
        select_extra = ", s.speichermenge_gb AS ssd_gb"
        join_sql = "LEFT JOIN ssd s ON s.id = k.id"
    elif typ == "cpu":
        select_extra = ", c.frequenz_ghz, c.watt AS cpu_watt"
        join_sql = "LEFT JOIN cpu c ON c.id = k.id"

    items = db_read(f"""
        SELECT k.* {select_extra}
        FROM pc_komponenten k
        {join_sql}
        WHERE k.typ=%s AND k.pc_id IS NULL AND k.user_id=%s
        ORDER BY k.preis ASC
    """, (typ, current_user.id))

    return render_template(
        "component_list.html",
        items=items,
        typ=typ,
        pc_id=pc_id
    )


@app.route("/pc/<int:pc_id>/add/<typ>/<int:item_id>")
@login_required
def add_component(pc_id, typ, item_id):
    if typ not in VALID_TYPES:
        return "Ungültiger Komponententyp", 400

    # Original-Komponente auslesen
    komp = db_read("SELECT * FROM pc_komponenten WHERE id=%s", (item_id,))
    if not komp:
        return "Komponente nicht gefunden", 404

    komp = komp[0]
    preis = komp["preis"]
    anzahl = komp["anzahl"]

    # Neue Komponente für den PC erstellen
    new_komp_id = db_write("""
        INSERT INTO pc_komponenten (typ, marke, modell, preis, anzahl, pc_id)
        VALUES (%s, %s, %s, %s, 1, %s)
    """, (komp["typ"], komp["marke"], komp["modell"], preis, pc_id))

    # Typ-spezifische Daten kopieren
    if typ in ["gpu", "ram", "psu", "ssd", "cpu"]:
        typ_values = db_read(f"SELECT * FROM {typ} WHERE id=%s", (item_id,))
        if typ_values:
            typ_values = typ_values[0]

            if typ == "gpu":
                vram = int(typ_values["vram"]) if typ_values["vram"] else None
                db_write("INSERT INTO gpu (id, vram) VALUES (%s, %s)", (new_komp_id, vram))

            elif typ == "ram":
                speicher = int(typ_values["speichermenge_gb"]) if typ_values["speichermenge_gb"] else None
                cl_rating = typ_values["cl_rating"] or None
                db_write("INSERT INTO ram (id, speichermenge_gb, cl_rating) VALUES (%s, %s, %s)",
                         (new_komp_id, speicher, cl_rating))

            elif typ == "psu":
                watt = int(typ_values["watt"]) if typ_values["watt"] else None
                db_write("INSERT INTO psu (id, watt) VALUES (%s, %s)", (new_komp_id, watt))

            elif typ == "ssd":
                gb = int(typ_values["speichermenge_gb"]) if typ_values["speichermenge_gb"] else None
                db_write("INSERT INTO ssd (id, speichermenge_gb) VALUES (%s, %s)", (new_komp_id, gb))

            elif typ == "cpu":
                freq = float(typ_values["frequenz_ghz"]) if typ_values["frequenz_ghz"] else None
                watt = int(typ_values["watt"]) if typ_values["watt"] else None
                db_write("INSERT INTO cpu (id, frequenz_ghz, watt) VALUES (%s, %s, %s)", 
                         (new_komp_id, freq, watt))

    # Original-Komponente anpassen (Anzahl reduzieren oder löschen)
    if anzahl > 1:
        db_write("UPDATE pc_komponenten SET anzahl = anzahl - 1 WHERE id=%s", (item_id,))
    else:
        db_write("DELETE FROM pc_komponenten WHERE id=%s", (item_id,))

    # Gesamtpreis updaten
    db_write("UPDATE pc SET gesamtpreis = gesamtpreis + %s WHERE id=%s", (preis, pc_id))

    # Zum nächsten Typ oder PC-Detail weiterleiten
    try:
        next_typ = COMPONENT_ORDER[COMPONENT_ORDER.index(typ) + 1]
        return redirect(url_for("add_component_list", pc_id=pc_id, typ=next_typ))
    except (ValueError, IndexError):
        return redirect(url_for("pc_detail", pc_id=pc_id))


@app.route("/pc/<int:pc_id>/sell", methods=["GET", "POST"])
@login_required
def sell_pc(pc_id):
    if request.method == "POST":
        preis = float(request.form["verkaufspreis"])

        db_write("INSERT INTO sales (pc_id, verkaufspreis) VALUES (%s, %s)", (pc_id, preis))
        db_write("UPDATE pc SET status='verkauft' WHERE id=%s", (pc_id,))

        return redirect(url_for("index"))

    pc = db_read("SELECT * FROM pc WHERE id=%s", (pc_id,))
    return render_template("sell_pc.html", pc=pc)


@app.route("/pc/<int:pc_id>/remove/<int:item_id>")
@login_required
def remove_component(pc_id, item_id):
    
    preis = db_read("SELECT preis FROM pc_komponenten WHERE id=%s", (item_id,))
    if not preis:
        return "Komponente nicht gefunden", 404
    preis = preis[0]["preis"]


    db_write("UPDATE pc_komponenten SET pc_id=NULL WHERE id=%s", (item_id,))

    db_write("UPDATE pc SET gesamtpreis = gesamtpreis - %s WHERE id=%s", (preis, pc_id))

    return redirect(url_for("pc_detail", pc_id=pc_id))

@app.route("/pc/<int:pc_id>/delete")
@login_required
def delete_pc(pc_id):
    
    db_write("UPDATE pc_komponenten SET pc_id=NULL WHERE pc_id=%s", (pc_id,))
    
    
    db_write("DELETE FROM sales WHERE pc_id=%s", (pc_id,))
    
    
    db_write("DELETE FROM pc WHERE id=%s", (pc_id,))
    
    return redirect(url_for("pc_list"))

@app.route("/component/<int:item_id>/delete")
@login_required
def delete_component(item_id):
    komp = db_read("SELECT typ, pc_id FROM pc_komponenten WHERE id=%s", (item_id,))
    if not komp or komp[0]["user_id"] != current_user.id:
        return "Komponente nicht gefunden", 404

    typ = komp[0]["typ"]
    pc_id = komp[0]["pc_id"]

    
    if pc_id is not None:
        return "Komponente ist einem PC zugeordnet! Entferne sie zuerst vom PC.", 400

    
    if typ in ["gpu", "ram", "psu", "ssd", "cpu", "mobo", "pc_case", "fans", "kuehler", "argb", "extensions"]:
        db_write(f"DELETE FROM {typ} WHERE id=%s", (item_id,))

    
    db_write("DELETE FROM pc_komponenten WHERE id=%s", (item_id,))

    return redirect(request.referrer or url_for("component_new", typ=typ))

