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


@app.route("/pcs")
@login_required
def pc_list():
    pcs = db_read(
        "SELECT id, name, status, gesamtpreis FROM pc WHERE user_id=%s ORDER BY id DESC",
        (current_user.id,)
    )

    print("PCS DEBUG:", pcs)  # 👈 DAS
    return "OK"


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

COMPONENT_ORDER = ["cpu", "mobo", "gpu", "ram", "ssd", "psu", "pc_case", "fans", "kuehler", "argb", "extensions"]

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
from decimal import Decimal



@app.route("/pc/new", methods=["GET", "POST"])
@login_required
def pc_new():
    if request.method == "POST":
        name = request.form["name"]
        status = request.form.get("status", "gebaut")

        # PC in DB einfügen
        pc_id = db_write(
            "INSERT INTO pc (name, status, user_id, gesamtpreis) VALUES (%s, %s, %s, 0)",
            (name, status, current_user.id)
        )

        # Direkt zur Komponentenseite des neuen PCs weiterleiten
        return redirect(url_for("component_new", typ="cpu"))

    return render_template("pc_new.html")


@app.route("/pc/<int:pc_id>")
@login_required
def pc_detail(pc_id):
    # PC-Daten abrufen
    pc = db_read(
        "SELECT * FROM pc WHERE id=%s AND user_id=%s",
        (pc_id, current_user.id),
        single=True
    )

    if not pc:
        return "PC nicht gefunden", 404

    # Komponenten abrufen
    komponenten = db_read(
        "SELECT * FROM pc_komponenten WHERE pc_id=%s",
        (pc_id,)
    )

    # Decimal-Felder konvertieren
    pc["gesamtpreis"] = float(pc["gesamtpreis"]) if isinstance(pc["gesamtpreis"], Decimal) else pc["gesamtpreis"]
    for k in komponenten:
        if isinstance(k.get("preis"), Decimal):
            k["preis"] = float(k["preis"])

    return render_template("pc_detail.html", pc=pc, komponenten=komponenten)

@app.route("/components/new/<typ>", methods=["GET", "POST"])
@login_required
def component_new(typ):
    if typ not in VALID_TYPES:
        return "Ungültiger Komponententyp", 400

    if request.method == "POST":
        marke = request.form["marke"]
        modell = request.form["modell"]
        preis = float(request.form["preis"])
        anzahl = 1 #int(request.form.get("anzahl", 1))

        komp_id = db_write("""
            INSERT INTO pc_komponenten
            (typ, marke, modell, preis, anzahl, pc_id, user_id)
            VALUES (%s, %s, %s, %s, %s, NULL, %s)
        """, (typ, marke, modell, preis, anzahl, current_user.id))

        
        if typ == "gpu":
            db_write("INSERT INTO gpu (id, vram) VALUES (%s, %s)",
                     (komp_id, request.form["vram"]))
        elif typ == "ram":
            db_write("INSERT INTO ram (id, speichermenge_gb, cl_rating) VALUES (%s,%s,%s)",
                     (komp_id, request.form["speichermenge_gb"], request.form["cl_rating"]))
        elif typ == "psu":
            db_write("INSERT INTO psu (id, watt) VALUES (%s,%s)",
                     (komp_id, request.form["watt"]))
        elif typ == "ssd":
            db_write("INSERT INTO ssd (id, speichermenge_gb) VALUES (%s,%s)",
                     (komp_id, request.form["speichermenge_gb"]))
        elif typ == "cpu":
            db_write("INSERT INTO cpu (id, frequenz_ghz, watt) VALUES (%s,%s,%s)",
                     (komp_id, request.form["frequenz_ghz"], request.form["watt"]))
        elif typ == "mobo":
            db_write("INSERT INTO mobo (id) VALUES (%s)", (komp_id,))
        else:
            db_write(f"INSERT INTO {typ} (id) VALUES (%s)", (komp_id,))

        return redirect(url_for("component_new", typ=typ))

    return render_template("component_new.html", typ=typ)


@app.route("/pc/<int:pc_id>/add/<int:item_id>")
@login_required
def add_component(pc_id, item_id):
    """
    Fügt eine Komponente einem PC hinzu.
    Wenn bereits vorhanden: Anzahl erhöhen.
    Preis wird korrekt angepasst.
    """

    
    komp = db_read("""
        SELECT preis, anzahl FROM pc_komponenten
        WHERE id=%s AND user_id=%s AND pc_id IS NULL
    """, (item_id, current_user.id), single=True)

    if not komp:
        return "Komponente nicht verfügbar", 404

    preis = komp["preis"]

    try:
        
        exists = db_read("""
            SELECT id, anzahl FROM pc_komponenten
            WHERE id=%s AND pc_id=%s
        """, (item_id, pc_id), single=True)

        #if exists:
            ###db_writ#e(
                ###"UPDATE pc_komponenten SET anzahl = anzahl + 1 WHERE id=%s",
                ##(item_id,)
            #)
        
            
        db_write(
            "UPDATE pc_komponenten SET pc_id=%s WHERE id=%s",
            (pc_id, item_id)
        )

        db_write(
            "UPDATE pc SET gesamtpreis = gesamtpreis + %s WHERE id=%s",
            (preis, pc_id)
        )

    except Exception as e:
        print("ADD COMPONENT ERROR:", e)
        return "Fehler beim Hinzufügen", 500

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


@app.route("/remove_component/<int:item_id>/<int:pc_id>")
@login_required
def remove_component(item_id, pc_id):

    component = db_read(
        "SELECT preis, anzahl FROM pc_komponenten WHERE id=%s AND pc_id=%s",
        (item_id, pc_id),
        single=True
    )

    if not component:
        abort(404)

    try:
        if component["anzahl"] > 1:
            
            db_write(
                "UPDATE pc_komponenten SET anzahl = anzahl - 1 WHERE id=%s",
                (item_id,)
            )
        else:
            
            db_write(
                "DELETE FROM pc_komponenten WHERE id=%s",
                (item_id,)
            )

       
        db_write(
            "UPDATE pc SET gesamtpreis = gesamtpreis - %s WHERE id=%s",
            (component["preis"], pc_id)
        )

    except Exception as e:
        print("REMOVE COMPONENT ERROR:", e)
        abort(500)

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

