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
    return 'Unathorized', 401

@app.get("/user")
def user():
    return "Hello Users";

# Auth routes
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



# App routes
#@app.route("/", methods=["GET", "POST"])
#@login_required
#def index():
    # GET
    #if request.method == "GET":
      #  todos = db_read("SELECT id, content, due FROM todos WHERE user_id=%s ORDER BY due", (current_user.id,))
     #   return render_template("main_page.html", todos=todos)

    # POST
    #content = request.form["contents"]
   # due = request.form["due_at"]
  #  db_write("INSERT INTO todos (user_id, content, due) VALUES (%s, %s, %s)", (current_user.id, content, due, ))
 #   return redirect(url_for("index"))

#@app.post("/complete")
#@login_required
#def complete():
   # todo_id = request.form.get("id")
  #  db_write("DELETE FROM todos WHERE user_id=%s AND id=%s", (current_user.id, todo_id,))
 #   return redirect(url_for("index"))

#if __name__ == "__main__":
#    app.run()

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
    pc = db_read("SELECT * FROM pc WHERE id=%s", (pc_id,), one=True)
    if not pc:
        return "PC nicht gefunden", 404
    components = db_read("SELECT * FROM pc_komponenten WHERE pc_id=%s", (pc_id,))

    return render_template("pc_detail.html", pc=pc, components=components)
    

@app.route("/pc/<int:pc_id>/add", methods=["GET", "POST"])
@login_required
def add_component(pc_id):
    if request.method == "POST":
        typ = request.form["typ"]
        marke = request.form["marke"]
        modell = request.form["modell"]
        preis = float(request.form["preis"])
        anzahl = int(request.form.get("anzahl", 1))

        db_write("""
            INSERT INTO pc_komponenten (typ, marke, modell, preis, anzahl, pc_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (typ, marke, modell, preis, anzahl, pc_id))

        # Gesamtpreis aktualisieren
        db_write("""
            UPDATE pc
            SET gesamtpreis = (
                SELECT SUM(preis * anzahl)
                FROM pc_komponenten
                WHERE pc_id = %s
            )
            WHERE id = %s
        """, (pc_id, pc_id))

        return redirect(url_for("pc_detail", pc_id=pc_id))

    return render_template("add_component.html", pc_id=pc_id)

@app.route("/pc/<int:pc_id>/sell", methods=["GET", "POST"])
@login_required
def sell_pc(pc_id):
    if request.method == "POST":
        preis = float(request.form["verkaufspreis"])

        db_write("INSERT INTO sales (pc_id, verkaufspreis) VALUES (%s, %s)", (pc_id, preis))
       
        db_write("UPDATE pc SET status='verkauft' WHERE id=%s", (pc_id,))

        return redirect(url_for("index"))

    pc = db_read("SELECT * FROM pc WHERE id=%s", (pc_id,), one=True)
    return render_template("sell_pc.html", pc=pc)
