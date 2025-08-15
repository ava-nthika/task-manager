from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            done INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- ROUTES ----------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("tasks"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        # Password requirements
        if len(password) < 8 or not any(ch.isdigit() for ch in password) or not any(ch.isupper() for ch in password):
            flash("Password must be at least 8 characters, contain a number and an uppercase letter.", "error")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(password, method="pbkdf2:sha256")

        try:
            conn = sqlite3.connect("database.db")
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            conn.close()
            flash("Account created successfully. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken.", "error")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session["user_id"] = user[0]
            return redirect(url_for("tasks"))
        else:
            flash("Invalid username or password.", "error")

    return render_template("login.html")

@app.route("/tasks", methods=["GET", "POST"])
def tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    if request.method == "POST":
        title = request.form["title"].strip()
        if title:
            c.execute("INSERT INTO tasks (user_id, title) VALUES (?, ?)", (session["user_id"], title))
            conn.commit()

    c.execute("SELECT id, title, done FROM tasks WHERE user_id = ?", (session["user_id"],))
    tasks = c.fetchall()
    conn.close()

    return render_template("tasks.html", tasks=tasks)

@app.route("/delete/<int:task_id>")
def delete_task(task_id):
    if "user_id" in session:
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, session["user_id"]))
        conn.commit()
        conn.close()
    return redirect(url_for("tasks"))

@app.route("/done/<int:task_id>")
def done_task(task_id):
    if "user_id" in session:
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("UPDATE tasks SET done = CASE WHEN done = 0 THEN 1 ELSE 0 END WHERE id = ? AND user_id = ?", (task_id, session["user_id"]))
        conn.commit()
        conn.close()
    return redirect(url_for("tasks"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
