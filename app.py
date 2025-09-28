from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId
from datetime import datetime
from dotenv import load_dotenv
import os


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# MongoDB configuration
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

ADMIN_ID = os.getenv("ADMIN_ID")

# ---------------- SIGNUP ----------------

@app.route("/", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        fullname = request.form["fullname"]
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirmPassword"]
        role = request.form.get("role", "student")  # student | leader | admin
        admin_id = request.form.get("admin_id")  # new field for admin

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("signup"))

        if mongo.db.students.find_one({"email": email}):
            flash("Email already registered!", "danger")
            return redirect(url_for("signup"))

        # Admin ID verification
        if role == "admin":
            REQUIRED_ADMIN_ID = ADMIN_ID  # Set your secret Admin ID here
            if admin_id != REQUIRED_ADMIN_ID:
                flash("Invalid Admin ID!", "danger")
                return redirect(url_for("signup"))

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

        mongo.db.students.insert_one({
            "name": fullname,
            "username": username,
            "email": email,
            "password": hashed_pw,
            "role": role,
            "interests": [],
            "joinedClubs": [],
            "notifications": []
        })

        flash("Account created successfully! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form.get("role", "student") 
        admin_id = request.form.get("admin_id")  

        user = mongo.db.students.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):

            # Admin login verification
            if user["role"] == "admin":
                REQUIRED_ADMIN_ID = ADMIN_ID  # same secret Admin ID
                if admin_id != REQUIRED_ADMIN_ID:
                    flash("Invalid Admin ID!", "danger")
                    return redirect(url_for("login"))

            session["user_id"] = str(user["_id"])
            session["user_name"] = user["name"]
            session["user_role"] = user["role"]
            flash(f"Login successful! Welcome {user['name']}", "success")

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            elif user["role"] == "leader":
                return redirect(url_for("leader_dashboard"))
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password!", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

# ---------------- STUDENT HOME ----------------
@app.route("/home")
def home():
    if "user_id" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    student = mongo.db.students.find_one({"_id": ObjectId(session["user_id"])})
    clubs = list(mongo.db.clubs.find())

    announcements = []
    for club in clubs:
        for ann in club.get("announcements", []):
            announcements.append({
                "club_name": club["name"],
                "message": ann["message"]
            })

    meetings = []
    for club in clubs:
        for event in club.get("events", []):
            meetings.append({
                "club_name": club["name"],
                "title": event.get("title", ""),
                "date": event.get("date", "")
            })

    return render_template(
        "home.html",
        student_name=student["name"],
        clubs=clubs,
        announcements=announcements,
        meetings=meetings
    )

# ---------------- ADMIN DASHBOARD ----------------
@app.route("/admin/dashboard")
def admin_dashboard():
    if session.get("user_role") != "admin":
        flash("Access denied!", "danger")
        return redirect(url_for("login"))

    clubs = list(mongo.db.clubs.find())
    return render_template("admin_dashboard.html", clubs=clubs)

# ---------------- ADD CLUB (Admin) ----------------
@app.route("/add_club", methods=["GET", "POST"])
def add_club():
    if session.get("user_role") != "admin":
        flash("Access denied!", "danger")
        return redirect(url_for("login"))

    leaders = list(mongo.db.students.find({"role": "leader"}))

    if request.method == "POST":
        club_name = request.form.get("club_name")
        description = request.form.get("description")
        leader_id = request.form.get("leader_id")

        if not club_name or not description or not leader_id:
            flash("All fields are required.", "danger")
            return redirect(url_for("add_club"))

        if mongo.db.clubs.find_one({"name": club_name}):
            flash("A club with this name already exists.", "warning")
            return redirect(url_for("add_club"))

        mongo.db.clubs.insert_one({
            "name": club_name,
            "description": description,
            "leader_id": ObjectId(leader_id),
            "announcements": [],
            "events": [],
            "members": []
        })

        flash(f"Club '{club_name}' created successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_club.html", leaders=leaders)

# ---------------- EDIT CLUB (Admin) ----------------
@app.route("/edit_club/<club_id>", methods=["GET", "POST"])
def edit_club(club_id):
    if session.get("user_role") != "admin":
        flash("Access denied!", "danger")
        return redirect(url_for("login"))

    club = mongo.db.clubs.find_one({"_id": ObjectId(club_id)})
    leaders = list(mongo.db.students.find({"role": "leader"}))

    if request.method == "POST":
        name = request.form["club_name"]
        description = request.form["description"]
        leader_id = request.form["leader_id"]

        mongo.db.clubs.update_one(
            {"_id": ObjectId(club_id)},
            {"$set": {"name": name, "description": description, "leader_id": ObjectId(leader_id)}}
        )
        flash("Club updated successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("edit_club.html", club=club, leaders=leaders)

# ---------------- LEADER DASHBOARD ----------------
@app.route("/leader/dashboard")
def leader_dashboard():
    if session.get("user_role") not in ["leader", "admin"]:
        flash("Access denied!", "danger")
        return redirect(url_for("login"))

    clubs = list(mongo.db.clubs.find({"leader_id": ObjectId(session["user_id"])}))
    return render_template("leader_dashboard.html", clubs=clubs)

# ---------------- ADD EVENT (Leader) ----------------
@app.route("/leader/add_event", methods=["GET", "POST"])
def add_event():
    if session.get("user_role") not in ["leader", "admin"]:
        flash("Access denied!", "danger")
        return redirect(url_for("login"))

    my_clubs = list(mongo.db.clubs.find({"leader_id": ObjectId(session["user_id"])}))

    if request.method == "POST":
        club_id = request.form["club_id"]
        title = request.form["title"]
        date = request.form["date"]
        time = request.form["time"]

        mongo.db.clubs.update_one(
            {"_id": ObjectId(club_id)},
            {"$push": {"events": {"title": title, "date": date, "time": time, "rsvps": []}}}
        )
        flash("Event scheduled successfully!", "success")
        return redirect(url_for("leader_dashboard"))

    return render_template("add_event.html", my_clubs=my_clubs)

# ---------------- ADD ANNOUNCEMENT (Leader) ----------------
@app.route("/leader/add_announcement/<club_id>", methods=["GET", "POST"])
def add_announcement(club_id):
    if session.get("user_role") not in ["leader", "admin"]:
        flash("Access denied!", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        message = request.form["message"]

        mongo.db.clubs.update_one(
            {"_id": ObjectId(club_id)},
            {"$push": {"announcements": {"message": message, "date": datetime.now().strftime('%Y-%m-%d')}}}
        )

        flash("Announcement added successfully!", "success")
        return redirect(url_for("leader_dashboard"))

    return render_template("add_announcement.html", club_id=club_id)

# ---------------- VIEW CLUB ----------------
@app.route("/view_club/<club_id>")
def view_club(club_id):
    club = mongo.db.clubs.find_one({"_id": ObjectId(club_id)})
    if not club:
        flash("Club not found", "danger")
        return redirect(url_for("home"))

    members = list(mongo.db.students.find({"joinedClubs": club_id}))
    joined_clubs = session.get("joinedClubs", [])

    return render_template("view_club.html", club=club, members=members, joined_clubs=joined_clubs)

# ---------------- JOIN CLUB ----------------
@app.route("/join_club/<club_id>")
def join_club(club_id):
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    student = mongo.db.students.find_one({"_id": ObjectId(session["user_id"])})
    if club_id not in student.get("joinedClubs", []):
        mongo.db.students.update_one(
            {"_id": ObjectId(session["user_id"])},
            {"$addToSet": {"joinedClubs": club_id, "notifications": "You joined a new club!"}}
        )
        flash("Joined the club successfully!", "success")
    else:
        flash("Already a member of this club!", "info")

    return redirect(url_for("view_club", club_id=club_id))

# ---------------- PROFILE ----------------
@app.route("/profile")
def profile():
    if "user_id" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    student = mongo.db.students.find_one({"_id": ObjectId(session["user_id"])})
    clubs = [mongo.db.clubs.find_one({"_id": ObjectId(cid)}) for cid in student["joinedClubs"]]

    return render_template("profile.html", student=student, clubs=clubs)



# ---------------- DELETE CLUB (Admin) ----------------
@app.route("/delete_club/<club_id>", methods=["POST"])
def delete_club(club_id):
    if "user_role" not in session or session["user_role"] != "admin":
        flash("Access denied!", "danger")
        return redirect(url_for("login"))

    mongo.db.clubs.delete_one({"_id": ObjectId(club_id)})
    flash("Club deleted successfully!", "success")
    return redirect(url_for("admin_dashboard"))


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))

# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app.run(debug=True)

