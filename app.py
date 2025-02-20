import os
import hashlib
import time
import random
from flask import Flask, render_template, request, url_for, send_file, jsonify, redirect
from reportlab.pdfgen import canvas
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from flask_session import Session
import logging
from google.oauth2 import id_token  # ✅ Import this
from google.auth.transport import requests as google_requests
from flask import session
from datetime import datetime

from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()


# ✅ Configure Logging
logging.basicConfig(
    filename="app.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"  # Stores session data
app.config["SESSION_COOKIE_SECURE"] = True  # Force HTTPS only
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JavaScript access
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Protect against CSRF attacks

Session(app)  # Initialize Flask-Session


# Load PayU credentials from environment variables
MERCHANT_KEY = os.getenv("PAYU_MERCHANT_KEY")
MERCHANT_SALT = os.getenv("PAYU_MERCHANT_SALT")

# Validate that the credentials are set
if not MERCHANT_KEY or not MERCHANT_SALT:
    raise ValueError("PayU credentials are missing. Set PAYU_MERCHANT_KEY and PAYU_MERCHANT_SALT environment variables.")

PAYU_URL = os.getenv("PAYU_URL", "https://secure.payu.in/_payment")  # Fetch from environment


# ✅ Database Configuration (Using ODBC)
DB_SERVER = os.getenv("DB_SERVER")
DB_NAME = os.getenv("DB_NAME")
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_DRIVER = os.getenv("DB_DRIVER", "ODBC Driver 18 for SQL Server")

DATABASE_URL = f"mssql+pyodbc://{DB_USERNAME}:{DB_PASSWORD}@{DB_SERVER}/{DB_NAME}?driver={DB_DRIVER.replace(' ', '+')}"

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'secret_key'

db = SQLAlchemy(app)

# ✅ Hash Generation Function for PayU
def generate_payu_hash(txnid, amount, productinfo, firstname, email):
    hash_sequence = f"{MERCHANT_KEY}|{txnid}|{amount}|{productinfo}|{firstname}|{email}|||||||||||{MERCHANT_SALT}"
    return hashlib.sha512(hash_sequence.encode('utf-8')).hexdigest().lower()

# ✅ Define User Model (With Picture)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(50), unique=True, nullable=False)  # ✅ Unique Google ID
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    picture = db.Column(db.String(300), nullable=True)

    def __init__(self, google_id, email, name, picture=None):
        self.google_id = google_id
        self.name = name
        self.email = email
        self.picture = picture


# ✅ Define Payment Model
class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)  # User's email
    name = db.Column(db.String(100), nullable=False)  # User's name
    plan_name = db.Column(db.String(50), nullable=False)  # Subscription Plan
    amount = db.Column(db.Float, nullable=False)  # Amount Paid
    txnid = db.Column(db.String(50), unique=True, nullable=False)  # Transaction ID
    payment_status = db.Column(db.String(20), nullable=False, default="Pending")  # Success, Failed, Pending
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp

    def __init__(self, email, name, plan_name, amount, txnid, payment_status="Pending"):
        self.email = email
        self.name = name
        self.plan_name = plan_name
        self.amount = amount
        self.txnid = txnid
        self.payment_status = payment_status

class ServiceLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    service_name = db.Column(db.String(255), nullable=False)  # Example: 'Worksheet', 'Flashcard'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("logs", lazy=True))

    def __repr__(self):
        return f"<ServiceLog {self.service_name} - {self.timestamp}>"


# ✅ Ensure Tables are Created
with app.app_context():
    db.create_all()
    print("✅ Database tables created successfully!")


app.secret_key = os.getenv("FLASK_SECRET_KEY")  # Load Flask secret key from .env
# Google OAuth Config
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

app.config["GOOGLE_DISCOVERY_URL"] = "https://accounts.google.com/.well-known/openid-configuration"



oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params={"scope": "openid email profile"},
    access_token_url="https://oauth2.googleapis.com/token",
    access_token_params=None,
    client_kwargs={"scope": "openid email profile"},
    server_metadata_url=app.config["GOOGLE_DISCOVERY_URL"],
)

# ✅ Admin Credentials (Change These)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")



@app.route("/")
def home():
    return render_template("index.html")

import secrets


@app.route("/login")
def login():
    """Handles login and sets next_url based on action"""

    allowed_domains = {
        "levelupai.azurewebsites.net": "https://levelupai.azurewebsites.net/auth/callback",
        "leveluponline.shop": "https://leveluponline.shop/auth/callback",
        "127.0.0.1": "http://127.0.0.1:8000/auth/callback",  # For local testing
    "localhost": "http://localhost:8000/auth/callback",  # Localhost testing
    }

    current_domain = request.host.split(":")[0]  # Extract domain without port
    redirect_url = allowed_domains.get(current_domain)

    if not redirect_url:
        return "Unauthorized domain", 400  # Reject if domain is not in the list

    # ✅ Store the next page user should visit
    next_url = request.args.get("next", url_for("chatbot"))  # Default is chatbot
    session["next_url"] = next_url  
    session["oauth_state"] = secrets.token_urlsafe(16)  # ✅ Store CSRF state token

    print(f"Redirecting to Google OAuth: {redirect_url}")  # Debugging
    return google.authorize_redirect(
        redirect_url, state=session["oauth_state"]  # ✅ Include CSRF state
    )

@app.route("/auth/callback")
def auth_callback():
    logging.info("🔄 Google OAuth callback hit!")

    try:
        # ✅ Validate OAuth state to prevent CSRF attacks
        received_state = request.args.get("state")
        expected_state = session.pop("oauth_state", None)
        if received_state != expected_state:
            logging.error("❌ CSRF Warning! State mismatch detected.")
            return "CSRF Warning! Invalid OAuth state.", 400

        # ✅ Retrieve OAuth Token
        token = google.authorize_access_token()
        if not token:
            logging.error("❌ No token received from Google!")
            return "Authentication failed", 400

        # ✅ Get user info from Google
        resp = google.get("https://www.googleapis.com/oauth2/v3/userinfo")
        if resp.status_code != 200:
            logging.error(f"❌ Google API Error: {resp.status_code} - {resp.text}")
            return "Error retrieving user info", 400

        user_info = resp.json()
        google_id = user_info.get("sub")
        email = user_info.get("email")
        name = user_info.get("name", "User")
        picture = user_info.get("picture")

        logging.info(f"✅ Google Login Successful - Google ID: {google_id}, Email: {email}, Name: {name}")

        # ✅ Store user details in session
        session.permanent = True
        session["google_id"] = google_id
        session["email"] = email
        session["name"] = name
        session["picture"] = picture

        logging.info(f"📌 Session Data After Login: {dict(session)}")

        # ✅ Store user details in database
        with app.app_context():
            db.create_all()

            user = User.query.filter((User.google_id == google_id) | (User.email == email)).first()
            if user:
                logging.info(f"🔄 User {email} exists. Updating info.")
                user.name = name
                user.picture = picture
            else:
                logging.info(f"🆕 Creating new user in DB: {email}")
                user = User(google_id=google_id, email=email, name=name, picture=picture)
                db.session.add(user)

            # ✅ Track Login Activity
            new_log = ServiceLog(user_id=user.id, service_name="User Login")
            db.session.add(new_log)

            db.session.commit()
            logging.info(f"✅ User {email} saved/updated in database with login activity.")

        # ✅ Redirect user to next page
        next_page = session.pop("next_url", url_for("chatbot"))
        logging.info(f"🔀 Redirecting user to: {next_page}")

        return redirect(next_page)

    except Exception as e:
        logging.error(f"❌ Error in OAuth callback: {str(e)}")
        return "Internal Server Error", 500








        


@app.route('/save_email', methods=['POST'])
def save_email():
    token = request.json.get('token')
    try:
        # Verify the token using Google ID Token verification
        info = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)

        google_id = info.get('sub')  # ✅ Extract Google ID
        email = info.get('email')
        name = info.get('name', 'Unknown User')  # ✅ Set a default name
        picture = info.get('picture')  # ✅ Store profile picture (optional)

        if email and google_id:
            with app.app_context():
                user = User.query.filter_by(email=email).first()

                if user:
                    # ✅ If user exists, update details
                    logging.info(f"🔄 User {email} already exists. Updating info.")
                    user.name = name
                    user.google_id = google_id  # ✅ Ensure correct Google ID is stored
                    user.picture = picture
                else:
                    # ✅ Create a new user with the correct Google ID
                    logging.info(f"🆕 Creating new user in DB: {email}")
                    new_user = User(google_id=google_id, email=email, name=name, picture=picture)
                    db.session.add(new_user)

                db.session.commit()
                logging.info(f"✅ User {email} saved/updated in database.")

            return jsonify({"success": True})

    except ValueError as e:
        logging.error(f"❌ Invalid token: {str(e)}")
        return jsonify({"success": False, "error": "Invalid token"}), 401

    except Exception as e:
        logging.error(f"❌ Error in save_email: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500




@app.route("/chatbot")
def chatbot():
    email = session.get("email")
    logging.info(f"📌 DEBUG: Session Data - {dict(session)}")

    if not email:
        logging.warning("🚫 No user session found! Redirecting to login.")
        return redirect(url_for("login"))  # ✅ Fixed incorrect redirect

    user = User.query.filter_by(email=email).first()
    if not user:
        logging.error(f"🚫 User {email} not found in database! Logging out user.")
        session.clear()  # ✅ Clear session to prevent looping redirects
        return redirect(url_for("login"))  # Redirect to login instead of 404

    # ✅ Only check for payment IF user came from "Subscribe"
    next_url = session.pop("next_url", None)
    if next_url == "pay":
        payment = Payment.query.filter_by(email=email, payment_status="Success").first()
        if not payment:
            logging.warning(f"🚫 Access Denied: {email} has NOT paid! Redirecting to home.")
            return redirect(url_for("home"))  # Redirect unpaid users

    # ✅ Normal login users get direct access
    return render_template("chatbot.html", name=user.name, email=user.email, picture=user.picture)




from flask import redirect, url_for  # ✅ Import redirect function

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    logging.info(f"Admin Login Attempt: {request.method}")

    if request.method == "POST":
        # ✅ Handle both Form Data and JSON requests
        if request.is_json:
            data = request.json
            username = data.get("username")
            password = data.get("password")
        else:
            username = request.form.get("username")
            password = request.form.get("password")

        logging.info(f"Entered Username: {username}")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True  # ✅ Store session
            
            # ✅ Redirect to admin_dashboard on successful login
            return redirect(url_for("admin_dashboard"))  

        return jsonify({"error": "Invalid credentials"}), 401  # ✅ JSON Response

    return render_template("admin_login.html")  # ✅ Render login page for browsers


@app.route("/admin_dashboard", methods=["GET"])
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    # Fetch total users, worksheets, and flashcards count
    total_users = User.query.count()
    total_worksheets = ServiceLog.query.filter(ServiceLog.service_name.like("View Worksheet%")).count()
    total_flashcards = ServiceLog.query.filter(ServiceLog.service_name.like("Download Worksheet%")).count()

    users = User.query.all()
    user_data = []

    for user in users:
        logs = ServiceLog.query.filter_by(user_id=user.id).order_by(ServiceLog.timestamp.desc()).all()

        user_data.append({
            "profile_picture": user.picture or "/static/images/default.png",
            "name": user.name,
            "email": user.email,
           "worksheets_used": sum(1 for log in logs if "Worksheet" in log.service_name),
            "flashcards_used": sum(1 for log in logs if "Flashcards" in log.service_name),

            "logs": [{"service_name": log.service_name, "timestamp": log.timestamp.strftime('%Y-%m-%d %H:%M:%S')} for log in logs],
            "subscription": "Paid" if Payment.query.filter_by(email=user.email, payment_status="Success").first() else "Free",
        })

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_worksheets=total_worksheets,
        total_flashcards=total_flashcards,
        users=user_data
    )



@app.route("/log_activity", methods=["POST"])
def log_activity():
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    activity_name = data.get("activity")

    if not activity_name:
        return jsonify({"error": "Invalid activity data"}), 400

    # Log only login, view worksheet, and download worksheet activities
    valid_activities = ["User Login", "View Worksheet", "Download Worksheet"]
    if activity_name not in valid_activities:
        return jsonify({"error": "Invalid activity type"}), 400

    new_log = ServiceLog(user_id=user.id, service_name=activity_name)
    db.session.add(new_log)
    db.session.commit()

    return jsonify({"message": f"{activity_name} logged successfully"})










@app.route("/admin_logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin_login"))


@app.route('/table')
def table():
    return render_template('table.html')





@app.route("/pay", methods=["GET", "POST"])
def pay():
    if "email" not in session:
        return redirect(url_for("login"))  # Ensure user is logged in

    email = session.get("email")
    name = session.get("name", "User")

    if request.method == "POST":  # Payment initiated via form submission
        txnid = str(int(time.time()))  # Unique transaction ID
        amount = request.form.get("amount", "0.00")
        productinfo = request.form.get("productinfo", "Subscription Plan")

    else:  # If request is GET (from a button click)
        plan = request.args.get("plan")
        amount = request.args.get("amount")
        txnid = "TXN" + str(int(time.time() * 1000)) + str(random.randint(1000, 9999))  # Unique txnid
        productinfo = plan if plan else "Subscription Plan"

    # ✅ Generate PayU Hash
    hash_value = generate_payu_hash(txnid, amount, productinfo, name, email)

    # ✅ Store transaction in DB (status: "Pending")
    payment = Payment(email=email, name=name, amount=amount, plan_name=productinfo, txnid=txnid, payment_status="Pending")
    db.session.add(payment)
    db.session.commit()

    # ✅ Prepare PayU Data
    payu_data = {
        "key": MERCHANT_KEY,
        "txnid": txnid,
        "amount": amount,
        "productinfo": productinfo,
        "firstname": name,
        "email": email,
        "phone": "9999999999",  # Required field
        "surl": url_for('success', _external=True) + f"?txnid={txnid}&productinfo={productinfo}&amount={amount}",  # Ensure values are passed
        "furl": url_for("failure", _external=True),
        "hash": hash_value
    }

    return render_template("payment.html", payu_url=PAYU_URL, payu_data=payu_data)



@app.route('/success', methods=['GET', 'POST'])
def success():
    if request.method == 'POST' and 'txnid' in request.form:
        print(request.form)  # Debug: Print PayU's response in logs
        txnid = request.form.get('txnid', 'Unknown')
        plan = request.form.get('productinfo', 'N/A')
        amount = request.form.get('amount', '0.00')
    else:  # Use GET as a fallback
        print(request.args)  # Debug: Print if PayU sends GET
        txnid = request.args.get('txnid', 'Unknown')
        plan = request.args.get('productinfo', 'N/A')
        amount = request.args.get('amount', '0.00')

    print(f"Received Payment Data -> Transaction ID: {txnid}, Plan: {plan}, Amount: {amount}")

    # ✅ Update payment status in database
    payment = Payment.query.filter_by(txnid=txnid).first()
    if payment:
        payment.payment_status = "Success"
        db.session.commit()
        logging.info(f"✅ Payment Success for {payment.email} - TXN: {txnid}")

    # ✅ Generate Receipt PDF
    pdf_path = f"receipt_{txnid}.pdf"
    generate_pdf(txnid, plan, amount, pdf_path)

    return render_template('payment_success.html', txnid=txnid, plan=plan, amount=amount, pdf_path=pdf_path)



@app.route('/generate_receipt/<txnid>')
def generate_receipt(txnid):
    plan = request.args.get('plan')
    amount = request.args.get('amount')
    pdf_path = f"receipt_{txnid}.pdf"
    generate_pdf(txnid, plan, amount, pdf_path)
    return send_file(pdf_path, as_attachment=True)

def generate_pdf(txnid, plan, amount, pdf_path):
    c = canvas.Canvas(pdf_path)
    
    c.setFont("Helvetica-Bold", 16)
    c.drawString(200, 800, "Payment Receipt")
    
    c.setFont("Helvetica", 12)
    c.drawString(100, 750, f"Transaction ID: {txnid}")
    c.drawString(100, 730, f"Plan: {plan}")
    c.drawString(100, 710, f"Amount Paid: ${amount}")
    
    c.drawString(100, 680, "Thank you for your purchase!")
    c.save()

# ✅ Failure Route (Update Payment Status)
@app.route('/failure')
def failure():
    txnid = request.args.get("txnid")
    payment = Payment.query.filter_by(txnid=txnid).first()
    
    if payment:
        payment.payment_status = "Failed"
        db.session.commit()
        logging.warning(f"🚨 Payment Failed for {payment.email} - TXN: {txnid}")
    
    return render_template('payment_failure.html')
    
@app.route("/logout")
def logout():
    logging.info(f"Logging out user: {session.get('email')}")
    session.clear()
    return redirect(url_for("home"))


# Run the Flask app
if __name__ == '__main__':
    logging.info("🚀 Starting Flask app...")
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8000)))


