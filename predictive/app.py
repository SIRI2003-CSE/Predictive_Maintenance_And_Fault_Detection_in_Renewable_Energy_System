from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
import joblib

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Change this to a strong secret key
bcrypt = Bcrypt(app)

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["UserDatabase"]
users_collection = db["Users"]

# Load the trained model
model = joblib.load(r'C:\Users\dell\Downloads\renewable project\code batch 12\code batch 12\logistic_regression_model_fa.pkl')

# Home Page (Redirects to Login if Not Authenticated)
@app.route("/")
def home():
    if "username" in session:
        return render_template("index.html", username=session["username"])
    return redirect("/login")

# Registration Page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if user already exists
        if users_collection.find_one({"username": username}):
            flash("Username already exists! Try a different one.", "danger")
            return redirect("/register")

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Store in MongoDB
        users_collection.insert_one({"username": username, "password": hashed_password})
        flash("Registration successful! Please login.", "success")
        return redirect("/login")

    return render_template("register.html")

# Login Page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Fetch user from database
        user = users_collection.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            session["username"] = username
            flash("Login successful!", "success")
            return redirect("/")  # Redirect to home after login
        else:
            flash("Invalid credentials! Try again.", "danger")

    return render_template("login.html")

# Logout
@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("Logged out successfully!", "info")
    return redirect("/login")

# Prediction Page
@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get user inputs
        features = [float(x) for x in request.form.values()]

        # Make prediction
        prediction = model.predict([features])
        
        # Interpret prediction
        result = "Maintenance is required." if prediction[0] == 1 else "Maintenance is not required."
    except Exception as e:
        result = f"Error in prediction: {str(e)}"

    return render_template('index.html', result=result, username=session.get("username", "Guest"))

if __name__ == "__main__":  # Corrected this line
    app.run(debug=True)
