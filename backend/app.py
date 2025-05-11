from flask import Flask, request, jsonify
import mysql.connector
import requests
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# MySQL Connection with error handling
try:
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="slg@1234",  # Replace with your actual MySQL password
        database="faknet_db"
    )
    cursor = conn.cursor()
    print("✅ Connected to MySQL successfully!")
except mysql.connector.Error as err:
    print(f"❌ MySQL Connection Error: {err}")
    conn = None

# Google Safe Browsing API for website lookup
def check_website(website_url):
    google_api_key = "YOUR_GOOGLE_API_KEY"  # Use environment variables instead
    google_api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={'AIzaSyCjPa-4KsVPxYptwTTQCW1H8X2Zm6g6Wis'}"

    payload = {
        "client": {"clientId": "faknet", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": website_url}]
        }
    }

    try:
        response = requests.post(google_api_url, json=payload)
        response.raise_for_status()
        data = response.json()
        return "matches" in data
    except requests.exceptions.RequestException as e:
        print(f"❌ Google API Error: {e}")
        return False  # Assume safe if API fails

@app.route("/check", methods=["POST"])
def detect_fake_website():
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    website_url = request.json.get("website")
    is_fake = check_website(website_url)

    try:
        cursor.execute("INSERT INTO websites (url, is_fake) VALUES (%s, %s)", (website_url, is_fake))
        conn.commit()
        return jsonify({"website": website_url, "is_fake": is_fake})
    except mysql.connector.Error as err:
        return jsonify({"error": f"Database error: {err}"}), 500

@app.route("/websites", methods=["GET"])
def get_websites():
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor.execute("SELECT url, is_fake FROM websites")
    results = cursor.fetchall()
    websites = [{"url": row[0], "is_fake": row[1]} for row in results]
    return jsonify(websites)

if __name__ == "__main__":
    app.run(debug=True)
