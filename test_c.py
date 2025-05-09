import pyodbc
from flask import Flask, request, jsonify

app = Flask(__name__)

# VULNERABILITY: Hardcoded database credentials
SERVER = "my-azure-sql-server.database.windows.net"
DATABASE = "customer_db"
USERNAME = "admin"
PASSWORD = "SuperSecretP@ssw0rd!"
DRIVER = "{ODBC Driver 17 for SQL Server}"


def get_connection():
    connection_string = f"DRIVER={DRIVER};SERVER={SERVER};DATABASE={DATABASE};UID={USERNAME};PWD={PASSWORD}"
    return pyodbc.connect(connection_string)


# VULNERABILITY: SQL Injection
@app.route("/api/users")
def get_user():
    user_id = request.args.get("id")

    conn = get_connection()
    cursor = conn.cursor()

    # Direct string concatenation - SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    rows = cursor.fetchall()
    conn.close()

    return jsonify(
        {
            "users": [
                dict(zip([column[0] for column in cursor.description], row))
                for row in rows
            ]
        }
    )


# VULNERABILITY: Excessive data exposure
@app.route("/api/user_data/<user_id>")
def get_all_user_data(user_id):
    conn = get_connection()
    cursor = conn.cursor()

    # Query that returns all data including sensitive information
    cursor.execute("SELECT * FROM users WHERE id = ?", user_id)

    columns = [column[0] for column in cursor.description]
    user_data = dict(zip(columns, cursor.fetchone()))
    conn.close()

    # Returns all data including PII and possibly passwords
    return jsonify(user_data)


if __name__ == "__main__":
    # VULNERABILITY: Debug mode in production
    app.run(debug=True, host="0.0.0.0")
