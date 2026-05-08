from flask import Flask, render_template, request, redirect, session, Response
from database import get_connection
from werkzeug.security import check_password_hash
from datetime import timedelta
import cv2
import blocker
import detector

app = Flask(__name__)
app.secret_key = "secret_key_123"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)


def save_log(ip, event_type, status):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO security_logs (ip, event_type, status, created_at)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
        """, (ip, event_type, status))
        conn.commit()
    except:
        conn.rollback()
    finally:
        conn.close()


@app.route("/", methods=["GET", "POST"])
def login():
    ip = request.remote_addr

    if blocker.is_blocked(ip):
        return "Access Denied: Your IP is permanently blocked.", 403

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT username, password FROM users WHERE username=%s",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if user and user[1] == password:
            session.permanent = True
            session["user"] = username

            detector.clear_failed_attempts(ip)

            save_log(ip, f"Login Success: {username}", "SUCCESS")
            return redirect("/dashboard")

        else:
            save_log(ip, f"Login Failed: {username}", "FAILED")

            detector.register_failed_attempt(ip)

            if detector.detect_attack(ip):
                blocker.block_ip(ip, "Brute force detected")

                save_log(ip, "Brute Force Detected", "ALERT")
                save_log(ip, "IP BLOCKED", "BLOCKED")

                return "Security Alert: IP Blocked.", 403

            return "Invalid login"

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='SUCCESS' AND created_at >= CURRENT_DATE")
    today_access = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='FAILED' AND created_at >= CURRENT_DATE")
    unauthorized = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM blocked_ips")
    unique_attackers = cursor.fetchone()[0]

    cursor.execute("""
        SELECT ip, event_type, status, created_at
        FROM security_logs
        ORDER BY created_at DESC
        LIMIT 7
    """)
    recent_alerts = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        user=session["user"],
        today_access=today_access,
        unauthorized=unauthorized,
        unique_attackers=unique_attackers,
        recent_alerts=recent_alerts
    )


@app.route("/live-cctv")
def live_cctv():
    if "user" not in session:
        return redirect("/")
    return render_template("live_cctv.html", user=session["user"])


@app.route("/threat-logs")
def threat_logs():
    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ip, event_type, status, created_at
        FROM security_logs
        ORDER BY created_at DESC
        LIMIT 50
    """)

    logs = cursor.fetchall()
    conn.close()

    return render_template("threat_logs.html", user=session["user"], logs=logs)


@app.route("/analytics")
def analytics():
    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='SUCCESS'")
    success_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='FAILED'")
    failed_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM blocked_ips")
    blocked_count = cursor.fetchone()[0]

    conn.close()

    return render_template(
        "analytics.html",
        user=session["user"],
        success_count=success_count,
        failed_count=failed_count,
        blocked_count=blocked_count
    )


camera = cv2.VideoCapture(0)
camera.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)


def generate_frames():
    while True:
        success, frame = camera.read()
        if not success:
            continue

        _, buffer = cv2.imencode('.jpg', frame)
        frame_bytes = buffer.tobytes()

        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' +
               frame_bytes +
               b'\r\n')


@app.route("/video_feed")
def video_feed():
    if "user" not in session:
        return "Unauthorized", 403

    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


import atexit

@atexit.register
def release_camera():
    camera.release()


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)