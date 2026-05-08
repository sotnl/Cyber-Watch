from database import get_connection

MAX_ATTEMPTS = 5


def register_failed_attempt(ip):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT count FROM failed_attempts WHERE ip=%s", (ip,))
    row = cursor.fetchone()

    if row:
        cursor.execute("""
            UPDATE failed_attempts
            SET count = count + 1,
                last_attempt = CURRENT_TIMESTAMP
            WHERE ip = %s
        """, (ip,))
    else:
        cursor.execute("""
            INSERT INTO failed_attempts (ip, count, last_attempt)
            VALUES (%s, 1, CURRENT_TIMESTAMP)
        """, (ip,))

    conn.commit()
    conn.close()


def detect_attack(ip):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT count FROM failed_attempts WHERE ip=%s", (ip,))
    row = cursor.fetchone()

    conn.close()

    if not row:
        return False

    return row[0] >= MAX_ATTEMPTS


def clear_failed_attempts(ip):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM failed_attempts WHERE ip=%s
    """, (ip,))

    conn.commit()
    conn.close()