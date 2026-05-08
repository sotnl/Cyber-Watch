from database import get_connection


def block_ip(ip, reason="Brute force detected"):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO blocked_ips (ip, reason)
        VALUES (%s, %s)
        ON CONFLICT (ip) DO UPDATE SET reason=%s
    """, (ip, reason, reason))

    conn.commit()
    conn.close()


def is_blocked(ip):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT 1 FROM blocked_ips WHERE ip=%s", (ip,))
    result = cursor.fetchone()

    conn.close()

    return result is not None