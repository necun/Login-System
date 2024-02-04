from utils import *


def check_user_exists(username, email, phone_number):
    conn = get_db_connection()
    cursor = conn.cursor(buffered=True)
    try:
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s OR phone_number = %s", (username, email, phone_number,))
        if cursor.fetchone():
            return True
        return False
    finally:
        cursor.close()
        conn.close()

def update_email_verify(fullname, username, password, email, phone_number, verification_token):
    conn = get_db_connection()
    cursor = conn.cursor(buffered=True)
    cursor.execute("SELECT email FROM email_verify")
    user = cursor.fetchone()
        
    if user:
        cursor.execute("UPDATE email_verify SET token = %s WHERE email=%s", (verification_token, user[0]))
        conn.commit()

    else:
        query = "INSERT INTO email_verify(fullname, username, password, email, token, phone_number) VALUES (%s, %s, %s, %s, %s, %s)"
        cursor.execute(query, (fullname, username, password, email, verification_token, phone_number))
        conn.commit()
    cursor.close()
    conn.close()

def fetch_user(token):
    conn = get_db_connection()
    cursor = conn.cursor(buffered=True)
    try:
        cursor.execute("SELECT email, fullname, password, username, phone_number FROM email_verify WHERE token = %s", (token,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

def create_user(fullname, username, password, email, phone_number):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "INSERT INTO users(fullname, username, password, email, phone_number) VALUES(%s, %s, %s, %s, %s)"
        cursor.execute(query, (fullname, username, password, email, phone_number))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

def delete_entry(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "DELETE FROM email_verify WHERE email = %s"
        cursor.execute(query, (email,))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

def fetch_user_password_hash(username):
    conn = get_db_connection()
    cursor = conn.cursor(buffered=True)
    try:
        query = "SELECT password FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()    

def fetch_user_id_by_email(email):
    conn = get_db_connection()
    cursor = conn.cursor(buffered=True)
    try:
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        return cursor.fetchone()  # Returns user_id or None
    finally:
        cursor.close()
        conn.close()

def update_reset_token_for_user(user_id, reset_token):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET reset_token = %s WHERE user_id = %s", (reset_token, user_id))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

def is_valid_reset_token(token):
    conn = get_db_connection()
    cursor = conn.cursor(buffered=True)
    try:
        cursor.execute("SELECT user_id FROM users WHERE reset_token = %s", (token,))
        return bool(cursor.fetchone())  # Returns True if token is valid, otherwise False
    finally:
        cursor.close()
        conn.close()

def update_user_password(token, new_password_hash):
    conn = get_db_connection()
    cursor = conn.cursor(buffered=True)
    try:
        cursor.execute("SELECT user_id FROM users WHERE reset_token = %s", (token,))
        user = cursor.fetchone()
        if user:
            cursor.execute("UPDATE users SET password = %s, reset_token = NULL WHERE user_id = %s", (new_password_hash, user[0]))
            conn.commit()
            return True
        else:
            return False
    finally:
        cursor.close()
        conn.close()

def update_user_pic_url(username, pic_url):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE USERS SET pic_url = %s WHERE username = %s", (pic_url, username))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

def get_user_password_hash(username):
    conn = get_db_connection()
    cursor = conn.cursor(buffered=True)
    try:
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        return result[0] if result else None
    finally:
        cursor.close()
        conn.close()

def update_user_password(username, new_password_hash):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET password = %s WHERE username = %s", (new_password_hash, username))
        conn.commit()
    finally:
        cursor.close()
        conn.close()