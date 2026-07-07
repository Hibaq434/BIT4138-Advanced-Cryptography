"""
engine.py — Secure University Messenger backend
=================================================
All cryptography, storage, and business logic for the messenger,
kept independent of any GUI so it can be tested from a plain
terminal. The Tkinter front end (app.py) imports this module and
never touches SQLite or crypto directly.

Security design
----------------
- Each user gets their own ElGamal key pair (encryption) and ECC
  key pair (digital signatures), generated at registration.
- Every message is signed by the sender's ECC private key, so the
  recipient can verify who really sent it and that it was not
  altered in transit/storage.
- Every message is encrypted TWICE at send time: once under the
  recipient's ElGamal public key (so they can read it) and once
  under the sender's own ElGamal public key (so the sender can also
  see their own sent messages later). Nobody can decrypt the other
  party's copy — this mirrors real end-to-end encrypted messengers.
- Private keys are never stored in plain text. Each user's ElGamal
  private key and ECC private key are encrypted at rest with a key
  derived from that user's login password (PBKDF2-HMAC-SHA256 +
  Fernet/AES). The keys only exist in plaintext in memory during an
  active logged-in session.
"""

import base64
import glob
import hashlib
import hmac
import json
import os
import shutil
import random
import sqlite3
import time

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature


DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "messenger.db")
ELGAMAL_BITS = 256   # demo-appropriate key size; see README for discussion


# =====================================================================
# ElGamal (from scratch)
# =====================================================================
def is_prime(n, rounds=40):
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n == sp:
            return True
        if n % sp == 0:
            return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(bits):
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


def generate_safe_prime(bits):
    while True:
        q = generate_large_prime(bits - 1)
        p = 2 * q + 1
        if is_prime(p):
            return p, q


def find_generator(p, q):
    while True:
        g = random.randrange(2, p - 1)
        if pow(g, 2, p) == 1:
            continue
        if pow(g, q, p) == 1:
            continue
        return g


def elgamal_generate_keys(bits=ELGAMAL_BITS):
    p, q = generate_safe_prime(bits)
    g = find_generator(p, q)
    x = random.randrange(2, p - 2)
    y = pow(g, x, p)
    return {"p": p, "g": g, "x": x, "y": y}


def elgamal_encrypt_block(p, g, y, m_int):
    if not (0 <= m_int < p):
        raise ValueError("Block too large for this ElGamal key size.")
    k = random.randrange(2, p - 2)
    c1 = pow(g, k, p)
    c2 = (m_int * pow(y, k, p)) % p
    return c1, c2


def elgamal_decrypt_block(p, x, c1, c2):
    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)
    return (c2 * s_inv) % p


def _block_size(p):
    """Bytes per block, kept strictly below p so every block value is a
    valid ElGamal plaintext integer."""
    size = (p.bit_length() // 8) - 1
    if size < 1:
        raise ValueError("ElGamal key too small to encrypt any data.")
    return size


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def elgamal_encrypt_message(p, g, y, text: str):
    """Encrypts an arbitrary-length message as a list of (c1, c2) blocks,
    each protected by its own fresh random k."""
    block_size = _block_size(p)
    data = _pkcs7_pad(text.encode("utf-8"), block_size)
    blocks = []
    for i in range(0, len(data), block_size):
        chunk = data[i:i + block_size]
        m_int = int.from_bytes(chunk, "big")
        blocks.append(elgamal_encrypt_block(p, g, y, m_int))
    return blocks


def elgamal_decrypt_message(p, x, blocks):
    block_size = _block_size(p)
    out = bytearray()
    for c1, c2 in blocks:
        m_int = elgamal_decrypt_block(p, x, c1, c2)
        out.extend(m_int.to_bytes(block_size, "big"))
    return _pkcs7_unpad(bytes(out)).decode("utf-8")


# =====================================================================
# Password-derived key wrapping (protects private keys at rest)
# =====================================================================
def derive_fernet_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_blob(password: str, salt: bytes, plaintext: bytes) -> bytes:
    f = Fernet(derive_fernet_key(password, salt))
    return f.encrypt(plaintext)


def decrypt_blob(password: str, salt: bytes, token: bytes) -> bytes:
    f = Fernet(derive_fernet_key(password, salt))
    return f.decrypt(token)


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)


# =====================================================================
# ECC signatures (digital signature verification requirement)
# =====================================================================
def ecc_generate_keys():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def ecc_sign(private_key, message: bytes) -> bytes:
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def ecc_verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def ecc_priv_to_pem(priv) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def ecc_pub_to_pem(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def ecc_priv_from_pem(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)


def ecc_pub_from_pem(pem: bytes):
    return serialization.load_pem_public_key(pem)


# =====================================================================
# Database layer
# =====================================================================
def get_connection(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=DB_PATH):
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            role TEXT NOT NULL,
            pw_salt BLOB NOT NULL,
            pw_hash BLOB NOT NULL,
            key_salt BLOB NOT NULL,
            elgamal_p TEXT NOT NULL,
            elgamal_g TEXT NOT NULL,
            elgamal_y TEXT NOT NULL,
            elgamal_x_enc BLOB NOT NULL,
            ecc_pub_pem TEXT NOT NULL,
            ecc_priv_pem_enc BLOB NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            for_user TEXT NOT NULL,
            timestamp REAL NOT NULL,
            blocks TEXT NOT NULL,
            signature BLOB NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def conversation_key(user_a, user_b):
    return "|".join(sorted([user_a, user_b]))


# ---------------------------------------------------------------------
# User registration / authentication
# ---------------------------------------------------------------------
class AuthError(Exception):
    pass


def register_user(username, password, role, db_path=DB_PATH):
    """Creates a new user with fresh ElGamal + ECC key pairs.
    Private keys are encrypted at rest using a key derived from
    `password`; the password itself is never stored."""
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        raise ValueError(f"Username '{username}' already exists.")

    pw_salt = os.urandom(16)
    pw_hash = hash_password(password, pw_salt)
    key_salt = os.urandom(16)

    eg = elgamal_generate_keys()
    priv, pub = ecc_generate_keys()
    ecc_priv_pem = ecc_priv_to_pem(priv)
    ecc_pub_pem = ecc_pub_to_pem(pub).decode("utf-8")

    elgamal_x_enc = encrypt_blob(password, key_salt, str(eg["x"]).encode("utf-8"))
    ecc_priv_pem_enc = encrypt_blob(password, key_salt, ecc_priv_pem)

    cur.execute("""
        INSERT INTO users (username, role, pw_salt, pw_hash, key_salt,
                            elgamal_p, elgamal_g, elgamal_y, elgamal_x_enc,
                            ecc_pub_pem, ecc_priv_pem_enc, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        username, role, pw_salt, pw_hash, key_salt,
        str(eg["p"]), str(eg["g"]), str(eg["y"]), elgamal_x_enc,
        ecc_pub_pem, ecc_priv_pem_enc, str(time.time()),
    ))
    conn.commit()
    conn.close()


class Session:
    """Represents a logged-in user with decrypted keys held in memory."""

    def __init__(self, username, role, elgamal_pub, elgamal_priv,
                 ecc_pub, ecc_priv):
        self.username = username
        self.role = role
        self.elgamal_p = elgamal_pub["p"]
        self.elgamal_g = elgamal_pub["g"]
        self.elgamal_y = elgamal_pub["y"]
        self.elgamal_x = elgamal_priv
        self.ecc_pub = ecc_pub
        self.ecc_priv = ecc_priv


def login(username, password, db_path=DB_PATH) -> Session:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if row is None:
        raise AuthError("No such user.")

    expected = hash_password(password, row["pw_salt"])
    if not hmac.compare_digest(expected, row["pw_hash"]):
        raise AuthError("Incorrect password.")

    try:
        x = int(decrypt_blob(password, row["key_salt"], row["elgamal_x_enc"]))
        ecc_priv_pem = decrypt_blob(password, row["key_salt"], row["ecc_priv_pem_enc"])
    except Exception:
        raise AuthError("Key decryption failed (corrupted account data).")

    ecc_priv = ecc_priv_from_pem(ecc_priv_pem)
    ecc_pub = ecc_priv.public_key()

    return Session(
        username=username,
        role=row["role"],
        elgamal_pub={"p": int(row["elgamal_p"]), "g": int(row["elgamal_g"]),
                     "y": int(row["elgamal_y"])},
        elgamal_priv=x,
        ecc_pub=ecc_pub,
        ecc_priv=ecc_priv,
    )


def list_users(exclude=None, db_path=DB_PATH):
    conn = get_connection(db_path)
    cur = conn.cursor()
    if exclude:
        cur.execute("SELECT username, role FROM users WHERE username != ? ORDER BY username",
                    (exclude,))
    else:
        cur.execute("SELECT username, role FROM users ORDER BY username")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_user_public_info(username, db_path=DB_PATH):
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT username, role, elgamal_p, elgamal_g, elgamal_y, ecc_pub_pem "
                "FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if row is None:
        raise ValueError("No such user.")
    return dict(row)


# ---------------------------------------------------------------------
# Messaging
# ---------------------------------------------------------------------
def _blocks_to_json(blocks):
    return json.dumps([[str(c1), str(c2)] for c1, c2 in blocks])


def _blocks_from_json(s):
    return [(int(c1), int(c2)) for c1, c2 in json.loads(s)]


def send_message(session: Session, recipient: str, text: str, db_path=DB_PATH):
    if not text:
        raise ValueError("Message cannot be empty.")

    recipient_info = get_user_public_info(recipient, db_path)
    conn = get_connection(db_path)
    cur = conn.cursor()

    signature = ecc_sign(session.ecc_priv, text.encode("utf-8"))
    conv_id = conversation_key(session.username, recipient)
    ts = time.time()

    # Copy for the recipient (encrypted under their ElGamal public key)
    blocks_r = elgamal_encrypt_message(
        int(recipient_info["elgamal_p"]), int(recipient_info["elgamal_g"]),
        int(recipient_info["elgamal_y"]), text,
    )
    # Copy for the sender's own history (encrypted under the sender's own key)
    blocks_s = elgamal_encrypt_message(
        session.elgamal_p, session.elgamal_g, session.elgamal_y, text,
    )

    cur.executemany("""
        INSERT INTO messages (conversation_id, sender, recipient, for_user,
                               timestamp, blocks, signature)
        VALUES (?,?,?,?,?,?,?)
    """, [
        (conv_id, session.username, recipient, recipient, ts, _blocks_to_json(blocks_r), signature),
        (conv_id, session.username, recipient, session.username, ts, _blocks_to_json(blocks_s), signature),
    ])
    conn.commit()
    conn.close()


def get_conversation(session: Session, other_user: str, db_path=DB_PATH):
    """Returns messages visible to `session.username` in their chat with
    `other_user`, decrypted with the session's own ElGamal private key,
    with each message's signature verified against the sender's ECC
    public key."""
    conv_id = conversation_key(session.username, other_user)
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM messages
        WHERE conversation_id = ? AND for_user = ?
        ORDER BY timestamp ASC, id ASC
    """, (conv_id, session.username))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    sender_pub_cache = {}
    results = []
    for row in rows:
        sender = row["sender"]
        if sender not in sender_pub_cache:
            info = get_user_public_info(sender, db_path)
            sender_pub_cache[sender] = ecc_pub_from_pem(info["ecc_pub_pem"].encode("utf-8"))

        try:
            blocks = _blocks_from_json(row["blocks"])
            text = elgamal_decrypt_message(session.elgamal_p, session.elgamal_x, blocks)
            verified = ecc_verify(sender_pub_cache[sender], text.encode("utf-8"), row["signature"])
        except Exception:
            # Ciphertext was corrupted/tampered with and no longer decodes
            # to a valid message -- surface this instead of crashing.
            text = "[unreadable: message may have been corrupted or tampered with]"
            verified = False

        results.append({
            "id": row["id"],
            "sender": sender,
            "recipient": row["recipient"],
            "timestamp": row["timestamp"],
            "text": text,
            "verified": verified,
        })
    return results


def list_conversations(session: Session, db_path=DB_PATH):
    """All conversation partners for the logged-in user, most recent first."""
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        SELECT sender, recipient, MAX(timestamp) as last_ts
        FROM messages
        WHERE for_user = ?
        GROUP BY conversation_id
        ORDER BY last_ts DESC
    """, (session.username,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    partners = []
    for row in rows:
        partner = row["recipient"] if row["sender"] == session.username else row["sender"]
        partners.append(partner)
    return partners


def search_messages(session: Session, keyword: str, db_path=DB_PATH):
    """Searches every conversation the logged-in user is part of for a
    keyword (case-insensitive), returning matches with partner context."""
    keyword_lower = keyword.lower()
    matches = []
    for partner in list_conversations(session, db_path):
        for msg in get_conversation(session, partner, db_path):
            if keyword_lower in msg["text"].lower():
                msg_with_partner = dict(msg)
                msg_with_partner["partner"] = partner
                matches.append(msg_with_partner)
    matches.sort(key=lambda m: m["timestamp"], reverse=True)
    return matches


# ---------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------
def export_conversation_txt(session: Session, other_user: str, out_path: str, db_path=DB_PATH):
    msgs = get_conversation(session, other_user, db_path)
    lines = [f"Conversation between {session.username} and {other_user}", "=" * 60, ""]
    for m in msgs:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(m["timestamp"]))
        tag = "OK" if m["verified"] else "SIGNATURE INVALID"
        lines.append(f"[{when}] {m['sender']} ({tag}): {m['text']}")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return out_path


def export_conversation_pdf(session: Session, other_user: str, out_path: str, db_path=DB_PATH):
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from xml.sax.saxutils import escape

    msgs = get_conversation(session, other_user, db_path)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], fontSize=16)
    mine_style = ParagraphStyle("Mine", parent=styles["Normal"], alignment=2,
                                 textColor=colors.HexColor("#1F3864"), spaceAfter=8)
    theirs_style = ParagraphStyle("Theirs", parent=styles["Normal"], alignment=0,
                                   textColor=colors.black, spaceAfter=8)
    meta_style = ParagraphStyle("Meta", parent=styles["Normal"], fontSize=8,
                                 textColor=colors.grey, spaceAfter=2)

    doc = SimpleDocTemplate(out_path, pagesize=letter,
                             leftMargin=0.75 * inch, rightMargin=0.75 * inch)
    story = [Paragraph(f"Conversation: {session.username} &amp; {other_user}", title_style),
             Spacer(1, 12)]

    for m in msgs:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(m["timestamp"]))
        tag = "verified" if m["verified"] else "SIGNATURE INVALID"
        style = mine_style if m["sender"] == session.username else theirs_style
        story.append(Paragraph(f"{escape(m['sender'])} &middot; {when} &middot; {tag}", meta_style))
        story.append(Paragraph(escape(m["text"]), style))

    doc.build(story)
    return out_path


# ---------------------------------------------------------------------
# QR code export of a user's public key (bonus feature)
# ---------------------------------------------------------------------
def public_key_qr_payload(username, db_path=DB_PATH):
    info = get_user_public_info(username, db_path)
    return (f"UNIVMSG-PUBKEY|user={info['username']}|p={info['elgamal_p']}|"
            f"g={info['elgamal_g']}|y={info['elgamal_y']}")


def make_qr_image(payload: str, out_path: str):
    import qrcode
    img = qrcode.make(payload)
    img.save(out_path)
    return out_path


# ---------------------------------------------------------------------
# Automatic backup (the database itself stores only ciphertext, so a
# backup copy is still fully encrypted -- it's not a plaintext leak)
# ---------------------------------------------------------------------
def backup_database(db_path=DB_PATH, backup_dir=None, keep=5):
    if backup_dir is None:
        backup_dir = os.path.join(os.path.dirname(os.path.abspath(db_path)), "backups")
    os.makedirs(backup_dir, exist_ok=True)

    ts = time.strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(backup_dir, f"messenger_backup_{ts}.db")
    shutil.copyfile(db_path, dest)

    backups = sorted(glob.glob(os.path.join(backup_dir, "messenger_backup_*.db")))
    while len(backups) > keep:
        os.remove(backups.pop(0))
    return dest