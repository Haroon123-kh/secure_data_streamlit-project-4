import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Encryption key generate kar rahe hain
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Streamlit session variables initialize kar rahe hain
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # Data temporary memory mein rakha jaega
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0  # Ghalat koshishon ka count
if "authorized" not in st.session_state:
    st.session_state.authorized = True  # Agar user block ho gaya ho to false ho jata hai

# Passkey ko SHA-256 algorithm se hash karte hain
def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

# Text ko encrypt (taala lagana) karne ka function
def encrypt_data(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

# Encrypt data ko decrypt (taala kholna) karne ka function
def decrypt_data(encrypted_text: str) -> str:
    return cipher.decrypt(encrypted_text.encode()).decode()

# App ka title
st.title("🔒 Secure Data Encryption System")

# Navigation menu sidebar mein
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home page
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# Data store karne ka page
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")

    user_data = st.text_area("Enter Data:")  # User se data input
    passkey = st.text_input("Enter Passkey:", type="password")  # Passkey lena

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)  # Passkey ko hash karte hain
            encrypted_text = encrypt_data(user_data)  # Data ko encrypt karte hain
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey,
            }
            st.success("✅ Data stored securely!")  # Success message
            st.write("🔐 Save your encrypted data (required for retrieval):")
            st.code(encrypted_text)
        else:
            st.error("⚠️ Dono fields zaroori hain!")  # Agar koi field khali ho

# Data retrieve karne ka page
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")

    # Agar 3 se zyada ghalat koshish ho chuki ho to block kar dete hain
    if not st.session_state.authorized:
        st.warning("🔒 Zyada ghalat koshishon ki wajah se block! Login zaroori hai.")
        st.stop()

    encrypted_text = st.text_area("Enter Encrypted Data:")  # Encrypted data input
    passkey = st.text_input("Enter Passkey:", type="password")  # Passkey input

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            hashed_passkey = hash_passkey(passkey)
            entry = st.session_state.stored_data.get(encrypted_text)  # Data dictionary se entry dhoondhna

            # Agar passkey sahi hai to decrypt karte hain
            if entry and entry["passkey"] == hashed_passkey:
                st.session_state.failed_attempts = 0
                decrypted = decrypt_data(encrypted_text)
                st.success(f"✅ Decrypted Data: {decrypted}")
            else:
                # Ghalat passkey par failed attempts badhate hain
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Ghalat passkey! Baqi koshishen: {attempts_left}")

                # Agar 3 failed attempts ho jaayein to block kar dete hain
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.warning("🔒 Zyada ghalat koshishon ki wajah se Login page par redirect ho rahe hain.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Dono fields bharna zaroori hai!")

# Login page (agar user block ho gaya ho)
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")

    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Demo ke liye static password
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Login successful! Ab dobara data decrypt kar sakte hain.")
            st.experimental_rerun()
        else:
            st.error("❌ Ghalat password!")
