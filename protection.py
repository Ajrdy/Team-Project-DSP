from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pymysql
import os
from flask import Flask, render_template
app = Flask(__name__)
# Connect to MySQL using pymysql
conn = pymysql.connect(
    host="127.0.0.1",
    user="root",
    password="W!f4vas2CX.TKLy",
    database="teamproject"
)

# Create a cursor object after connecting to the database
cursor = conn.cursor()
# Create the encrypted_person_data table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS encrypted_person_data (
        id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(50) NOT NULL,
        last_name VARCHAR(50) NOT NULL,
        encrypted_gender VARBINARY(255) NOT NULL,
        iv_gender VARBINARY(255) NOT NULL,
        tag_gender VARBINARY(255) NOT NULL,
        encrypted_age VARBINARY(255) NOT NULL,
        iv_age VARBINARY(255) NOT NULL,
        tag_age VARBINARY(255) NOT NULL,
        weight FLOAT NOT NULL,
        height FLOAT NOT NULL,
        health_history TEXT,
        UNIQUE KEY unique_encrypted_person_data (first_name, last_name)
    )
""")

# Function to derive a key from a password using PBKDF2
def derive_key(password):
    salt = b'some_random_salt'  # Change this to a secure random value
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key

def encrypt_data(data, key):
    # Generate a random IV
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    tag = encryptor.tag
    return ciphertext, iv, tag

# ...



def decrypt_data(ciphertext, iv, tag, key):
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data.decode()
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None

# Function to protect sensitive attributes and insert into the encrypted_person_data table
def protect_and_insert(first_name, last_name, gender, age, weight, height, health_history, password):
    # Derive a key from the password
    key = derive_key(password)

    # Encrypt sensitive attributes
    encrypted_gender, iv_gender, tag_gender = encrypt_data(gender, key)
    encrypted_age, iv_age, tag_age = encrypt_data(str(age), key)

    # Insert data into the encrypted_person_data table
    query = """
    INSERT INTO encrypted_person_data
    (first_name, last_name, encrypted_gender, iv_gender, tag_gender, encrypted_age, iv_age, tag_age, weight, height, health_history)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""
    values = (first_name, last_name, encrypted_gender, iv_gender, tag_gender, encrypted_age, iv_age, tag_age, weight, height, health_history)

    print("Query:", query)
    print("Values:", values)

    cursor.execute(query, values)

    conn.commit()

# Function to retrieve and decrypt data from the encrypted_person_data table
def retrieve_and_decrypt():
    cursor.execute("SELECT * FROM encrypted_person_data")
    data = cursor.fetchall()

    decrypted_data = []
    for row in data:
        key = derive_key(input("Enter password to decrypt data: "))  # Use a secure method to get the password
        decrypted_gender = decrypt_data(row[3], row[4], row[5], key)
        decrypted_age = decrypt_data(row[6], row[7], row[8], key)
        decrypted_data.append((row[0], row[1], decrypted_gender, decrypted_age, row[9], row[10], row[11]))

    return decrypted_data
@app.route('/')
def display_encrypted_person_data():
    # Retrieve encrypted person data from the database
    cursor.execute("SELECT * FROM encrypted_person_data")
    data = cursor.fetchall()

    # Close the connection
    conn.close()

    # Render the template with the retrieved data
    return render_template('display_encrypted_person_data.html', data=data)

if __name__ == '__main__':
    app.run(debug=True)
    # Insert data with protected sensitive attributes
    protect_and_insert(
        first_name="Meghan",
        last_name="Mckinney",
        gender="Male",
        age=58,
        weight=95.24,
        height=156.89,
        health_history='Chronic genitourinary conditions',
        password="kent"
    )

    # Retrieve and decrypt data
    decrypted_data = retrieve_and_decrypt()

    # Display the decrypted data or use it as needed
    for row in decrypted_data:
        print(f"ID: {row[0]}, First Name: {row[1]}, Decrypted Gender: {row[2]}, Decrypted Age: {row[3]}, Weight: {row[4]}, Height: {row[5]}, Health History: {row[6]}")

    # Close the connection
    conn.close()

