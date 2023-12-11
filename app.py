from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from nacl import secret, utils
from nacl.secret import SecretBox
from nacl.encoding import Base64Encoder
import base64

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Connect to MySQL using pymysql
conn = pymysql.connect(
    host="127.0.0.1",
    user="root",
    password="W!f4vas2CX.TKLy",
    database="teamproject"
)

cursor = conn.cursor()

# Create the users table if not exists
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(256) NOT NULL,
        user_role VARCHAR(10) NOT NULL
    )
""")
conn.commit()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS encrypted_person_data (
        id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(50) NOT NULL,
        last_name VARCHAR(50) NOT NULL,
        encrypted_gender VARBINARY(255) NOT NULL,
        encrypted_age VARBINARY(255) NOT NULL,
        weight FLOAT NOT NULL,
        height FLOAT NOT NULL,
        health_history TEXT,
        UNIQUE KEY unique_encrypted_person_data (first_name, last_name, encrypted_gender, encrypted_age)
    )
""")
conn.commit()
# Generate a random key for encryption
encryption_key = utils.random(secret.SecretBox.KEY_SIZE)
encryption_box = secret.SecretBox(encryption_key)

# Example function to encrypt sensitive data before storing in the database
def encrypt_sensitive_data(data):
    if isinstance(data, str):
        encoded_data = data.encode()
    else:
        encoded_data = data
    nonce = utils.random(secret.SecretBox.NONCE_SIZE)
    encrypted_data = encryption_box.encrypt(encoded_data, nonce)
    return encrypted_data

# Example function to decrypt sensitive data when retrieving from the database
def decrypt_sensitive_data(encrypted_data):
    if isinstance(encrypted_data, bytes):
        decrypted_data = encryption_box.decrypt(encrypted_data).decode()
    elif isinstance(encrypted_data, int):
        # Handle integer input separately (assuming it's an age)
        decrypted_data = str(encrypted_data)
    else:
        raise ValueError("Unsupported data type for decryption")
    
    return decrypted_data


# Example usage for inserting data into the person_data table
def insert_person_data(first_name, last_name, gender, age, weight, height, health_history):
    # Encrypt sensitive data before storing in the database
    encrypted_gender = encrypt_sensitive_data(gender)
    encrypted_age = encrypt_sensitive_data(str(age))  # Ensure age is converted to string before encryption

    # Insert the encrypted data into the person_data table
    cursor.execute("""
        INSERT INTO person_data (first_name, last_name, gender, age, weight, height, health_history)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (first_name, last_name, encrypted_gender, encrypted_age, weight, height, health_history))
    conn.commit()

def create_user(username, password, user_role):
    # Hash the password
    hashed_password = generate_password_hash(password)

    # Insert the user into the table
    cursor.execute("""
        INSERT INTO users (username, password_hash, user_role)
        VALUES (%s, %s, %s)
    """, (username, hashed_password, user_role))
    conn.commit()

def authenticate_user(username, password):
    # Fetch the hashed password and user role for the given username
    cursor.execute("SELECT password_hash, user_role FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()

    if result:
        # Check if the provided password matches the stored hash
        return check_password_hash(result[0], password), result[1]

    return False, None  # Return a tuple with two values
def is_user_h():
    return 'user_role' in session and session['user_role'] == 'H'
def can_access_all_fields(user_role):
    return user_role == 'H'
def access_person_data():
    # Retrieve and display data from the person_data table
    cursor.execute("SELECT * FROM person_data")
    data = cursor.fetchall()
    return data
# Example function to decrypt sensitive data when retrieving from the database
def decrypt_sensitive_data(encrypted_data):
    box = SecretBox(encryption_key)
    decrypted_data = box.decrypt(encrypted_data, encoder=Base64Encoder)
    return decrypted_data.decode()

def encrypt_person_data_table():
    cursor.execute("SELECT * FROM encrypted_person_data")
    data = cursor.fetchall()

    for row in data:
        # Assuming columns 3 (gender) and 4 (age) are sensitive
        encrypted_gender = encrypt_sensitive_data(row[3])
        encrypted_age = encrypt_sensitive_data(str(row[4]))

        # Update the table with encrypted data
        cursor.execute("""
            UPDATE person_data
            SET gender = %s, age = %s
            WHERE id = %s
        """, (encrypted_gender, encrypted_age, row[0]))

    conn.commit()
def update_existing_records():
    cursor.execute("SELECT id, age FROM person_data")
    data = cursor.fetchall()

    for row in data:
        if isinstance(row[1], int):
            # If age is already an integer, no need to encrypt, just use it
            decrypted_age = row[1]
        else:
            # Encrypt sensitive data before storing in the database
            encrypted_age = encrypt_sensitive_data(str(row[1]))

            # Decrypt the age for processing in the application
            decrypted_age = int(decrypt_sensitive_data(encrypted_age))

        # Update the table with decrypted age
        cursor.execute("""
            UPDATE person_data
            SET age = %s
            WHERE id = %s
        """, (decrypted_age, row[0]))

    conn.commit()


def decrypt_person_data_table():
    cursor.execute("SELECT * FROM encrypted_person_data")
    data = cursor.fetchall()

    decrypted_data = []
    for row in data:
        decrypted_gender = decrypt_sensitive_data(row[3])
        decrypted_age = decrypt_sensitive_data(str(row[4]))

        decrypted_data.append((row[0], row[1], row[2], decrypted_gender, decrypted_age, row[5], row[6], row[7]))

    return decrypted_data


@app.route('/encrypt_person_data', methods=['GET'])
def encrypt_person_data():
    encrypt_person_data_table()
    return 'person_data table encrypted successfully'

@app.route('/decrypt_person_data', methods=['GET'])
def decrypt_person_data():
    decrypted_data = decrypt_person_data_table()
    # You can use the decrypted_data as needed, for example, pass it to a template for display
    return render_template('decrypted_data.html', data=decrypted_data)

@app.route('/display_encrypted_person_data', methods=['GET'])
def display_encrypted_person_data():
    # Fetch encrypted data from the person_data table
    cursor.execute("SELECT id, gender, age FROM encrypted_person_data")
    data = cursor.fetchall()

    # Display the encrypted data
    encrypted_data = [(row[0], row[1], row[2]) for row in data]
    return render_template('display_encrypted_person_data.html', encrypted_data=encrypted_data)

@app.route('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        authenticated, user_role = authenticate_user(username, password)

        if authenticated:
            session['username'] = username
            session['user_role'] = user_role
            return redirect(url_for('view_person_data'))

        return 'Login failed. Invalid username or password.'

    return render_template('login.html')

@app.route('/retrive_data')
def retrieve_person_data():
    # Retrieve the encrypted data from the person_data table
    cursor.execute("SELECT id, first_name, last_name, gender, age, weight, height, health_history FROM person_data")
    data = cursor.fetchall()

    # Decrypt and print the retrieved data
    decrypted_data = []
    for row in data:
        decrypted_gender = decrypt_sensitive_data(row[3])
        decrypted_age = int(decrypt_sensitive_data(str(row[4])))  # Convert to integer after decryption

        decrypted_data.append((row[0], row[1], row[2], decrypted_gender, decrypted_age, row[5], row[6], row[7]))
        print("ID", row[0])
        print("First Name:", row[1])
        print("Last Name:", row[2])
        print("Decrypted Gender:", decrypted_gender)
        print("Decrypted Age:", decrypted_age)
        print("Weight:", row[5])
        print("Height:", row[6])
        print("Health History:", row[7])
        print("\n")

    return render_template('retrieve_data.html', data=decrypted_data)
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_role = request.form['user_role']

        # Check if the username already exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        if result[0] > 0:
            return 'Registration failed. Username already exists.'

        create_user(username, password, user_role)
        return 'Registration successful. <a href="/login">Login</a>'

    return render_template('register.html')
@app.route('/person_data')
def view_person_data():
    if 'username' in session:
        # Fetch user role
        user_role = session.get('user_role', 'R')
        
        # Check if the user can access all fields
        access_all_fields = can_access_all_fields(user_role)

        # Fetch data from the person_data table
        if access_all_fields:
            cursor.execute("SELECT * FROM person_data")
        else:
            cursor.execute("SELECT id, gender, age, weight, height, health_history FROM person_data")

        data = cursor.fetchall()

        # Add links to encrypt, decrypt, and display encrypted data
        encrypt_link = url_for('encrypt_person_data')
        decrypt_link = url_for('decrypt_person_data')
        display_encrypted_link = url_for('display_encrypted_person_data')

        return render_template('view_person_data.html', data=data, access_all_fields=access_all_fields,
                                encrypt_link=encrypt_link, decrypt_link=decrypt_link,
                                display_encrypted_link=display_encrypted_link)

    return redirect(url_for('login'))


@app.route('/add_person_data', methods=['GET', 'POST'])
def add_person_data():
    if 'username' in session:
        # Check if the user has access to add data
        if can_access_all_fields(session.get('user_role', 'R')):
            if request.method == 'POST':
                # Extract data from the form
                first_name = request.form['first_name']
                last_name = request.form['last_name']
                gender = request.form['gender'] == '1'
                age = int(request.form['age'])
                weight = float(request.form['weight'])
                height = float(request.form['height'])
                health_history = request.form['health_history']

                # Insert data into the person_data table
                cursor.execute("""
                    INSERT INTO person_data (first_name, last_name, gender, age, weight, height, health_history)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (first_name, last_name, gender, age, weight, height, health_history))
                conn.commit()

                return 'Data added successfully.'

            return render_template('add_person_data.html')

        return 'Access denied. You do not have permission to add data.'

    return redirect(url_for('login'))
@app.route('/add_entry', methods=['GET', 'POST'])
def add_entry():
    if request.method == 'POST':
        if not is_user_h():
            return 'Access denied. Only users with role "H" can add new entries.'
        
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        gender = request.form['gender']
        age = request.form['age']
        weight = request.form['weight']
        height = request.form['height']
        health_history = request.form['health_history']

        # Encrypt sensitive data before storing in the database
        encrypted_gender = encrypt_sensitive_data(gender)
        encrypted_age = encrypt_sensitive_data(age)

        encrypted_gender_str = encrypted_gender.decode()
        encrypted_age_str = encrypted_age.decode()

        cursor.execute("""
                INSERT INTO person_data (first_name, last_name, gender, age, weight, height, health_history)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (first_name, last_name, encrypted_gender_str, encrypted_age_str, weight, height, health_history))
        conn.commit()

        # Redirect to the view_person_data route after adding the entry
        return redirect(url_for('view_person_data'))

    return render_template('add_entry.html')

def calculate_data_hash(data):
    """Calculate a hash for the given data using Werkzeug."""
    return generate_password_hash(str(data))

@app.route('/query_data')
def query_data():
    # Check user authentication and authorization
    if 'username' not in session or 'user_role' not in session:
        return redirect(url_for('login'))

    user_role = session['user_role']

    # Simulate querying data
    cursor.execute("SELECT first_name, last_name, gender, age, weight, height, health_history FROM person_data")
    result = [user for user in cursor.fetchall()]

    # Calculate checksums for each row
    checksums = [calculate_data_hash(user) for user in result]

    # Send checksums to the client
    if user_role == 'H':
        return render_template('query_data.html', result=result, checksums=checksums, show_passwords=True)
    else:
        return render_template('query_data.html', result=result, checksums=checksums, show_passwords=False)

if __name__ == '__main__':
    app.run(debug=True)

