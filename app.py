from flask import Flask, render_template, request, redirect, session,jsonify
import mysql.connector
from bcrypt import hashpw, gensalt, checkpw
from flask_cors import CORS  
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
CORS(app)

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",  
    database="intime"
)
def encrypt_caesar(text, key):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift = key % 26  
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

 
# Display the main page
@app.route('/')
def home():
    return render_template('index.html')

# Handle user login
@app.route('/login', methods=['POST'])
def login():
    content_type = request.headers.get('Content-Type')

    if content_type == 'application/json':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
    elif content_type == 'application/x-www-form-urlencoded':
        email = request.form.get('email')
        password = request.form.get('password')
    else:
        return jsonify({'error': 'Unsupported content type'}), 400

    my_cursor = db.cursor()
    select_query = '''
        SELECT id, password FROM users WHERE email = %s
    '''
    my_cursor.execute(select_query, (email,))
    user = my_cursor.fetchone()

    if user and checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
        session['user_id'] = user[0]  # Store user's ID in the session
        return redirect('/journal')  # Redirect to the journal page after successful login
    else:
        return jsonify({'login': False, 'message': 'Login failed'})  # Authentication failed

    if credentials_are_valid(request.form['username'], request.form['password']):
        session['user_id'] = get_user_id(request.form['username'])
        return redirect(url_for('dashboard'))
    else:
        return 'Identifiants invalides', 401

@app.route('/sign-up', methods=['POST'])
def sign_up():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    hashed_password = hashpw(password.encode('utf-8'), gensalt())

    try:
        cursor = db.cursor()
        insert_query = '''
            INSERT INTO users (username, email, password)
            VALUES (%s, %s, %s)
        '''
        cursor.execute(insert_query, (username, email, hashed_password))
        db.commit()
        print("Data inserted successfully")
    except Exception as e:
        print("Error inserting data:", e)
        db.rollback()  
    finally:
        cursor.close()

    session['username'] = email  
    return redirect('/journal')  
@app.route('/journal')
def journal():
    if 'username' in session:
        return render_template('journal.html')
    else:
        return redirect('/')  



def decrypt_caesar(encrypted_text, key):
    decrypted_text = ""
    for char in encrypted_text:
        if char.isalpha():
            shift = key % 26
            shifted = ord(char) - shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            decrypted_text += chr(shifted)
        else:
            decrypted_text += char
    return decrypted_text

@app.route('/add-note', methods=['POST'])
def add_note():
    if 'username' in session:
        note_content = request.form.get('note_content')
        user_id = session['user_id'] 
        try:
           
            secret_key = 3  # Caesar cipher key
            decrypted_note = decrypt_caesar(note_content, secret_key)

            cursor = db.cursor()
            insert_note_query = '''
                INSERT INTO note (note, user_id) VALUES (%s, %s)  # Ajouter user_id dans l'insertion de la note
            '''
            cursor.execute(insert_note_query, (decrypted_note, user_id))
            db.commit()

           
            inserted_note_id = cursor.lastrowid

            print("Note inserted successfully")

            # Return the ID of the inserted note as a response
            return str(inserted_note_id), 200
        except Exception as e:
            print("Error inserting note:", e)
            db.rollback()
            return "Error while saving the note", 500
        finally:
            cursor.close()
    else:
        return redirect('/')


    
@app.route('/delete-note/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    try:
        if 'username' in session:
            delete_note_from_db(note_id)
            return "Note supprimée avec succès", 200
        else:
            return "Non autorisé à supprimer la note", 401
    except Exception as e:
        print("Erreur lors de la suppression de la note :", e)
        return "Erreur lors de la suppression de la note", 500

# Fonction de suppression dans la base de données
def delete_note_from_db(note_id):
    try:
        cursor = db.cursor()
        delete_note_query = '''
            DELETE FROM note WHERE id = %s
        '''
        cursor.execute(delete_note_query, (note_id,))
        db.commit()
        print("Note deleted successfully from the database")
    except Exception as e:
        print("Error deleting note from the database:", e)
        db.rollback()  # Rollback changes in case of an error
    finally:
        cursor.close()
@app.route('/update-note/<int:note_id>', methods=['POST'])
def update_note(note_id):
    if 'username' in session:
        new_content = request.form.get('new_content')

        try:
            cursor = db.cursor()
            update_note_query = '''
                UPDATE note SET note = %s WHERE id = %s
            '''
            cursor.execute(update_note_query, (new_content, note_id))
            db.commit()

            print("Note updated successfully")
            return "Note mise à jour avec succès", 200
        except Exception as e:
            print("Error updating note:", e)
            db.rollback()
            return "Erreur lors de la mise à jour de la note", 500
        finally:
            cursor.close()
    else:
        return redirect('/')

@app.route('/decrypt-note', methods=['POST'])
def decrypt_note():
    if 'username' in session:
        try:
            data = request.get_json()
            encrypted_content = data.get('encrypted_content')

            secret_key = 3  # Caesar cipher key
            decrypted_note = decrypt_caesar(encrypted_content, secret_key)

            return decrypted_note, 200
        except Exception as e:
            print("Error decrypting note:", e)
            return "Error decrypting the note", 500
    else:
        return redirect('/')

@app.route('/get-notes', methods=['POST'])
def get_notes():
 if 'user_id' in session:

    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        cursor = db.cursor()
        select_query = '''
            SELECT id, password FROM users WHERE email = %s
        '''
        cursor.execute(select_query, (email,))
        user = cursor.fetchone()

        if user and checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            session['user_id'] = user[0] 

            select_notes_query = '''
                SELECT note FROM note WHERE user_id = %s
            '''
            cursor.execute(select_notes_query, (user[0],))
            notes = cursor.fetchall()

            note_list = [note[0] for note in notes]

            return jsonify(note_list), 200
        else:
            return jsonify({'message': 'Invalid credentials'}), 401

    except Exception as e:
        print("Error fetching notes:", e)
        return "Error fetching notes", 500
    finally:
        cursor.close()


    

    
if __name__ == '__main__':
    app.run(debug=True)
