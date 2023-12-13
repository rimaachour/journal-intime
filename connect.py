import mysql.connector

# Connexion à la base de données MySQL
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",  
    database="intime",
    port=3306  
)

my_cursor = db.cursor()

# créer la table "users" 
create_table_query = '''
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
    )
'''

# créer la table "note" 
create_note_table_query = '''
    CREATE TABLE IF NOT EXISTS note (
        id INT AUTO_INCREMENT PRIMARY KEY,
        note TEXT,
         user_id INT ,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
    )
'''

my_cursor.execute(create_table_query)
my_cursor.execute(create_note_table_query)

# Fermeture de la connexion à la base de données
db.close()
print("Connexion créée avec succès !")
