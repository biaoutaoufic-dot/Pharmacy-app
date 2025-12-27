from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
import os
import logging
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'hackerai_demo_secret_key_for_flask')
DATABASE_NAME = os.environ.get('DB_NAME', 'pharmacy_app.db')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', "pharma2025")

# ---- LOGGING CONFIGURATION ----
handlers = [logging.StreamHandler()]

# Try to add file logging; fall back to stderr if it fails (for production environments)
try:
    handlers.append(logging.FileHandler('pharmacy_app.log'))
except Exception as e:
    logging.warning(f"Could not create pharmacy_app.log: {e}. Logging to stderr only.")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=handlers
)
logger = logging.getLogger(__name__)

# ---- SECURITY HEADERS ----
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    return response

# --- HELPER FUNCTIONS ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def is_logged_in():
    return session.get('logged_in') == True

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            logger.warning(f"Unauthorized access attempt to {request.path}")
            flash('Veuillez vous connecter.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---

# ---- HOME PAGE (VIEW CLASSIFICATIONS WITH SEARCH) ----
@app.route('/')
def index():
    conn = get_db_connection()
    search_term = request.args.get('search', '').strip()
    
    query = """
    SELECT 
        d.Name AS DiseaseName, 
        m.Name AS MedicationName, 
        t.Notes,
        m.ActiveIngredient,
        t.MapID
    FROM Diseases d
    JOIN TreatmentMap t ON d.DiseaseID = t.DiseaseID
    JOIN Medications m ON t.MedicationID = m.MedicationID
    """
    params = []
    if search_term:
        search_like = f'%{search_term}%'
        query += " WHERE d.Name LIKE ? OR m.Name LIKE ? OR m.ActiveIngredient LIKE ?"
        params = [search_like, search_like, search_like]
    query += " ORDER BY d.Name, m.Name;"

    classification_data = conn.execute(query, params).fetchall()
    conn.close()
    
    classified_sicknesses = {}
    for row in classification_data:
        disease = row['DiseaseName']
        medication_info = {
            'name': row['MedicationName'],
            'active_ing': row['ActiveIngredient'],
            'notes': row['Notes'],
            'map_id': row['MapID']
        }
        if disease not in classified_sicknesses:
            classified_sicknesses[disease] = []
        classified_sicknesses[disease].append(medication_info)

    return render_template('index.html', classified_sicknesses=classified_sicknesses, search_term=search_term)

# ---- LOGIN ----
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        if password == ADMIN_PASSWORD:
            session['logged_in'] = True
            flash('Connexion réussie !', 'success')
            return redirect(url_for('admin'))
        else:
            flash('Mot de passe incorrect.', 'error')
    return render_template('login.html')

# ---- PRIVACY POLICY ----
@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

# ---- TERMS OF SERVICE ----
@app.route('/terms')
def terms():
    return render_template('terms.html')

# ---- LOGOUT ----
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('login'))

# ---- ADMIN PANEL ----
@app.route('/admin')
@login_required
def admin():
    conn = get_db_connection()
    diseases = conn.execute('SELECT * FROM Diseases ORDER BY Name').fetchall()
    medications_list = conn.execute('SELECT * FROM Medications ORDER BY Name').fetchall()
    conn.close()
    return render_template('admin.html', diseases=diseases, medications_list=medications_list)

# ---- ADD DATA ----
@app.route('/admin/add', methods=('POST',))
@login_required
def add_data():
    conn = get_db_connection()
    form_type = request.form['form_type']
    try:
        if form_type == 'add_disease':
            name = request.form['name']
            existing = conn.execute('SELECT 1 FROM Diseases WHERE Name = ?', (name,)).fetchone()
            if existing:
                flash(f'La maladie "{name}" existe déjà.', 'error')
            else:
                description = request.form.get('description', '')
                conn.execute('INSERT INTO Diseases (Name, Description) VALUES (?, ?)', (name, description))
                flash('Maladie ajoutée avec succès !', 'success')

        elif form_type == 'add_medication':
            name = request.form['name']
            active_ingredient = request.form['active_ingredient']
            existing = conn.execute('SELECT 1 FROM Medications WHERE Name = ?', (name,)).fetchone()
            if existing:
                flash(f'Le médicament "{name}" existe déjà.', 'error')
            else:
                conn.execute('INSERT INTO Medications (Name, ActiveIngredient) VALUES (?, ?)', (name, active_ingredient))
                flash('Médicament ajouté avec succès !', 'success')

        elif form_type == 'map_treatment':
            disease_id = request.form['disease_id']
            medication_id = request.form['medication_id']
            notes = request.form['notes']
            existing = conn.execute('''
                SELECT 1 FROM TreatmentMap 
                WHERE DiseaseID = ? AND MedicationID = ?
            ''', (disease_id, medication_id)).fetchone()
            if existing:
                flash('Ce lien entre la maladie et le médicament existe déjà.', 'error')
            else:
                conn.execute('INSERT INTO TreatmentMap (DiseaseID, MedicationID, Notes) VALUES (?, ?, ?)', 
                             (disease_id, medication_id, notes))
                flash('Lien de classification créé !', 'success')
        conn.commit()
    except Exception as e:
        conn.rollback()
        flash(f'Erreur : {str(e)}', 'error')
    finally:
        conn.close()
    return redirect(url_for('admin'))

# ---- EDIT PAGE ----
@app.route('/admin/edit/<item_type>/<int:item_id>', methods=('GET',))
def edit_form(item_type, item_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    valid_types = ['Diseases', 'Medications', 'TreatmentMap']
    if item_type not in valid_types:
        flash('Type d\'élément non valide.', 'error')
        return redirect(url_for('admin'))
    conn = get_db_connection()
    item = conn.execute(f'SELECT * FROM {item_type} WHERE {item_type[:-1]}ID = ?', (item_id,)).fetchone()
    if not item:
        flash(f'{item_type[:-1]} non trouvé.', 'error')
        conn.close()
        return redirect(url_for('admin'))

    if item_type == 'TreatmentMap':
        item = conn.execute('''
            SELECT t.*, d.Name AS DiseaseName, m.Name AS MedicationName
            FROM TreatmentMap t
            JOIN Diseases d ON t.DiseaseID = d.DiseaseID
            JOIN Medications m ON t.MedicationID = m.MedicationID
            WHERE t.MapID = ?
        ''', (item_id,)).fetchone()
        all_diseases = conn.execute('SELECT DiseaseID as ID, Name FROM Diseases ORDER BY Name').fetchall()
        all_medications = conn.execute('SELECT MedicationID as ID, Name FROM Medications ORDER BY Name').fetchall()
        conn.close()
        return render_template('edit_mapping.html', item=item, all_diseases=all_diseases, all_medications=all_medications)
    else:
        conn.close()
        return render_template('edit_form.html', item_type=item_type, item=item)

# ---- SAVE EDITED DATA ----
@app.route('/admin/edit/<item_type>/<int:item_id>', methods=('POST',))
def edit_item(item_type, item_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    conn = get_db_connection()
    try:
        if item_type == 'Diseases':
            name = request.form['name']
            description = request.form['description']
            conn.execute('UPDATE Diseases SET Name = ?, Description = ? WHERE DiseaseID = ?', (name, description, item_id))
        elif item_type == 'Medications':
            name = request.form['name']
            active_ingredient = request.form['active_ingredient']
            conn.execute('UPDATE Medications SET Name = ?, ActiveIngredient = ? WHERE MedicationID = ?', (name, active_ingredient, item_id))
        elif item_type == 'TreatmentMap':
            disease_id = request.form['disease_id']
            medication_id = request.form['medication_id']
            notes = request.form['notes']
            existing_map = conn.execute('''
                SELECT * FROM TreatmentMap 
                WHERE DiseaseID = ? AND MedicationID = ? AND MapID != ?
            ''', (disease_id, medication_id, item_id)).fetchone()
            if existing_map:
                flash('Ce lien existe déjà entre cette maladie et ce médicament.', 'error')
                return redirect(url_for('edit_form', item_type=item_type, item_id=item_id))
            conn.execute('UPDATE TreatmentMap SET DiseaseID = ?, MedicationID = ?, Notes = ? WHERE MapID = ?', 
                         (disease_id, medication_id, notes, item_id))
        conn.commit()
        flash('Élément mis à jour avec succès !', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erreur lors de la mise à jour : {str(e)}', 'error')
    finally:
        conn.close()
    return redirect(url_for('admin'))

# ---- DELETE DATA ----
@app.route('/admin/delete/<item_type>/<int:item_id>', methods=('POST',))
def delete_item(item_type, item_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    valid_types = ['Diseases', 'Medications', 'TreatmentMap']
    if item_type not in valid_types:
        flash('Type d\'élément à supprimer non valide.', 'error')
        return redirect(url_for('admin'))
    conn = get_db_connection()
    try:
        if item_type == 'Diseases':
            conn.execute('DELETE FROM TreatmentMap WHERE DiseaseID = ?', (item_id,))
            conn.execute('DELETE FROM Diseases WHERE DiseaseID = ?', (item_id,))
        elif item_type == 'Medications':
            conn.execute('DELETE FROM TreatmentMap WHERE MedicationID = ?', (item_id,))
            conn.execute('DELETE FROM Medications WHERE MedicationID = ?', (item_id,))
        elif item_type == 'TreatmentMap':
            conn.execute('DELETE FROM TreatmentMap WHERE MapID = ?', (item_id,))
        conn.commit()
        flash(f'{item_type[:-1]} supprimé avec succès !', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erreur de suppression : {str(e)}', 'error')
    finally:
        conn.close()
    return redirect(url_for('admin'))

# --- PRODUCTION SETTINGS ---
@app.after_request
def add_security_headers(response):
    """Ajouter les headers de sécurité pour production"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response

if __name__ == '__main__':
    if not os.path.exists(DATABASE_NAME):
        print("Base de données absente. Exécutez 'python init_db.py' d'abord.")
        exit(1)
    
    # Configuration pour production et développement
    host = os.getenv('HOST', '127.0.0.1')
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.run(host=host, port=port, debug=debug)

# ---- ERROR HANDLERS ----
@app.errorhandler(404)
def page_not_found(error):
    logger.warning(f"404 error: {request.path}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {str(error)}")
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(error):
    logger.warning(f"403 error: {request.path}")
    return render_template('403.html'), 403

if __name__ == '__main__':

    # Read host/port/debug from environment so the server can be bound to the network
    # for access from other devices (phone) or for packaging.
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 8080))
    debug_env = os.environ.get('FLASK_DEBUG')
    debug = True if (debug_env is None or debug_env.lower() in ('1','true','yes')) else False

    logger.info(f"Starting Pharmacy App on {host}:{port}")
    app.run(debug=debug, host=host, port=port)
