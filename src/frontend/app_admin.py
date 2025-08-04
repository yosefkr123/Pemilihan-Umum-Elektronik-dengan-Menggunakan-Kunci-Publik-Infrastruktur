from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash
import requests
import logging
import os
from datetime import datetime
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.secret_key = 'evoting-admin-secret-123'
app.static_folder = 'static'
app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'candidate_photos')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Server URLs
AUTH_SERVER = "http://localhost:8081"
VOTING_SERVER = "http://localhost:8082"
TABULASI_SERVER = "http://localhost:8083"
REQUEST_TIMEOUT = 5

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_data' not in session or session['admin_data'].get('username') != 'admin':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
@admin_required
def dashboard():
    try:
        # Get stats with proper defaults
        stats_response = requests.post(
            AUTH_SERVER,
            json={"endpoint": "/get_voting_stats"},
            timeout=5
        )
        
        # Initialize with default values
        stats = {
            'total_voters': 0,
            'verified_voters': 0,
            'total_votes': 0,
            'total_candidates': 0
        }
        
        # Update with actual values if available
        if stats_response.status_code == 200:
            stats.update(stats_response.json().get('stats', {}))
        
        # Get election time
        election_time_response = requests.post(
            AUTH_SERVER,
            json={"endpoint": "/get_election_time"},
            timeout=5
        )
        election_time = election_time_response.json() if election_time_response.status_code == 200 else {}
        
        # Process election time format
        if election_time and election_time.get('start_time'):
            try:
                election_time['start_time'] = election_time['start_time'].replace('T', ' ')
            except Exception as e:
                logger.error(f"Error processing start_time: {str(e)}")
                election_time['start_time'] = ""
        
        if election_time and election_time.get('end_time'):
            try:
                election_time['end_time'] = election_time['end_time'].replace('T', ' ')
            except Exception as e:
                logger.error(f"Error processing end_time: {str(e)}")
                election_time['end_time'] = ""

        # Get encrypted votes count
        encrypted_votes = 0
        try:
            encrypted_response = requests.post(
                VOTING_SERVER,
                json={"endpoint": "/get_stats"},
                timeout=5
            )
            if encrypted_response.status_code == 200:
                encrypted_votes = encrypted_response.json().get('total_encrypted_votes', 0)
        except Exception as e:
            logger.error(f"Error getting encrypted votes: {str(e)}")

        # Get election results from TabulasiServer
        results = {}
        try:
            results_response = requests.post(
                TABULASI_SERVER,
                json={"endpoint": "/get_tabulasi"},
                timeout=5
            )
            if results_response.status_code == 200:
                results = results_response.json()
        except Exception as e:
            logger.error(f"Error getting election results: {str(e)}")

        return render_template('admin/dashboard.html',
                            stats=stats,
                            election_time=election_time,
                            encrypted_votes=encrypted_votes,
                            results=results,
                            datetime=datetime)
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return render_template('admin/dashboard.html',
                            stats={
                                'total_voters': 0,
                                'verified_voters': 0,
                                'total_votes': 0,
                                'total_candidates': 0
                            },
                            election_time={},
                            encrypted_votes=0,
                            results={},
                            datetime=datetime)
            
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        try:
            data = {
                "endpoint": "/login_officer",
                "username": request.form['username'],
                "password": request.form['password']
            }
            
            response = requests.post(
                AUTH_SERVER,
                json=data,
                headers={'Content-Type': 'application/json'},
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success' and result['officer_data']['username'] == 'admin':
                    session['admin_data'] = result['officer_data']
                    return redirect(url_for('dashboard'))
                else:
                    error = result.get('message', 'Login gagal')
            else:
                error = f"Server error: {response.status_code}"
                
        except requests.exceptions.RequestException as e:
            error = f"Gagal terhubung ke server: {str(e)}"
        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            logger.exception("Login error")
    
    return render_template('admin/login.html', error=error)

@app.route('/officers')
@admin_required
def list_officers():
    try:
        response = requests.post(
            AUTH_SERVER,
            json={"endpoint": "/list_officers"},
            headers={'Content-Type': 'application/json'},
            timeout=REQUEST_TIMEOUT
        )
        officers = response.json().get('officers', []) if response.status_code == 200 else []
    except Exception as e:
        officers = []
        logger.error(f"Error getting officers: {str(e)}")
    
    return render_template('admin/officers.html', officers=officers)

@app.route('/officers/add', methods=['GET', 'POST'])
@admin_required
def add_officer():
    error = None
    success = None
    
    if request.method == 'POST':
        try:
            data = {
                "endpoint": "/add_officer",
                "username": request.form['username'],
                "password": request.form['password'],
                "nama": request.form['nama'],
                "created_by": session['admin_data']['officer_id']
            }
            
            response = requests.post(
                AUTH_SERVER,
                json=data,
                headers={'Content-Type': 'application/json'},
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    success = "Petugas berhasil ditambahkan"
                    return redirect(url_for('list_officers'))
                else:
                    error = result.get('message', 'Gagal menambahkan petugas')
            else:
                error = f"Server error: {response.status_code}"
                
        except requests.exceptions.RequestException as e:
            error = f"Gagal terhubung ke server: {str(e)}"
        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            logger.exception("Add officer error")
    
    return render_template('admin/add_officer.html', error=error, success=success)

@app.route('/officers/edit/<officer_id>', methods=['GET', 'POST'])
@admin_required
def edit_officer(officer_id):
    error = None
    success = None
    officer = None
    
    if request.method == 'POST':
        try:
            data = {
                "endpoint": "/update_officer",
                "officer_id": officer_id,
                "username": request.form['username'],
                "nama": request.form['nama'],
                "password": request.form.get('password')
            }
            
            response = requests.post(
                AUTH_SERVER,
                json=data,
                headers={'Content-Type': 'application/json'},
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    success = "Petugas berhasil diperbarui"
                    return redirect(url_for('list_officers'))
                else:
                    error = result.get('message', 'Gagal memperbarui petugas')
            else:
                error = f"Server error: {response.status_code}"
                
        except requests.exceptions.RequestException as e:
            error = f"Gagal terhubung ke server: {str(e)}"
        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            logger.exception("Edit officer error")
    else:
        try:
            response = requests.post(
                AUTH_SERVER,
                json={"endpoint": "/get_officer", "officer_id": officer_id},
                headers={'Content-Type': 'application/json'},
                timeout=REQUEST_TIMEOUT
            )
            if response.status_code == 200:
                officer = response.json().get('officer')
                if not officer:
                    return redirect(url_for('list_officers'))
            else:
                return redirect(url_for('list_officers'))
        except Exception as e:
            logger.error(f"Error getting officer: {str(e)}")
            return redirect(url_for('list_officers'))
    
    return render_template('admin/edit_officer.html', officer=officer, error=error, success=success)

@app.route('/officers/delete/<officer_id>', methods=['POST'])
@admin_required
def delete_officer(officer_id):
    try:
        response = requests.post(
            AUTH_SERVER,
            json={
                "endpoint": "/delete_officer",
                "officer_id": officer_id
            },
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                return jsonify({"status": "success"})
        
        return jsonify({
            "status": "error",
            "message": response.json().get('message', 'Failed to delete officer')
        }), 400
        
    except Exception as e:
        logger.error(f"Error deleting officer: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/candidates')
@admin_required
def list_candidates():
    try:
        response = requests.post(
            AUTH_SERVER,
            json={"endpoint": "/list_candidates"},
            headers={'Content-Type': 'application/json'},
            timeout=REQUEST_TIMEOUT
        )
        candidates = response.json().get('candidates', []) if response.status_code == 200 else []
    except Exception as e:
        candidates = []
        logger.error(f"Error getting candidates: {str(e)}")
    
    return render_template('admin/candidates.html', candidates=candidates)

@app.route('/add_candidate', methods=['GET', 'POST'])
@admin_required
def add_candidate():
    error = None
    if request.method == 'POST':
        try:
            # Validate form data
            if not all(k in request.form for k in ['nama', 'partai', 'nomor_urut']):
                raise ValueError("Mohon isi semua field yang diperlukan")
            
            # Handle file upload
            photo_url = None
            if 'photo' in request.files:
                file = request.files['photo']
                if file.filename != '':
                    if not allowed_file(file.filename):
                        raise ValueError("Format file tidak didukung. Gunakan JPG, PNG")
                    
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    photo_url = filename

            data = {
                "endpoint": "/add_candidate",
                "nama": request.form['nama'],
                "partai": request.form['partai'],
                "nomor_urut": int(request.form['nomor_urut']),
                "photo_url": photo_url,
                "created_by": session['admin_data']['officer_id']
            }

            response = requests.post(
                AUTH_SERVER,
                json=data,
                headers={'Content-Type': 'application/json'},
                timeout=10  # Increased timeout
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    flash('Kandidat berhasil ditambahkan', 'success')
                    return redirect(url_for('list_candidates'))
                error = result.get('message', 'Gagal menambahkan kandidat')
            else:
                error = f"Server error: {response.status_code}"

        except requests.exceptions.RequestException as e:
            error = f"Gagal terhubung ke server: {str(e)}"
        except ValueError as e:
            error = str(e)
        except Exception as e:
            error = f"Terjadi kesalahan: {str(e)}"
            logger.exception("Error adding candidate")
        
        # Clean up file if error occurred
        if error and photo_url and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], photo_url)):
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo_url))

    return render_template('admin/add_candidate.html', error=error)

@app.route('/candidates/edit/<candidate_id>', methods=['GET', 'POST'])
@admin_required
def edit_candidate(candidate_id):
    error = None
    success = None
    candidate = None
    
    if request.method == 'POST':
        try:
            # Handle file upload
            photo_url = None
            if 'photo' in request.files:
                file = request.files['photo']
                if file.filename != '' and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    photo_url = filename
            
            data = {
                "endpoint": "/update_candidate",
                "candidate_id": candidate_id,
                "nama": request.form['nama'],
                "partai": request.form['partai'],
                "nomor_urut": int(request.form['nomor_urut']),
                "photo_url": photo_url
            }
            
            response = requests.post(
                AUTH_SERVER,
                json=data,
                headers={'Content-Type': 'application/json'},
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    success = "Kandidat berhasil diperbarui"
                    return redirect(url_for('list_candidates'))
                else:
                    error = result.get('message', 'Gagal memperbarui kandidat')
                    if photo_url:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo_url))
            else:
                error = f"Server error: {response.status_code}"
                if photo_url:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo_url))
                
        except requests.exceptions.RequestException as e:
            error = f"Gagal terhubung ke server: {str(e)}"
        except ValueError as e:
            error = str(e)
        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            logger.exception("Edit candidate error")
    else:
        try:
            response = requests.post(
                AUTH_SERVER,
                json={"endpoint": "/get_candidate", "candidate_id": candidate_id},
                headers={'Content-Type': 'application/json'},
                timeout=REQUEST_TIMEOUT
            )
            if response.status_code == 200:
                candidate = response.json().get('candidate')
                if not candidate:
                    return redirect(url_for('list_candidates'))
            else:
                return redirect(url_for('list_candidates'))
        except Exception as e:
            logger.error(f"Error getting candidate: {str(e)}")
            return redirect(url_for('list_candidates'))
    
    return render_template('admin/edit_candidate.html', candidate=candidate, error=error, success=success)

@app.route('/candidates/delete/<candidate_id>', methods=['POST'])
@admin_required
def delete_candidate(candidate_id):
    try:
        response = requests.post(
            AUTH_SERVER,
            json={"endpoint": "/delete_candidate", "candidate_id": candidate_id},
            headers={'Content-Type': 'application/json'},
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                return jsonify({"status": "success"})
        
        return jsonify({"status": "error", "message": "Failed to delete candidate"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/voters')
@admin_required
def list_voters():
    try:
        response = requests.post(
            AUTH_SERVER,
            json={"endpoint": "/list_voters"},
            headers={'Content-Type': 'application/json'},
            timeout=REQUEST_TIMEOUT
        )
        voters = response.json().get('voters', []) if response.status_code == 200 else []
    except Exception as e:
        voters = []
        logger.error(f"Error getting voters: {str(e)}")
    
    return render_template('admin/voters.html', voters=voters)

@app.route('/get_voter_details/<voter_id>')
@admin_required
def get_voter_details(voter_id):
    try:
        response = requests.post(
            AUTH_SERVER,
            json={
                "endpoint": "/get_voter_details",
                "voter_id": voter_id
            },
            headers={'Content-Type': 'application/json'},
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to get voter details"
            }), 400
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500
    
@app.route('/election_time', methods=['GET', 'POST'])
@admin_required
def election_time():
    error = None
    success = None
    current_settings = None
    
    # Get current settings
    try:
        response = requests.post(
            AUTH_SERVER,
            json={"endpoint": "/get_election_time"},
            headers={'Content-Type': 'application/json'},
            timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            current_settings = response.json()
            # Convert ISO format to datetime for form display
            if current_settings.get('start_time'):
                try:
                    start_time = datetime.fromisoformat(current_settings['start_time'].replace('Z', '+00:00'))
                    current_settings['start_time'] = start_time.strftime('%Y-%m-%dT%H:%M')
                except ValueError:
                    current_settings['start_time'] = ""
            
            if current_settings.get('end_time'):
                try:
                    end_time = datetime.fromisoformat(current_settings['end_time'].replace('Z', '+00:00'))
                    current_settings['end_time'] = end_time.strftime('%Y-%m-%dT%H:%M')
                except ValueError:
                    current_settings['end_time'] = ""
    except Exception as e:
        error = f"Gagal mendapatkan pengaturan waktu: {str(e)}"
    
    if request.method == 'POST':
        try:
            # Validate time inputs
            start_time = request.form['start_time']
            end_time = request.form['end_time']
            
            if not start_time or not end_time:
                raise ValueError("Waktu mulai dan selesai harus diisi")
            
            # Convert to ISO format for backend (replace T with space for SQLite)
            start_iso = datetime.strptime(start_time, '%Y-%m-%dT%H:%M').strftime('%Y-%m-%d %H:%M:%S.000')
            end_iso = datetime.strptime(end_time, '%Y-%m-%dT%H:%M').strftime('%Y-%m-%d %H:%M:%S.000')
            
            data = {
                "endpoint": "/set_election_time",
                "start_time": start_iso,
                "end_time": end_iso,
                "officer_id": session['admin_data']['officer_id']
            }
            
            response = requests.post(
                AUTH_SERVER,
                json=data,
                headers={'Content-Type': 'application/json'},
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    flash('Waktu pemilihan berhasil diperbarui', 'success')
                    return redirect(url_for('election_time'))
                else:
                    error = result.get('message', 'Gagal memperbarui waktu pemilihan')
            else:
                error = f"Server error: {response.status_code}"
                
        except ValueError as e:
            error = "Format waktu tidak valid. Gunakan format YYYY-MM-DD HH:MM"
        except requests.exceptions.RequestException as e:
            error = f"Gagal terhubung ke server: {str(e)}"
        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            logger.exception("Election time error")
    
    return render_template('admin/election_time.html', 
                         error=error, 
                         success=success,
                         current_settings=current_settings)

@app.route('/statistics')
@admin_required
def statistics():
    try:
        # Get all data from TabulasiServer
        response = requests.post(
            TABULASI_SERVER,
            json={"endpoint": "/get_tabulasi"},
            headers={'Content-Type': 'application/json'},
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Calculate participation rate properly
            total_voters = data.get('total_voters', 0)
            total_votes = data.get('total_votes_cast', 0)
            participation_rate = 0
            if total_voters > 0:
                participation_rate = round((total_votes / total_voters) * 100, 2)

            # Process the data for the template
            stats = {
                'total_voters': total_voters,
                'verified_voters': total_voters,  # Assuming all voters are verified
                'total_votes': total_votes,
                'total_candidates': len(data.get('candidates', [])),
                'participation_rate': participation_rate
            }
            
            # Process election time
            election_time = data.get('election_time', {})
            if election_time:
                # Convert timestamps to readable format
                try:
                    if 'start_time' in election_time:
                        election_time['start_time'] = election_time['start_time'].replace('T', ' ')
                    if 'end_time' in election_time:
                        election_time['end_time'] = election_time['end_time'].replace('T', ' ')
                except Exception as e:
                    logger.error(f"Error processing election time: {str(e)}")
            
            return render_template('admin/statistics.html', 
                                stats=stats,
                                results=data,
                                election_time=election_time,
                                datetime=datetime)
        
    except Exception as e:
        logger.error(f"Error getting statistics: {str(e)}")
    
    # Fallback if error occurs
    return render_template('admin/statistics.html', 
                         stats={
                             'total_voters': 0,
                             'verified_voters': 0,
                             'total_votes': 0,
                             'total_candidates': 0,
                             'participation_rate': 0
                         },
                         results={},
                         election_time={},
                         datetime=datetime)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(port=5002, debug=True)