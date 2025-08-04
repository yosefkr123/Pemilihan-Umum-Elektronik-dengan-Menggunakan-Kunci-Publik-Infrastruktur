from flask import Flask, render_template, request, session, redirect, url_for
import requests
import logging
from functools import wraps
from flask import flash, jsonify
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'evoting-officer-secret-123'
app.static_folder = 'static'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Server URLs
AUTH_SERVER = "http://localhost:8081"
TABULASI_SERVER = "http://localhost:8083"

# Timeout for requests in seconds
REQUEST_TIMEOUT = 10

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'officer_data' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def make_server_request(endpoint, data=None):
    try:
        response = requests.post(
            AUTH_SERVER,
            json={"endpoint": endpoint, **(data or {})},
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code == 200:
            return response.json()
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Connection error: {str(e)}")
        return None

@app.route('/')
@login_required
def dashboard():
    # Get voting stats
    stats = {}
    officer = None  # Inisialisasi variabel officer
    election_time = None

    try:
        # Get stats from auth server
        response = requests.post(
            AUTH_SERVER,
            json={"endpoint": "/get_voting_stats"},
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                stats = result.get('stats', {})
                # Extract election time info
                if stats.get('start_time') and stats.get('end_time'):
                    election_time = {
                        'start_time': stats['start_time'],
                        'end_time': stats['end_time'],
                        'formatted_start_time': stats.get('formatted_start_time', ''),
                        'formatted_end_time': stats.get('formatted_end_time', ''),
                        'election_status': stats.get('election_status', 'not_set'),
                        'time_remaining': stats.get('time_remaining', ''),
                        'time_until_start': stats.get('time_until_start', '')
                    }

        # Get special officer data if current officer is special
        if session.get('officer_data', {}).get('is_special', False):
            response = requests.post(
                AUTH_SERVER,
                json={"endpoint": "/get_special_officer"},
                timeout=REQUEST_TIMEOUT,
                headers={'Content-Type': 'application/json'}
            )
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    officer = result.get('officer')

    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
    
    return render_template('officer/dashboard.html', 
                         stats=stats, 
                         officer=officer,
                         election_time=election_time)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error_msg = None
    if request.method == 'POST':
        data = {
            "endpoint": "/login_officer",
            "username": request.form['username'],
            "password": request.form['password']
        }
        
        try:
            response = requests.post(
                AUTH_SERVER,
                json=data,
                timeout=REQUEST_TIMEOUT,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    session['officer_data'] = result['officer_data']
                    # Explicitly set is_special flag
                    session['officer_data']['is_special'] = result.get('is_special', False)
                    logger.info(f"Officer {result['officer_data']['username']} logged in successfully")
                    return redirect(url_for('dashboard'))
                else:
                    error_msg = result.get('message', 'Login gagal. Periksa username dan password.')
                    logger.warning(f"Failed login attempt for username: {data['username']}")
            else:
                error_msg = f"Server error: {response.status_code}"
                logger.error(f"Auth server returned status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            error_msg = f"Gagal terhubung ke server: {str(e)}"
            logger.error(f"Connection error to auth server: {str(e)}")
    
    return render_template('officer/login.html', error=error_msg)

@app.route('/list_voters')
@login_required
def list_voters():
    search_term = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    
    voters = []
    try:
        data = {
            "endpoint": "/list_voters",
            "search": search_term,
            "status": status_filter
        }
        
        response = requests.post(
            AUTH_SERVER,
            json=data,
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = response.json()
            if result and result.get('status') == 'success':
                voters = result.get('voters', [])
            else:
                flash('Gagal memuat data pemilih', 'error')
        else:
            flash('Gagal memuat data pemilih', 'error')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    # Handle AJAX requests
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'voters': voters,
            'search_term': search_term,
            'status_filter': status_filter
        })
    
    return render_template('officer/list_voters.html', 
                         voters=voters,
                         search_term=search_term,
                         status_filter=status_filter)

@app.route('/decrypt_votes', methods=['GET', 'POST'])
@login_required
def decrypt_votes():
    if not session.get('officer_data', {}).get('is_special', False):
        flash('Akses ditolak: Hanya officer khusus yang bisa mengakses fitur ini', 'error')
        return redirect(url_for('dashboard'))

    error_msg = None
    results = None
    officer = None

    # Get officer key info
    try:
        response = requests.post(
            AUTH_SERVER,
            json={"endpoint": "/get_special_officer"},
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                officer = result.get('officer')
    except Exception as e:
        logger.error(f"Error getting officer info: {str(e)}")

    if request.method == 'POST':
        try:
            if not request.form.get('private_key'):
                error_msg = "Private key harus diisi"
            else:
                data = {
                    "endpoint": "/decrypt_votes",
                    "officer_id": session['officer_data']['officer_id'],
                    "private_key": request.form['private_key']
                }

                response = requests.post(
                    AUTH_SERVER,
                    json=data,
                    timeout=60,
                    headers={'Content-Type': 'application/json'}
                )

                if response.status_code == 200:
                    result = response.json()
                    if result.get('status') == 'success':
                        # Process votes and candidates
                        votes = result.get('votes', [])
                        candidates = {c['candidate_id']: c for c in result.get('candidates', [])}
                        
                        # Initialize vote count for all candidates
                        for candidate in candidates.values():
                            candidate['vote_count'] = 0
                        
                        valid_votes = 0
                        invalid_votes = 0
                        processed_votes = []
                        
                        for vote in votes:
                            vote_data = {
                                'vote_id': vote.get('vote_id', 'UNKNOWN'),
                                'status': 'Invalid',  # Default status
                                'message': 'Belum diproses'
                            }
                            
                            try:
                                if vote.get('status') == 'valid' and 'candidate_id' in vote:
                                    candidate_id = vote['candidate_id']
                                    if candidate_id in candidates:
                                        valid_votes += 1
                                        candidates[candidate_id]['vote_count'] += 1
                                        
                                        vote_data.update({
                                            'status': 'Valid',
                                            'candidate_id': candidate_id,
                                            'candidate_name': candidates[candidate_id].get('nama'),
                                            'candidate_party': candidates[candidate_id].get('partai'),
                                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        })
                                    else:
                                        invalid_votes += 1
                                        vote_data['message'] = 'Kandidat tidak valid'
                                else:
                                    invalid_votes += 1
                                    vote_data['message'] = vote.get('message', 'Dekripsi gagal')
                                    
                            except Exception as e:
                                invalid_votes += 1
                                vote_data['message'] = f"Error processing: {str(e)}"
                            
                            processed_votes.append(vote_data)

                        results = {
                            'valid_votes': valid_votes,
                            'invalid_votes': invalid_votes,
                            'total_votes': valid_votes + invalid_votes,
                            'votes': processed_votes,
                            'candidates': list(candidates.values())
                        }
                        
                        flash('Dekripsi suara berhasil dilakukan!', 'success')
                    else:
                        error_msg = result.get('message', 'Gagal mendekripsi suara')
                else:
                    error_msg = f"Error server: {response.status_code}"
        except Exception as e:
            error_msg = f"Terjadi kesalahan: {str(e)}"
            logger.error(f"Error decrypting votes: {str(e)}")

    return render_template(
        'officer/decrypt_votes.html',
        officer=officer,
        results=results,
        error=error_msg
    )

@app.route('/verify_voter_action', methods=['POST'])
@login_required
def verify_voter_action():
    try:
        voter_id = request.form.get('voter_id')
        action = request.form.get('action')
        
        if not voter_id or not action:
            flash('Data tidak lengkap', 'error')
            return redirect(url_for('list_voters'))

        data = {
            "endpoint": "/verify_voter",
            "voter_id": voter_id,
            "is_verified": action == 'approve',
            "officer_id": session['officer_data']['officer_id']
        }
        
        response = requests.post(
            AUTH_SERVER,
            json=data,
            timeout=10,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code != 200:
            flash('Gagal memverifikasi pemilih', 'error')
            return redirect(url_for('view_voter_details', voter_id=voter_id))
            
        result = response.json()
        if result.get('status') == 'success':
            flash('Status verifikasi berhasil diperbarui', 'success')
            return redirect(url_for('view_voter_details', voter_id=voter_id))
        else:
            flash(result.get('message', 'Gagal memverifikasi pemilih'), 'error')
            return redirect(url_for('view_voter_details', voter_id=voter_id))
            
    except Exception as e:
        logger.error(f"Error in verify_voter_action: {str(e)}")
        flash('Terjadi kesalahan sistem', 'error')
        return redirect(url_for('list_voters'))
            
@app.route('/view_voter_details/<voter_id>')
@login_required
def view_voter_details(voter_id):
    try:
        response = requests.post(
            AUTH_SERVER,
            json={
                "endpoint": "/get_voter_details",
                "voter_id": voter_id
            },
            timeout=10,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                return render_template('officer/voter_details.html', voter=result.get('voter'))
        
        flash('Gagal memuat detail pemilih', 'error')
    except Exception as e:
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
    
    return redirect(url_for('list_voters'))

@app.route('/edit_voter/<voter_id>', methods=['GET', 'POST'])
@login_required
def edit_voter(voter_id):
    # Get voter details
    voter = None
    try:
        response = requests.post(
            AUTH_SERVER,
            json={
                "endpoint": "/get_voter_details",
                "voter_id": voter_id
            },
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                voter = result.get('voter')
            else:
                flash('Gagal memuat data pemilih: ' + result.get('message', 'Unknown error'), 'error')
                return redirect(url_for('list_voters'))
    except Exception as e:
        flash(f'Gagal memuat data pemilih: {str(e)}', 'error')
        return redirect(url_for('list_voters'))

    if not voter:
        flash('Pemilih tidak ditemukan', 'error')
        return redirect(url_for('list_voters'))

    if request.method == 'POST':
        try:
            # Prepare update data
            update_data = {
                "endpoint": "/update_voter",
                "voter_id": voter_id,
                "nama": request.form['nama'],
                "tempat_lahir": request.form['tempat_lahir'],
                "tanggal_lahir": request.form['tanggal_lahir'],
                "jenis_kelamin": request.form['jenis_kelamin'],
                "alamat": request.form['alamat'],
                "status_pernikahan": request.form['status_pernikahan'],
                "email": request.form['email'],
                "officer_id": session['officer_data']['officer_id']
            }

            response = requests.post(
                AUTH_SERVER,
                json=update_data,
                timeout=REQUEST_TIMEOUT,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    flash('Data pemilih berhasil diperbarui!', 'success')
                    return redirect(url_for('view_voter_details', voter_id=voter_id))
                else:
                    flash(result.get('message', 'Gagal memperbarui data pemilih'), 'error')
            else:
                flash(f'Error server: {response.status_code}', 'error')
        except Exception as e:
            flash(f'Terjadi kesalahan: {str(e)}', 'error')

    return render_template('officer/edit_voter.html', voter=voter)

# Fungsi untuk officer khusus
@app.route('/special_tools')
@login_required
def special_tools():
    if not session.get('officer_data', {}).get('is_special', False):
        flash('Akses ditolak: Hanya officer khusus yang bisa mengakses fitur ini', 'error')
        return redirect(url_for('dashboard'))
    
    # Get officer key info
    officer = None
    try:
        response = requests.post(
            AUTH_SERVER,
            json={"endpoint": "/get_special_officer"},
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                officer = result.get('officer')
    except Exception as e:
        logger.error(f"Error getting officer info: {str(e)}")
    
    return render_template('officer/special_tools.html', officer=officer)

# Fungsi approve login untuk semua officer
@app.route('/approve_logins')
@login_required
def approve_logins():
    try:
        response = requests.post(
            AUTH_SERVER,
            json={"endpoint": "/get_pending_logins"},
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = response.json()
            voters = result.get('voters', [])
            
            # Get additional details for each voter
            detailed_voters = []
            for voter in voters:
                details_response = requests.post(
                    AUTH_SERVER,
                    json={
                        "endpoint": "/get_voter_details",
                        "voter_id": voter['voter_id']
                    },
                    timeout=REQUEST_TIMEOUT,
                    headers={'Content-Type': 'application/json'}
                )
                
                if details_response.status_code == 200:
                    details = details_response.json().get('voter', {})
                    voter.update({
                        'nama': details.get('nama', ''),
                        'tempat_lahir': details.get('tempat_lahir', ''),
                        'tanggal_lahir': details.get('tanggal_lahir', ''),
                        'jenis_kelamin': details.get('jenis_kelamin', ''),
                        'alamat': details.get('alamat', ''),
                        'status_pernikahan': details.get('status_pernikahan', ''),
                        'is_active': details.get('is_active', False),
                        'registered_at': details.get('registered_at', '')
                    })
                
                detailed_voters.append(voter)
            
            return render_template('officer/approve_logins.html', 
                                voters=detailed_voters)
    
    except Exception as e:
        logger.error(f"Error getting pending logins: {str(e)}")
    
    flash('Gagal memuat daftar pemilih yang menunggu approval', 'error')
    return redirect(url_for('dashboard'))

@app.route('/approve_login/<voter_id>', methods=['POST'])
@login_required
def approve_login(voter_id):
    try:
        data = {
            "endpoint": "/approve_login",
            "voter_id": voter_id,
            "officer_id": session['officer_data']['officer_id'],
            "action": "approve"
        }
        
        response = requests.post(
            AUTH_SERVER,
            json=data,
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                flash('Login pemilih berhasil diapprove', 'success')
            else:
                flash(result.get('message', 'Gagal approve login'), 'error')
        else:
            flash('Gagal approve login', 'error')
    except Exception as e:
        logger.error(f"Error approving login: {str(e)}")
        flash('Terjadi kesalahan sistem', 'error')
    
    return redirect(url_for('approve_logins'))

@app.route('/get_voter_details')
@login_required
def get_voter_details_ajax():
    voter_id = request.args.get('voter_id')
    if not voter_id:
        return jsonify({'status': 'error', 'message': 'Missing voter_id'}), 400
    
    try:
        response = requests.post(
            AUTH_SERVER,
            json={
                "endpoint": "/get_voter_details_with_login_status",  # Changed endpoint
                "voter_id": voter_id
            },
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                return jsonify(result)
            else:
                return jsonify({'status': 'error', 'message': result.get('message', 'Failed to get voter details')}), 400
        else:
            return jsonify({'status': 'error', 'message': 'Failed to connect to auth server'}), 500
            
    except Exception as e:
        logger.error(f"Error getting voter details: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    
@app.route('/reject_login/<voter_id>', methods=['POST'])
@login_required
def reject_login(voter_id):
    try:
        data = {
            "endpoint": "/approve_login",
            "voter_id": voter_id,
            "officer_id": session['officer_data']['officer_id'],
            "action": "reject"
        }
        
        response = requests.post(
            AUTH_SERVER,
            json=data,
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                flash('Status login pemilih dikembalikan ke pending', 'success')
            else:
                flash(result.get('message', 'Gagal mengubah status login'), 'error')
        else:
            flash('Gagal mengubah status login', 'error')
    except Exception as e:
        logger.error(f"Error rejecting login: {str(e)}")
        flash('Terjadi kesalahan sistem', 'error')
    
    return redirect(url_for('approve_logins'))

@app.route('/tabulasi')
@login_required
def tabulasi():
    tabulasi_data = {
        'candidates': [],
        'total_valid_votes': 0,
        'total_voters': 0,
        'total_votes_cast': 0,
        'invalid_votes': 0,
        'voter_turnout': 0,
        'election_status': 'not_set',
        'last_updated': None
    }
    error_msg = None
    
    try:
        # Get tabulation data
        response = requests.post(
            TABULASI_SERVER,
            json={"endpoint": "/get_tabulasi"},
            timeout=30,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                tabulasi_data.update({
                    'candidates': result.get('candidates', []),
                    'total_valid_votes': result.get('total_valid_votes', 0),
                    'total_voters': result.get('total_voters', 0),
                    'total_votes_cast': result.get('total_votes_cast', 0),
                    'invalid_votes': result.get('invalid_votes', 0),
                    'voter_turnout': result.get('voter_turnout', 0),
                    'last_updated': result.get('last_updated', '')
                })

        # Get election status from auth server
        auth_response = requests.post(
            AUTH_SERVER,
            json={"endpoint": "/get_voting_stats"},
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )

        if auth_response.status_code == 200:
            auth_result = auth_response.json()
            if auth_result.get('status') == 'success':
                tabulasi_data['election_status'] = auth_result.get('stats', {}).get('election_status', 'not_set')

    except requests.exceptions.RequestException as e:
        error_msg = f"Gagal terhubung ke server: {str(e)}"
        app.logger.error(f"Connection error: {error_msg}")
    except Exception as e:
        error_msg = f"Terjadi kesalahan: {str(e)}"
        app.logger.error(f"Unexpected error: {error_msg}")

    return render_template(
        'officer/tabulasi.html',
        error=error_msg,
        tabulasi=tabulasi_data,
        current_time=datetime.now()
    )
    
@app.route('/voting_status')
@login_required
def voting_status():
    status_filter = request.args.get('status', 'all')  # 'voted', 'not_voted', or 'all'
    
    voters = []
    try:
        data = {
            "endpoint": "/list_voters_with_voting_status",
            "status": status_filter
        }
        
        response = requests.post(
            AUTH_SERVER,
            json=data,
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = response.json()
            if result and result.get('status') == 'success':
                voters = result.get('voters', [])
            else:
                flash('Gagal memuat data pemilih', 'error')
        else:
            flash('Gagal memuat data pemilih', 'error')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    return render_template('officer/voting_status.html', 
                         voters=voters,
                         status_filter=status_filter)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(port=5001, debug=True)