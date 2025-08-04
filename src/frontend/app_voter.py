from flask import Flask, render_template, request, session, redirect, url_for, flash
import requests
import json
import time
import logging
from functools import wraps
import hashlib
import base64
from datetime import datetime
from flask import jsonify
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import serialization
from datetime import timedelta
from cryptography.hazmat.primitives.asymmetric import utils
import re
import secrets
import os

# Inisialisasi aplikasi Flask
app = Flask(__name__)
app.secret_key = 'evoting-secret-key-123'  # Kunci rahasia untuk session (harus diganti di production)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)  # Session berlaku 1 hari
app.static_folder = 'static'

# Konfigurasi logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# URL server backend
AUTH_SERVER = "http://localhost:8081"        # Server autentikasi
VOTING_SERVER = "http://localhost:8082"      # Server voting
TABULASI_SERVER = "http://localhost:8083"    # Server tabulasi

# Timeout untuk request ke server (dalam detik)
REQUEST_TIMEOUT = 5

# Decorator untuk memastikan user sudah login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'voter_data' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator untuk memeriksa status vote pemilih
def check_vote_status_once(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'has_voted' not in session:
            try:
                # Buat request ke server voting untuk memeriksa status vote
                data = {
                    "endpoint": "/check_vote_status",
                    "voter_id": session['voter_data']['voter_id']
                }
                response = requests.post(
                    VOTING_SERVER,
                    json=data,
                    timeout=REQUEST_TIMEOUT,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code == 200:
                    result = response.json()
                    session['has_voted'] = result.get('has_voted', False)
                    if result.get('has_voted'):
                        session['vote_id'] = result.get('vote_id')
                    session.modified = True
                else:
                    logger.error(f"Server error: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Connection error: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")
        
        return f(*args, **kwargs)
    return decorated_function

# Route untuk halaman utama/dashboard pemilih
@app.route('/')
@login_required
@check_vote_status_once  # Pastikan status vote terupdate
def dashboard():
    try:
        # Force refresh status vote dari server (untuk data real-time)
        data = {
            "endpoint": "/check_vote_status",
            "voter_id": session['voter_data']['voter_id']
        }
        response = requests.post(
            VOTING_SERVER,
            json=data,
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = response.json()
            session['has_voted'] = result.get('has_voted', False)
            
            # Simpan data kandidat jika sudah memilih
            if session['has_voted'] and 'vote_hash' in result:
                session['vote_hash'] = result['vote_hash']
                candidate_response = requests.post(
                    AUTH_SERVER,
                    json={
                        "endpoint": "/get_candidate",
                        "candidate_id": result.get('candidate_id')
                    },
                    timeout=REQUEST_TIMEOUT,
                    headers={'Content-Type': 'application/json'}
                )
                if candidate_response.status_code == 200:
                    session['candidate_data'] = candidate_response.json().get('candidate')
            
            session.modified = True
            logger.info(f"Vote status refreshed - has_voted: {session['has_voted']}")
        else:
            logger.error(f"Failed to check vote status: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Error in dashboard vote check: {str(e)}")
        flash('Gagal memuat status pemilihan terbaru', 'error')
    
    return render_template('voter/dashboard.html')

# Route untuk registrasi pemilih baru
@app.route('/register', methods=['GET', 'POST'])
def register():
    error_msg = None
    
    if request.method == 'POST':
        try:
            # Validasi input
            required_fields = ['nik', 'nama', 'tempat_lahir', 'tanggal_lahir',
                             'jenis_kelamin', 'alamat', 'status_pernikahan',
                             'email', 'password']
            
            for field in required_fields:
                if not request.form.get(field):
                    error_msg = f"Field {field} harus diisi"
                    return render_template('voter/register.html', error=error_msg)

            nik = request.form['nik']
            email = request.form['email']
            private_key = request.form.get('private_key')
            public_key = request.form.get('public_key')

            # Validasi format
            if len(nik) != 16 or not nik.isdigit():
                error_msg = "NIK harus 16 digit angka"
                return render_template('voter/register.html', error=error_msg)

            if '@' not in email or '.' not in email.split('@')[1]:
                error_msg = "Format email tidak valid"
                return render_template('voter/register.html', error=error_msg)

            if not public_key or not private_key:
                error_msg = "Kunci keamanan gagal digenerate"
                return render_template('voter/register.html', error=error_msg)

            # Siapkan data untuk API
            payload = {
                "endpoint": "/register",
                "nik": nik,
                "nama": request.form['nama'],
                "tempat_lahir": request.form['tempat_lahir'],
                "tanggal_lahir": request.form['tanggal_lahir'],
                "jenis_kelamin": request.form['jenis_kelamin'],
                "alamat": request.form['alamat'],
                "status_pernikahan": request.form['status_pernikahan'],
                "email": email,
                "password": request.form['password'],
                "public_key": public_key,
                "private_key": private_key  # Hanya untuk response
            }

            # Kirim request ke auth server
            response = requests.post(
                AUTH_SERVER,
                json=payload,
                timeout=REQUEST_TIMEOUT,
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            )

            # Debugging: Cetak response
            print(f"Response Status: {response.status_code}")
            print(f"Response Content: {response.text}")

            try:
                response_data = response.json()
            except ValueError:
                # Jika response bukan JSON
                error_msg = "Format response tidak valid dari server"
                return render_template('voter/register.html', error=error_msg)

            if response.status_code == 200:
                if response_data.get('status') == 'success':
                    return render_template(
                        'voter/register_success.html',
                        message='Registrasi berhasil!',
                        email=email,
                        private_key=private_key,
                        nama=request.form['nama'],
                        nik=nik,
                        tempat_lahir=request.form['tempat_lahir'],
                        tanggal_lahir=request.form['tanggal_lahir'],
                        jenis_kelamin=request.form['jenis_kelamin'],
                        alamat=request.form['alamat'],
                        status_pernikahan=request.form['status_pernikahan']
                    )
                else:
                    error_msg = response_data.get('message', 'Registrasi gagal')
            else:
                error_msg = f"Error {response.status_code}: {response_data.get('message', 'Unknown error')}"

        except requests.exceptions.RequestException as e:
            error_msg = f"Gagal terhubung ke server: {str(e)}"
            logger.error(f"Connection error: {str(e)}")
        except Exception as e:
            error_msg = f"Terjadi kesalahan: {str(e)}"
            logger.error(f"Unexpected error: {str(e)}", exc_info=True)

    return render_template('voter/register.html', error=error_msg)

# Route untuk login pemilih
@app.route('/login', methods=['GET', 'POST'])
def login():
    error_msg = None
    if request.method == 'POST':
        try:
            # Validasi input
            if not request.form.get('nik') or not request.form.get('password'):
                flash('NIK dan password harus diisi', 'error')
                return redirect(url_for('login'))

            data = {
                "endpoint": "/login_voter",
                "nik": request.form['nik'],
                "password": request.form['password']
            }

            response = requests.post(
                AUTH_SERVER,
                json=data,
                timeout=REQUEST_TIMEOUT,
                headers={'Content-Type': 'application/json'}
            )

            # Handle response
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    session['voter_data'] = result['voter_data']
                    return redirect(url_for('dashboard'))
                else:
                    error_msg = result.get('message', 'Login gagal')
            else:
                try:
                    error_data = response.json()
                    error_msg = f"Error {response.status_code}: {error_data.get('message')}"
                except:
                    error_msg = f"Server error: {response.status_code}"

        except requests.exceptions.RequestException as e:
            error_msg = f"Gagal terhubung ke server: {str(e)}"
        except Exception as e:
            logger.error(f"Login error: {str(e)}", exc_info=True)
            error_msg = "Terjadi kesalahan sistem"

    return render_template('voter/login.html', error=error_msg)

def generate_nonce():
    """Generate a cryptographically secure nonce"""
    return base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')

def verify_signature(data: str, signature: str, public_key_pem: str) -> bool:
    """Improved signature verification function"""
    try:
        # Normalize public key format
        public_key_pem = public_key_pem.strip()
        if not public_key_pem.startswith('-----BEGIN PUBLIC KEY-----'):
            public_key_pem = '-----BEGIN PUBLIC KEY-----\n' + public_key_pem
        if not public_key_pem.endswith('-----END PUBLIC KEY-----'):
            public_key_pem = public_key_pem + '\n-----END PUBLIC KEY-----'

        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )

        # Verify signature
        signature_bytes = base64.b64decode(signature)
        public_key.verify(
            signature_bytes,
            data.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {str(e)}")
        return False
    
@app.route('/enter_private_key', methods=['GET'])
@login_required
@check_vote_status_once
def enter_private_key():
    # Redirect if already voted
    if session.get('has_voted'):
        flash('Anda sudah memberikan suara', 'info')
        return redirect(url_for('already_voted'))
    
    # Generate new nonce for the page
    session['private_key_nonce'] = secrets.token_urlsafe(16)
    return render_template('voter/enter_private_key.html')

def validate_key_format(key_str, key_type):
    required_begin = f"-----BEGIN {key_type} KEY-----"
    required_end = f"-----END {key_type} KEY-----"
    
    return (key_str.startswith(required_begin) and 
            key_str.endswith(required_end) and
            "MII" in key_str)

def normalize_key(key_str, key_type):
    print(f"\n[DEBUG] Normalizing {key_type} key...")
    print(f"[DEBUG] Original key (first 100 chars): {key_str[:100]}")
    
    try:
        # Remove all headers/footers and whitespace
        key_str = key_str.strip()
        key_str = re.sub(r'-----BEGIN.*?-----', '', key_str, flags=re.DOTALL|re.IGNORECASE)
        key_str = re.sub(r'-----END.*?-----', '', key_str, flags=re.DOTALL|re.IGNORECASE)
        key_str = re.sub(r'\s+', '', key_str)
        
        # Validate base64
        if not re.match(r'^[A-Za-z0-9+/=]+$', key_str):
            raise ValueError("Invalid key format (not base64)")
            
        # Rebuild proper PEM format
        begin_header = f"-----BEGIN {key_type} KEY-----\n"
        end_header = f"\n-----END {key_type} KEY-----\n"
        
        # Split into 64 character lines
        key_lines = [key_str[i:i+64] for i in range(0, len(key_str), 64)]
        normalized_key = begin_header + '\n'.join(key_lines) + end_header
        
        # Verify the key can be loaded
        if key_type == 'PRIVATE':
            try:
                private_key = serialization.load_pem_private_key(
                    normalized_key.encode(),
                    password=None,
                    backend=default_backend()
                )
                # Verify private key by exporting public key
                public_key = private_key.public_key()
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            except Exception as e:
                raise ValueError(f"Invalid private key: {str(e)}")
        else:
            try:
                serialization.load_pem_public_key(
                    normalized_key.encode(),
                    backend=default_backend()
                )
            except Exception as e:
                raise ValueError(f"Invalid public key: {str(e)}")
        
        print(f"[DEBUG] Normalized key (first 100 chars): {normalized_key[:100]}")
        return normalized_key
        
    except Exception as e:
        print(f"[DEBUG] Key normalization error: {str(e)}")
        raise ValueError(f"Invalid {key_type} key format: {str(e)}")
            
def verify_signature(data, signature, public_key_str):
    try:
        print("[DEBUG] Starting signature verification...")
        
        # Normalize and validate public key
        public_key_str = normalize_key(public_key_str, 'PUBLIC')
        public_key = serialization.load_pem_public_key(
            public_key_str.encode(),
            backend=default_backend()
        )
        
        # Convert data to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Decode signature
        signature_bytes = base64.b64decode(signature)
        
        # Verify signature
        public_key.verify(
            signature_bytes,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        print("[DEBUG] Signature verified successfully")
        return True
        
    except Exception as e:
        print(f"[VERIFY ERROR] Signature verification failed: {str(e)}")
        return False

@app.route('/already_voted')
@login_required
def already_voted():
    if not session.get('has_voted'):
        return redirect(url_for('vote'))
    
    # Ambil data vote terakhir jika ada
    vote_receipt = session.get('vote_receipt', {})
    candidate = session.get('candidate_data', {})
    
    return render_template('voter/already_voted.html', 
                         candidate=candidate,
                         vote_receipt=vote_receipt)

@app.route('/vote', methods=['GET', 'POST'])
@login_required
@check_vote_status_once
def vote():
    if request.args.get('verified') == '1' and request.args.get('token'):
        try:
            # 1. Decode token dengan error handling
            try:
                token_str = base64.b64decode(request.args.get('token')).decode('utf-8')
                token_data = json.loads(token_str)
                logger.info(f"Decoded token data: {token_data}")
            except Exception as e:
                logger.error(f"Token decode failed: {str(e)}")
                flash('Format token tidak valid', 'error')
                return redirect(url_for('enter_private_key'))

            # 2. Validasi field wajib
            required_fields = ['data', 'signature', 'timestamp', 'voter_id']
            if not all(field in token_data for field in required_fields):
                logger.error(f"Missing required fields in token")
                flash('Data verifikasi tidak lengkap', 'error')
                return redirect(url_for('enter_private_key'))

            # 3. Verifikasi waktu (10 menit tolerance)
            current_time = int(time.time())
            if abs(current_time - int(token_data['timestamp'])) > 600:
                logger.error("Token expired")
                flash('Sesi verifikasi kadaluarsa', 'error')
                return redirect(url_for('enter_private_key'))

            # 4. Verifikasi voter_id
            if token_data['voter_id'] != session['voter_data']['voter_id']:
                logger.error("Voter ID mismatch")
                flash('ID pemilih tidak valid', 'error')
                return redirect(url_for('enter_private_key'))

            # 5. Dapatkan public key dari session (tidak perlu request ke auth server)
            if 'voter_data' not in session or 'public_key' not in session['voter_data']:
                logger.error("Public key not found in session")
                flash('Data kunci tidak valid', 'error')
                return redirect(url_for('enter_private_key'))

            public_key_pem = session['voter_data']['public_key']
            logger.info(f"Using public key from session")

            # 6. Verifikasi signature lokal (tidak perlu request ke auth server)
            try:
                data_to_verify = token_data['data']
                signature = token_data['signature']
                
                if not verify_signature(data_to_verify, signature, public_key_pem):
                    logger.error("Local signature verification failed")
                    flash('Verifikasi tanda tangan gagal', 'error')
                    return redirect(url_for('enter_private_key'))
                    
                logger.info("Local signature verification passed")
            except Exception as e:
                logger.error(f"Signature verification error: {str(e)}")
                flash('Gagal memverifikasi tanda tangan', 'error')
                return redirect(url_for('enter_private_key'))

            # 7. Set session sebagai verified
            session['private_key_verified'] = True
            session['last_verified'] = current_time
            flash('Verifikasi kunci berhasil!', 'success')
            logger.info("Private key verification completed successfully")

        except Exception as e:
            logger.error(f"Verification process failed: {str(e)}", exc_info=True)
            flash('Proses verifikasi gagal', 'error')
            return redirect(url_for('enter_private_key'))

    # Cek jika sudah vote
    if session.get('has_voted'):
        flash('Anda sudah memberikan suara!', 'warning')
        return redirect(url_for('already_voted'))

    # Cek verifikasi kunci privat
    if not session.get('private_key_verified'):
        flash('Harap verifikasi kunci privat terlebih dahulu', 'error')
        return redirect(url_for('enter_private_key'))

    # Cek waktu pemilihan
    election_status = get_election_time()
    if election_status.get('status') != 'ongoing':
        flash('Pemilihan belum dibuka atau sudah berakhir!', 'error')
        return redirect(url_for('dashboard'))

    # Handle POST request (vote submission)
    if request.method == 'POST':
        candidate_id = request.form.get('candidate_id')
        if not candidate_id:
            flash('Pilih kandidat terlebih dahulu!', 'error')
            return redirect(url_for('vote'))

        # Simpan sementara di session
        candidate = get_candidate_data(candidate_id)
        if not candidate:
            flash('Kandidat tidak valid!', 'error')
            return redirect(url_for('vote'))

        session['selected_candidate'] = candidate
        return redirect(url_for('confirm_vote'))

    # GET request - show voting page
    candidates = get_candidate_list()
    return render_template('voter/vote.html', 
                         candidates=candidates, 
                         election_time_info=election_status)

# Fungsi helper untuk mendapatkan waktu pemilihan
def get_election_time():
    try:
        # Debug: Print request being made
        print(f"[DEBUG] Making request to {AUTH_SERVER} for election time")
        
        response = requests.post(
            AUTH_SERVER,
            json={"endpoint": "/get_election_time"},
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        
        # Debug: Print response status and content
        print(f"[DEBUG] Response status: {response.status_code}")
        print(f"[DEBUG] Response content: {response.text}")

        if response.status_code == 200:
            time_data = response.json()
            now = datetime.now()
            
            # Debug: Print received time data
            print(f"[DEBUG] Received time data: {time_data}")
            
            # Handle empty or invalid time data
            if not time_data.get('start_time') or not time_data.get('end_time'):
                print("[DEBUG] Missing start_time or end_time in response")
                return {
                    'status': 'not_set',
                    'message': 'Waktu pemilihan belum ditetapkan'
                }
                
            try:
                # Parse the timestamps - handle multiple possible formats
                try:
                    start_time = datetime.strptime(time_data['start_time'], '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    start_time = datetime.strptime(time_data['start_time'], '%Y-%m-%dT%H:%M:%S.%f')
                
                try:
                    end_time = datetime.strptime(time_data['end_time'], '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    end_time = datetime.strptime(time_data['end_time'], '%Y-%m-%dT%H:%M:%S.%f')

                # Debug: Print parsed times
                print(f"[DEBUG] Parsed start_time: {start_time}")
                print(f"[DEBUG] Parsed end_time: {end_time}")
                print(f"[DEBUG] Current time: {now}")

                # Determine election status
                if start_time <= now <= end_time:
                    status = 'ongoing'
                elif now < start_time:
                    status = 'not_started'
                else:
                    status = 'ended'

                return {
                    'status': status,
                    'start_time': start_time.strftime('%d %B %Y, %H:%M'),
                    'end_time': end_time.strftime('%d %B %Y, %H:%M'),
                    'start_time_iso': start_time.isoformat(),
                    'end_time_iso': end_time.isoformat(),
                    'time_left': str(end_time - now) if start_time <= now <= end_time else None,
                    'message': None
                }
                
            except ValueError as e:
                print(f"[ERROR] Failed to parse time: {str(e)}")
                return {
                    'status': 'error',
                    'message': f'Format waktu pemilihan tidak valid: {str(e)}'
                }
        else:
            print(f"[ERROR] Server returned status {response.status_code}")
            return {
                'status': 'error',
                'message': f'Tidak bisa memeriksa waktu pemilihan (HTTP {response.status_code})'
            }
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed: {str(e)}")
        return {
            'status': 'error',
            'message': 'Gagal terhubung ke server'
        }
    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        return {
            'status': 'error',
            'message': 'Gagal memproses waktu pemilihan'
        }
                
# Fungsi helper untuk mendapatkan daftar kandidat
def get_candidate_list():
    response = requests.post(
        AUTH_SERVER,
        json={"endpoint": "/list_candidates"},
        timeout=REQUEST_TIMEOUT
    )
    if response.status_code == 200:
        candidates = response.json().get('candidates', [])
        return sorted(candidates, key=lambda x: x.get('nomor_urut', 0))
    raise Exception(f"Server returned {response.status_code}")

# Fungsi helper untuk mendapatkan data kandidat
def get_candidate_data(candidate_id):
    response = requests.post(
        AUTH_SERVER,
        json={"endpoint": "/get_candidate", "candidate_id": candidate_id},
        timeout=REQUEST_TIMEOUT
    )
    if response.status_code == 200:
        return response.json().get('candidate')
    return None

# Fungsi untuk mengenkripsi vote
def encrypt_vote(data, public_key_str):
    try:
        # Normalize and validate public key
        public_key_str = normalize_key(public_key_str, 'PUBLIC')
        public_key = serialization.load_pem_public_key(
            public_key_str.encode(),
            backend=default_backend()
        )
        
        # Convert data to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Encrypt in chunks
        chunk_size = 190  # For 2048-bit RSA with PKCS1 padding
        encrypted_chunks = []
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            encrypted_chunk = public_key.encrypt(
                chunk,
                padding.PKCS1v15()
            )
            encrypted_chunks.append(encrypted_chunk)
            
        # Combine and base64 encode
        encrypted_data = b''.join(encrypted_chunks)
        encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
        
        return encrypted_base64
        
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise ValueError(f"Encryption failed: {str(e)}")

def sign_vote(data, private_key_str):
    try:
        # Normalize and validate private key
        private_key_str = normalize_key(private_key_str, 'PRIVATE')
        private_key = serialization.load_pem_private_key(
            private_key_str.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Convert data to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Create signature
        signature = private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Return base64 encoded signature
        return base64.b64encode(signature).decode('utf-8')
        
    except Exception as e:
        logger.error(f"Signing failed: {str(e)}")
        raise ValueError(f"Signing failed: {str(e)}")    

def decrypt_vote(encrypted_data, private_key_str):
    try:
        print("[DEBUG] Starting vote decryption...")
        
        # Normalize and validate private key
        private_key_str = normalize_key(private_key_str, 'PRIVATE')
        private_key = serialization.load_pem_private_key(
            private_key_str.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Decode base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Decrypt in chunks
        chunk_size = 256  # For 2048-bit RSA
        decrypted_chunks = []
        
        for i in range(0, len(encrypted_bytes), chunk_size):
            chunk = encrypted_bytes[i:i+chunk_size]
            decrypted_chunk = private_key.decrypt(
                chunk,
                padding.PKCS1v15()
            )
            decrypted_chunks.append(decrypted_chunk)
            
        # Combine and return as string
        decrypted_data = b''.join(decrypted_chunks).decode('utf-8')
        
        print("[DEBUG] Vote decrypted successfully")
        return decrypted_data
        
    except Exception as e:
        print(f"[DECRYPT ERROR] Failed to decrypt vote: {str(e)}")
        raise ValueError(f"Decryption failed: {str(e)}")
                    
# Route untuk konfirmasi vote
@app.route('/vote/confirm', methods=['GET', 'POST'])
@login_required
def confirm_vote():
    """
    Menangani halaman konfirmasi vote.
    - GET: Menampilkan detail kandidat yang dipilih.
    - POST: Memproses penyimpanan vote setelah konfirmasi.
    """
    # Cek jika belum memilih kandidat
    if 'selected_candidate' not in session:
        flash('Anda belum memilih kandidat!', 'error')
        return redirect(url_for('vote'))

    # Cek jika sudah pernah vote
    if session.get('has_voted'):
        flash('Anda sudah memberikan suara!', 'warning')
        return redirect(url_for('already_voted'))

    # Cek waktu pemilihan
    election_status = get_election_time()
    if election_status.get('status') != 'ongoing':
        flash('Pemilihan belum dibuka atau sudah berakhir!', 'error')
        return redirect(url_for('dashboard'))

    # Handle POST (konfirmasi vote)
    if request.method == 'POST':
        try:
            # 1. Dapatkan kunci publik petugas khusus
            officer_response = requests.post(
                AUTH_SERVER,
                json={"endpoint": "/get_special_officer"},
                timeout=REQUEST_TIMEOUT,
                headers={'Content-Type': 'application/json'}
            )
            if officer_response.status_code != 200:
                flash('Gagal mendapatkan kunci enkripsi!', 'error')
                return redirect(url_for('vote'))

            officer_public_key = officer_response.json().get('officer', {}).get('public_key')
            if not officer_public_key:
                flash('Kunci enkripsi tidak valid!', 'error')
                return redirect(url_for('vote'))

            # 2. Siapkan data vote
            vote_payload = {
                "candidate_id": session['selected_candidate']['candidate_id'],
                "timestamp": datetime.now().isoformat(),
                "random_nonce": secrets.token_hex(16)  # Anti-replay attack
            }
            vote_data_str = json.dumps(vote_payload, separators=(',', ':'))

            # 3. Enkripsi data
            try:
                encrypted_vote = encrypt_vote(vote_data_str, officer_public_key)
                vote_hash = hashlib.sha3_256(vote_data_str.encode()).hexdigest()
            except Exception as e:
                logger.error(f"Gagal enkripsi: {str(e)}")
                flash('Gagal mengenkripsi vote!', 'error')
                return redirect(url_for('vote'))

            # 4. Kirim ke server voting
            payload = {
                "endpoint": "/submit_vote",
                "voter_id": session['voter_data']['voter_id'],
                "encrypted_vote": encrypted_vote,
                "vote_hash": vote_hash
            }
            response = requests.post(
                VOTING_SERVER,
                json=payload,
                timeout=REQUEST_TIMEOUT,
                headers={'Content-Type': 'application/json'}
            )

            # 5. Handle response
            if response.status_code == 200:
                # Simpan receipt vote
                session['has_voted'] = True
                session['vote_receipt'] = {
                    'vote_id': response.json().get('vote_id'),
                    'timestamp': vote_payload['timestamp'],
                    'candidate': session['selected_candidate'],
                    'hash': vote_hash[:16] + '...'  # Simpan sebagian hash untuk display
                }
                session.pop('selected_candidate', None)  # Bersihkan data sementara

                logger.info(f"Vote berhasil oleh {session['voter_data']['voter_id']}")
                return redirect(url_for('vote_success'))
            else:
                error_msg = response.json().get('message', 'Gagal menyimpan vote')
                flash(f'Error: {error_msg}', 'error')

        except requests.exceptions.RequestException as e:
            logger.error(f"Koneksi gagal: {str(e)}")
            flash('Gagal terhubung ke server voting!', 'error')
        except Exception as e:
            logger.error(f"Error sistem: {str(e)}", exc_info=True)
            flash('Terjadi kesalahan sistem!', 'error')

    # Tampilkan halaman konfirmasi (GET request)
    return render_template(
        'voter/vote_confirm.html',
        candidate=session['selected_candidate'],
        election_time=election_status
    )

# Route untuk halaman sukses voting
@app.route('/vote/success')
@login_required
def vote_success():
    # Cek jika belum vote
    if not session.get('has_voted') or 'vote_receipt' not in session:
        flash('Anda belum memberikan suara!', 'error')
        return redirect(url_for('vote'))

    # Format timestamp jika berupa string
    receipt = session['vote_receipt']
    if isinstance(receipt.get('timestamp'), str):
        try:
            receipt['timestamp'] = datetime.fromisoformat(receipt['timestamp'])
        except ValueError:
            receipt['timestamp'] = None

    # Dapatkan data kandidat terbaru
    try:
        candidate_response = requests.post(
            AUTH_SERVER,
            json={
                "endpoint": "/get_candidate",
                "candidate_id": receipt['candidate']['candidate_id']
            },
            timeout=REQUEST_TIMEOUT
        )
        candidate = candidate_response.json().get('candidate', receipt['candidate'])
    except:
        candidate = receipt['candidate']

    return render_template(
        'voter/vote_success.html',
        receipt=receipt,
        candidate=candidate,
        election_time=get_election_time()
    )

from datetime import datetime

# Tambahkan filter custom untuk format datetime
@app.template_filter('format_datetime')
def format_datetime_filter(value, format="%d %B %Y %H:%M"):
    """Filter untuk memformat datetime di template Jinja2"""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    if value is None:
        return ""
    return value.strftime(format)
            
# Route untuk melihat hasil pemilihan
@app.route('/results')
@login_required
@check_vote_status_once
def results():
    try:
        # Get data from TabulasiServer
        response = requests.post(
            TABULASI_SERVER,
            json={"endpoint": "/get_tabulasi"},
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        
        if response.status_code != 200:
            raise Exception(f"Server error: {response.status_code}")
            
        data = response.json()
        
        # Process candidate data
        candidates = []
        total_votes = data.get('total_valid_votes', 0)
        total_voters = data.get('total_voters', 0)
        
        for candidate in data.get('candidates', []):
            vote_count = candidate.get('vote_count', 0)
            percentage = (vote_count * 100.0 / total_votes) if total_votes > 0 else 0
            candidates.append({
                'candidate_id': candidate.get('candidate_id'),
                'nama': candidate.get('nama'),
                'partai': candidate.get('partai'),
                'nomor_urut': candidate.get('nomor_urut'),
                'photo_url': candidate.get('photo_url'),
                'vote_count': vote_count,
                'percentage': round(percentage, 2)
            })
        
        # Calculate participation rate
        participation_rate = round((total_votes / total_voters * 100), 2) if total_voters > 0 else 0
        
        return render_template(
            'voter/results.html',
            candidates=candidates,
            total_voters=total_voters,
            total_votes=total_votes,
            participation_rate=participation_rate,
            now=datetime.now().strftime('%d %B %Y %H:%M:%S')
        )
        
    except Exception as e:
        logger.error(f"Error in results: {str(e)}")
        return render_template(
            'voter/results.html',
            error=str(e),
            candidates=[],
            total_voters=0,
            total_votes=0,
            participation_rate=0,
            now=datetime.now().strftime('%d %B %Y %H:%M:%S')
        )
    
# Route untuk health check server
@app.route('/health')
def health_check():
    servers = {
        'auth_server': AUTH_SERVER,
        'voting_server': VOTING_SERVER,
        'tabulasi_server': TABULASI_SERVER
    }
    
    status = {}
    for name, url in servers.items():
        try:
            response = requests.post(url, json={"endpoint":"/"}, timeout=2)
            status[name] = response.status_code == 200
        except:
            status[name] = False
    
    return jsonify(status)

# Route untuk lupa password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    error = None
    if request.method == 'POST':
        try:
            data = {
                "endpoint": "/request_password_reset",
                "nik": request.form['nik'],
                "email": request.form['email']
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
                    session['reset_voter_id'] = result.get('voter_id')
                    return redirect(url_for('verify_otp'))
                else:
                    error = result.get('message', 'Gagal memproses permintaan reset password')
            else:
                error = f"Error server: {response.status_code}"
        except requests.exceptions.RequestException as e:
            error = f"Gagal terhubung ke server: {str(e)}"
    
    return render_template('voter/forgot_password.html', error=error)

# Route untuk verifikasi OTP
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'reset_voter_id' not in session:
        return redirect(url_for('forgot_password'))
    
    error = None
    if request.method == 'POST':
        try:
            data = {
                "endpoint": "/verify_password_reset",
                "voter_id": session['reset_voter_id'],
                "otp": request.form['otp']
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
                    session['reset_otp'] = request.form['otp']
                    return redirect(url_for('reset_password'))
                else:
                    error = result.get('message', 'OTP tidak valid')
            else:
                error = f"Error server: {response.status_code}"
        except requests.exceptions.RequestException as e:
            error = f"Gagal terhubung ke server: {str(e)}"
    
    return render_template('voter/verify_otp.html', error=error)

# Route untuk reset password
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_voter_id' not in session or 'reset_otp' not in session:
        return redirect(url_for('forgot_password'))
    
    error = None
    if request.method == 'POST':
        if request.form['new_password'] != request.form['confirm_password']:
            error = "Password dan konfirmasi password tidak cocok"
        else:
            try:
                data = {
                    "endpoint": "/reset_password",
                    "voter_id": session['reset_voter_id'],
                    "otp": session['reset_otp'],
                    "new_password": request.form['new_password']
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
                        session.pop('reset_voter_id', None)
                        session.pop('reset_otp', None)
                        flash('Password berhasil diperbarui', 'success')
                        return redirect(url_for('login'))
                    else:
                        error = result.get('message', 'Gagal memperbarui password')
                else:
                    error = f"Error server: {response.status_code}"
            except requests.exceptions.RequestException as e:
                error = f"Gagal terhubung ke server: {str(e)}"
    
    return render_template('voter/reset_password.html', error=error)

# Route untuk mengubah password
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        data = request.get_json()
        
        # Handle OTP request
        if data.get('request_otp'):
            current_password = data.get('current_password')
            
            # Verifikasi password saat ini
            try:
                verify_data = {
                    "endpoint": "/verify_current_password",
                    "voter_id": session['voter_data']['voter_id'],
                    "password": current_password
                }
                
                response = requests.post(
                    AUTH_SERVER,
                    json=verify_data,
                    timeout=REQUEST_TIMEOUT,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code != 200 or not response.json().get('verified'):
                    return jsonify({"status": "error", "message": "Current password is incorrect"}), 400
                    
                # Request OTP
                otp_data = {
                    "endpoint": "/request_password_change_otp",
                    "voter_id": session['voter_data']['voter_id']
                }
                
                otp_response = requests.post(
                    AUTH_SERVER,
                    json=otp_data,
                    timeout=REQUEST_TIMEOUT,
                    headers={'Content-Type': 'application/json'}
                )
                
                if otp_response.status_code == 200:
                    return jsonify({"status": "success", "message": "OTP has been sent to your email"})
                else:
                    return jsonify({"status": "error", "message": "Failed to send OTP"}), 400
                    
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500
        
        # Handle password change
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        otp = data.get('otp')
        
        # Validasi input
        if not all([current_password, new_password, confirm_password, otp]):
            return jsonify({"status": "error", "message": "All fields are required"}), 400
        
        if new_password != confirm_password:
            return jsonify({"status": "error", "message": "New password and confirmation do not match"}), 400
        
        try:
            change_data = {
                "endpoint": "/verify_password_change",
                "voter_id": session['voter_data']['voter_id'],
                "otp": otp,
                "new_password": new_password
            }
            
            response = requests.post(
                AUTH_SERVER,
                json=change_data,
                timeout=REQUEST_TIMEOUT,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    return jsonify({"status": "success", "message": "Password changed successfully!"})
                else:
                    return jsonify({"status": "error", "message": result.get('message', 'Failed to change password')}), 400
            else:
                return jsonify({"status": "error", "message": "Failed to verify OTP"}), 400
                
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    
    return render_template('voter/change_password.html')

# Route untuk logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Jalankan aplikasi jika dijalankan langsung
if __name__ == '__main__':
    app.run(port=5000, debug=True)
