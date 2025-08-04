/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package backend;

/**
 *
 * @author lapto
 */
import static backend.DatabaseHelper.getConnection;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

public class AuthenticationServer {

    private static final int PORT = 8081;
    private static final Logger logger = Logger.getLogger(AuthenticationServer.class.getName());

    public static void main(String[] args) throws Exception {
        DatabaseHelper.initializeDatabase();
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Authentication Server running on port " + PORT);

        while (true) {
            try {
                final Socket clientSocket = serverSocket.accept();
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            handleClient(clientSocket);
                        } catch (Exception ex) {
                            logger.log(Level.SEVERE, "Error handling client", ex);
                        } finally {
                            try {
                                clientSocket.close();
                            } catch (IOException e) {
                                logger.log(Level.WARNING, "Error closing client socket", e);
                            }
                        }
                    }
                }).start();
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error accepting client connection", e);
            }
        }
    }

    private static void handleClient(Socket clientSocket) throws Exception {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

            StringBuilder requestBuilder = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null && !line.isEmpty()) {
                requestBuilder.append(line).append("\n");
            }

            StringBuilder bodyBuilder = new StringBuilder();
            if (in.ready()) {
                while (in.ready()) {
                    bodyBuilder.append((char) in.read());
                }
            }

            String body = bodyBuilder.toString().trim();
            JSONObject jsonRequest;

            try {
                if (body.startsWith("{")) {
                    jsonRequest = new JSONObject(body);

                    // Handle encrypted requests
                    if (jsonRequest.has("encrypted_data")) {
                        try {
                            String decrypted = CryptoUtils.decrypt(jsonRequest.getString("encrypted_data"));
                            jsonRequest = new JSONObject(decrypted);
                        } catch (Exception e) {
                            sendErrorResponse(out, 400, "Failed to decrypt request");
                            return;
                        }
                    }

                    // Process endpoints as before
                    String endpoint = jsonRequest.getString("endpoint");

                    switch (endpoint) {
                        case "/login_officer":
                            handleLoginOfficer(out, jsonRequest);
                            break;
                        case "/login_voter":
                            handleLoginVoter(out, jsonRequest);
                            break;
                        case "/check_vote_status":
                            handleCheckVoteStatus(out, jsonRequest);
                            break;
                        case "/add_candidate":
                            handleAddCandidate(out, jsonRequest);
                            break;
                        case "/add_officer":
                            handleAddOfficer(out, jsonRequest);
                            break;
                        case "/list_officers":
                            handleListOfficers(out);
                            break;
                        case "/list_candidates":
                            handleListCandidates(out);
                            break;
                        case "/list_voters":
                            handleListVoters(out, jsonRequest);
                            break;
                        case "/verify_voter":
                            handleVerifyVoter(out, jsonRequest);
                            break;
                        case "/register":
                            handleRegisterVoter(out, jsonRequest);
                            break;
                        case "/get_officer":
                            handleGetOfficer(out, jsonRequest);
                            break;
                        case "/get_candidate":
                            handleGetCandidate(out, jsonRequest);
                            break;
                        case "/update_officer":
                            handleUpdateOfficer(out, jsonRequest);
                            break;
                        case "/update_candidate":
                            handleUpdateCandidate(out, jsonRequest);
                            break;
                        case "/delete_officer":
                            handleDeleteOfficer(out, jsonRequest);
                            break;
                        case "/get_election_time":
                            handleGetElectionTime(out);
                            break;
                        case "/set_election_time":
                            handleSetElectionTime(out, jsonRequest);
                            break;
                        case "/delete_candidate":
                            handleDeleteCandidate(out, jsonRequest);
                            break;
                        case "/get_voting_stats":
                            handleGetVotingStats(out);
                            break;
                        case "/get_election_results":
                            handleGetElectionResults(out);
                            break;
                        case "/get_voter_details":
                            handleGetVoterDetails(out, jsonRequest);
                            break;
                        case "/get_tabulasi":
                            handleGetTabulasi(out);
                            break;
                        case "/verify_encrypted_vote":
                            handleVerifyEncryptedVote(out, jsonRequest);
                            break;
                        case "/update_voter":
                            handleUpdateVoter(out, jsonRequest);
                            break;
                        case "/request_password_reset":
                            handleRequestPasswordReset(out, jsonRequest);
                            break;
                        case "/verify_password_reset":
                            handleVerifyPasswordReset(out, jsonRequest);
                            break;
                        case "/reset_password":
                            handleResetPassword(out, jsonRequest);
                            break;
                        case "/verify_current_password":
                            handleVerifyCurrentPassword(out, jsonRequest);
                            break;
                        case "/request_password_change_otp":
                            handleRequestPasswordChangeOtp(out, jsonRequest);
                            break;
                        case "/verify_password_change":
                            handleVerifyPasswordChange(out, jsonRequest);
                            break;
                        case "/list_voters_with_voting_status":
                            handleListVotersWithVotingStatus(out, jsonRequest);
                            break;
                        case "/approve_login":
                            handleApproveLogin(out, jsonRequest);
                            break;
                        case "/get_special_officer":
                            handleGetSpecialOfficer(out);
                            break;
                        case "/verify_signature":
                            handleVerifySignature(out, jsonRequest);
                            break;
                        case "/create_signature":
                            handleCreateSignature(out, jsonRequest);
                            break;
                        case "/encrypt_data":
                            handleEncryptData(out, jsonRequest);
                            break;
                        case "/check_special_officer":
                            handleCheckSpecialOfficer(out, jsonRequest);
                            break;
                        case "/get_pending_logins":
                            handleGetPendingLogins(out);
                            break;
                        case "/decrypt_votes":
                            handleDecryptVotes(out, jsonRequest);
                            break;
                        case "/get_voter_details_with_login_status":
                            handleGetVoterDetailsWithLoginStatus(out, jsonRequest);
                            break;
                        default:
                            sendErrorResponse(out, 404, "Endpoint not found");
                    }
                } else {
                    sendErrorResponse(out, 400, "Invalid request format");
                }
            } catch (JSONException e) {
                sendErrorResponse(out, 400, "Invalid JSON: " + e.getMessage());
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "IO Error: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error closing socket: " + e.getMessage());
            }
        }
    }

    private static void handleLoginOfficer(PrintWriter out, JSONObject request) throws Exception {
        try {
            if (!request.has("username") || !request.has("password")) {
                sendErrorResponse(out, 400, "Missing username or password");
                return;
            }

            String username = request.getString("username");
            String password = request.getString("password");

            JSONObject officer = DatabaseHelper.authenticateOfficer(username, password);

            if (officer != null) {
                JSONObject response = new JSONObject();
                response.put("status", "success");
                response.put("officer_data", officer);
                // Add special officer status
                response.put("is_special", DatabaseHelper.isSpecialOfficer(officer.getString("officer_id")));
                sendSuccessResponse(out, response);
            } else {
                sendErrorResponse(out, 401, "Invalid credentials");
            }
        } catch (JSONException | SQLException e) {
            sendErrorResponse(out, 500, "Internal server error");
        }
    }

    private static void handleLoginVoter(PrintWriter out, JSONObject request) throws Exception {
        try {
            // Validasi input
            if (!request.has("nik") || !request.has("password")) {
                sendErrorResponse(out, 400, "NIK dan password harus diisi");
                return;
            }

            String nik = request.getString("nik");
            String password = request.getString("password");

            // Authentikasi
            JSONObject voter = DatabaseHelper.authenticateVoter(nik, password);

            if (voter == null) {
                sendErrorResponse(out, 401, "NIK atau password salah");
                return;
            }

            // Cek status aktif
            if (!voter.optBoolean("is_active", false)) {
                sendErrorResponse(out, 403, "Akun belum diverifikasi oleh petugas");
                return;
            }

            // Cek approval login
            boolean isLoginApproved = DatabaseHelper.isLoginApproved(voter.getString("voter_id"));
            voter.put("login_approved", isLoginApproved);

            // Response sukses
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("voter_data", voter);
            sendSuccessResponse(out, response);

        } catch (Exception e) {
            Logger.getLogger(AuthenticationServer.class.getName())
                    .log(Level.SEVERE, "Login error", e);
            sendErrorResponse(out, 500, "Terjadi kesalahan sistem: " + e.getMessage());
        }
    }

    private static void handleVerifyVoter(PrintWriter out, JSONObject request) {
        try {
            if (!request.has("voter_id") || !request.has("is_verified")) {
                sendErrorResponse(out, 400, "Missing required fields");
                return;
            }

            String voterId = request.getString("voter_id");
            boolean isVerified = request.getBoolean("is_verified");

            System.out.println("Verifying voter " + voterId + " with status: " + isVerified);

            boolean updated = DatabaseHelper.updateVoterVerification(voterId, isVerified);

            if (updated) {
                JSONObject voter = DatabaseHelper.getVoterDetails(voterId);

                JSONObject response = new JSONObject();
                response.put("status", "success");
                response.put("message", "Verifikasi berhasil");
                response.put("voter", voter);

                if (isVerified) {
                    new Thread(() -> {
                        try {
                            JSONObject voterDetails = DatabaseHelper.getVoterDetails(voterId);
                            EmailHelper.sendApprovalEmail(
                                    voterDetails.getString("email"),
                                    voterDetails.getString("nama"),
                                    voterDetails.getString("nik")
                            );
                        } catch (Exception e) {
                            System.err.println("Failed to send approval email: " + e.getMessage());
                        }
                    }).start();
                }

                sendSuccessResponse(out, response);
            } else {
                sendErrorResponse(out, 500, "Gagal memperbarui status verifikasi");
            }
        } catch (Exception e) {
            System.err.println("Error in verify voter: " + e.getMessage());
            e.printStackTrace();
            sendErrorResponse(out, 500, "Error: " + e.getMessage());
        }
    }

    private static void handleRegisterVoter(PrintWriter out, JSONObject request) {
        try {
            // Log incoming request
            System.out.println("[DEBUG] Registration request received: " + request.toString());

            // Validate endpoint
            if (!request.has("endpoint") || !request.getString("endpoint").equals("/register")) {
                sendErrorResponse(out, 400, "Invalid endpoint");
                return;
            }

            // Validate required fields
            String[] requiredFields = {
                "nik", "nama", "tempat_lahir", "tanggal_lahir",
                "jenis_kelamin", "alamat", "status_pernikahan",
                "email", "password", "public_key"
            };

            for (String field : requiredFields) {
                if (!request.has(field)) {
                    System.out.println("[ERROR] Missing field: " + field);
                    sendErrorResponse(out, 400, "Field " + field + " harus diisi");
                    return;
                }
            }

            // Validate NIK (16 digits)
            String nik = request.getString("nik");
            if (nik.length() != 16 || !nik.matches("\\d+")) {
                sendErrorResponse(out, 400, "NIK harus 16 digit angka");
                return;
            }

            // Validate email format
            String email = request.getString("email");
            if (!email.matches("^[\\w-.]+@([\\w-]+\\.)+[\\w-]{2,4}$")) {
                sendErrorResponse(out, 400, "Format email tidak valid");
                return;
            }

            // Check if NIK already exists
            if (DatabaseHelper.checkNikExists(nik)) {
                sendErrorResponse(out, 400, "NIK sudah terdaftar");
                return;
            }

            // Validate public key format
            String publicKey = request.getString("public_key");
            try {
                PublicKey pubKey = KeyGenerator.getPublicKeyFromString(publicKey);
                if (pubKey == null) {
                    throw new Exception("Invalid public key");
                }
            } catch (Exception e) {
                System.out.println("[ERROR] Invalid public key: " + e.getMessage());
                sendErrorResponse(out, 400, "Format public key tidak valid");
                return;
            }

            // Generate voter ID
            String voterId = "V" + System.currentTimeMillis();

            // Save voter to database (without private key)
            boolean saved = DatabaseHelper.saveVoter(
                    voterId,
                    nik,
                    request.getString("nama"),
                    request.getString("tempat_lahir"),
                    request.getString("tanggal_lahir"),
                    request.getString("jenis_kelamin"),
                    request.getString("alamat"),
                    request.getString("status_pernikahan"),
                    email,
                    request.getString("password"),
                    publicKey
            );

            if (!saved) {
                sendErrorResponse(out, 500, "Gagal menyimpan data pemilih");
                return;
            }

            // Prepare success response
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("message", "Registrasi berhasil");
            response.put("voter_id", voterId);

            // Get voter details for response
            JSONObject voterDetails = DatabaseHelper.getVoterDetails(voterId);
            response.put("voter", voterDetails);

            // Send email with private key (from client, not stored in DB)
            if (request.has("private_key")) {
                // Simpan private key secara aman di database/penyimpanan aman
                // Hanya beri tahu user cara mengaksesnya secara aman
                new Thread(() -> {
                    try {
                        EmailHelper.sendVerificationEmail(
                                email,
                                request.getString("nama"),
                                "Registrasi berhasil.\n\n"
                                + "Anda telah mendapatkan kunci privat. "
                                + "Silakan login ke sistem untuk melihat kunci privat Anda "
                                + "dan simpan dengan aman untuk verifikasi voting."
                        );
                    } catch (Exception e) {
                        System.err.println("Failed to send email: " + e.getMessage());
                    }
                }).start();
            }

            sendSuccessResponse(out, response);

        } catch (JSONException e) {
            sendErrorResponse(out, 400, "Format data tidak valid");
        } catch (SQLException e) {
            sendErrorResponse(out, 500, "Database error: " + e.getMessage());
        } catch (Exception e) {
            sendErrorResponse(out, 500, "Server error: " + e.getMessage());
        }
    }

    private static void handleListVoters(PrintWriter out, JSONObject request) throws SQLException {
        try {
            String searchTerm = request.optString("search", "");
            String statusFilter = request.optString("status", "");

            String sql = "SELECT voter_id, nik, nama, email, is_active as is_verified, "
                    + "strftime('%Y-%m-%d %H:%M:%S', registered_at) as registered_at "
                    + "FROM voters WHERE 1=1";

            if (!searchTerm.isEmpty()) {
                sql += " AND (nik LIKE ? OR nama LIKE ?)";
            }

            if (!statusFilter.isEmpty()) {
                if ("verified".equals(statusFilter)) {
                    sql += " AND is_active = 1";
                } else if ("unverified".equals(statusFilter)) {
                    sql += " AND is_active = 0";
                }
            }

            sql += " ORDER BY registered_at DESC";

            List<JSONObject> voters = new ArrayList<>();
            try (Connection conn = DatabaseHelper.getConnection();
                    PreparedStatement pstmt = conn.prepareStatement(sql)) {

                if (!searchTerm.isEmpty()) {
                    String likeTerm = "%" + searchTerm + "%";
                    pstmt.setString(1, likeTerm);
                    pstmt.setString(2, likeTerm);
                }

                ResultSet rs = pstmt.executeQuery();
                while (rs.next()) {
                    JSONObject voter = new JSONObject();
                    voter.put("voter_id", rs.getString("voter_id"));
                    voter.put("nik", rs.getString("nik"));
                    voter.put("nama", rs.getString("nama"));
                    voter.put("email", rs.getString("email"));
                    voter.put("is_verified", rs.getBoolean("is_verified"));
                    voter.put("registered_at", rs.getString("registered_at"));
                    voters.add(voter);
                }
            }

            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("voters", voters);
            sendSuccessResponse(out, response);

        } catch (SQLException e) {
            sendErrorResponse(out, 500, "Database error");
        }
    }

    private static void handleListOfficers(PrintWriter out) throws SQLException {
        List<JSONObject> officers = DatabaseHelper.getAllOfficers();
        JSONObject response = new JSONObject();
        response.put("status", "success");
        response.put("officers", officers);
        sendSuccessResponse(out, response);
    }

    private static void handleListCandidates(PrintWriter out) throws SQLException {
        List<JSONObject> candidates = DatabaseHelper.getAllCandidatesWithPhotos();
        JSONObject response = new JSONObject();
        response.put("status", "success");
        response.put("candidates", candidates);
        sendSuccessResponse(out, response);
    }

    private static void handleGetOfficer(PrintWriter out, JSONObject request) throws SQLException {
        if (!request.has("officer_id")) {
            sendErrorResponse(out, 400, "Missing officer_id");
            return;
        }

        JSONObject officer = DatabaseHelper.getOfficerById(request.getString("officer_id"));
        if (officer != null) {
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("officer", officer);
            sendSuccessResponse(out, response);
        } else {
            sendErrorResponse(out, 404, "Officer not found");
        }
    }

    private static void handleGetCandidate(PrintWriter out, JSONObject request) throws SQLException {
        if (!request.has("candidate_id")) {
            sendErrorResponse(out, 400, "Missing candidate_id");
            return;
        }

        JSONObject candidate = DatabaseHelper.getCandidateById(request.getString("candidate_id"));
        if (candidate != null) {
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("candidate", candidate);
            sendSuccessResponse(out, response);
        } else {
            sendErrorResponse(out, 404, "Candidate not found");
        }
    }

    private static void handleAddOfficer(PrintWriter out, JSONObject request) throws Exception {
        try {
            if (!request.has("username") || !request.has("password")
                    || !request.has("nama") || !request.has("created_by")) {
                sendErrorResponse(out, 400, "Missing required fields");
                return;
            }

            String officerId = "O" + System.currentTimeMillis();
            boolean saved = DatabaseHelper.saveOfficer(
                    officerId,
                    request.getString("username"),
                    request.getString("password"),
                    request.getString("nama"),
                    request.getString("created_by")
            );

            if (saved) {
                JSONObject response = new JSONObject();
                response.put("status", "success");
                response.put("officer_id", officerId);
                sendSuccessResponse(out, response);
            } else {
                sendErrorResponse(out, 500, "Failed to save officer");
            }
        } catch (SQLException e) {
            if (e.getMessage().contains("UNIQUE constraint failed")) {
                sendErrorResponse(out, 400, "Username already exists");
            } else {
                sendErrorResponse(out, 500, "Database error");
            }
        }
    }

    private static void handleUpdateOfficer(PrintWriter out, JSONObject request) throws Exception {
        try {
            if (!request.has("officer_id") || !request.has("username") || !request.has("nama")) {
                sendErrorResponse(out, 400, "Missing required fields");
                return;
            }

            boolean updated;
            if (request.has("password") && !request.getString("password").isEmpty()) {
                updated = DatabaseHelper.updateOfficer(
                        request.getString("officer_id"),
                        request.getString("username"),
                        request.getString("nama"),
                        request.getString("password")
                );
            } else {
                updated = DatabaseHelper.updateOfficer(
                        request.getString("officer_id"),
                        request.getString("username"),
                        request.getString("nama"),
                        null
                );
            }

            if (updated) {
                JSONObject response = new JSONObject();
                response.put("status", "success");
                sendSuccessResponse(out, response);
            } else {
                sendErrorResponse(out, 500, "Failed to update officer");
            }
        } catch (SQLException e) {
            sendErrorResponse(out, 500, "Database error");
        }
    }

    private static void handleDeleteOfficer(PrintWriter out, JSONObject request) throws SQLException {
        if (!request.has("officer_id")) {
            sendErrorResponse(out, 400, "Missing officer_id");
            return;
        }

        boolean deleted = DatabaseHelper.deleteOfficer(request.getString("officer_id"));
        if (deleted) {
            JSONObject response = new JSONObject();
            response.put("status", "success");
            sendSuccessResponse(out, response);
        } else {
            sendErrorResponse(out, 500, "Failed to delete officer");
        }
    }

    private static void handleAddCandidate(PrintWriter out, JSONObject request) {
        try {
            if (!request.has("nama") || !request.has("partai")
                    || !request.has("nomor_urut") || !request.has("created_by")) {
                sendErrorResponse(out, 400, "Missing required fields");
                return;
            }

            String candidateId = "C" + System.currentTimeMillis();
            boolean saved = DatabaseHelper.saveCandidate(
                    candidateId,
                    request.getString("nama"),
                    request.getString("partai"),
                    request.getInt("nomor_urut"),
                    request.optString("photo_url", null),
                    request.getString("created_by")
            );

            if (saved) {
                JSONObject response = new JSONObject();
                response.put("status", "success");
                response.put("candidate_id", candidateId);
                sendSuccessResponse(out, response);
            } else {
                sendErrorResponse(out, 500, "Failed to save candidate");
            }
        } catch (JSONException | SQLException e) {
            sendErrorResponse(out, 400, "Invalid request data");
        }
    }

    private static void handleUpdateCandidate(PrintWriter out, JSONObject request) throws SQLException {
        try {
            if (!request.has("candidate_id") || !request.has("nama")
                    || !request.has("partai") || !request.has("nomor_urut")) {
                sendErrorResponse(out, 400, "Missing required fields");
                return;
            }

            boolean updated = DatabaseHelper.updateCandidate(
                    request.getString("candidate_id"),
                    request.getString("nama"),
                    request.getString("partai"),
                    request.getInt("nomor_urut"),
                    request.optString("photo_url", null)
            );

            if (updated) {
                JSONObject response = new JSONObject();
                response.put("status", "success");
                sendSuccessResponse(out, response);
            } else {
                sendErrorResponse(out, 500, "Failed to update candidate");
            }
        } catch (JSONException e) {
            sendErrorResponse(out, 400, "Invalid request data");
        }
    }

    private static void handleDeleteCandidate(PrintWriter out, JSONObject request) throws SQLException {
        if (!request.has("candidate_id")) {
            sendErrorResponse(out, 400, "Missing candidate_id");
            return;
        }

        boolean deleted = DatabaseHelper.deleteCandidate(request.getString("candidate_id"));
        if (deleted) {
            JSONObject response = new JSONObject();
            response.put("status", "success");
            sendSuccessResponse(out, response);
        } else {
            sendErrorResponse(out, 500, "Failed to delete candidate");
        }
    }

    private static void handleGetElectionResults(PrintWriter out) throws SQLException {
        JSONObject results = DatabaseHelper.getElectionResults();
        JSONObject response = new JSONObject();
        response.put("status", "success");
        response.put("results", results);
        sendSuccessResponse(out, response);
    }

    private static void handleCheckVoteStatus(PrintWriter out, JSONObject jsonRequest) throws SQLException {
        if (!jsonRequest.has("voter_id")) {
            sendErrorResponse(out, 400, "Missing voter_id");
            return;
        }

        String voterId = jsonRequest.getString("voter_id");
        boolean hasVoted = DatabaseHelper.hasVoted(voterId);

        JSONObject response = new JSONObject();
        response.put("has_voted", hasVoted);
        sendSuccessResponse(out, response);
    }

    private static void handleGetVoterDetails(PrintWriter out, JSONObject request) throws SQLException, Exception {
        if (!request.has("voter_id")) {
            sendErrorResponse(out, 400, "Missing voter_id");
            return;
        }

        JSONObject voter = DatabaseHelper.getVoterDetails(request.getString("voter_id"));
        if (voter != null) {
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("voter", voter);
            sendSuccessResponse(out, response);
        } else {
            sendErrorResponse(out, 404, "Voter not found");
        }
    }

    private static void handleGetTabulasi(PrintWriter out) {
        try {
            JSONObject tabulasiData = new JSONObject();

            // 1. Ambil data kandidat + hasil voting
            List<JSONObject> candidates = DatabaseHelper.getCandidatesWithVotes();

            // 2. Hitung total suara
            int totalVotes = candidates.stream()
                    .mapToInt(c -> c.getInt("vote_count"))
                    .sum();

            // 3. Hitung persentase per kandidat
            candidates.forEach(candidate -> {
                double percentage = totalVotes > 0
                        ? (candidate.getInt("vote_count") * 100.0 / totalVotes) : 0;
                candidate.put("percentage", Math.round(percentage * 100) / 100.0);
            });

            // 4. Format response
            tabulasiData.put("candidates", new JSONArray(candidates));
            tabulasiData.put("total_votes", totalVotes);

            // 5. Kirim response
            sendSuccessResponse(out, tabulasiData);

        } catch (Exception e) {
            System.err.println("Error in handleGetTabulasi: " + e.getMessage());
            sendErrorResponse(out, 500, "Failed to get tabulation data");
        }
    }

// Update handleVerifyEncryptedVote
    private static void handleVerifyEncryptedVote(PrintWriter out, JSONObject request) {
        try {
            if (!request.has("voter_id") || !request.has("encrypted_vote")
                    || !request.has("signature") || !request.has("private_key")) {
                sendErrorResponse(out, 400, "Missing required fields");
                return;
            }

            String voterId = request.getString("voter_id");
            String encryptedVote = request.getString("encrypted_vote");
            String signature = request.getString("signature");
            String privateKeyPem = request.getString("private_key");

            // 1. Verify voter exists and is active
            JSONObject voter = DatabaseHelper.getVoterDetails(voterId);
            if (voter == null || !voter.getBoolean("is_active")) {
                sendErrorResponse(out, 404, "Voter not found or not active");
                return;
            }

            // 2. Parse keys
            PrivateKey privateKey = KeyGenerator.getPrivateKeyFromString(privateKeyPem);
            PublicKey publicKey = KeyGenerator.getPublicKeyFromString(voter.getString("public_key"));

            // 3. Verify signature
            boolean isSignatureValid = KeyGenerator.verify(encryptedVote, signature, publicKey);

            // 4. Verify vote structure
            String decryptedVote = KeyGenerator.decryptVote(encryptedVote, privateKey);
            JSONObject voteData = new JSONObject(decryptedVote);

            if (!voteData.has("candidate_id")) {
                sendErrorResponse(out, 400, "Invalid vote format");
                return;
            }

            // 5. Verify candidate exists
            if (!DatabaseHelper.isValidCandidate(voteData.getString("candidate_id"))) {
                sendErrorResponse(out, 400, "Invalid candidate");
                return;
            }

            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("verified", true);
            response.put("integrity_check", isSignatureValid);
            response.put("timestamp", new Timestamp(System.currentTimeMillis()).toString());

            sendSuccessResponse(out, response);

        } catch (Exception e) {
            sendErrorResponse(out, 500, "Verification failed: " + e.getMessage());
        }
    }

    private static void sendSuccessResponse(PrintWriter out, JSONObject data) {
        out.println("HTTP/1.1 200 OK");
        out.println("Content-Type: application/json");
        out.println("Connection: close");
        out.println();
        out.println(data.toString());
    }

    private static void sendErrorResponse(PrintWriter out, int statusCode, String message) {
        JSONObject error = new JSONObject();
        error.put("status", "error");
        error.put("message", message);

        out.println("HTTP/1.1 " + statusCode + " " + getStatusMessage(statusCode));
        out.println("Content-Type: application/json");
        out.println("Connection: close");
        out.println();
        out.println(error.toString());
    }

    private static void handleGetElectionTime(PrintWriter out) throws SQLException {
        String sql = "SELECT start_time, end_time FROM election_settings ORDER BY id DESC LIMIT 1";

        try (Connection conn = DatabaseHelper.getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            JSONObject response = new JSONObject();
            if (rs.next()) {
                String startTimeStr = rs.getString("start_time");
                String endTimeStr = rs.getString("end_time");

                response.put("start_time", startTimeStr.replace(" ", "T"));
                response.put("end_time", endTimeStr.replace(" ", "T"));
            } else {
                response.put("start_time", "");
                response.put("end_time", "");
            }
            response.put("status", "success");
            sendSuccessResponse(out, response);
        }
    }

    private static void handleGetVotingStats(PrintWriter out) throws SQLException {
        try {
            JSONObject stats = new JSONObject();

            // 1. Total voters
            try (Connection conn = DatabaseHelper.getConnection();
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM voters")) {
                if (rs.next()) {
                    stats.put("total_voters", rs.getInt(1));
                }
            }

            // 2. Total votes
            try (Connection conn = DatabaseHelper.getConnection();
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM votes WHERE is_counted = 1")) {
                if (rs.next()) {
                    stats.put("total_votes", rs.getInt(1));
                }
            }

            // 2. Verified voters
            try (Connection conn = DatabaseHelper.getConnection();
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM voters WHERE is_active = 1")) {
                if (rs.next()) {
                    stats.put("verified_voters", rs.getInt(1));
                }
            }

            // 3. Voters who have voted
            try (Connection conn = DatabaseHelper.getConnection();
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM voted_voters")) {
                if (rs.next()) {
                    stats.put("voters_voted", rs.getInt(1));
                }
            }

            // 4. Total votes
            try (Connection conn = DatabaseHelper.getConnection();
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM votes")) {
                if (rs.next()) {
                    stats.put("total_votes", rs.getInt(1));
                }
            }

            // 5. Total candidates
            try (Connection conn = DatabaseHelper.getConnection();
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM candidates")) {
                if (rs.next()) {
                    stats.put("total_candidates", rs.getInt(1));
                }
            }

            // 6. Total officers
            try (Connection conn = DatabaseHelper.getConnection();
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM officers")) {
                if (rs.next()) {
                    stats.put("total_officers", rs.getInt(1));
                }
            }

            // 7. Election time info
            try (Connection conn = DatabaseHelper.getConnection();
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT start_time, end_time FROM election_settings ORDER BY id DESC LIMIT 1")) {

                if (rs.next()) {
                    String startTime = rs.getString("start_time");
                    String endTime = rs.getString("end_time");

                    stats.put("start_time", startTime);
                    stats.put("end_time", endTime);

                    // Parse and calculate election status
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                    try {
                        java.util.Date startDate = sdf.parse(startTime);
                        java.util.Date endDate = sdf.parse(endTime);
                        java.util.Date now = new java.util.Date();

                        if (now.before(startDate)) {
                            stats.put("election_status", "upcoming");
                            // Calculate time until election starts
                            long diff = startDate.getTime() - now.getTime();
                            long days = TimeUnit.MILLISECONDS.toDays(diff);
                            long hours = TimeUnit.MILLISECONDS.toHours(diff) % 24;
                            stats.put("time_until_start", days + " hari " + hours + " jam");
                        } else if (now.after(startDate) && now.before(endDate)) {
                            stats.put("election_status", "ongoing");
                            // Calculate time remaining
                            long diff = endDate.getTime() - now.getTime();
                            long days = TimeUnit.MILLISECONDS.toDays(diff);
                            long hours = TimeUnit.MILLISECONDS.toHours(diff) % 24;
                            stats.put("time_remaining", days + " hari " + hours + " jam");
                        } else {
                            stats.put("election_status", "ended");
                        }

                        // Format for display (Indonesian locale)
                        SimpleDateFormat displayFormat = new SimpleDateFormat("dd MMMM yyyy HH:mm", new Locale("id", "ID"));
                        stats.put("formatted_start_time", displayFormat.format(startDate));
                        stats.put("formatted_end_time", displayFormat.format(endDate));

                    } catch (ParseException e) {
                        // If parsing fails, keep the raw string
                        stats.put("formatted_start_time", startTime);
                        stats.put("formatted_end_time", endTime);
                    }
                } else {
                    stats.put("election_status", "not_set");
                }
            }

            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("stats", stats);
            sendSuccessResponse(out, response);

        } catch (SQLException e) {
            sendErrorResponse(out, 500, "Database error: " + e.getMessage());
        }
    }

    private static void handleSetElectionTime(PrintWriter out, JSONObject request) throws SQLException {
        if (!request.has("start_time") || !request.has("end_time") || !request.has("officer_id")) {
            sendErrorResponse(out, 400, "Missing required fields");
            return;
        }

        String sql = "INSERT INTO election_settings (start_time, end_time, updated_by) VALUES (?, ?, ?)";

        try (Connection conn = DatabaseHelper.getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            String startTime = request.getString("start_time").replace("T", " ");
            String endTime = request.getString("end_time").replace("T", " ");

            pstmt.setString(1, startTime);
            pstmt.setString(2, endTime);
            pstmt.setString(3, request.getString("officer_id"));

            int rowsInserted = pstmt.executeUpdate();

            JSONObject response = new JSONObject();
            if (rowsInserted > 0) {
                response.put("status", "success");
                response.put("message", "Waktu pemilihan berhasil diperbarui");
            } else {
                response.put("status", "error");
                response.put("message", "Gagal memperbarui waktu pemilihan");
            }
            sendSuccessResponse(out, response);
        }
    }

    private static void handleUpdateVoter(PrintWriter out, JSONObject request) throws SQLException {
        try {
            if (!request.has("voter_id") || !request.has("nama") || !request.has("tempat_lahir")
                    || !request.has("tanggal_lahir") || !request.has("jenis_kelamin")
                    || !request.has("alamat") || !request.has("status_pernikahan") || !request.has("email")) {
                sendErrorResponse(out, 400, "Missing required fields");
                return;
            }

            String sql = "UPDATE voters SET nama = ?, tempat_lahir = ?, tanggal_lahir = ?, "
                    + "jenis_kelamin = ?, alamat = ?, status_pernikahan = ?, email = ? "
                    + "WHERE voter_id = ?";

            try (Connection conn = DatabaseHelper.getConnection();
                    PreparedStatement pstmt = conn.prepareStatement(sql)) {

                pstmt.setString(1, request.getString("nama"));
                pstmt.setString(2, request.getString("tempat_lahir"));
                pstmt.setString(3, request.getString("tanggal_lahir"));
                pstmt.setString(4, request.getString("jenis_kelamin"));
                pstmt.setString(5, request.getString("alamat"));
                pstmt.setString(6, request.getString("status_pernikahan"));
                pstmt.setString(7, request.getString("email"));
                pstmt.setString(8, request.getString("voter_id"));

                int rowsUpdated = pstmt.executeUpdate();

                JSONObject response = new JSONObject();
                if (rowsUpdated > 0) {
                    JSONObject updatedVoter = DatabaseHelper.getVoterDetails(request.getString("voter_id"));
                    response.put("status", "success");
                    response.put("voter", updatedVoter);
                } else {
                    response.put("status", "error");
                    response.put("message", "Gagal memperbarui data pemilih");
                }
                sendSuccessResponse(out, response);
            }
        } catch (Exception e) {
            sendErrorResponse(out, 500, "Error: " + e.getMessage());
        }
    }

    public static boolean setElectionTime(Timestamp startTime, Timestamp endTime, String officerId) throws SQLException {
        String sql = "INSERT INTO election_settings (start_time, end_time, updated_by) VALUES (?, ?, ?)";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setTimestamp(1, startTime);
            pstmt.setTimestamp(2, endTime);
            pstmt.setString(3, officerId);

            return pstmt.executeUpdate() > 0;
        }
    }

    private static void handleRequestPasswordReset(PrintWriter out, JSONObject request) {
        try {
            if (!request.has("nik") || !request.has("email")) {
                sendErrorResponse(out, 400, "NIK dan email harus diisi");
                return;
            }

            String nik = request.getString("nik");
            String email = request.getString("email");

            // Check if NIK and email match
            JSONObject voter = DatabaseHelper.getVoterByNikAndEmail(nik, email);
            if (voter == null) {
                sendErrorResponse(out, 404, "NIK dan email tidak cocok dengan data pemilih");
                return;
            }

            // Generate OTP (6 digits)
            String otp = String.format("%06d", new Random().nextInt(999999));
            long otpExpiry = System.currentTimeMillis() + (5 * 60 * 1000); // 5 minutes from now

            // Save OTP to database
            boolean saved = DatabaseHelper.savePasswordResetOtp(voter.getString("voter_id"), otp, otpExpiry);
            if (!saved) {
                sendErrorResponse(out, 500, "Gagal memproses permintaan reset password");
                return;
            }

            // Send OTP via email
            new Thread(() -> {
                try {
                    EmailHelper.sendPasswordResetEmail(
                            email,
                            voter.getString("nama"),
                            otp
                    );
                } catch (Exception e) {
                    System.err.println("Failed to send password reset email: " + e.getMessage());
                }
            }).start();

            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("message", "OTP telah dikirim ke email Anda");
            response.put("voter_id", voter.getString("voter_id"));
            sendSuccessResponse(out, response);

        } catch (Exception e) {
            sendErrorResponse(out, 500, "Terjadi kesalahan: " + e.getMessage());
        }
    }

    private static void handleVerifyPasswordReset(PrintWriter out, JSONObject request) {
        try {
            if (!request.has("voter_id") || !request.has("otp")) {
                sendErrorResponse(out, 400, "Data tidak lengkap");
                return;
            }

            String voterId = request.getString("voter_id");
            String otp = request.getString("otp");

            // Verify OTP
            boolean isValid = DatabaseHelper.verifyPasswordResetOtp(voterId, otp);
            if (!isValid) {
                sendErrorResponse(out, 401, "OTP tidak valid atau sudah kadaluarsa");
                return;
            }

            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("message", "OTP valid");
            sendSuccessResponse(out, response);

        } catch (Exception e) {
            sendErrorResponse(out, 500, "Terjadi kesalahan: " + e.getMessage());
        }
    }

    private static void handleResetPassword(PrintWriter out, JSONObject request) {
        try {
            if (!request.has("voter_id") || !request.has("otp") || !request.has("new_password")) {
                sendErrorResponse(out, 400, "Data tidak lengkap");
                return;
            }

            String voterId = request.getString("voter_id");
            String otp = request.getString("otp");
            String newPassword = request.getString("new_password");

            // Verify OTP first
            boolean isValid = DatabaseHelper.verifyPasswordResetOtp(voterId, otp);
            if (!isValid) {
                sendErrorResponse(out, 401, "OTP tidak valid atau sudah kadaluarsa");
                return;
            }

            // Get voter details for email
            JSONObject voter = DatabaseHelper.getVoterDetails(voterId);
            if (voter == null) {
                sendErrorResponse(out, 404, "Data pemilih tidak ditemukan");
                return;
            }

            // Update password
            boolean updated = DatabaseHelper.updateVoterPassword(voterId, newPassword);
            if (!updated) {
                sendErrorResponse(out, 500, "Gagal memperbarui password");
                return;
            }

            // Clear used OTP
            DatabaseHelper.clearPasswordResetOtp(voterId);

            // Send success email in background thread
            new Thread(() -> {
                try {
                    EmailHelper.sendPasswordResetSuccessEmail(
                            voter.getString("email"),
                            voter.getString("nama")
                    );
                } catch (Exception e) {
                    System.err.println("Failed to send success email: " + e.getMessage());
                }
            }).start();

            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("message", "Password berhasil diperbarui");
            sendSuccessResponse(out, response);

        } catch (Exception e) {
            sendErrorResponse(out, 500, "Terjadi kesalahan: " + e.getMessage());
        }
    }

    private static void handleVerifyCurrentPassword(PrintWriter out, JSONObject request) throws SQLException {
        try {
            if (!request.has("voter_id") || !request.has("password")) {
                sendErrorResponse(out, 400, "Missing required fields");
                return;
            }

            String voterId = request.getString("voter_id");
            String password = request.getString("password");

            JSONObject voter = DatabaseHelper.getVoterDetails(voterId);
            if (voter == null) {
                sendErrorResponse(out, 404, "Voter not found");
                return;
            }

            // Verify password (you'll need to implement this in DatabaseHelper)
            boolean isVerified = DatabaseHelper.verifyVoterPassword(voterId, password);

            JSONObject response = new JSONObject();
            response.put("verified", isVerified);
            sendSuccessResponse(out, response);

        } catch (Exception e) {
            sendErrorResponse(out, 500, "Error verifying password: " + e.getMessage());
        }
    }

    private static void handleRequestPasswordChangeOtp(PrintWriter out, JSONObject request) {
        try {
            if (!request.has("voter_id")) {
                sendErrorResponse(out, 400, "Missing voter_id");
                return;
            }

            String voterId = request.getString("voter_id");
            JSONObject voter = DatabaseHelper.getVoterDetails(voterId);
            if (voter == null) {
                sendErrorResponse(out, 404, "Voter not found");
                return;
            }

            // Generate OTP (6 digits)
            String otp = String.format("%06d", new Random().nextInt(999999));
            long otpExpiry = System.currentTimeMillis() + (5 * 60 * 1000); // 5 minutes from now

            // Save OTP to database
            boolean saved = DatabaseHelper.savePasswordResetOtp(voterId, otp, otpExpiry);
            if (!saved) {
                sendErrorResponse(out, 500, "Failed to generate OTP");
                return;
            }

            // Send OTP via email
            new Thread(() -> {
                try {
                    EmailHelper.sendPasswordResetEmail(
                            voter.getString("email"),
                            voter.getString("nama"),
                            otp
                    );
                } catch (Exception e) {
                    System.err.println("Failed to send password reset email: " + e.getMessage());
                }
            }).start();

            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("message", "OTP has been sent to your email");
            sendSuccessResponse(out, response);

        } catch (Exception e) {
            sendErrorResponse(out, 500, "Error requesting OTP: " + e.getMessage());
        }
    }

    private static void handleVerifyPasswordChange(PrintWriter out, JSONObject request) {
        try {
            if (!request.has("voter_id") || !request.has("otp") || !request.has("new_password")) {
                sendErrorResponse(out, 400, "Missing required fields");
                return;
            }

            String voterId = request.getString("voter_id");
            String otp = request.getString("otp");
            String newPassword = request.getString("new_password");

            // Verify OTP first
            boolean isValid = DatabaseHelper.verifyPasswordResetOtp(voterId, otp);
            if (!isValid) {
                sendErrorResponse(out, 401, "Invalid or expired OTP");
                return;
            }

            // Update password
            boolean updated = DatabaseHelper.updateVoterPassword(voterId, newPassword);
            if (!updated) {
                sendErrorResponse(out, 500, "Failed to update password");
                return;
            }

            // Clear used OTP
            DatabaseHelper.clearPasswordResetOtp(voterId);

            // Get voter details for email
            JSONObject voter = DatabaseHelper.getVoterDetails(voterId);
            if (voter != null) {
                // Send success email in background thread
                new Thread(() -> {
                    try {
                        EmailHelper.sendPasswordResetSuccessEmail(
                                voter.getString("email"),
                                voter.getString("nama")
                        );
                    } catch (Exception e) {
                        System.err.println("Failed to send success email: " + e.getMessage());
                    }
                }).start();
            }

            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("message", "Password updated successfully");
            sendSuccessResponse(out, response);

        } catch (Exception e) {
            sendErrorResponse(out, 500, "Error changing password: " + e.getMessage());
        }
    }

    private static void handleListVotersWithVotingStatus(PrintWriter out, JSONObject request) throws SQLException {
        try {
            String statusFilter = request.optString("status", "all");

            String sql = "SELECT v.voter_id, v.nik, v.nama, v.email, v.is_active as is_verified, "
                    + "CASE WHEN vv.voter_id IS NOT NULL THEN 1 ELSE 0 END as has_voted "
                    + "FROM voters v LEFT JOIN voted_voters vv ON v.voter_id = vv.voter_id "
                    + "WHERE 1=1";

            // Apply filter
            if ("voted".equals(statusFilter)) {
                sql += " AND vv.voter_id IS NOT NULL";
            } else if ("not_voted".equals(statusFilter)) {
                sql += " AND vv.voter_id IS NULL";
            }

            sql += " ORDER BY v.registered_at DESC";

            List<JSONObject> voters = new ArrayList<>();
            try (Connection conn = DatabaseHelper.getConnection();
                    PreparedStatement pstmt = conn.prepareStatement(sql)) {

                ResultSet rs = pstmt.executeQuery();
                while (rs.next()) {
                    JSONObject voter = new JSONObject();
                    voter.put("voter_id", rs.getString("voter_id"));
                    voter.put("nik", rs.getString("nik"));
                    voter.put("nama", rs.getString("nama"));
                    voter.put("email", rs.getString("email"));
                    voter.put("is_verified", rs.getBoolean("is_verified"));
                    voter.put("has_voted", rs.getBoolean("has_voted"));
                    voters.add(voter);
                }
            }

            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("voters", voters);
            sendSuccessResponse(out, response);

        } catch (SQLException e) {
            sendErrorResponse(out, 500, "Database error");
        }
    }

    private static void handleApproveLogin(PrintWriter out, JSONObject request) throws SQLException {
        if (!request.has("voter_id") || !request.has("officer_id") || !request.has("action")) {
            sendErrorResponse(out, 400, "Missing required fields");
            return;
        }

        String voterId = request.getString("voter_id");
        String officerId = request.getString("officer_id");
        String action = request.getString("action");

        boolean updated;
        if ("approve".equals(action)) {
            updated = DatabaseHelper.approveVoterLogin(voterId, officerId);

            // Kirim email notifikasi jika berhasil
            if (updated) {
                new Thread(() -> {
                    try {
                        JSONObject voterDetails = DatabaseHelper.getVoterDetails(voterId);
                        if (voterDetails != null) {
                            EmailHelper.sendLoginApprovalEmail(
                                    voterDetails.getString("email"),
                                    voterDetails.getString("nama")
                            );
                        }
                    } catch (Exception e) {
                        System.err.println("Failed to send approval email: " + e.getMessage());
                    }
                }).start();
            }
        } else {
            updated = DatabaseHelper.rejectVoterLogin(voterId);
        }

        JSONObject response = new JSONObject();
        if (updated) {
            response.put("status", "success");
            response.put("message", "Voter login status updated");
        } else {
            response.put("status", "error");
            response.put("message", "Failed to update voter login status");
        }
        sendSuccessResponse(out, response);
    }

    private static void handleGetPendingLogins(PrintWriter out) throws SQLException {
        // Get all voters with login status (not just pending)
        String sql = "SELECT v.voter_id, v.nik, v.nama, v.email, v.is_active, "
                + "CASE WHEN la.approved = 1 THEN 1 ELSE 0 END as login_approved "
                + "FROM voters v "
                + "LEFT JOIN login_approvals la ON v.voter_id = la.voter_id "
                + "WHERE v.is_active = TRUE";

        List<JSONObject> voters = new ArrayList<>();
        try (Connection conn = DatabaseHelper.getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                JSONObject voter = new JSONObject();
                voter.put("voter_id", rs.getString("voter_id"));
                voter.put("nik", rs.getString("nik"));
                voter.put("nama", rs.getString("nama"));
                voter.put("email", rs.getString("email"));
                voter.put("is_active", rs.getBoolean("is_active"));
                voter.put("login_approved", rs.getBoolean("login_approved"));
                voters.add(voter);
            }
        }

        JSONObject response = new JSONObject();
        response.put("status", "success");
        response.put("voters", voters);
        sendSuccessResponse(out, response);
    }

    private static void handleGetSpecialOfficer(PrintWriter out) throws SQLException {
        JSONObject officer = DatabaseHelper.getSpecialOfficer();
        if (officer != null) {
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("officer", officer);
            sendSuccessResponse(out, response);
        } else {
            sendErrorResponse(out, 404, "Special officer not found");
        }
    }

    private static void handleVerifySignature(PrintWriter out, JSONObject request) {
        try {
            if (!request.has("data") || !request.has("signature")) {
                sendErrorResponse(out, 400, "Missing data or signature");
                return;
            }

            JSONObject specialOfficer = DatabaseHelper.getSpecialOfficer();
            if (specialOfficer == null) {
                sendErrorResponse(out, 500, "Special officer not configured");
                return;
            }

            String data = request.getString("data");
            String signature = request.getString("signature");
            String publicKey = specialOfficer.getString("public_key");

            boolean isValid = KeyGenerator.verify(data, signature,
                    KeyGenerator.getPublicKeyFromString(publicKey));

            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("verified", isValid);
            sendSuccessResponse(out, response);

        } catch (Exception e) {
            sendErrorResponse(out, 500, "Verification failed: " + e.getMessage());
        }
    }

    private static void handleCreateSignature(PrintWriter out, JSONObject request) {
        try {
            if (!request.has("data")) {
                sendErrorResponse(out, 400, "Missing data");
                return;
            }

            JSONObject specialOfficer = DatabaseHelper.getSpecialOfficer();
            if (specialOfficer == null) {
                sendErrorResponse(out, 500, "Special officer not configured");
                return;
            }

            String data = request.getString("data");
            String privateKey = specialOfficer.getString("private_key");

            String signature = KeyGenerator.sign(data,
                    KeyGenerator.getPrivateKeyFromString(privateKey));

            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("signature", signature);
            sendSuccessResponse(out, response);

        } catch (Exception e) {
            sendErrorResponse(out, 500, "Signature creation failed: " + e.getMessage());
        }
    }

    private static void handleEncryptData(PrintWriter out, JSONObject request) {
        try {
            if (!request.has("data")) {
                sendErrorResponse(out, 400, "Missing data");
                return;
            }

            JSONObject specialOfficer = DatabaseHelper.getSpecialOfficer();
            if (specialOfficer == null) {
                sendErrorResponse(out, 500, "Special officer not configured");
                return;
            }

            String data = request.getString("data");
            String publicKey = specialOfficer.getString("public_key");

            String encryptedData = KeyGenerator.encrypt(data,
                    KeyGenerator.getPublicKeyFromString(publicKey));

            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("encrypted_data", encryptedData);
            sendSuccessResponse(out, response);

        } catch (Exception e) {
            sendErrorResponse(out, 500, "Encryption failed: " + e.getMessage());
        }
    }

    private static void handleCheckSpecialOfficer(PrintWriter out, JSONObject request) throws SQLException {
        if (!request.has("officer_id")) {
            sendErrorResponse(out, 400, "Missing officer_id");
            return;
        }

        boolean isSpecial = DatabaseHelper.isSpecialOfficer(request.getString("officer_id"));

        JSONObject response = new JSONObject();
        response.put("status", "success");
        response.put("is_special", isSpecial);
        sendSuccessResponse(out, response);
    }

    private static void handleDecryptVotes(PrintWriter out, JSONObject request) {
        try {
            System.out.println("[DEBUG] Starting decrypt votes process");

            // 1. Validate input
            if (!request.has("officer_id") || !request.has("private_key")) {
                System.err.println("[ERROR] Missing required fields");
                sendErrorResponse(out, 400, "Missing required fields");
                return;
            }

            String officerId = request.getString("officer_id");
            String privateKeyPem = request.getString("private_key");
            System.out.println("[DEBUG] Officer ID: " + officerId);

            // 2. Verify special officer
            System.out.println("[DEBUG] Verifying officer...");
            JSONObject officer = DatabaseHelper.getOfficerById(officerId);
            if (officer == null || !officer.optBoolean("is_special", false)) {
                System.err.println("[ERROR] Unauthorized access attempt by officer: " + officerId);
                sendErrorResponse(out, 403, "Unauthorized access");
                return;
            }

            // 3. Verify key pair
            System.out.println("[DEBUG] Verifying key pair...");
            try {
                PublicKey publicKey = KeyGenerator.getPublicKeyFromString(officer.getString("public_key"));
                PrivateKey privateKey = KeyGenerator.getPrivateKeyFromString(privateKeyPem);

                String testData = "TEST_" + System.currentTimeMillis();
                System.out.println("[DEBUG] Test data: " + testData);

                String signature = KeyGenerator.sign(testData, privateKey);
                System.out.println("[DEBUG] Signature generated");

                boolean isValid = KeyGenerator.verify(testData, signature, publicKey);
                System.out.println("[DEBUG] Key verification result: " + isValid);

                if (!isValid) {
                    System.err.println("[ERROR] Invalid key pair");
                    sendErrorResponse(out, 401, "Invalid key pair");
                    return;
                }
            } catch (Exception e) {
                System.err.println("[ERROR] Key verification failed: " + e.getMessage());
                e.printStackTrace();
                sendErrorResponse(out, 400, "Key verification failed: " + e.getMessage());
                return;
            }

            // 4. Get encrypted votes
            System.out.println("[DEBUG] Retrieving encrypted votes...");
            List<JSONObject> encryptedVotes = DatabaseHelper.getAllEncryptedVotes();
            System.out.println("[DEBUG] Found " + encryptedVotes.size() + " votes to decrypt");

            JSONArray votes = new JSONArray();
            int validVotes = 0;
            int invalidVotes = 0;

            // 5. Process each vote
            for (JSONObject encryptedVote : encryptedVotes) {
                JSONObject voteResult = new JSONObject();
                String voteId = encryptedVote.getString("vote_id");
                voteResult.put("vote_id", voteId);
                System.out.println("[DEBUG] Processing vote ID: " + voteId);

                try {
                    // 5.1 Decrypt vote
                    String encryptedData = encryptedVote.getString("encrypted_vote");
                    System.out.println("[DEBUG] Encrypted data length: " + encryptedData.length());

                    String decrypted = KeyGenerator.decryptVote(
                            encryptedData,
                            KeyGenerator.getPrivateKeyFromString(privateKeyPem)
                    );
                    System.out.println("[DEBUG] Decrypted data: " + decrypted);

                    // 5.2 Parse JSON - PERBAIKAN DI SINI
                    JSONObject voteData = new JSONObject(decrypted);

                    // Menerima format dengan field 'c' atau 'candidate_id'
                    String candidateId = voteData.optString("candidate_id", voteData.optString("c"));
                    System.out.println("[DEBUG] Candidate ID from vote: " + candidateId);

                    if (candidateId == null || candidateId.isEmpty()) {
                        throw new Exception("Invalid vote format - missing candidate ID (baik 'c' maupun 'candidate_id')");
                    }

                    // 5.3 Validate candidate
                    boolean isValidCandidate = DatabaseHelper.isValidCandidate(candidateId);
                    System.out.println("[DEBUG] Candidate validation result: " + isValidCandidate);

                    voteResult.put("candidate_id", candidateId);
                    voteResult.put("status", isValidCandidate ? "valid" : "invalid");

                    if (isValidCandidate) {
                        validVotes++;
                        // 5.4 Update database
                        boolean updateSuccess = DatabaseHelper.updateDecryptedVote(voteId, candidateId);
                        System.out.println("[DEBUG] Vote update result: " + updateSuccess);
                    } else {
                        invalidVotes++;
                    }
                } catch (Exception e) {
                    System.err.println("[ERROR] Error processing vote " + voteId + ": " + e.getMessage());
                    e.printStackTrace();
                    voteResult.put("status", "error");
                    voteResult.put("message", "Decryption failed: " + e.getMessage());
                    invalidVotes++;
                }
                votes.put(voteResult);
            }
            // 6. Get candidates for reference
            System.out.println("[DEBUG] Retrieving candidates list...");
            List<JSONObject> candidates = DatabaseHelper.getAllCandidates();

            // 7. Prepare response
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("valid_votes", validVotes);
            response.put("invalid_votes", invalidVotes);
            response.put("votes", votes);
            response.put("candidates", candidates);

            System.out.println("[DEBUG] Sending success response");
            sendSuccessResponse(out, response);

        } catch (Exception e) {
            System.err.println("[FATAL ERROR] in handleDecryptVotes: " + e.getMessage());
            e.printStackTrace();
            sendErrorResponse(out, 500, "Decryption process failed: " + e.getMessage());
        }
    }

// Helper method to abbreviate long data in logs
    private static String abbreviateData(String data) {
        if (data == null) {
            return "null";
        }
        if (data.length() <= 100) {
            return data;
        }
        return data.substring(0, 100) + "... [length=" + data.length() + "]";
    }

    private static void handleGetVoterDetailsWithLoginStatus(PrintWriter out, JSONObject request) throws SQLException, Exception {
        if (!request.has("voter_id")) {
            sendErrorResponse(out, 400, "Missing voter_id");
            return;
        }

        JSONObject voter = DatabaseHelper.getVoterDetailsWithLoginStatus(request.getString("voter_id"));
        if (voter != null) {
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("voter", voter);
            sendSuccessResponse(out, response);
        } else {
            sendErrorResponse(out, 404, "Voter not found");
        }
    }

    private static String getStatusMessage(int statusCode) {
        switch (statusCode) {
            case 200:
                return "OK";
            case 400:
                return "Bad Request";
            case 401:
                return "Unauthorized";
            case 403:
                return "Forbidden";
            case 404:
                return "Not Found";
            case 500:
                return "Internal Server Error";
            default:
                return "Unknown Status";
        }
    }

}
