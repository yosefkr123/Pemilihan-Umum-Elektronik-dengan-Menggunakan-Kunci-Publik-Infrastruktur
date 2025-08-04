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
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
import static backend.KeyGenerator.hashData;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.sql.*;
import java.util.*;
import org.json.JSONObject;
import org.json.JSONArray;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import org.json.JSONException;

public class DatabaseHelper {

    private static final String DB_URL = "jdbc:sqlite:evoting.db";
    private static Connection connection;
    private static final String ADMIN_EMAIL = "yosefgrogot123@gmail.com";

    static {
        try {
            Class.forName("org.sqlite.JDBC");
            initializeDatabase();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static synchronized Connection getConnection() throws SQLException {
        if (connection == null || connection.isClosed()) {
            connection = DriverManager.getConnection(DB_URL);
        }
        return connection;
    }

    public static void initializeDatabase() throws SQLException, Exception {
        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement()) {

            stmt.execute("PRAGMA foreign_keys = ON");

            // Voters table
            stmt.executeUpdate(
                    "CREATE TABLE IF NOT EXISTS voters ("
                    + "voter_id TEXT PRIMARY KEY, "
                    + "nik TEXT UNIQUE NOT NULL, "
                    + "nama TEXT NOT NULL, "
                    + "tempat_lahir TEXT NOT NULL, "
                    + "tanggal_lahir TEXT NOT NULL, "
                    + "jenis_kelamin TEXT NOT NULL, "
                    + "alamat TEXT NOT NULL, "
                    + "status_pernikahan TEXT NOT NULL, "
                    + "email TEXT NOT NULL, "
                    + "password TEXT NOT NULL, "
                    + "public_key TEXT NOT NULL, "
                    + "is_active BOOLEAN DEFAULT FALSE, "
                    + "registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
            );

            // Password reset OTPs
            stmt.executeUpdate(
                    "CREATE TABLE IF NOT EXISTS password_reset_otps ("
                    + "voter_id TEXT PRIMARY KEY, "
                    + "otp TEXT NOT NULL, "
                    + "expiry_time INTEGER NOT NULL, "
                    + "FOREIGN KEY (voter_id) REFERENCES voters (voter_id))"
            );

            // Officers table
            stmt.executeUpdate(
                    "CREATE TABLE IF NOT EXISTS officers ("
                    + "officer_id TEXT PRIMARY KEY, "
                    + "username TEXT UNIQUE NOT NULL, "
                    + "password TEXT NOT NULL, "
                    + "nama TEXT NOT NULL, "
                    + "created_by TEXT, "
                    + "is_special BOOLEAN DEFAULT FALSE, "
                    + "public_key TEXT, "
                    + "private_key TEXT, "
                    + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
            );

            // Election settings
            stmt.executeUpdate(
                    "CREATE TABLE IF NOT EXISTS election_settings ("
                    + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    + "start_time TIMESTAMP NOT NULL, "
                    + "end_time TIMESTAMP NOT NULL, "
                    + "updated_by TEXT, "
                    + "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
            );

            // Candidates table
            stmt.executeUpdate(
                    "CREATE TABLE IF NOT EXISTS candidates ("
                    + "candidate_id TEXT PRIMARY KEY, "
                    + "nama TEXT NOT NULL, "
                    + "partai TEXT, "
                    + "nomor_urut INTEGER UNIQUE, "
                    + "photo_url TEXT, "
                    + "created_by TEXT, "
                    + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
            );

            // Voted voters table (only tracks who has voted)
            stmt.executeUpdate(
                    "CREATE TABLE IF NOT EXISTS voted_voters ("
                    + "voter_id TEXT PRIMARY KEY, "
                    + "voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
            );
            stmt.executeUpdate(
                    "CREATE TABLE IF NOT EXISTS login_approvals ("
                    + "voter_id TEXT PRIMARY KEY, "
                    + "approved BOOLEAN DEFAULT FALSE, "
                    + "approved_by TEXT, "
                    + "approved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
                    + "FOREIGN KEY (voter_id) REFERENCES voters (voter_id))"
            );

            // Votes table (completely anonymous)
            stmt.executeUpdate(
                    "CREATE TABLE IF NOT EXISTS votes ("
                    + "vote_id TEXT PRIMARY KEY, "
                    + "encrypted_vote TEXT NOT NULL, "
                    + "officer_signature TEXT NOT NULL, "
                    + "vote_hash TEXT NOT NULL, "
                    + "decrypted_candidate_id TEXT, "
                    + "is_counted BOOLEAN DEFAULT FALSE, "
                    + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
            );

            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM officers WHERE username = 'admin'");
            if (rs.getInt(1) == 0) {
                // Generate key pair untuk admin with a seed
                KeyPair keyPair = KeyGenerator.generateKeyPair("admin_secret_seed_123");
                String publicKey = KeyGenerator.keyToPEM(keyPair.getPublic());
                String privateKey = KeyGenerator.keyToPEM(keyPair.getPrivate());

                stmt.executeUpdate(
                        "INSERT INTO officers (officer_id, username, password, nama, "
                        + "is_special, public_key, private_key, created_by) VALUES ("
                        + "'ADM001', "
                        + "'admin', "
                        + "'" + KeyGenerator.hashData("admin123") + "', "
                        + "'Administrator', "
                        + "TRUE, "
                        + "'" + publicKey + "', "
                        + "'" + privateKey + "', "
                        + "'system')"
                );
                new Thread(() -> {
                    try {
                        EmailHelper.sendPrivateKeyEmail(ADMIN_EMAIL, "Administrator", privateKey);
                        System.out.println("Admin private key sent to email: " + ADMIN_EMAIL);
                    } catch (Exception e) {
                        System.err.println("Failed to send admin private key email: " + e.getMessage());
                    }
                }).start();
            } else {
                // Update admin jika sudah ada tapi belum di-set sebagai special
                rs = stmt.executeQuery("SELECT is_special FROM officers WHERE username = 'admin'");
                if (!rs.next() || !rs.getBoolean("is_special")) {
                    // Generate key pair untuk admin with a seed
                    KeyPair keyPair = KeyGenerator.generateKeyPair("admin_secret_seed_123");
                    String publicKey = KeyGenerator.keyToPEM(keyPair.getPublic());
                    String privateKey = KeyGenerator.keyToPEM(keyPair.getPrivate());

                    stmt.executeUpdate(
                            "UPDATE officers SET "
                            + "is_special = TRUE, "
                            + "public_key = '" + publicKey + "', "
                            + "private_key = '" + privateKey + "' "
                            + "WHERE username = 'admin'"
                    );
                    new Thread(() -> {
                        try {
                            EmailHelper.sendPrivateKeyEmail(ADMIN_EMAIL, "Administrator", privateKey);
                            System.out.println("Admin private key sent to email: " + ADMIN_EMAIL);
                        } catch (Exception e) {
                            System.err.println("Failed to send admin private key email: " + e.getMessage());
                        }
                    }).start();
                }
            }
        }
    }

    public static boolean updateVoterVerification(String voterId, boolean isVerified) throws SQLException {
        String sql = "UPDATE voters SET is_active = ? WHERE voter_id = ?";
        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setBoolean(1, isVerified);
            pstmt.setString(2, voterId);

            int rowsUpdated = pstmt.executeUpdate();
            return rowsUpdated > 0;
        }
    }

    public static JSONObject getVoterDetails(String voterId) throws SQLException, Exception {
        String sql = "SELECT voter_id, nik, nama, tempat_lahir, tanggal_lahir, "
                + "jenis_kelamin, alamat, status_pernikahan, email, public_key, is_active, "
                + "registered_at FROM voters WHERE voter_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, voterId);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject voter = new JSONObject();
                voter.put("voter_id", rs.getString("voter_id"));
                voter.put("nik", rs.getString("nik"));
                voter.put("nama", rs.getString("nama"));
                voter.put("tempat_lahir", rs.getString("tempat_lahir"));
                voter.put("tanggal_lahir", rs.getString("tanggal_lahir"));
                voter.put("jenis_kelamin", rs.getString("jenis_kelamin"));
                voter.put("alamat", rs.getString("alamat"));
                voter.put("status_pernikahan", rs.getString("status_pernikahan"));
                voter.put("email", rs.getString("email"));
                // Ensure proper PEM format for public key
                String publicKey = rs.getString("public_key");
                if (!publicKey.contains("BEGIN PUBLIC KEY")) {
                    publicKey = KeyGenerator.keyToPEM(
                            KeyGenerator.getPublicKeyFromString(publicKey)
                    );
                }
                voter.put("public_key", rs.getString("public_key"));
                voter.put("is_active", rs.getBoolean("is_active"));
                voter.put("registered_at", rs.getString("registered_at"));
                return voter;
            }
            return null;
        }
    }

    public static List<JSONObject> getAllOfficers() throws SQLException {
        String sql = "SELECT officer_id, username, nama, created_by, created_at FROM officers ORDER BY created_at DESC";
        List<JSONObject> officers = new ArrayList<>();

        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                JSONObject officer = new JSONObject();
                officer.put("officer_id", rs.getString("officer_id"));
                officer.put("username", rs.getString("username"));
                officer.put("nama", rs.getString("nama"));
                officer.put("created_by", rs.getString("created_by"));
                officer.put("created_at", rs.getString("created_at"));
                officers.add(officer);
            }
        }
        return officers;
    }

    public static JSONObject getOfficerById(String officerId) throws SQLException {
        String sql = "SELECT *, (is_special = 1) as is_special FROM officers WHERE officer_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, officerId);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    JSONObject officer = new JSONObject();
                    officer.put("officer_id", rs.getString("officer_id"));
                    officer.put("username", rs.getString("username"));
                    officer.put("nama", rs.getString("nama"));
                    officer.put("is_special", rs.getBoolean("is_special"));
                    officer.put("public_key", rs.getString("public_key"));
                    return officer;
                }
            }
        }
        return null;
    }

    public static boolean updateOfficer(String officerId, String username, String nama, String password) throws Exception {
        if (password != null && !password.isEmpty()) {
            String sql = "UPDATE officers SET username = ?, nama = ?, password = ? WHERE officer_id = ?";

            try (Connection conn = getConnection();
                    PreparedStatement pstmt = conn.prepareStatement(sql)) {

                pstmt.setString(1, username);
                pstmt.setString(2, nama);
                pstmt.setString(3, KeyGenerator.hashData(password));
                pstmt.setString(4, officerId);

                return pstmt.executeUpdate() > 0;
            }
        } else {
            String sql = "UPDATE officers SET username = ?, nama = ? WHERE officer_id = ?";

            try (Connection conn = getConnection();
                    PreparedStatement pstmt = conn.prepareStatement(sql)) {

                pstmt.setString(1, username);
                pstmt.setString(2, nama);
                pstmt.setString(3, officerId);

                return pstmt.executeUpdate() > 0;
            }
        }
    }

    public static boolean deleteOfficer(String officerId) throws SQLException {
        if ("ADM001".equals(officerId)) {
            return false;
        }

        String sql = "DELETE FROM officers WHERE officer_id = ?";
        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, officerId);
            return pstmt.executeUpdate() > 0;
        }
    }

    public static List<JSONObject> getAllCandidates() throws SQLException {
        String sql = "SELECT c.*, o.nama as created_by_name FROM candidates c "
                + "LEFT JOIN officers o ON c.created_by = o.officer_id "
                + "ORDER BY c.nomor_urut";
        List<JSONObject> candidates = new ArrayList<>();

        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                JSONObject candidate = new JSONObject();
                candidate.put("candidate_id", rs.getString("candidate_id"));
                candidate.put("nama", rs.getString("nama"));
                candidate.put("partai", rs.getString("partai"));
                candidate.put("nomor_urut", rs.getInt("nomor_urut"));
                candidate.put("photo_url", rs.getString("photo_url"));
                candidate.put("created_by", rs.getString("created_by_name"));
                candidate.put("created_at", rs.getString("created_at"));
                candidates.add(candidate);
            }
        }
        return candidates;
    }

    public static JSONObject getCandidateById(String candidateId) throws SQLException {
        String sql = "SELECT c.*, o.nama as created_by_name FROM candidates c "
                + "LEFT JOIN officers o ON c.created_by = o.officer_id "
                + "WHERE c.candidate_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, candidateId);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject candidate = new JSONObject();
                candidate.put("candidate_id", rs.getString("candidate_id"));
                candidate.put("nama", rs.getString("nama"));
                candidate.put("partai", rs.getString("partai"));
                candidate.put("nomor_urut", rs.getInt("nomor_urut"));
                candidate.put("photo_url", rs.getString("photo_url"));
                candidate.put("created_by", rs.getString("created_by_name"));
                candidate.put("created_at", rs.getString("created_at"));
                return candidate;
            }
            return null;
        }
    }

    public static boolean updateCandidate(String candidateId, String nama, String partai,
            int nomorUrut, String photoUrl) throws SQLException {
        if (photoUrl != null) {
            String sql = "UPDATE candidates SET nama = ?, partai = ?, nomor_urut = ?, photo_url = ? WHERE candidate_id = ?";

            try (Connection conn = getConnection();
                    PreparedStatement pstmt = conn.prepareStatement(sql)) {

                pstmt.setString(1, nama);
                pstmt.setString(2, partai);
                pstmt.setInt(3, nomorUrut);
                pstmt.setString(4, photoUrl);
                pstmt.setString(5, candidateId);

                return pstmt.executeUpdate() > 0;
            }
        } else {
            String sql = "UPDATE candidates SET nama = ?, partai = ?, nomor_urut = ? WHERE candidate_id = ?";

            try (Connection conn = getConnection();
                    PreparedStatement pstmt = conn.prepareStatement(sql)) {

                pstmt.setString(1, nama);
                pstmt.setString(2, partai);
                pstmt.setInt(3, nomorUrut);
                pstmt.setString(4, candidateId);

                return pstmt.executeUpdate() > 0;
            }
        }
    }

    public static boolean deleteCandidate(String candidateId) throws SQLException {
        String sql = "DELETE FROM candidates WHERE candidate_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, candidateId);
            return pstmt.executeUpdate() > 0;
        }
    }

    public static boolean saveVoter(String voterId, String nik, String nama,
            String tempatLahir, String tanggalLahir,
            String jenisKelamin, String alamat,
            String statusPernikahan, String email,
            String password, String publicKey) throws SQLException, Exception {

        // Validate public key format before storing
        try {
            KeyGenerator.getPublicKeyFromString(publicKey);
        } catch (Exception e) {
            throw new Exception("Invalid public key format: " + e.getMessage());
        }
        String sql = "INSERT INTO voters(voter_id, nik, nama, tempat_lahir, "
                + "tanggal_lahir, jenis_kelamin, alamat, status_pernikahan, "
                + "email, password, public_key, is_active) "
                + "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, voterId);
            pstmt.setString(2, nik);
            pstmt.setString(3, nama);
            pstmt.setString(4, tempatLahir);
            pstmt.setString(5, tanggalLahir);
            pstmt.setString(6, jenisKelamin);
            pstmt.setString(7, alamat);
            pstmt.setString(8, statusPernikahan);
            pstmt.setString(9, email);
            pstmt.setString(10, KeyGenerator.hashData(password));
            pstmt.setString(11, publicKey);
            pstmt.setBoolean(12, false);

            return pstmt.executeUpdate() > 0;
        }
    }

    public static JSONObject getVoterByNik(String nik) throws SQLException {
        String sql = "SELECT voter_id, nik, nama, public_key FROM voters WHERE nik = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, nik);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject voter = new JSONObject();
                voter.put("voter_id", rs.getString("voter_id"));
                voter.put("nik", rs.getString("nik"));
                voter.put("nama", rs.getString("nama"));
                voter.put("public_key", rs.getString("public_key"));
                return voter;
            }
            return null;
        }
    }

    public static JSONObject getVoterByVoterId(String voterId) throws SQLException {
        System.out.println("[DB_DEBUG] Fetching voter: " + voterId); // Debug log

        String sql = "SELECT voter_id, nik, nama, is_active, public_key FROM voters WHERE voter_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, voterId);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject voter = new JSONObject();
                voter.put("voter_id", rs.getString("voter_id"));
                voter.put("nik", rs.getString("nik"));
                voter.put("nama", rs.getString("nama"));
                voter.put("is_active", rs.getBoolean("is_active")); // CRITICAL FIELD

                String publicKey = rs.getString("public_key");
                if (!publicKey.contains("BEGIN PUBLIC KEY")) {
                    publicKey = "-----BEGIN PUBLIC KEY-----\n"
                            + publicKey.replaceAll("(.{64})", "$1\n")
                            + "\n-----END PUBLIC KEY-----\n";
                }
                voter.put("public_key", publicKey);

                System.out.println("[DB_DEBUG] Voter data: " + voter); // Debug log
                return voter;
            }
            System.out.println("[DB_DEBUG] Voter not found"); // Debug log
            return null;
        }
    }

    public static JSONObject authenticateVoter(String nik, String password) throws Exception {
        String sql = "SELECT voter_id, nik, nama, public_key, is_active FROM voters "
                + "WHERE nik = ? AND password = ? LIMIT 1";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // Hash password input sebelum query
            pstmt.setString(1, nik);
            pstmt.setString(2, KeyGenerator.hashData(password));

            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject voter = new JSONObject();
                voter.put("voter_id", rs.getString("voter_id"));
                voter.put("nik", rs.getString("nik"));
                voter.put("nama", rs.getString("nama"));

                // Pastikan public key dalam format yang benar
                String publicKey = rs.getString("public_key");
                if (!publicKey.contains("BEGIN PUBLIC KEY")) {
                    publicKey = "-----BEGIN PUBLIC KEY-----\n"
                            + publicKey.replaceAll("(.{64})", "$1\n")
                            + "\n-----END PUBLIC KEY-----\n";
                }
                voter.put("public_key", publicKey);

                voter.put("is_active", rs.getBoolean("is_active"));
                return voter;
            }
            return null;
        }
    }

    public static boolean saveOfficer(String officerId, String username, String password,
            String nama, String createdBy) throws Exception {
        String sql = "INSERT INTO officers(officer_id, username, password, nama, created_by) "
                + "VALUES(?,?,?,?,?)";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, officerId);
            pstmt.setString(2, username);
            pstmt.setString(3, KeyGenerator.hashData(password));
            pstmt.setString(4, nama);
            pstmt.setString(5, createdBy);

            return pstmt.executeUpdate() > 0;
        }
    }

    public static JSONObject authenticateOfficer(String username, String password) throws Exception {
        String sql = "SELECT officer_id, username, nama FROM officers WHERE username = ? AND password = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username);
            pstmt.setString(2, KeyGenerator.hashData(password));
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject officer = new JSONObject();
                officer.put("officer_id", rs.getString("officer_id"));
                officer.put("username", rs.getString("username"));
                officer.put("nama", rs.getString("nama"));
                return officer;
            }
            return null;
        }
    }

    public static boolean saveCandidate(String candidateId, String nama, String partai,
            int nomorUrut, String photoUrl, String createdBy) throws SQLException {
        String sql = "INSERT INTO candidates(candidate_id, nama, partai, nomor_urut, photo_url, created_by) "
                + "VALUES(?,?,?,?,?,?)";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, candidateId);
            pstmt.setString(2, nama);
            pstmt.setString(3, partai);
            pstmt.setInt(4, nomorUrut);
            pstmt.setString(5, photoUrl);
            pstmt.setString(6, createdBy);

            return pstmt.executeUpdate() > 0;
        }
    }

    public static JSONObject getVoterByVoterId(Connection conn, String voterId) throws SQLException {
        System.out.println("[DEBUG] Getting voter by ID: " + voterId);
        String sql = "SELECT voter_id, nik, nama, public_key FROM voters WHERE voter_id = ?";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, voterId);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject voter = new JSONObject();
                voter.put("voter_id", rs.getString("voter_id"));
                voter.put("nik", rs.getString("nik"));
                voter.put("nama", rs.getString("nama"));

                String publicKey = rs.getString("public_key");
                if (!publicKey.contains("BEGIN PUBLIC KEY")) {
                    publicKey = "-----BEGIN PUBLIC KEY-----\n"
                            + publicKey.replaceAll("(.{64})", "$1\n")
                            + "\n-----END PUBLIC KEY-----\n";
                }
                voter.put("public_key", publicKey);

                System.out.println("[DEBUG] Voter found: " + voter.toString());
                return voter;
            }
            System.out.println("[DEBUG] Voter not found");
            return null;
        }
    }

    public static boolean saveVote(String voteId, String encryptedVote,
            String officerSignature, String voteHash) throws SQLException {
        Connection conn = null;
        boolean isSuccess = false;

        try {
            conn = getConnection();
            conn.setAutoCommit(false); // Start transaction

            // 1. Validasi hash unik
            try (PreparedStatement checkHash = conn.prepareStatement(
                    "SELECT 1 FROM votes WHERE vote_hash = ?")) {
                checkHash.setString(1, voteHash);
                if (checkHash.executeQuery().next()) {
                    throw new SQLException("Duplicate vote hash");
                }
            }

            // 2. Simpan vote anonim
            try (PreparedStatement insertVote = conn.prepareStatement(
                    "INSERT INTO votes (vote_id, encrypted_vote, officer_signature, vote_hash) "
                    + "VALUES (?, ?, ?, ?)")) {

                insertVote.setString(1, voteId);
                insertVote.setString(2, encryptedVote);
                insertVote.setString(3, officerSignature);
                insertVote.setString(4, voteHash);

                int affectedRows = insertVote.executeUpdate();
                if (affectedRows == 0) {
                    throw new SQLException("Failed to insert vote");
                }

                conn.commit();
                isSuccess = true;
                System.out.println("[DB] Vote saved successfully. ID: " + voteId);
            }
        } catch (SQLException e) {
            if (conn != null) {
                try {
                    conn.rollback();
                    System.err.println("[DB] Transaction rolled back: " + e.getMessage());
                } catch (SQLException rollbackEx) {
                    System.err.println("[DB] Rollback failed: " + rollbackEx.getMessage());
                }
            }
            throw e;
        } finally {
            if (conn != null) {
                try {
                    conn.setAutoCommit(true);
                    conn.close();
                } catch (SQLException e) {
                    System.err.println("[DB] Connection close error: " + e.getMessage());
                }
            }
        }
        return isSuccess;
    }

    public static boolean markVoterAsVoted(String voterId) throws SQLException {
        String sql = "INSERT INTO voted_voters (voter_id) VALUES (?)";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, voterId);
            return pstmt.executeUpdate() > 0;
        }
    }

    public static List<JSONObject> getEncryptedVotesForDecryption() throws SQLException {
        List<JSONObject> votes = new ArrayList<>();
        String sql = "SELECT vote_id, encrypted_vote FROM votes "
                + "WHERE decrypted_candidate_id IS NULL "
                + "ORDER BY created_at";

        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                JSONObject vote = new JSONObject();
                vote.put("vote_id", rs.getString("vote_id"));
                vote.put("encrypted_vote", rs.getString("encrypted_vote"));
                votes.add(vote);
            }
        }
        return votes;
    }

    public static boolean hasVoted(String voterId) throws SQLException {
        String sql = "SELECT 1 FROM voted_voters WHERE voter_id = ?";
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, voterId);
            rs = pstmt.executeQuery();
            return rs.next();
        } finally {
            // Close resources in reverse order
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException e) {
                    /* ignored */ }
            }
            if (pstmt != null) {
                try {
                    pstmt.close();
                } catch (SQLException e) {
                    /* ignored */ }
            }
            // Don't close connection here - let the connection pool handle it
        }
    }

    // Di DatabaseHelper.java
    public static List<JSONObject> getAllEncryptedVotes() throws SQLException {
        System.out.println("[DB] Getting all encrypted votes");
        List<JSONObject> votes = new ArrayList<>();
        String sql = "SELECT vote_id, encrypted_vote FROM votes WHERE decrypted_candidate_id IS NULL";

        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            System.out.println("[DB] Executing query: " + sql);
            while (rs.next()) {
                JSONObject vote = new JSONObject();
                vote.put("vote_id", rs.getString("vote_id"));
                vote.put("encrypted_vote", rs.getString("encrypted_vote"));
                System.out.println("[DB] Found vote ID: " + vote.getString("vote_id"));
                votes.add(vote);
            }
        } catch (SQLException e) {
            System.err.println("[DB ERROR] Failed to get encrypted votes: " + e.getMessage());
            throw e;
        }
        return votes;
    }

    public static boolean updateDecryptedVote(String voteId, String candidateId) throws SQLException {
        System.out.println("[DB] Updating vote " + voteId + " with candidate " + candidateId);
        String sql = "UPDATE votes SET decrypted_candidate_id = ?, is_counted = 1 WHERE vote_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, candidateId);
            pstmt.setString(2, voteId);
            System.out.println("[DB] Executing update: " + pstmt.toString());

            int rowsUpdated = pstmt.executeUpdate();
            System.out.println("[DB] Rows updated: " + rowsUpdated);

            return rowsUpdated > 0;
        } catch (SQLException e) {
            System.err.println("[DB ERROR] Failed to update vote: " + e.getMessage());
            throw e;
        }
    }

    public static boolean markVoterAsVoted(String voterId, String voteId) throws SQLException {
        String sql = "INSERT INTO voted_voters (voter_id, vote_id) VALUES (?, ?)";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, voterId);
            pstmt.setString(2, voteId);
            return pstmt.executeUpdate() > 0;
        }
    }

    public static String getEncryptedVoteByVoterId(String voterId) throws SQLException {
        // Hanya voter yang bersangkutan yang bisa akses encrypted_vote miliknya
        String sql = "SELECT v.encrypted_vote FROM votes v "
                + "JOIN voted_voters vv ON v.vote_id = vv.vote_id "
                + "WHERE vv.voter_id = ? LIMIT 1";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, voterId);
            ResultSet rs = pstmt.executeQuery();
            return rs.next() ? rs.getString("encrypted_vote") : null;
        }
    }

    public static JSONObject getCandidateByVote(String voterId, String voteHash) throws SQLException {
        // First verify that voter has voted
        if (!hasVoted(voterId)) {
            return null;
        }

        String sql = "SELECT c.* FROM candidates c "
                + "JOIN votes v ON c.candidate_id = v.candidate_id "
                + "LIMIT 1"; // Can't reliably match to specific voter

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject candidate = new JSONObject();
                candidate.put("candidate_id", rs.getString("candidate_id"));
                candidate.put("nama", rs.getString("nama"));
                candidate.put("partai", rs.getString("partai"));
                candidate.put("nomor_urut", rs.getInt("nomor_urut"));
                candidate.put("photo_url", rs.getString("photo_url"));
                return candidate;
            }
            return null;
        }
    }

    public static List<JSONObject> getCandidatesWithVotes() throws SQLException {
        String sql = "SELECT c.candidate_id, c.nama, c.partai, c.nomor_urut, c.photo_url, "
                + "COUNT(v.vote_id) as vote_count "
                + "FROM candidates c LEFT JOIN votes v ON c.candidate_id = v.candidate_id "
                + "GROUP BY c.candidate_id "
                + "ORDER BY vote_count DESC";

        List<JSONObject> candidates = new ArrayList<>();

        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                JSONObject candidate = new JSONObject();
                candidate.put("candidate_id", rs.getString("candidate_id"));
                candidate.put("nama", rs.getString("nama"));
                candidate.put("partai", rs.getString("partai"));
                candidate.put("nomor_urut", rs.getInt("nomor_urut"));
                candidate.put("photo_url", rs.getString("photo_url"));
                candidate.put("vote_count", rs.getInt("vote_count"));
                candidates.add(candidate);
            }
        }
        return candidates;
    }

    public static JSONObject getTabulationData() throws SQLException {
        JSONObject result = new JSONObject();
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {
            conn = getConnection();
            stmt = conn.createStatement();

            // 1. Get candidates data
            JSONArray candidates = new JSONArray();
            String candidateSql = "SELECT candidate_id, nama, partai, nomor_urut, photo_url "
                    + "FROM candidates ORDER BY nomor_urut";
            rs = stmt.executeQuery(candidateSql);
            while (rs.next()) {
                JSONObject candidate = new JSONObject();
                candidate.put("candidate_id", rs.getString("candidate_id"));
                candidate.put("nama", rs.getString("nama"));
                candidate.put("partai", rs.getString("partai"));
                candidate.put("nomor_urut", rs.getInt("nomor_urut"));
                candidate.put("photo_url", rs.getString("photo_url"));
                candidates.put(candidate);
            }
            result.put("candidates", candidates);

            // 2. Get vote counts per candidate - FIXED QUERY
            String voteSql = "SELECT c.candidate_id, COUNT(v.vote_id) as vote_count "
                    + "FROM candidates c LEFT JOIN votes v ON c.candidate_id = v.decrypted_candidate_id "
                    + "WHERE v.is_counted = 1 "
                    + "GROUP BY c.candidate_id";
            rs = stmt.executeQuery(voteSql);
            JSONObject voteCounts = new JSONObject();
            while (rs.next()) {
                voteCounts.put(rs.getString("candidate_id"), rs.getInt("vote_count"));
            }
            result.put("vote_counts", voteCounts);

            // 3. Get total active voters
            rs = stmt.executeQuery("SELECT COUNT(*) FROM voters WHERE is_active = 1");
            result.put("total_voters", rs.next() ? rs.getInt(1) : 0);

            // 4. Get total votes cast
            rs = stmt.executeQuery("SELECT COUNT(*) FROM voted_voters");
            result.put("total_votes_cast", rs.next() ? rs.getInt(1) : 0);

            // 5. Get election time info
            rs = stmt.executeQuery("SELECT start_time, end_time FROM election_settings ORDER BY id DESC LIMIT 1");
            if (rs.next()) {
                JSONObject electionTime = new JSONObject();
                electionTime.put("start_time", rs.getString("start_time"));
                electionTime.put("end_time", rs.getString("end_time"));
                result.put("election_time", electionTime);
            }

            return result;

        } catch (SQLException e) {
            System.err.println("[Database Error] Failed to get tabulation data: " + e.getMessage());
            throw e;
        } finally {
            try {
                if (rs != null) {
                    rs.close();
                }
            } catch (SQLException e) {
                /* ignored */ }
            try {
                if (stmt != null) {
                    stmt.close();
                }
            } catch (SQLException e) {
                /* ignored */ }
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException e) {
                /* ignored */ }
        }
    }

    public static JSONObject getVotingStats() throws SQLException {
        JSONObject stats = new JSONObject();

        try (Connection conn = getConnection()) {
            // Total voters
            try (Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM voters")) {
                if (rs.next()) {
                    stats.put("total_voters", rs.getInt(1));
                }
            }

            // Verified voters
            try (Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM voters WHERE is_active = 1")) {
                if (rs.next()) {
                    stats.put("verified_voters", rs.getInt(1));
                }
            }

            // Voters who have voted
            try (Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM voted_voters")) {
                if (rs.next()) {
                    stats.put("voters_voted", rs.getInt(1));
                }
            }

            // Total votes
            try (Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM votes")) {
                if (rs.next()) {
                    stats.put("total_votes", rs.getInt(1));
                }
            }

            // Total candidates
            try (Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM candidates")) {
                if (rs.next()) {
                    stats.put("total_candidates", rs.getInt(1));
                }
            }

            // Total officers
            try (Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM officers")) {
                if (rs.next()) {
                    stats.put("total_officers", rs.getInt(1));
                }
            }
        }

        return stats;
    }

    public static List<JSONObject> getVotersWithVotingStatus(String status) throws SQLException {
        String sql = "SELECT v.voter_id, v.nik, v.nama, v.email, v.is_active, "
                + "CASE WHEN vv.voter_id IS NOT NULL THEN 1 ELSE 0 END as has_voted "
                + "FROM voters v LEFT JOIN voted_voters vv ON v.voter_id = vv.voter_id";

        if ("voted".equals(status)) {
            sql += " WHERE vv.voter_id IS NOT NULL";
        } else if ("not_voted".equals(status)) {
            sql += " WHERE vv.voter_id IS NULL";
        }

        sql += " ORDER BY v.registered_at DESC";

        List<JSONObject> voters = new ArrayList<>();
        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject voter = new JSONObject();
                voter.put("voter_id", rs.getString("voter_id"));
                voter.put("nik", rs.getString("nik"));
                voter.put("nama", rs.getString("nama"));
                voter.put("email", rs.getString("email"));
                voter.put("is_active", rs.getBoolean("is_active"));
                voter.put("has_voted", rs.getBoolean("has_voted"));
                voters.add(voter);
            }
        }
        return voters;
    }

    public static List<JSONObject> getAllVoters() throws SQLException {
        String sql = "SELECT voter_id, nik, nama, tempat_lahir, tanggal_lahir, "
                + "jenis_kelamin, alamat, status_pernikahan, email, is_active as is_verified "
                + "FROM voters ORDER BY registered_at DESC";

        List<JSONObject> voters = new ArrayList<>();

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql);
                ResultSet rs = pstmt.executeQuery()) {

            while (rs.next()) {
                JSONObject voter = new JSONObject();
                voter.put("voter_id", rs.getString("voter_id"));
                voter.put("nik", rs.getString("nik"));
                voter.put("nama", rs.getString("nama"));
                voter.put("tempat_lahir", rs.getString("tempat_lahir"));
                voter.put("tanggal_lahir", rs.getString("tanggal_lahir"));
                voter.put("jenis_kelamin", rs.getString("jenis_kelamin"));
                voter.put("alamat", rs.getString("alamat"));
                voter.put("status_pernikahan", rs.getString("status_pernikahan"));
                voter.put("email", rs.getString("email"));
                voter.put("is_verified", rs.getBoolean("is_verified"));

                voters.add(voter);
            }
        } catch (SQLException e) {
            System.err.println("Error getting voters: " + e.getMessage());
            throw e;
        }
        return voters;
    }

    public static boolean verifyVoter(String voterId, boolean isVerified) throws SQLException {
        String sql = "UPDATE voters SET is_active = ? WHERE voter_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setBoolean(1, isVerified);
            pstmt.setString(2, voterId);

            return pstmt.executeUpdate() > 0;
        }
    }

    public static JSONObject getElectionResults() throws SQLException {
        String sql = "SELECT c.candidate_id, c.nama, c.partai, c.nomor_urut, "
                + "COUNT(v.vote_id) as vote_count "
                + "FROM candidates c LEFT JOIN votes v ON c.candidate_id = v.candidate_id "
                + "GROUP BY c.candidate_id "
                + "ORDER BY vote_count DESC";

        JSONObject results = new JSONObject();
        JSONArray candidates = new JSONArray();
        int totalVotes = 0;

        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                JSONObject candidate = new JSONObject();
                candidate.put("candidate_id", rs.getString("candidate_id"));
                candidate.put("nama", rs.getString("nama"));
                candidate.put("partai", rs.getString("partai"));
                candidate.put("nomor_urut", rs.getInt("nomor_urut"));
                candidate.put("vote_count", rs.getInt("vote_count"));
                candidates.put(candidate);
                totalVotes += rs.getInt("vote_count");
            }

            results.put("total_votes", totalVotes);
            results.put("candidates", candidates);
        }
        return results;
    }

    public static boolean updateCandidatePhoto(String candidateId, String photoUrl) throws SQLException {
        String sql = "UPDATE candidates SET photo_url = ? WHERE candidate_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, photoUrl);
            pstmt.setString(2, candidateId);

            return pstmt.executeUpdate() > 0;
        }
    }

    public static JSONObject getCandidateWithPhoto(String candidateId) throws SQLException {
        String sql = "SELECT c.*, o.nama as created_by_name FROM candidates c "
                + "LEFT JOIN officers o ON c.created_by = o.officer_id "
                + "WHERE c.candidate_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, candidateId);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject candidate = new JSONObject();
                candidate.put("candidate_id", rs.getString("candidate_id"));
                candidate.put("nama", rs.getString("nama"));
                candidate.put("partai", rs.getString("partai"));
                candidate.put("nomor_urut", rs.getInt("nomor_urut"));
                candidate.put("photo_url", rs.getString("photo_url"));
                candidate.put("created_by", rs.getString("created_by_name"));
                candidate.put("created_at", rs.getString("created_at"));
                return candidate;
            }
            return null;
        }
    }

    public static List<JSONObject> getAllCandidatesWithPhotos() throws SQLException {
        String sql = "SELECT c.*, o.nama as created_by_name FROM candidates c "
                + "LEFT JOIN officers o ON c.created_by = o.officer_id "
                + "ORDER BY c.nomor_urut";
        List<JSONObject> candidates = new ArrayList<>();

        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                JSONObject candidate = new JSONObject();
                candidate.put("candidate_id", rs.getString("candidate_id"));
                candidate.put("nama", rs.getString("nama"));
                candidate.put("partai", rs.getString("partai"));
                candidate.put("nomor_urut", rs.getInt("nomor_urut"));
                candidate.put("photo_url", rs.getString("photo_url"));
                candidate.put("created_by", rs.getString("created_by_name"));
                candidate.put("created_at", rs.getString("created_at"));
                candidates.add(candidate);
            }
        }
        return candidates;
    }

    public static boolean checkNikExists(String nik) throws SQLException {
        String sql = "SELECT 1 FROM voters WHERE nik = ? LIMIT 1";
        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, nik);
            ResultSet rs = pstmt.executeQuery();
            return rs.next();
        }
    }

    public static JSONObject getElectionTime() throws SQLException {
        String sql = "SELECT start_time, end_time FROM election_settings ORDER BY id DESC LIMIT 1";

        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            JSONObject result = new JSONObject();
            if (rs.next()) {
                result.put("start_time", rs.getString("start_time"));
                result.put("end_time", rs.getString("end_time"));
            } else {
                result.put("start_time", "");
                result.put("end_time", "");
            }
            return result;
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

    public static JSONObject getVoterByNikAndEmail(String nik, String email) throws SQLException {
        String sql = "SELECT voter_id, nik, nama, email FROM voters WHERE nik = ? AND email = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, nik);
            pstmt.setString(2, email);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject voter = new JSONObject();
                voter.put("voter_id", rs.getString("voter_id"));
                voter.put("nik", rs.getString("nik"));
                voter.put("nama", rs.getString("nama"));
                voter.put("email", rs.getString("email"));
                return voter;
            }
            return null;
        }
    }

    public static boolean savePasswordResetOtp(String voterId, String otp, long expiryTime) throws SQLException {
        String sql = "INSERT OR REPLACE INTO password_reset_otps (voter_id, otp, expiry_time) VALUES (?, ?, ?)";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, voterId);
            pstmt.setString(2, otp);
            pstmt.setLong(3, expiryTime);

            return pstmt.executeUpdate() > 0;
        }
    }

    public static boolean verifyPasswordResetOtp(String voterId, String otp) throws SQLException {
        String sql = "SELECT otp, expiry_time FROM password_reset_otps WHERE voter_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, voterId);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedOtp = rs.getString("otp");
                long expiryTime = rs.getLong("expiry_time");

                // Check if OTP matches and is not expired
                return storedOtp.equals(otp) && System.currentTimeMillis() < expiryTime;
            }
            return false;
        }
    }

    public static boolean updateVoterPassword(String voterId, String newPassword) throws Exception {
        String sql = "UPDATE voters SET password = ? WHERE voter_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, KeyGenerator.hashData(newPassword));
            pstmt.setString(2, voterId);

            return pstmt.executeUpdate() > 0;
        }
    }

    public static boolean clearPasswordResetOtp(String voterId) throws SQLException {
        String sql = "DELETE FROM password_reset_otps WHERE voter_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, voterId);
            return pstmt.executeUpdate() > 0;
        }
    }

    public static boolean verifyVoterPassword(String voterId, String password) throws Exception {
        String sql = "SELECT password FROM voters WHERE voter_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, voterId);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedHash = rs.getString("password");
                String inputHash = KeyGenerator.hashData(password);
                return storedHash.equals(inputHash);
            }
            return false;
        }
    }

    public static boolean isValidCandidate(String candidateId) {
        if (candidateId == null || candidateId.isEmpty()) {
            return false;
        }

        // Remove the is_active check since it doesn't exist in the table
        String sql = "SELECT 1 FROM candidates WHERE candidate_id = ? LIMIT 1";
        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, candidateId);
            return pstmt.executeQuery().next();
        } catch (SQLException e) {
            System.err.println("Error checking candidate: " + e.getMessage());
            return false;
        }
    }

    public static boolean isLoginApproved(String voterId) throws SQLException {
        String sql = "SELECT approved FROM login_approvals WHERE voter_id = ?";
        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, voterId);
            ResultSet rs = pstmt.executeQuery();
            return rs.next() && rs.getBoolean("approved");
        }
    }

    public static JSONObject getSpecialOfficer() throws SQLException {
        String sql = "SELECT officer_id, username, nama, public_key, private_key "
                + "FROM officers WHERE is_special = TRUE LIMIT 1";

        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                JSONObject officer = new JSONObject();
                officer.put("officer_id", rs.getString("officer_id"));
                officer.put("username", rs.getString("username"));
                officer.put("nama", rs.getString("nama"));
                officer.put("public_key", rs.getString("public_key"));
                officer.put("private_key", rs.getString("private_key"));
                return officer;
            }
            return null;
        }
    }

    public static boolean isSpecialOfficer(String officerId) throws SQLException {
        String sql = "SELECT is_special FROM officers WHERE officer_id = ?";
        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, officerId);
            ResultSet rs = pstmt.executeQuery();
            return rs.next() && rs.getBoolean("is_special");
        }
    }

    public static List<JSONObject> getPendingLoginVoters() throws SQLException {
        String sql = "SELECT v.voter_id, v.nik, v.nama, v.email, v.registered_at "
                + "FROM voters v "
                + "LEFT JOIN login_approvals la ON v.voter_id = la.voter_id "
                + "WHERE v.is_active = TRUE AND (la.approved IS NULL OR la.approved = FALSE)";

        List<JSONObject> voters = new ArrayList<>();
        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                JSONObject voter = new JSONObject();
                voter.put("voter_id", rs.getString("voter_id"));
                voter.put("nik", rs.getString("nik"));
                voter.put("nama", rs.getString("nama"));
                voter.put("email", rs.getString("email"));
                voter.put("registered_at", rs.getString("registered_at"));
                voters.add(voter);
            }
        }
        return voters;
    }

    public static boolean updateVoteAfterDecryption(String voteId, String candidateId) {
        String sql = "UPDATE votes SET decrypted_candidate_id = ?, is_counted = TRUE WHERE vote_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, candidateId);
            pstmt.setString(2, voteId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean rejectVoterLogin(String voterId) throws SQLException {
        String sql = "UPDATE login_approvals SET approved = FALSE, approved_at = CURRENT_TIMESTAMP "
                + "WHERE voter_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, voterId);
            return pstmt.executeUpdate() > 0;
        }
    }

    public static JSONObject getVoterDetailsWithLoginStatus(String voterId) throws SQLException {
        String sql = "SELECT v.*, la.approved as login_approved, "
                + "la.approved_at, la.approved_by "
                + "FROM voters v "
                + "LEFT JOIN login_approvals la ON v.voter_id = la.voter_id "
                + "WHERE v.voter_id = ?";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, voterId);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject voter = new JSONObject();
                // Add all voter details
                voter.put("voter_id", rs.getString("voter_id"));
                voter.put("nik", rs.getString("nik"));
                voter.put("nama", rs.getString("nama"));
                voter.put("tempat_lahir", rs.getString("tempat_lahir"));
                voter.put("tanggal_lahir", rs.getString("tanggal_lahir"));
                voter.put("jenis_kelamin", rs.getString("jenis_kelamin"));
                voter.put("alamat", rs.getString("alamat"));
                voter.put("status_pernikahan", rs.getString("status_pernikahan"));
                voter.put("email", rs.getString("email"));
                voter.put("is_active", rs.getBoolean("is_active"));
                voter.put("registered_at", rs.getString("registered_at"));

                // Add login approval info
                voter.put("login_approved", rs.getBoolean("login_approved"));
                voter.put("approved_at", rs.getString("approved_at"));
                voter.put("approved_by", rs.getString("approved_by"));

                return voter;
            }
            return null;
        }
    }

    public static boolean approveVoterLogin(String voterId, String officerId) throws SQLException {
        String sql = "INSERT OR REPLACE INTO login_approvals (voter_id, approved, approved_by, approved_at) "
                + "VALUES (?, 1, ?, CURRENT_TIMESTAMP)";

        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, voterId);
            pstmt.setString(2, officerId);
            return pstmt.executeUpdate() > 0;
        }
    }

    public static boolean verifyVoteHash(String voteHash) throws SQLException {
        String sql = "SELECT 1 FROM votes WHERE vote_hash = ?";
        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, voteHash);
            return pstmt.executeQuery().next();
        }
    }

    public static JSONObject getVoteByHash(String voteHash) throws SQLException {
        String sql = "SELECT vote_id, created_at FROM votes WHERE vote_hash = ?";
        try (Connection conn = getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, voteHash);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject vote = new JSONObject();
                vote.put("vote_id", rs.getString("vote_id"));
                vote.put("timestamp", rs.getString("created_at"));
                return vote;
            }
            return null;
        }
    }
}
