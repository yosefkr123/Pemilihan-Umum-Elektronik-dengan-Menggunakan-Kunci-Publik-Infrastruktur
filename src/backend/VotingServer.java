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
import java.io.*;
import java.net.*;
import java.security.*;
import java.sql.*;
import org.json.JSONException;
import org.json.JSONObject;
import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.util.UUID;
import org.json.JSONArray;

public class VotingServer {

    private static final int PORT = 8082;

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Voting Server running on port " + PORT);

        while (true) {
            try {
                Socket clientSocket = serverSocket.accept();
                new Thread(() -> handleClient(clientSocket)).start();
            } catch (Exception e) {
                System.err.println("Error accepting client connection: " + e.getMessage());
            }
        }
    }

    private static void handleClient(Socket clientSocket) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

            // Read request
            StringBuilder requestBuilder = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null && !line.isEmpty()) {
                requestBuilder.append(line).append("\n");
            }

            // Read body if exists
            StringBuilder bodyBuilder = new StringBuilder();
            if (in.ready()) {
                int contentLength = 0;
                for (String header : requestBuilder.toString().split("\n")) {
                    if (header.toLowerCase().startsWith("content-length:")) {
                        contentLength = Integer.parseInt(header.substring(15).trim());
                        break;
                    }
                }

                if (contentLength > 0) {
                    char[] body = new char[contentLength];
                    in.read(body, 0, contentLength);
                    bodyBuilder.append(body);
                }
            }

            String requestBody = bodyBuilder.toString().trim();

            // Validate JSON
            if (requestBody.isEmpty() || !requestBody.startsWith("{")) {
                sendErrorResponse(out, 400, "Invalid JSON format");
                return;
            }

            try {
                JSONObject jsonRequest = new JSONObject(requestBody);
                String endpoint = jsonRequest.optString("endpoint", "");

                switch (endpoint) {
                    case "/submit_vote":
                        handleSubmitVote(out, jsonRequest);
                        break;
                    case "/check_vote_status":
                        handleCheckVoteStatus(out, jsonRequest);
                        break;
                    default:
                        sendErrorResponse(out, 404, "Endpoint not found");
                }
            } catch (JSONException e) {
                sendErrorResponse(out, 400, "Invalid JSON: " + e.getMessage());
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("Error closing client socket: " + e.getMessage());
            }
        }
    }

    private static void handleSubmitVote(PrintWriter out, JSONObject request) {
        try {
            // 1. Validasi input
            String[] requiredFields = {"voter_id", "encrypted_vote", "vote_hash"};
            for (String field : requiredFields) {
                if (!request.has(field)) {
                    System.err.println("[VALIDATION] Missing field: " + field);
                    sendErrorResponse(out, 400, "Field " + field + " is required");
                    return;
                }
            }

            String voterId = request.getString("voter_id");
            String encryptedVote = request.getString("encrypted_vote");
            String voteHash = request.getString("vote_hash");

            // 2. Verifikasi hak pilih
            if (DatabaseHelper.hasVoted(voterId)) {
                sendErrorResponse(out, 403, "Voter has already voted");
                return;
            }

            // 3. Verifikasi waktu pemilihan
            JSONObject electionTime = DatabaseHelper.getElectionTime();
            if (electionTime == null) {
                sendErrorResponse(out, 500, "Election schedule not set");
                return;
            }

            LocalDateTime now = LocalDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss[.SSS]");
            LocalDateTime startTime = LocalDateTime.parse(electionTime.getString("start_time"), formatter);
            LocalDateTime endTime = LocalDateTime.parse(electionTime.getString("end_time"), formatter);

            if (now.isBefore(startTime) || now.isAfter(endTime)) {
                sendErrorResponse(out, 403, "Election is not active");
                return;
            }

            // 4. Dapatkan petugas khusus
            JSONObject specialOfficer = DatabaseHelper.getSpecialOfficer();
            if (specialOfficer == null) {
                sendErrorResponse(out, 500, "Special officer not configured");
                return;
            }

            // 5. Buat tanda tangan petugas (BUKAN pemilih)
            PrivateKey officerKey = KeyGenerator.getPrivateKeyFromString(specialOfficer.getString("private_key"));
            String officerSignature = KeyGenerator.sign(encryptedVote, officerKey);

            // 6. Generate vote ID
            String voteId = "VT-" + UUID.randomUUID().toString();

            // 7. Simpan ke database
            boolean isSaved = DatabaseHelper.saveVote(
                    voteId,
                    encryptedVote,
                    officerSignature,
                    voteHash
            );

            if (!isSaved) {
                sendErrorResponse(out, 500, "Failed to save vote");
                return;
            }

            // 8. Tandai pemilih sudah memilih
            DatabaseHelper.markVoterAsVoted(voterId);

            // 9. Kirim response
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("vote_id", voteId);
            response.put("timestamp", now.format(formatter));

            System.out.println("[SUCCESS] Vote recorded. Vote ID: " + voteId);
            sendSuccessResponse(out, response);

        } catch (DateTimeParseException e) {
            System.err.println("[ERROR] Invalid timestamp format: " + e.getMessage());
            sendErrorResponse(out, 500, "Invalid time format");
        } catch (Exception e) {
            System.err.println("[ERROR] System error: " + e.getMessage());
            sendErrorResponse(out, 500, "Internal server error");
        }
    }

// Di handleCheckVoteStatus
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

// Method baru untuk verifikasi hash
    private static void handleVerifyVoteHash(PrintWriter out, JSONObject request) {
        try {
            if (!request.has("vote_hash")) {
                sendErrorResponse(out, 400, "Missing vote_hash");
                return;
            }

            String voteHash = request.getString("vote_hash");
            boolean exists = DatabaseHelper.verifyVoteHash(voteHash);

            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("exists", exists);
            sendSuccessResponse(out, response);
        } catch (Exception e) {
            sendErrorResponse(out, 500, "Verification failed");
        }
    }

    private static void sendErrorResponse(PrintWriter out, int statusCode, String message) {
        try {
            out.println("HTTP/1.1 " + statusCode + " " + getStatusMessage(statusCode));
            out.println("Content-Type: application/json");
            out.println("Connection: close");
            out.println();

            JSONObject response = new JSONObject();
            response.put("status", "error");
            response.put("message", message);
            out.println(response.toString());
            out.flush();
        } catch (Exception e) {
            System.err.println("Failed to send error response: " + e.getMessage());
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

    private static void sendSuccessResponse(PrintWriter out, JSONObject data) {
        out.println("HTTP/1.1 200 OK");
        out.println("Content-Type: application/json");
        out.println("Connection: close");
        out.println();
        out.println(data.toString());
    }
}
