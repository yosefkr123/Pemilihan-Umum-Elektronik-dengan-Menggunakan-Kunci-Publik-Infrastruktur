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
import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import org.json.*;
import java.security.*;
import java.util.stream.Collectors;
import java.sql.Timestamp;
import java.nio.charset.StandardCharsets;

public class TabulasiServer {

    private static final int PORT = 8083;
    private static final String DB_URL = "jdbc:sqlite:evoting.db";

    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Tabulasi Server running on port " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(() -> handleClient(clientSocket)).start();
            }
        } catch (IOException e) {
            System.err.println("Server startup error: " + e.getMessage());
        }
    }

    private static void handleClient(Socket clientSocket) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

            // Read HTTP headers
            StringBuilder requestBuilder = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null && !line.isEmpty()) {
                requestBuilder.append(line).append("\n");
            }

            // Read JSON body if exists
            StringBuilder bodyBuilder = new StringBuilder();
            if (in.ready()) {
                int contentLength = 0;
                String[] headers = requestBuilder.toString().split("\n");
                for (String header : headers) {
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
            System.out.println("Received request: " + requestBody);

            if (requestBody.isEmpty() || !requestBody.startsWith("{")) {
                sendErrorResponse(out, 400, "Invalid JSON format");
                return;
            }

            try {
                JSONObject jsonRequest = new JSONObject(requestBody);
                String endpoint = jsonRequest.getString("endpoint");

                switch (endpoint) {
                    case "/get_tabulasi":
                        handleGetTabulasi(out);
                        break;
                    case "/get_stats":
                        handleGetStats(out);
                        break;
                    case "/verify_vote":
                        handleVerifyVote(out, jsonRequest);
                        break;
                    default:
                        sendErrorResponse(out, 404, "Endpoint not found");
                }
            } catch (JSONException e) {
                sendErrorResponse(out, 400, "Invalid JSON: " + e.getMessage());
            }
        } catch (Exception e) {
            System.err.println("Client handling error: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("Error closing socket: " + e.getMessage());
            }
        }
    }

    private static void handleGetTabulasi(PrintWriter out) {
        try {
            System.out.println("[DEBUG] Starting tabulation process...");

            // 1. Get raw data from database
            JSONObject rawData = DatabaseHelper.getTabulationData();
            System.out.println("[DEBUG] Raw data retrieved: " + rawData.toString());

            JSONObject result = new JSONObject();
            JSONArray candidates = rawData.getJSONArray("candidates");
            JSONObject voteCounts = rawData.optJSONObject("vote_counts", new JSONObject());

            // 2. Process candidates and calculate totals
            int totalValidVotes = 0;
            JSONArray processedCandidates = new JSONArray();

            for (int i = 0; i < candidates.length(); i++) {
                JSONObject candidate = candidates.getJSONObject(i);
                String candidateId = candidate.getString("candidate_id");
                int voteCount = voteCounts.optInt(candidateId, 0);

                candidate.put("vote_count", voteCount);
                processedCandidates.put(candidate);
                totalValidVotes += voteCount;

                System.out.println("[DEBUG] Processed candidate: " + candidateId
                        + " with " + voteCount + " votes");
            }

            // 3. Get other metrics
            int totalVoters = rawData.optInt("total_voters", 0);
            int totalVotesCast = rawData.optInt("total_votes_cast", 0);
            int invalidVotes = Math.max(0, totalVotesCast - totalValidVotes);

            System.out.println("[DEBUG] Calculated totals - "
                    + "Valid: " + totalValidVotes
                    + ", Voters: " + totalVoters
                    + ", Cast: " + totalVotesCast
                    + ", Invalid: " + invalidVotes);

            // 4. Calculate percentages
            for (int i = 0; i < processedCandidates.length(); i++) {
                JSONObject candidate = processedCandidates.getJSONObject(i);
                int voteCount = candidate.getInt("vote_count");
                double percentage = totalValidVotes > 0
                        ? (voteCount * 100.0 / totalValidVotes) : 0.0;
                candidate.put("percentage", Math.round(percentage * 100) / 100.0);
            }

            // 5. Prepare final response
            result.put("status", "success");
            result.put("candidates", processedCandidates);
            result.put("total_valid_votes", totalValidVotes);
            result.put("total_voters", totalVoters);
            result.put("total_votes_cast", totalVotesCast);
            result.put("invalid_votes", invalidVotes);
            result.put("voter_turnout", totalVoters > 0
                    ? Math.round((totalVotesCast * 100.0 / totalVoters) * 100) / 100.0 : 0);
            result.put("election_time", rawData.optJSONObject("election_time", new JSONObject()));
            result.put("last_updated", new Timestamp(System.currentTimeMillis()).toString());

            System.out.println("[DEBUG] Final tabulation result: " + result.toString(2));
            sendSuccessResponse(out, result);

        } catch (SQLException e) {
            System.err.println("[ERROR] Database error in tabulation: " + e.getMessage());
            sendErrorResponse(out, 500, "Database error: " + e.getMessage());
        } catch (JSONException e) {
            System.err.println("[ERROR] JSON processing error in tabulation: " + e.getMessage());
            sendErrorResponse(out, 500, "Data processing error");
        } catch (Exception e) {
            System.err.println("[ERROR] Unexpected error in tabulation: " + e.getMessage());
            sendErrorResponse(out, 500, "Internal server error");
        }
    }

    private static int calculateTotalVotes(JSONArray candidates) throws JSONException {
        int total = 0;
        for (int i = 0; i < candidates.length(); i++) {
            total += candidates.getJSONObject(i).getInt("vote_count");
        }
        return total;
    }

    private static void handleVerifyVote(PrintWriter out, JSONObject request) {
        try {
            // Validate request
            if (!request.has("voter_id") || !request.has("vote_hash")) {
                sendErrorResponse(out, 400, "Missing required fields (voter_id and vote_hash)");
                return;
            }

            String voterId = request.getString("voter_id");
            String voteHash = request.getString("vote_hash");

            // Check if vote exists with matching hash
            String sql = "SELECT 1 FROM votes v "
                    + "JOIN voted_voters vv ON v.vote_id = vv.vote_id "
                    + "WHERE vv.voter_id = ? AND v.vote_hash = ? "
                    + "LIMIT 1";

            boolean verified = false;
            try (Connection conn = DriverManager.getConnection(DB_URL);
                    PreparedStatement pstmt = conn.prepareStatement(sql)) {

                pstmt.setString(1, voterId);
                pstmt.setString(2, voteHash);

                try (ResultSet rs = pstmt.executeQuery()) {
                    verified = rs.next();
                }
            }

            // Prepare response
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("verified", verified);
            response.put("timestamp", new Timestamp(System.currentTimeMillis()).toString());

            if (verified) {
                response.put("message", "Vote verified successfully");
            } else {
                response.put("message", "No matching vote found");
            }

            sendSuccessResponse(out, response);

        } catch (SQLException e) {
            System.err.println("Database error during verification: " + e.getMessage());
            sendErrorResponse(out, 500, "Database error during verification");
        } catch (Exception e) {
            System.err.println("Error during verification: " + e.getMessage());
            sendErrorResponse(out, 500, "Error during vote verification");
        }
    }

    private static void handleGetStats(PrintWriter out) {
        try {
            JSONObject stats = DatabaseHelper.getVotingStats();
            sendSuccessResponse(out, stats);
        } catch (SQLException e) {
            sendErrorResponse(out, 500, "Database error");
        }
    }

    private static void sendSuccessResponse(PrintWriter out, JSONObject data) {
        out.println("HTTP/1.1 200 OK");
        out.println("Content-Type: application/json");
        out.println("Connection: close");
        out.println();
        out.println(data.toString());
    }

    private static void sendErrorResponse(PrintWriter out, int code, String message) {
        out.println("HTTP/1.1 " + code + " " + getStatusMessage(code));
        out.println("Content-Type: application/json");
        out.println("Connection: close");
        out.println();

        JSONObject error = new JSONObject();
        error.put("status", "error");
        error.put("message", message);
        out.println(error.toString());
    }

    private static String getStatusMessage(int code) {
        switch (code) {
            case 200:
                return "OK";
            case 400:
                return "Bad Request";
            case 404:
                return "Not Found";
            case 500:
                return "Internal Server Error";
            default:
                return "Unknown Status";
        }
    }
}
