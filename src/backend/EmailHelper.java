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
import java.util.Properties;
import javax.mail.*;
import javax.mail.internet.*;

public class EmailHelper {

    private static final String SMTP_HOST = "smtp.gmail.com";
    private static final String SMTP_PORT = "587";
    private static final String EMAIL_USERNAME = "";
    private static final String EMAIL_PASSWORD = "";
    private static final String EMAIL_FROM_NAME = "E-Voting System";

    public static void sendVerificationEmail(String toEmail, String name, String message) {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", SMTP_HOST);
        props.put("mail.smtp.port", SMTP_PORT);
        props.put("mail.smtp.ssl.protocols", "TLSv1.2");

        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(EMAIL_USERNAME, EMAIL_PASSWORD);
            }
        });

        try {
            Message email = new MimeMessage(session);
            email.setFrom(new InternetAddress(EMAIL_USERNAME, EMAIL_FROM_NAME));
            email.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toEmail));
            email.setSubject("Status Registrasi E-Voting");

            // Enhanced HTML Email Content
            String htmlContent = "<!DOCTYPE html>"
                    + "<html>"
                    + "<head>"
                    + "<meta charset='UTF-8'>"
                    + "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                    + "<style>"
                    + "  * { box-sizing: border-box; margin: 0; padding: 0; }"
                    + "  body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #444; background-color: #f5f7fa; padding: 20px; }"
                    + "  .email-container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }"
                    + "  .email-header { background: linear-gradient(135deg, #4F46E5, #6D63FF); padding: 30px 20px; text-align: center; }"
                    + "  .email-header h1 { color: white; font-size: 24px; font-weight: 600; margin-bottom: 10px; }"
                    + "  .email-logo { width: 80px; height: auto; margin-bottom: 15px; }"
                    + "  .email-body { padding: 30px; }"
                    + "  .greeting { font-size: 18px; margin-bottom: 20px; color: #333; }"
                    + "  .message { margin-bottom: 25px; line-height: 1.7; }"
                    + "  .status-box { background-color: #f8f9fe; border-left: 4px solid #4F46E5; padding: 20px; margin: 25px 0; border-radius: 0 8px 8px 0; }"
                    + "  .status-title { font-weight: 600; color: #4F46E5; margin-bottom: 10px; display: flex; align-items: center; }"
                    + "  .status-title svg { margin-right: 10px; }"
                    + "  .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 13px; color: #777; }"
                    + "  .action-button { display: inline-block; background: #4F46E5; color: white; text-decoration: none; padding: 12px 25px; border-radius: 6px; font-weight: 500; margin-top: 15px; }"
                    + "  .note { font-size: 13px; color: #666; margin-top: 25px; }"
                    + "</style>"
                    + "</head>"
                    + "<body>"
                    + "<div class='email-container'>"
                    + "  <div class='email-header'>"
                    + "    <h1>E-Voting System</h1>"
                    + "  </div>"
                    + "  <div class='email-body'>"
                    + "    <h2 class='greeting'>Halo, " + name + "!</h2>"
                    + "    <p class='message'>" + message + "</p>"
                    + "    <div class='status-box'>"
                    + "      <h3 class='status-title'>"
                    + "        <svg width='20' height='20' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'>"
                    + "          <path d='M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z' stroke='#4F46E5' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "          <path d='M12 16V12' stroke='#4F46E5' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "          <path d='M12 8H12.01' stroke='#4F46E5' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "        </svg>"
                    + "        Status Pendaftaran"
                    + "      </h3>"
                    + "      <p>Akun Anda sedang dalam proses verifikasi oleh petugas kami.</p>"
                    + "      <p>Anda akan menerima email notifikasi begitu akun Anda telah diverifikasi.</p>"
                    + "    </div>"
                    + "    <p class='note'>Jika Anda tidak melakukan registrasi ini, silakan abaikan email ini atau hubungi tim dukungan kami.</p>"
                    + "    <div class='footer'>"
                    + "      <p>&copy; 2025 E-Voting System. Semua hak dilindungi.</p>"
                    + "      <p>Email ini dikirim secara otomatis, mohon tidak membalas.</p>"
                    + "    </div>"
                    + "  </div>"
                    + "</div>"
                    + "</body>"
                    + "</html>";

            email.setContent(htmlContent, "text/html");
            Transport.send(email);
        } catch (Exception e) {
            System.err.println("Failed to send email: " + e.getMessage());
            throw new RuntimeException("Gagal mengirim email: " + e.getMessage());
        }
    }

    public static void sendApprovalEmail(String toEmail, String name, String nik) {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", SMTP_HOST);
        props.put("mail.smtp.port", SMTP_PORT);
        props.put("mail.smtp.ssl.protocols", "TLSv1.2");

        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(EMAIL_USERNAME, EMAIL_PASSWORD);
            }
        });

        try {
            Message email = new MimeMessage(session);
            email.setFrom(new InternetAddress(EMAIL_USERNAME, EMAIL_FROM_NAME));
            email.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toEmail));
            email.setSubject("🎉 Akun Anda Telah Diverifikasi - E-Voting System");

            // Enhanced Modern HTML Email Content
            String htmlContent = "<!DOCTYPE html>"
                    + "<html>"
                    + "<head>"
                    + "<meta charset='UTF-8'>"
                    + "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                    + "<title>Akun Diverifikasi</title>"
                    + "<link href='https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600&display=swap' rel='stylesheet'>"
                    + "<style>"
                    + "  * { box-sizing: border-box; margin: 0; padding: 0; }"
                    + "  body { font-family: 'Poppins', sans-serif; line-height: 1.6; color: #4a4a4a; background-color: #f8f9fa; padding: 20px; }"
                    + "  .email-container { max-width: 600px; margin: 0 auto; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.08); transition: all 0.3s ease; }"
                    + "  .email-container:hover { box-shadow: 0 15px 35px rgba(0,0,0,0.12); transform: translateY(-2px); }"
                    + "  .email-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 20px; text-align: center; position: relative; overflow: hidden; }"
                    + "  .email-header::before { content: ''; position: absolute; top: -50%; left: -50%; width: 200%; height: 200%; background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0) 70%); transform: rotate(30deg); }"
                    + "  .email-header h1 { color: white; font-size: 28px; font-weight: 600; margin-bottom: 10px; position: relative; z-index: 1; }"
                    + "  .email-logo { width: 80px; height: 80px; margin-bottom: 15px; background: rgba(255,255,255,0.2); border-radius: 50%; padding: 15px; display: inline-flex; align-items: center; justify-content: center; backdrop-filter: blur(5px); border: 2px solid rgba(255,255,255,0.3); }"
                    + "  .email-body { padding: 40px; }"
                    + "  .greeting { font-size: 20px; margin-bottom: 20px; color: #2d3748; font-weight: 500; }"
                    + "  .message { margin-bottom: 25px; line-height: 1.7; color: #4a5568; }"
                    + "  .highlight-box { background: linear-gradient(to right, #f6f7ff, #f9fafc); border-left: 4px solid #667eea; padding: 25px; margin: 30px 0; border-radius: 0 12px 12px 0; position: relative; }"
                    + "  .highlight-box::after { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px; background: linear-gradient(to right, #667eea, #764ba2); }"
                    + "  .highlight-title { font-weight: 600; color: #667eea; margin-bottom: 15px; display: flex; align-items: center; font-size: 18px; }"
                    + "  .highlight-title svg { margin-right: 12px; }"
                    + "  .footer { text-align: center; margin-top: 40px; padding-top: 30px; border-top: 1px solid #edf2f7; font-size: 14px; color: #718096; }"
                    + "  .action-button { display: inline-block; background: linear-gradient(to right, #667eea, #764ba2); color: white; text-decoration: none; padding: 14px 30px; border-radius: 50px; font-weight: 500; margin-top: 20px; transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3); border: none; cursor: pointer; font-size: 16px; }"
                    + "  .action-button:hover { transform: translateY(-3px); box-shadow: 0 8px 25px rgba(102, 126, 234, 0.4); background: linear-gradient(to right, #5a6fd1, #6a4199); }"
                    + "  .features { list-style: none; margin: 20px 0; }"
                    + "  .features li { padding: 10px 0; padding-left: 35px; position: relative; margin-bottom: 8px; }"
                    + "  .features li::before { content: '✓'; position: absolute; left: 0; color: #48bb78; font-weight: bold; background: #ebf8f2; width: 26px; height: 26px; border-radius: 50%; display: flex; align-items: center; justify-content: center; }"
                    + "  .highlight { font-weight: 600; color: #2d3748; background: #e2e8f0; padding: 2px 6px; border-radius: 4px; }"
                    + "  .confetti { position: absolute; width: 10px; height: 10px; background-color: #f0f; border-radius: 50%; opacity: 0; }"
                    + "  @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }"
                    + "  .animate-fade-in { animation: fadeIn 0.6s ease-out forwards; }"
                    + "  @media (max-width: 600px) { .email-body { padding: 30px 20px; } .email-header h1 { font-size: 24px; } }"
                    + "</style>"
                    + "</head>"
                    + "<body>"
                    + "<div class='email-container animate-fade-in'>"
                    + "  <div class='email-header'>"
                    + "    <div class='email-logo'>"
                    + "      <svg width='40' height='40' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'>"
                    + "        <path d='M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "        <path d='M8 14C8 14 9.5 16 12 16C14.5 16 16 14 16 14' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "        <path d='M9 9H9.01' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "        <path d='M15 9H15.01' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "      </svg>"
                    + "    </div>"
                    + "    <h1>Verifikasi Berhasil</h1>"
                    + "  </div>"
                    + "  <div class='email-body'>"
                    + "    <h2 class='greeting'>Selamat, " + name + "!</h2>"
                    + "    <p class='message'>Akun Anda dengan NIK <span class='highlight'>" + nik + "</span> telah berhasil diverifikasi oleh tim kami. Selamat datang di sistem E-Voting yang aman dan terpercaya.</p>"
                    + "    "
                    + "    <div class='highlight-box'>"
                    + "      <h3 class='highlight-title'>"
                    + "        <svg width='24' height='24' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'>"
                    + "          <path d='M22 11.08V12C21.9988 14.1564 21.3005 16.2547 20.0093 17.9818C18.7182 19.7089 16.9033 20.9725 14.8354 21.5839C12.7674 22.1953 10.5573 22.1219 8.53447 21.3746C6.51168 20.6273 4.78465 19.2461 3.61096 17.4371C2.43727 15.628 1.87979 13.4881 2.02168 11.3363C2.16356 9.18455 2.99721 7.13631 4.39828 5.49706C5.79935 3.85781 7.69279 2.71537 9.79619 2.24013C11.8996 1.7649 14.1003 1.98232 16.07 2.86' stroke='#667eea' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "          <path d='M22 4L12 14.01L9 11.01' stroke='#667eea' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "        </svg>"
                    + "        Akses Eksklusif Anda"
                    + "      </h3>"
                    + "      <p>Anda sekarang dapat:</p>"
                    + "      <ul class='features'>"
                    + "        <li>Login ke sistem E-Voting dengan aman</li>"
                    + "        <li>Memberikan suara dalam pemilihan online</li>"
                    + "        <li>Melacak status dan verifikasi suara Anda</li>"
                    + "        <li>Mengakses informasi pemilihan terbaru</li>"
                    + "      </ul>"
                    + "    </div>"
                    + "    "
                    + "    "
                    + "    <div class='footer'>"
                    + "      <p>© 2025 E-Voting System. All rights reserved.</p>"
                    + "      <p>Email ini dikirim secara otomatis, mohon tidak membalas.</p>"
                    + "    </div>"
                    + "  </div>"
                    + "</div>"
                    + "</body>"
                    + "</html>";

            email.setContent(htmlContent, "text/html");
            Transport.send(email);
        } catch (Exception e) {
            System.err.println("Failed to send approval email: " + e.getMessage());
        }
    }

    public static void sendPasswordResetEmail(String toEmail, String name, String otp) {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", SMTP_HOST);
        props.put("mail.smtp.port", SMTP_PORT);

        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(EMAIL_USERNAME, EMAIL_PASSWORD);
            }
        });

        try {
            Message email = new MimeMessage(session);
            email.setFrom(new InternetAddress(EMAIL_USERNAME, EMAIL_FROM_NAME));
            email.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toEmail));
            email.setSubject("Kode OTP Reset Password");

            // Enhanced HTML Email Content
            String htmlContent = "<!DOCTYPE html>"
                    + "<html>"
                    + "<head>"
                    + "<meta charset='UTF-8'>"
                    + "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                    + "<style>"
                    + "  * { box-sizing: border-box; margin: 0; padding: 0; }"
                    + "  body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #444; background-color: #f5f7fa; padding: 20px; }"
                    + "  .email-container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }"
                    + "  .email-header { background: linear-gradient(135deg, #3B82F6, #60A5FA); padding: 30px 20px; text-align: center; }"
                    + "  .email-header h1 { color: white; font-size: 24px; font-weight: 600; margin-bottom: 10px; }"
                    + "  .email-body { padding: 30px; }"
                    + "  .greeting { font-size: 18px; margin-bottom: 20px; color: #333; }"
                    + "  .message { margin-bottom: 25px; line-height: 1.7; }"
                    + "  .otp-container { margin: 30px 0; text-align: center; }"
                    + "  .otp-code { display: inline-block; font-size: 32px; font-weight: 700; letter-spacing: 5px; color: #1E40AF; background: #EFF6FF; padding: 15px 30px; border-radius: 8px; border: 2px dashed #3B82F6; }"
                    + "  .warning { background-color: #FEF2F2; color: #B91C1C; padding: 15px; border-radius: 8px; margin: 20px 0; font-size: 14px; border-left: 4px solid #EF4444; }"
                    + "  .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 13px; color: #777; }"
                    + "  .note { font-size: 14px; color: #666; margin-top: 20px; }"
                    + "</style>"
                    + "</head>"
                    + "<body>"
                    + "<div class='email-container'>"
                    + "  <div class='email-header'>"
                    + "    <h1>Permintaan Reset Password</h1>"
                    + "  </div>"
                    + "  <div class='email-body'>"
                    + "    <h2 class='greeting'>Halo, " + name + "!</h2>"
                    + "    <p class='message'>Kami menerima permintaan reset password untuk akun E-Voting Anda. Berikut adalah kode OTP Anda:</p>"
                    + "    <div class='otp-container'>"
                    + "      <div class='otp-code'>" + otp + "</div>"
                    + "    </div>"
                    + "    <p class='note'>Kode ini akan kadaluarsa dalam <strong>5 menit</strong>. Jangan berikan kode ini kepada siapapun, termasuk petugas kami.</p>"
                    + "    <div class='warning'>"
                    + "      <strong>Peringatan Keamanan:</strong> Jika Anda tidak meminta reset password, segera ubah password akun Anda dan hubungi tim dukungan kami."
                    + "    </div>"
                    + "    <div class='footer'>"
                    + "      <p>&copy; 2025 E-Voting System. Semua hak dilindungi.</p>"
                    + "      <p>Email ini dikirim secara otomatis, mohon tidak membalas.</p>"
                    + "    </div>"
                    + "  </div>"
                    + "</div>"
                    + "</body>"
                    + "</html>";

            email.setContent(htmlContent, "text/html");
            Transport.send(email);
        } catch (Exception e) {
            System.err.println("Failed to send password reset email: " + e.getMessage());
        }
    }

    public static void sendPasswordResetSuccessEmail(String toEmail, String name) {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", SMTP_HOST);
        props.put("mail.smtp.port", SMTP_PORT);

        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(EMAIL_USERNAME, EMAIL_PASSWORD);
            }
        });

        try {
            Message email = new MimeMessage(session);
            email.setFrom(new InternetAddress(EMAIL_USERNAME, EMAIL_FROM_NAME));
            email.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toEmail));
            email.setSubject("Password Anda Telah Diperbarui");

            String htmlContent = "<!DOCTYPE html>"
                    + "<html>"
                    + "<head>"
                    + "<meta charset='UTF-8'>"
                    + "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                    + "<style>"
                    + "  * { box-sizing: border-box; margin: 0; padding: 0; }"
                    + "  body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #444; background-color: #f5f7fa; padding: 20px; }"
                    + "  .email-container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }"
                    + "  .email-header { background: linear-gradient(135deg, #10B981, #34D399); padding: 30px 20px; text-align: center; }"
                    + "  .email-header h1 { color: white; font-size: 24px; font-weight: 600; margin-bottom: 10px; }"
                    + "  .email-body { padding: 30px; }"
                    + "  .greeting { font-size: 18px; margin-bottom: 20px; color: #333; }"
                    + "  .message { margin-bottom: 25px; line-height: 1.7; }"
                    + "  .success-icon { text-align: center; margin: 25px 0; }"
                    + "  .success-icon svg { width: 80px; height: 80px; color: #10B981; }"
                    + "  .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 13px; color: #777; }"
                    + "  .action-button { display: inline-block; background: #10B981; color: white; text-decoration: none; padding: 12px 25px; border-radius: 6px; font-weight: 500; margin-top: 15px; transition: all 0.3s ease; }"
                    + "  .action-button:hover { background: #059669; transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.1); }"
                    + "  .note { font-size: 14px; color: #666; margin-top: 20px; }"
                    + "  .security-note { background-color: #F3F4F6; padding: 15px; border-radius: 8px; margin-top: 25px; font-size: 13px; }"
                    + "</style>"
                    + "</head>"
                    + "<body>"
                    + "<div class='email-container'>"
                    + "  <div class='email-header'>"
                    + "    <h1>Password Berhasil Diperbarui</h1>"
                    + "  </div>"
                    + "  <div class='email-body'>"
                    + "    <h2 class='greeting'>Halo, " + name + "!</h2>"
                    + "    <p class='message'>Password akun E-Voting Anda telah berhasil diperbarui pada " + java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("dd MMMM yyyy HH:mm")) + ".</p>"
                    + "    <div class='success-icon'>"
                    + "      <svg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor'>"
                    + "        <path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' />"
                    + "      </svg>"
                    + "    </div>"
                    + "    <div class='security-note'>"
                    + "      <p><strong>Catatan Keamanan:</strong> Jika Anda tidak melakukan perubahan ini, segera hubungi administrator sistem melalui email resmi atau kontak yang tertera di website kami.</p>"
                    + "    </div>"
                    + "    <div class='footer'>"
                    + "      <p>&copy; 2025 E-Voting System. Semua hak dilindungi.</p>"
                    + "      <p>Email ini dikirim secara otomatis, mohon tidak membalas.</p>"
                    + "    </div>"
                    + "  </div>"
                    + "</div>"
                    + "</body>"
                    + "</html>";

            email.setContent(htmlContent, "text/html");
            Transport.send(email);
        } catch (Exception e) {
            System.err.println("Failed to send password reset success email: " + e.getMessage());
        }
    }

    public static void sendLoginApprovalEmail(String toEmail, String name) {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", SMTP_HOST);
        props.put("mail.smtp.port", SMTP_PORT);
        props.put("mail.smtp.ssl.protocols", "TLSv1.2");

        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(EMAIL_USERNAME, EMAIL_PASSWORD);
            }
        });

        try {
            Message email = new MimeMessage(session);
            email.setFrom(new InternetAddress(EMAIL_USERNAME, EMAIL_FROM_NAME));
            email.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toEmail));
            email.setSubject("✨ Akses Diberikan! Login Anda Telah Disetujui");

            // Ultra-Modern HTML Email Design
            String htmlContent = "<!DOCTYPE html>"
                    + "<html>"
                    + "<head>"
                    + "<meta charset='UTF-8'>"
                    + "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                    + "<title>Akses Disetujui</title>"
                    + "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap' rel='stylesheet'>"
                    + "<style>"
                    + "  * { box-sizing: border-box; margin: 0; padding: 0; }"
                    + "  body { font-family: 'Inter', sans-serif; line-height: 1.6; color: #1a1a1a; background: #f9fafb; padding: 20px; }"
                    + "  .email-container { max-width: 600px; margin: 0 auto; background: white; border-radius: 24px; overflow: hidden; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.1); transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.1); position: relative; }"
                    + "  .email-container:hover { transform: translateY(-5px); box-shadow: 0 30px 60px -10px rgba(0,0,0,0.15); }"
                    + "  .email-header { background: linear-gradient(135deg, #8e2de2 0%, #4a00e0 100%); padding: 60px 20px 40px; text-align: center; position: relative; overflow: hidden; }"
                    + "  .email-header::before { content: ''; position: absolute; top: -50%; left: -50%; width: 200%; height: 200%; background: radial-gradient(circle, rgba(255,255,255,0.15) 0%, rgba(255,255,255,0) 70%); transform: rotate(30deg); animation: shine 8s infinite linear; }"
                    + "  .logo-badge { width: 100px; height: 100px; margin: 0 auto 20px; background: rgba(255,255,255,0.2); border-radius: 50%; padding: 20px; display: flex; align-items: center; justify-content: center; backdrop-filter: blur(8px); border: 2px solid rgba(255,255,255,0.3); box-shadow: 0 10px 30px rgba(0,0,0,0.2); position: relative; z-index: 2; }"
                    + "  .email-header h1 { color: white; font-size: 32px; font-weight: 700; margin-bottom: 10px; position: relative; z-index: 2; text-shadow: 0 2px 4px rgba(0,0,0,0.1); }"
                    + "  .email-header p { color: rgba(255,255,255,0.9); font-size: 16px; position: relative; z-index: 2; }"
                    + "  .email-body { padding: 50px 40px; position: relative; }"
                    + "  .greeting { font-size: 24px; margin-bottom: 20px; color: #111827; font-weight: 600; position: relative; }"
                    + "  .greeting::after { content: ''; position: absolute; bottom: -10px; left: 0; width: 60px; height: 4px; background: linear-gradient(to right, #8e2de2, #4a00e0); border-radius: 2px; }"
                    + "  .message { margin-bottom: 30px; line-height: 1.7; color: #4b5563; font-size: 16px; }"
                    + "  .feature-card { background: white; border-radius: 16px; padding: 30px; margin: 30px 0; box-shadow: 0 10px 20px rgba(142, 45, 226, 0.08); border: 1px solid rgba(142, 45, 226, 0.1); position: relative; overflow: hidden; }"
                    + "  .feature-card::before { content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: linear-gradient(to bottom, #8e2de2, #4a00e0); }"
                    + "  .feature-title { font-weight: 600; color: #7c3aed; margin-bottom: 20px; display: flex; align-items: center; font-size: 18px; }"
                    + "  .feature-title svg { margin-right: 12px; flex-shrink: 0; }"
                    + "  .features { list-style: none; margin: 20px 0; }"
                    + "  .features li { padding: 12px 0; padding-left: 40px; position: relative; margin-bottom: 10px; }"
                    + "  .features li::before { content: ''; position: absolute; left: 0; top: 12px; width: 24px; height: 24px; background-color: #8e2de2; mask-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='white'%3E%3Cpath d='M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z'/%3E%3C/svg%3E\"); mask-repeat: no-repeat; mask-position: center; background-color: #8e2de2; border-radius: 50%; }"
                    + "  .action-button { display: inline-block; background: linear-gradient(to right, #8e2de2, #4a00e0); color: white; text-decoration: none; padding: 16px 40px; border-radius: 50px; font-weight: 600; margin-top: 20px; transition: all 0.3s ease; box-shadow: 0 10px 20px rgba(142, 45, 226, 0.3); font-size: 16px; border: none; cursor: pointer; position: relative; overflow: hidden; }"
                    + "  .action-button::before { content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: linear-gradient(to right, rgba(255,255,255,0.2), rgba(255,255,255,0)); transform: translateX(-100%); transition: transform 0.6s ease; }"
                    + "  .action-button:hover { transform: translateY(-3px); box-shadow: 0 15px 30px rgba(142, 45, 226, 0.4); }"
                    + "  .action-button:hover::before { transform: translateX(100%); }"
                    + "  .footer { text-align: center; margin-top: 50px; padding-top: 30px; border-top: 1px solid #e5e7eb; font-size: 14px; color: #6b7280; }"
                    + "  .confetti { position: absolute; width: 12px; height: 12px; background: linear-gradient(45deg, #8e2de2, #4a00e0); border-radius: 50%; opacity: 0; }"
                    + "  @keyframes shine { 0% { transform: rotate(30deg) translate(-30%, -30%); } 100% { transform: rotate(30deg) translate(30%, 30%); } }"
                    + "  @keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-10px); } }"
                    + "  @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }"
                    + "  .animate-float { animation: float 4s ease-in-out infinite; }"
                    + "  .animate-fade-in { animation: fadeIn 0.8s ease-out forwards; }"
                    + "  .delay-1 { animation-delay: 0.2s; }"
                    + "  .delay-2 { animation-delay: 0.4s; }"
                    + "  .delay-3 { animation-delay: 0.6s; }"
                    + "  @media (max-width: 600px) { .email-body { padding: 30px 20px; } .email-header h1 { font-size: 26px; } .greeting { font-size: 22px; } }"
                    + "</style>"
                    + "</head>"
                    + "<body>"
                    + "<div class='email-container animate-fade-in'>"
                    + "  <div class='email-header'>"
                    + "    <div class='logo-badge animate-float'>"
                    + "      <svg width='48' height='48' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'>"
                    + "        <path d='M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "        <path d='M12 16V12' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "        <path d='M12 8H12.01' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "      </svg>"
                    + "    </div>"
                    + "    <h1>Akses Disetujui!</h1>"
                    + "    <p>Login Anda telah diverifikasi oleh tim kami</p>"
                    + "  </div>"
                    + "  <div class='email-body'>"
                    + "    <h2 class='greeting'>Halo, " + name + "!</h2>"
                    + "    <p class='message'>Kami senang memberitahukan bahwa permintaan login Anda telah disetujui. Anda sekarang dapat mengakses semua fitur eksklusif dari sistem E-Voting kami.</p>"
                    + "    "
                    + "    <div class='feature-card animate-fade-in delay-1'>"
                    + "      <h3 class='feature-title'>"
                    + "        <svg width='24' height='24' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'>"
                    + "          <path d='M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z' stroke='#8e2de2' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "          <path d='M16 16L8 8' stroke='#8e2de2' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "          <path d='M16 8L8 16' stroke='#8e2de2' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>"
                    + "        </svg>"
                    + "        Fitur Eksklusif Anda"
                    + "      </h3>"
                    + "      <ul class='features'>"
                    + "        <li class='animate-fade-in delay-2'>Akses penuh ke dashboard pemilihan</li>"
                    + "        <li class='animate-fade-in delay-2'>Memberikan suara dengan aman dan terenkripsi</li>"
                    + "      </ul>"
                    + "    </div>"
                    + "    "
                    + "    "
                    + "    <div class='footer animate-fade-in delay-3'>"
                    + "      <p>© 2025 E-Voting System Premium. All rights reserved.</p>"
                    + "      <p style='margin-top: 8px;'>Email ini dikirim otomatis - mohon tidak membalas</p>"
                    + "    </div>"
                    + "  </div>"
                    + "</div>"
                    + "</body>"
                    + "</html>";

            email.setContent(htmlContent, "text/html");
            Transport.send(email);
        } catch (Exception e) {
            System.err.println("Failed to send login approval email: " + e.getMessage());
        }
    }

    public static void sendPrivateKeyEmail(String toEmail, String name, String privateKey) {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", SMTP_HOST);
        props.put("mail.smtp.port", SMTP_PORT);
        props.put("mail.smtp.ssl.protocols", "TLSv1.2");

        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(EMAIL_USERNAME, EMAIL_PASSWORD);
            }
        });

        try {
            Message email = new MimeMessage(session);
            email.setFrom(new InternetAddress(EMAIL_USERNAME, EMAIL_FROM_NAME));
            email.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toEmail));
            email.setSubject("Private Key Officer Khusus - E-Voting System");

            // Enhanced HTML Email Content with Blue Theme
            String htmlContent = "<!DOCTYPE html>"
                    + "<html>"
                    + "<head>"
                    + "<meta charset='UTF-8'>"
                    + "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                    + "<style>"
                    + "  * { box-sizing: border-box; margin: 0; padding: 0; }"
                    + "  body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f8fafc; padding: 20px; }"
                    + "  .email-container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.08); border: 1px solid #e2e8f0; }"
                    + "  .email-header { background: linear-gradient(135deg, #2563eb, #1d4ed8); padding: 32px 20px; text-align: center; }"
                    + "  .email-header h1 { color: white; font-size: 26px; font-weight: 600; margin-bottom: 8px; letter-spacing: 0.5px; }"
                    + "  .email-header p { color: rgba(255,255,255,0.9); font-size: 14px; }"
                    + "  .email-body { padding: 32px; }"
                    + "  .greeting { font-size: 18px; margin-bottom: 20px; color: #1e293b; font-weight: 500; }"
                    + "  .message { margin-bottom: 24px; line-height: 1.7; color: #475569; }"
                    + "  .key-container { margin: 28px 0; position: relative; }"
                    + "  .key-label { font-size: 14px; color: #334155; margin-bottom: 8px; font-weight: 500; display: flex; align-items: center; }"
                    + "  .key-label svg { margin-right: 8px; }"
                    + "  .private-key { background-color: #f1f5f9; padding: 16px; border-radius: 8px; font-family: 'Courier New', monospace; word-break: break-all; border: 1px solid #cbd5e1; font-size: 13px; line-height: 1.5; color: #1e40af; position: relative; }"
                    + "  .private-key:before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 24px; background: linear-gradient(to bottom, #f1f5f9, transparent); pointer-events: none; }"
                    + "  .private-key:after { content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 24px; background: linear-gradient(to top, #f1f5f9, transparent); pointer-events: none; }"
                    + "  .warning { background-color: #eff6ff; color: #1e40af; padding: 16px; border-radius: 8px; margin: 24px 0; font-size: 14px; border-left: 4px solid #2563eb; display: flex; }"
                    + "  .warning svg { flex-shrink: 0; margin-right: 12px; margin-top: 2px; }"
                    + "  .warning-content { flex: 1; }"
                    + "  .warning strong { color: #1e3a8a; }"
                    + "  .note { font-size: 14px; color: #64748b; margin-top: 24px; line-height: 1.6; }"
                    + "  .note-item { display: flex; margin-bottom: 12px; }"
                    + "  .note-item svg { margin-right: 8px; flex-shrink: 0; margin-top: 3px; }"
                    + "  .footer { text-align: center; margin-top: 32px; padding-top: 24px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #94a3b8; }"
                    + "  .highlight { background-color: #dbeafe; padding: 2px 4px; border-radius: 4px; font-weight: 500; }"
                    + "</style>"
                    + "</head>"
                    + "<body>"
                    + "<div class='email-container'>"
                    + "  <div class='email-header'>"
                    + "    <h1>Private Key Officer Khusus</h1>"
                    + "    <p>Sistem E-Voting - Akses Terbatas</p>"
                    + "  </div>"
                    + "  <div class='email-body'>"
                    + "    <h2 class='greeting'>Halo, " + name + "!</h2>"
                    + "    <p class='message'>Anda telah ditetapkan sebagai <span class='highlight'>Officer Khusus</span> dalam sistem E-Voting. Berikut adalah private key Anda yang harus disimpan dengan aman dan rahasia:</p>"
                    + "    <div class='key-container'>"
                    + "      <div class='key-label'>"
                    + "        <svg width='16' height='16' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'><path d='M12 15C13.6569 15 15 13.6569 15 12C15 10.3431 13.6569 9 12 9C10.3431 9 9 10.3431 9 12C9 13.6569 10.3431 15 12 15Z' fill='#1e40af'/><path d='M17 7V5C17 3.89543 16.1046 3 15 3H9C7.89543 3 7 3.89543 7 5V7H5C3.89543 7 3 7.89543 3 9V19C3 20.1046 3.89543 21 5 21H19C20.1046 21 21 20.1046 21 19V9C21 7.89543 20.1046 7 19 7H17ZM7 5C7 4.44772 7.44772 4 8 4H16C16.5523 4 17 4.44772 17 5V7H7V5Z' fill='#1e40af'/></svg>"
                    + "        Private Key Anda"
                    + "      </div>"
                    + "      <div class='private-key'>" + privateKey + "</div>"
                    + "    </div>"
                    + "    <div class='warning'>"
                    + "      <svg width='20' height='20' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'><path d='M12 9V11M12 15H12.01M5.07183 19H18.9282C20.4678 19 21.4301 17.3333 20.6603 16L13.7321 4C12.9623 2.66667 11.0378 2.66667 10.268 4L3.33978 16C2.56998 17.3333 3.53223 19 5.07183 19Z' stroke='#1e40af' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/></svg>"
                    + "      <div class='warning-content'>"
                    + "        <strong>PERINGATAN KEAMANAN TINGGI:</strong> Private key ini adalah <span class='highlight'>rahasia resmi</span> dan hanya boleh diketahui oleh Anda. Jangan bagikan, salin, atau simpan di tempat yang tidak aman."
                    + "      </div>"
                    + "    </div>"
                    + "    <div class='note'>"
                    + "      <div class='note-item'>"
                    + "        <svg width='16' height='16' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'><path d='M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z' stroke='#64748b' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/><path d='M12 8V12M12 16H12.01' stroke='#64748b' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/></svg>"
                    + "        <span>Private key ini akan digunakan untuk proses <span class='highlight'>dekripsi suara</span> dan verifikasi tanda tangan digital.</span>"
                    + "      </div>"
                    + "      <div class='note-item'>"
                    + "        <svg width='16' height='16' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'><path d='M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z' stroke='#64748b' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/><path d='M12 16V12M12 8H12.01' stroke='#64748b' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/></svg>"
                    + "        <span>Simpan private key ini di tempat <span class='highlight'>aman</span> dan <span class='highlight'>offline</span> (tidak terhubung ke internet).</span>"
                    + "      </div>"
                    + "      <div class='note-item'>"
                    + "        <svg width='16' height='16' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'><path d='M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z' stroke='#64748b' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/><path d='M12 16V12M12 8H12.01' stroke='#64748b' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/></svg>"
                    + "        <span>Key ini <span class='highlight'>tidak akan dikirim ulang</span> melalui email atau saluran digital lainnya.</span>"
                    + "      </div>"
                    + "    </div>"
                    + "    <div class='footer'>"
                    + "      <p>&copy; 2025 Sistem E-Voting. Semua hak dilindungi.</p>"
                    + "      <p>Email ini dikirim secara otomatis - jangan dibalas.</p>"
                    + "    </div>"
                    + "  </div>"
                    + "</div>"
                    + "</body>"
                    + "</html>";

            email.setContent(htmlContent, "text/html");
            Transport.send(email);
        } catch (Exception e) {
            System.err.println("Failed to send private key email: " + e.getMessage());
        }
    }
}
