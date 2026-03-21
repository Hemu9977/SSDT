const nodemailer = require('nodemailer');

// Create transporter
const transporter = nodemailer.createTransport({
  service: 'gmail', 
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Generate 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send OTP email
const sendOTPEmail = async (email, otp) => {
  const mailOptions = {
    to: email,
  subject: 'Your SSDT Verification Code',
  html: `
    <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0f18; padding: 30px; border-radius: 8px; border: 1px solid #2a3b5f;">
      
      <div style="text-align: center; margin-bottom: 20px;">
        <h1 style="color: #00E0FF; margin: 0; font-size: 36px; letter-spacing: 2px; font-weight: bold;">SSDT</h1>
        <p style="color: #999; font-size: 14px; margin: 5px 0 0 0;">Security Scanner Detection Tool</p>
      </div>
  
      <div style="padding: 20px; background-color: #101827; border-radius: 5px;">
        <h2 style="color: #ffffff; text-align: left; margin-top: 0;">Your Verification Code</h2>
        
        <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">Hello,</p>
        
        <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">Your one-time password (OTP) for account verification is:</p>
        
        <div style="background-color: #000000; border: 1px solid #00E0FF; border-radius: 5px; padding: 20px; text-align: center; font-size: 28px; font-weight: bold; letter-spacing: 5px; color: #00E0FF; margin: 25px 0;">
          ${otp}
        </div>
        
        <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">This code will expire in 10 minutes.</p>
        
        <p style="font-size: 14px; color: #999999;">If you did not request this code, please ignore this email or contact support.</p>
      </div>

      <div style="text-align: center; padding-top: 20px;">
        <p style="font-size: 14px; color: #999999; margin: 0;">Best regards,<br>Your SSDT Team</p>
      </div>
      
    </div>
  `,
};

  try {
    await transporter.sendMail(mailOptions);
    console.log(`OTP email sent to ${email}`);
  } catch (error) {
    console.error('Error sending OTP email:', error);
    throw error;
  }
};

const crypto = require('crypto');

// Send reset password email
const sendResetPasswordEmail = async (email, resetToken) => {
  const resetUrl = `http://localhost:3000/reset-password/${resetToken}`;

  const mailOptions = {
    to: email,
    subject: 'Password Reset Request - SSDT',
    html: `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0f18; padding: 30px; border-radius: 8px; border: 1px solid #2a3b5f;">
        
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #00E0FF; margin: 0; font-size: 36px; letter-spacing: 2px; font-weight: bold;">SSDT</h1>
          <p style="color: #999; font-size: 14px; margin: 5px 0 0 0;">Security Scanner Detection Tool</p>
        </div>
    
        <div style="padding: 20px; background-color: #101827; border-radius: 5px;">
          <h2 style="color: #ffffff; text-align: left; margin-top: 0;">Password Reset Request</h2>
          
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">Hello,</p>
          
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">You have requested to reset your password. Click the button below to reset your password:</p>
          
          <div style="text-align: center; margin: 25px 0;">
            <a href="${resetUrl}" style="background-color: #00E0FF; color: #000000; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Reset Password</a>
          </div>
          
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">This link will expire in 1 hour.</p>
          
          <p style="font-size: 14px; color: #999999;">If you did not request this password reset, please ignore this email. Your password will remain unchanged.</p>
        </div>

        <div style="text-align: center; padding-top: 20px;">
          <p style="font-size: 14px; color: #999999; margin: 0;">Best regards,<br>Your SSDT Team</p>
        </div>
        
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Password reset email sent to ${email}`);
  } catch (error) {
    console.error('Error sending password reset email:', error);
    throw error;
  }
};

// Send scan completion notification email
const sendScanCompletionEmail = async (email, userName, scanDetails) => {
  const { scanType, targetUrl, scanId, completedAt, dashboardLink } = scanDetails;

  const formattedTime = new Date(completedAt).toLocaleString('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short'
  });

  const mailOptions = {
    to: email,
    subject: 'SSDT Scan Completed – Your Security Scan Results Are Ready',
    html: `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0f18; padding: 30px; border-radius: 8px; border: 1px solid #2a3b5f;">
        
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #00E0FF; margin: 0; font-size: 36px; letter-spacing: 2px; font-weight: bold;">SSDT</h1>
          <p style="color: #999; font-size: 14px; margin: 5px 0 0 0;">Security Scanner Detection Tool</p>
        </div>
    
        <div style="padding: 20px; background-color: #101827; border-radius: 5px;">
          <h2 style="color: #ffffff; text-align: left; margin-top: 0;">✅ Scan Completed</h2>
          
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">Hello ${userName},</p>
          
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">Your security scan has been successfully completed.</p>
          
          <div style="background-color: #000000; border: 1px solid #2a3b5f; border-radius: 5px; padding: 20px; margin: 20px 0;">
            <h3 style="color: #00E0FF; margin-top: 0; font-size: 16px;">Scan Details</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="color: #999; padding: 6px 0; font-size: 14px;">Scan Type:</td>
                <td style="color: #f0f0f0; padding: 6px 0; font-size: 14px; text-align: right;">${scanType}</td>
              </tr>
              <tr>
                <td style="color: #999; padding: 6px 0; font-size: 14px;">Target URL:</td>
                <td style="color: #00E0FF; padding: 6px 0; font-size: 14px; text-align: right; word-break: break-all;">${targetUrl}</td>
              </tr>
              <tr>
                <td style="color: #999; padding: 6px 0; font-size: 14px;">Scan ID:</td>
                <td style="color: #f0f0f0; padding: 6px 0; font-size: 14px; text-align: right; font-family: monospace;">${scanId}</td>
              </tr>
              <tr>
                <td style="color: #999; padding: 6px 0; font-size: 14px;">Completion Time:</td>
                <td style="color: #f0f0f0; padding: 6px 0; font-size: 14px; text-align: right;">${formattedTime}</td>
              </tr>
            </table>
          </div>
          
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">You can now log in to SSDT to view the full vulnerability report and security analysis.</p>
          
          <div style="text-align: center; margin: 25px 0;">
            <a href="${dashboardLink}" style="background-color: #00E0FF; color: #000000; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">View Results</a>
          </div>
        </div>

        <div style="text-align: center; padding-top: 20px;">
          <p style="font-size: 14px; color: #999999; margin: 0;">Thank you for using SSDT – Security Scanning & Detection Tool.</p>
          <p style="font-size: 14px; color: #999999; margin: 5px 0 0 0;">Best regards,<br>Your SSDT Team</p>
        </div>
        
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Scan completion email sent to ${email}`);
  } catch (error) {
    console.error('Error sending scan completion email:', error);
    throw error;
  }
};

module.exports = {
  generateOTP,
  sendOTPEmail,
  sendResetPasswordEmail,
  sendScanCompletionEmail,
};
