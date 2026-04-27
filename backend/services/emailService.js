const IS_AWS = process.env.USE_AWS_SES === 'true';
const FROM_EMAIL = process.env.SES_FROM_EMAIL;
const SENDER = `SSDT Security <${FROM_EMAIL}>`;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

let sesClient, SendEmailCommand;
if (IS_AWS) {
  const { SESClient, SendEmailCommand: _SendEmailCommand } = require('@aws-sdk/client-ses');
  SendEmailCommand = _SendEmailCommand;
  sesClient = new SESClient({ region: process.env.AWS_REGION });
}

let transporter;
if (!IS_AWS) {
  const nodemailer = require('nodemailer');
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
}

async function sendEmail(to, subject, html) {
  if (IS_AWS) {
    try {
      await sesClient.send(new SendEmailCommand({
        Source: SENDER,
        Destination: { ToAddresses: [to] },
        Message: {
          Subject: { Data: subject },
          Body: { Html: { Data: html } },
        },
      }));
    } catch (err) {
      // In production, a missing IAM role is fatal — let it propagate
      if (process.env.NODE_ENV === 'production') throw err;
      // In local dev, AWS credentials aren't available; log the email instead
      if (err.name === 'CredentialsProviderError' || err.tryNextLink === false) {
        console.warn(`[DEV] SES unavailable (no credentials). Would have sent to <${to}>: "${subject}"`);
        return;
      }
      throw err;
    }
  } else {
    await transporter.sendMail({ from: `SSDT Security <${process.env.EMAIL_USER}>`, to, subject, html });
  }
}

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

const sendOTPEmail = async (email, otp) => {
  try {
    await sendEmail(email, 'Your SSDT Verification Code', `
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
  `);
    console.log(`OTP email sent to ${email}`);
  } catch (error) {
    console.error('Error sending OTP email:', error);
    throw error;
  }
};

const sendResetPasswordEmail = async (email, resetToken) => {
  const resetUrl = `${FRONTEND_URL}/reset-password/${resetToken}`;
  try {
    await sendEmail(email, 'Password Reset Request - SSDT', `
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
    `);
    console.log(`Password reset email sent to ${email}`);
  } catch (error) {
    console.error('Error sending password reset email:', error);
    throw error;
  }
};

const sendScanCompletionEmail = async (email, userName, scanDetails) => {
  const { scanType, targetUrl, scanId, completedAt, dashboardLink } = scanDetails;
  const formattedTime = new Date(completedAt).toLocaleString('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
  try {
    await sendEmail(email, 'SSDT Scan Completed – Your Security Scan Results Are Ready', `
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
            <a href="${dashboardLink}" style="background-color: #00E0FF; color: #000000; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">View Report</a>
          </div>
        </div>
        <div style="text-align: center; padding-top: 20px;">
          <p style="font-size: 14px; color: #999999; margin: 0;">Thank you for using SSDT – Security Scanning & Detection Tool.</p>
          <p style="font-size: 14px; color: #999999; margin: 5px 0 0 0;">Best regards,<br>Your SSDT Team</p>
        </div>
      </div>
    `);
    console.log(`Scan completion email sent to ${email}`);
  } catch (error) {
    console.error('Error sending scan completion email:', error);
    throw error;
  }
};

const sendScanTriggeredEmail = async (email, userName, scanDetails) => {
  const { scanType, targetUrl } = scanDetails;
  try {
    await sendEmail(email, `SSDT: Scheduled ${scanType} Triggered`, `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0f18; padding: 30px; border-radius: 8px; border: 1px solid #2a3b5f;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #00E0FF; margin: 0; font-size: 36px;">SSDT</h1>
          <p style="color: #999; font-size: 14px;">Security Scanner Detection Tool</p>
        </div>
        <div style="padding: 20px; background-color: #101827; border-radius: 5px;">
          <h2 style="color: #ffffff; text-align: left; margin-top: 0;">🚀 Scheduled Scan Started</h2>
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">Hello ${userName},</p>
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">Your automated ${scanType} for <b style="color: #00E0FF;">${targetUrl}</b> has just started executing.</p>
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">You will receive another email once the scan is complete and the report is ready.</p>
        </div>
      </div>
    `);
    console.log(`Scan triggered email sent to ${email}`);
  } catch (error) {
    console.error('Error sending scan triggered email:', error);
  }
};

const sendScanFailedEmail = async (email, userName, scanDetails) => {
  const { scanType, targetUrl, failureReason } = scanDetails;
  try {
    await sendEmail(email, `SSDT: Scheduled ${scanType} Failed`, `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0f18; padding: 30px; border-radius: 8px; border: 1px solid #2a3b5f;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #00E0FF; margin: 0; font-size: 36px;">SSDT</h1>
          <p style="color: #999; font-size: 14px;">Security Scanner Detection Tool</p>
        </div>
        <div style="padding: 20px; background-color: #101827; border-radius: 5px; border-left: 4px solid #ef4444;">
          <h2 style="color: #ef4444; text-align: left; margin-top: 0;">❌ Scan Failed</h2>
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">Hello ${userName},</p>
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">Unfortunately, your automated ${scanType} for <b style="color: #00E0FF;">${targetUrl}</b> failed to complete.</p>
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;"><strong>Reason:</strong> ${failureReason || 'An unexpected error occurred.'}</p>
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">Please check your dashboard to review your configurations or run the scan manually.</p>
        </div>
      </div>
    `);
    console.log(`Scan failed email sent to ${email}`);
  } catch (error) {
    console.error('Error sending scan failed email:', error);
  }
};

const sendScheduleConfirmationEmail = async (email, userName, scheduleDetails) => {
  const { scanType, targetUrl, scheduleType, displayTime } = scheduleDetails;
  try {
    await sendEmail(email, 'SSDT: Scan Scheduled Successfully', `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0f18; padding: 30px; border-radius: 8px; border: 1px solid #2a3b5f;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #00E0FF; margin: 0; font-size: 36px;">SSDT</h1>
          <p style="color: #999; font-size: 14px;">Security Scanner Detection Tool</p>
        </div>
        <div style="padding: 20px; background-color: #101827; border-radius: 5px; border-left: 4px solid #10b981;">
          <h2 style="color: #10b981; text-align: left; margin-top: 0;">📅 Scan Scheduled</h2>
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">Hello ${userName},</p>
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">You have successfully scheduled a <b>${scanType}</b> for <b style="color: #00E0FF;">${targetUrl}</b>.</p>
          <div style="background-color: #000000; border: 1px solid #2a3b5f; border-radius: 5px; padding: 15px; margin: 15px 0;">
            <p style="margin: 0; color: #999; font-size: 14px;">Schedule Details:</p>
            <p style="margin: 5px 0 0 0; color: #f0f0f0;"><b>Type:</b> ${scheduleType}</p>
            <p style="margin: 5px 0 0 0; color: #f0f0f0;"><b>Execution:</b> ${displayTime}</p>
          </div>
          <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">We will notify you again once the scan starts and when the results are ready.</p>
        </div>
      </div>
    `);
    console.log(`Schedule confirmation email sent to ${email}`);
  } catch (error) {
    console.error('Error sending schedule confirmation email:', error);
  }
};

module.exports = {
  generateOTP,
  sendOTPEmail,
  sendResetPasswordEmail,
  sendScanCompletionEmail,
  sendScanTriggeredEmail,
  sendScanFailedEmail,
  sendScheduleConfirmationEmail,
};
