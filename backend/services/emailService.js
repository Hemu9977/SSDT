const IS_AWS = process.env.NODE_ENV === 'production';
const FROM_EMAIL = process.env.SES_FROM_EMAIL;
const SENDER = `FORTEXA <${FROM_EMAIL}>`;
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
    await transporter.sendMail({ from: `FORTEXA <${process.env.EMAIL_USER}>`, to, subject, html });
  }
}

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

const sendOTPEmail = async (email, otp) => {
  try {
    await sendEmail(email, 'Your FORTEXA Verification Code', `
    <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0a0a; padding: 30px; border-radius: 8px; border: 1px solid #3a1a00;">
      <div style="text-align: center; margin-bottom: 20px;">
        <h1 style="color: #FF6B00; margin: 0; font-size: 36px; letter-spacing: 3px; font-weight: bold;">FORTEXA</h1>
        <p style="color: #999; font-size: 13px; margin: 5px 0 0 0; letter-spacing: 1px; text-transform: uppercase;">Security Scanner</p>
      </div>
      <div style="padding: 25px; background-color: #111111; border-radius: 6px; border: 1px solid #2a2a2a;">
        <h2 style="color: #ffffff; text-align: left; margin-top: 0; font-size: 20px;">Your Verification Code</h2>
        <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">Hello,</p>
        <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">Your one-time password (OTP) for account verification is:</p>
        <div style="background-color: #1a0a00; border: 2px solid #FF6B00; border-radius: 6px; padding: 25px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #FF6B00; margin: 25px 0;">
          ${otp}
        </div>
        <p style="font-size: 15px; line-height: 1.6; color: #cccccc;">This code will expire in <strong style="color: #FFA366;">10 minutes</strong>.</p>
        <p style="font-size: 13px; color: #777777;">If you did not request this code, please ignore this email or contact support.</p>
      </div>
      <div style="text-align: center; padding-top: 20px; border-top: 1px solid #2a2a2a; margin-top: 20px;">
        <p style="font-size: 13px; color: #555555; margin: 0;">Best regards,<br><span style="color: #FF6B00; font-weight: bold;">The FORTEXA Team</span></p>
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
    await sendEmail(email, 'Password Reset Request - FORTEXA', `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0a0a; padding: 30px; border-radius: 8px; border: 1px solid #3a1a00;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #FF6B00; margin: 0; font-size: 36px; letter-spacing: 3px; font-weight: bold;">FORTEXA</h1>
          <p style="color: #999; font-size: 13px; margin: 5px 0 0 0; letter-spacing: 1px; text-transform: uppercase;">Security Scanner</p>
        </div>
        <div style="padding: 25px; background-color: #111111; border-radius: 6px; border: 1px solid #2a2a2a;">
          <h2 style="color: #ffffff; text-align: left; margin-top: 0; font-size: 20px;">Password Reset Request</h2>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">Hello,</p>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">You have requested to reset your FORTEXA password. Click the button below to set a new password:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" style="background-color: #FF6B00; color: #ffffff; padding: 14px 32px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 15px; display: inline-block; letter-spacing: 0.5px;">Reset Password</a>
          </div>
          <p style="font-size: 15px; line-height: 1.6; color: #cccccc;">This link will expire in <strong style="color: #FFA366;">1 hour</strong>.</p>
          <p style="font-size: 13px; color: #777777;">If you did not request this password reset, please ignore this email. Your password will remain unchanged.</p>
        </div>
        <div style="text-align: center; padding-top: 20px; border-top: 1px solid #2a2a2a; margin-top: 20px;">
          <p style="font-size: 13px; color: #555555; margin: 0;">Best regards,<br><span style="color: #FF6B00; font-weight: bold;">The FORTEXA Team</span></p>
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
    await sendEmail(email, 'FORTEXA – Your Security Scan Results Are Ready', `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0a0a; padding: 30px; border-radius: 8px; border: 1px solid #3a1a00;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #FF6B00; margin: 0; font-size: 36px; letter-spacing: 3px; font-weight: bold;">FORTEXA</h1>
          <p style="color: #999; font-size: 13px; margin: 5px 0 0 0; letter-spacing: 1px; text-transform: uppercase;">Security Scanner</p>
        </div>
        <div style="padding: 25px; background-color: #111111; border-radius: 6px; border: 1px solid #2a2a2a;">
          <h2 style="color: #ffffff; text-align: left; margin-top: 0; font-size: 20px;">Scan Completed</h2>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">Hello ${userName},</p>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">Your security scan has completed successfully. Your vulnerability report and full analysis are ready to view.</p>
          <div style="background-color: #1a0a00; border: 1px solid #3a1a00; border-radius: 6px; padding: 20px; margin: 20px 0;">
            <h3 style="color: #FF6B00; margin-top: 0; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;">Scan Details</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="color: #777; padding: 7px 0; font-size: 14px; border-bottom: 1px solid #2a2a2a;">Scan Type</td>
                <td style="color: #f0f0f0; padding: 7px 0; font-size: 14px; text-align: right; border-bottom: 1px solid #2a2a2a;">${scanType}</td>
              </tr>
              <tr>
                <td style="color: #777; padding: 7px 0; font-size: 14px; border-bottom: 1px solid #2a2a2a;">Target URL</td>
                <td style="color: #FF6B00; padding: 7px 0; font-size: 14px; text-align: right; word-break: break-all; border-bottom: 1px solid #2a2a2a;">${targetUrl}</td>
              </tr>
              <tr>
                <td style="color: #777; padding: 7px 0; font-size: 14px; border-bottom: 1px solid #2a2a2a;">Scan ID</td>
                <td style="color: #f0f0f0; padding: 7px 0; font-size: 14px; text-align: right; font-family: monospace; border-bottom: 1px solid #2a2a2a;">${scanId}</td>
              </tr>
              <tr>
                <td style="color: #777; padding: 7px 0; font-size: 14px;">Completed</td>
                <td style="color: #f0f0f0; padding: 7px 0; font-size: 14px; text-align: right;">${formattedTime}</td>
              </tr>
            </table>
          </div>
          <p style="font-size: 15px; line-height: 1.6; color: #cccccc;">Log in to FORTEXA and visit your <strong style="color: #FFA366;">Profile</strong> page to view the full report, download a PDF, or export raw scan data.</p>
        </div>
        <div style="text-align: center; padding-top: 20px; border-top: 1px solid #2a2a2a; margin-top: 20px;">
          <p style="font-size: 13px; color: #555555; margin: 0;">Thank you for using FORTEXA.<br><span style="color: #FF6B00; font-weight: bold;">The FORTEXA Team</span></p>
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
    await sendEmail(email, `FORTEXA: Scheduled ${scanType} Started`, `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0a0a; padding: 30px; border-radius: 8px; border: 1px solid #3a1a00;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #FF6B00; margin: 0; font-size: 36px; letter-spacing: 3px; font-weight: bold;">FORTEXA</h1>
          <p style="color: #999; font-size: 13px; margin: 5px 0 0 0; letter-spacing: 1px; text-transform: uppercase;">Security Scanner</p>
        </div>
        <div style="padding: 25px; background-color: #111111; border-radius: 6px; border: 1px solid #2a2a2a; border-left: 4px solid #FF6B00;">
          <h2 style="color: #ffffff; text-align: left; margin-top: 0; font-size: 20px;">Scheduled Scan Started</h2>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">Hello ${userName},</p>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">Your automated <strong style="color: #FFA366;">${scanType}</strong> for <strong style="color: #FF6B00;">${targetUrl}</strong> has just started executing.</p>
          <p style="font-size: 15px; line-height: 1.6; color: #cccccc;">You will receive another email once the scan is complete and the report is ready.</p>
        </div>
        <div style="text-align: center; padding-top: 20px; border-top: 1px solid #2a2a2a; margin-top: 20px;">
          <p style="font-size: 13px; color: #555555; margin: 0;">Best regards,<br><span style="color: #FF6B00; font-weight: bold;">The FORTEXA Team</span></p>
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
    await sendEmail(email, `FORTEXA: Scheduled ${scanType} Failed`, `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0a0a; padding: 30px; border-radius: 8px; border: 1px solid #3a1a00;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #FF6B00; margin: 0; font-size: 36px; letter-spacing: 3px; font-weight: bold;">FORTEXA</h1>
          <p style="color: #999; font-size: 13px; margin: 5px 0 0 0; letter-spacing: 1px; text-transform: uppercase;">Security Scanner</p>
        </div>
        <div style="padding: 25px; background-color: #111111; border-radius: 6px; border: 1px solid #2a2a2a; border-left: 4px solid #ef4444;">
          <h2 style="color: #ef4444; text-align: left; margin-top: 0; font-size: 20px;">Scan Failed</h2>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">Hello ${userName},</p>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">Unfortunately, your automated <strong style="color: #FFA366;">${scanType}</strong> for <strong style="color: #FF6B00;">${targetUrl}</strong> failed to complete.</p>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;"><strong>Reason:</strong> ${failureReason || 'An unexpected error occurred.'}</p>
          <p style="font-size: 15px; line-height: 1.6; color: #cccccc;">Please check your FORTEXA dashboard to review your scan configuration or run the scan manually.</p>
        </div>
        <div style="text-align: center; padding-top: 20px; border-top: 1px solid #2a2a2a; margin-top: 20px;">
          <p style="font-size: 13px; color: #555555; margin: 0;">Best regards,<br><span style="color: #FF6B00; font-weight: bold;">The FORTEXA Team</span></p>
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
    await sendEmail(email, 'FORTEXA: Scan Scheduled Successfully', `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0a0a; padding: 30px; border-radius: 8px; border: 1px solid #3a1a00;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #FF6B00; margin: 0; font-size: 36px; letter-spacing: 3px; font-weight: bold;">FORTEXA</h1>
          <p style="color: #999; font-size: 13px; margin: 5px 0 0 0; letter-spacing: 1px; text-transform: uppercase;">Security Scanner</p>
        </div>
        <div style="padding: 25px; background-color: #111111; border-radius: 6px; border: 1px solid #2a2a2a; border-left: 4px solid #10b981;">
          <h2 style="color: #10b981; text-align: left; margin-top: 0; font-size: 20px;">Scan Scheduled</h2>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">Hello ${userName},</p>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">You have successfully scheduled a <strong style="color: #FFA366;">${scanType}</strong> for <strong style="color: #FF6B00;">${targetUrl}</strong>.</p>
          <div style="background-color: #1a0a00; border: 1px solid #3a1a00; border-radius: 6px; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; color: #777; font-size: 13px; text-transform: uppercase; letter-spacing: 1px;">Schedule Details</p>
            <p style="margin: 8px 0 0 0; color: #f0f0f0; font-size: 15px;"><strong>Type:</strong> ${scheduleType}</p>
            <p style="margin: 6px 0 0 0; color: #f0f0f0; font-size: 15px;"><strong>Execution:</strong> ${displayTime}</p>
          </div>
          <p style="font-size: 15px; line-height: 1.6; color: #cccccc;">FORTEXA will notify you when the scan starts and again when your results are ready.</p>
        </div>
        <div style="text-align: center; padding-top: 20px; border-top: 1px solid #2a2a2a; margin-top: 20px;">
          <p style="font-size: 13px; color: #555555; margin: 0;">Best regards,<br><span style="color: #FF6B00; font-weight: bold;">The FORTEXA Team</span></p>
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
