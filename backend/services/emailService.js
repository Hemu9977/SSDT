const sgMail = require('@sendgrid/mail');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const sendMail = async ({ to, subject, html }) => {
  try {
    const msg = {
      to,
      from: process.env.EMAIL_FROM, // must be verified in SendGrid
      subject,
      html,
    };

    const response = await sgMail.send(msg);
    console.log(`📧 Email sent via SendGrid to ${to}`);
    return response;
  } catch (error) {
    console.error('❌ SendGrid Error:', error.response?.body || error);
    throw error;
  }
};

// Generate 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send OTP email
const sendOTPEmail = async (email, otp) => {
  const html = `
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
  `;

  return await sendMail({ to: email, subject: 'Your SSDT Verification Code', html });
};

// Send reset password email
const sendResetPasswordEmail = async (email, resetToken) => {
  const resetUrl = `${process.env.CLIENT_URL || 'http://localhost:3000'}/reset-password/${resetToken}`;

  const html = `
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
  `;

  return await sendMail({ to: email, subject: 'Password Reset Request - SSDT', html });
};

// Send scan completion notification email
const sendScanCompletionEmail = async (email, userName, scanDetails) => {
  const { scanType, targetUrl, scanId, completedAt, dashboardLink } = scanDetails;
  const formattedTime = new Date(completedAt).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });

  const html = `
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
            <tr><td style="color: #999; padding: 6px 0; font-size: 14px;">Scan Type:</td><td style="color: #f0f0f0; padding: 6px 0; font-size: 14px; text-align: right;">${scanType}</td></tr>
            <tr><td style="color: #999; padding: 6px 0; font-size: 14px;">Target URL:</td><td style="color: #00E0FF; padding: 6px 0; font-size: 14px; text-align: right; word-break: break-all;">${targetUrl}</td></tr>
            <tr><td style="color: #999; padding: 6px 0; font-size: 14px;">Scan ID:</td><td style="color: #f0f0f0; padding: 6px 0; font-size: 14px; text-align: right; font-family: monospace;">${scanId}</td></tr>
            <tr><td style="color: #999; padding: 6px 0; font-size: 14px;">Completion Time:</td><td style="color: #f0f0f0; padding: 6px 0; font-size: 14px; text-align: right;">${formattedTime}</td></tr>
          </table>
        </div>
        <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">You can now log in to SSDT to view the full vulnerability report and security analysis.</p>
        <div style="text-align: center; margin: 25px 0;"><a href="${dashboardLink}" style="background-color: #00E0FF; color: #000000; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">View Report</a></div>
      </div>
    </div>
  `;

  return await sendMail({ to: email, subject: 'SSDT Scan Completed – Your Security Scan Results Are Ready', html });
};

// Send scan triggered notification email
const sendScanTriggeredEmail = async (email, userName, scanDetails) => {
  const { scanType, targetUrl } = scanDetails;

  const html = `
    <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0f18; padding: 30px; border-radius: 8px; border: 1px solid #2a3b5f;">
      <div style="text-align: center; margin-bottom: 20px;">
        <h1 style="color: #00E0FF; margin: 0; font-size: 36px;">SSDT</h1>
        <p style="color: #999; font-size: 14px;">Security Scanner Detection Tool</p>
      </div>
      <div style="padding: 20px; background-color: #101827; border-radius: 5px;">
        <h2 style="color: #ffffff; text-align: left; margin-top: 0;">🚀 Scheduled Scan Started</h2>
        <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">Hello ${userName},</p>
        <p style="font-size: 16px; line-height: 1.5; color: #f0f0f0;">Your automated ${scanType} for <b style="color: #00E0FF;">${targetUrl}</b> has just started executing.</p>
      </div>
    </div>
  `;

  return await sendMail({ to: email, subject: `SSDT: Scheduled ${scanType} Triggered`, html });
};

// Send scan failure notification email
const sendScanFailedEmail = async (email, userName, scanDetails) => {
  const { scanType, targetUrl, failureReason } = scanDetails;

  const html = `
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
      </div>
    </div>
  `;

  return await sendMail({ to: email, subject: `SSDT: Scheduled ${scanType} Failed`, html });
};

// Send schedule confirmation notification email
const sendScheduleConfirmationEmail = async (email, userName, scheduleDetails) => {
  const { scanType, targetUrl, scheduleType, displayTime } = scheduleDetails;

  const html = `
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
      </div>
    </div>
  `;

  return await sendMail({ to: email, subject: `SSDT: Scan Scheduled Successfully`, html });
};

// Send organization invite email
const sendInviteEmail = async (toEmail, { orgName, inviterName, role, token }) => {
  const joinUrl = `${process.env.CLIENT_URL || 'http://localhost:3000'}/join?token=${token}`;
  const roleLabel = role.charAt(0).toUpperCase() + role.slice(1);

  const html = `
    <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0f18; padding: 40px; border-radius: 12px; border: 1px solid #FF6B00;">
      <div style="text-align: center; margin-bottom: 30px;">
        <h1 style="color: #FF6B00; margin: 0; font-size: 32px; letter-spacing: 4px; font-weight: 900;">FORTEXA</h1>
        <p style="color: #888; font-size: 13px; margin: 6px 0 0 0; letter-spacing: 2px; text-transform: uppercase;">Security Intelligence Platform</p>
      </div>
      <div style="padding: 30px; background-color: #101827; border-radius: 8px; border-left: 3px solid #FF6B00;">
        <h2 style="color: #ffffff; margin-top: 0; font-size: 22px;">You've Been Invited</h2>
        <p style="font-size: 16px; line-height: 1.6; color: #d0d0d0;">
          ${inviterName ? `<strong style="color: #FF6B00;">${inviterName}</strong> has invited you` : 'You have been invited'} to join the organization <strong style="color: #FFA366;">${orgName}</strong> on FORTEXA.
        </p>
        <div style="background-color: #000; border: 1px solid #2a3b5f; border-radius: 6px; padding: 16px; margin: 20px 0;">
          <p style="margin: 0; color: #888; font-size: 13px; text-transform: uppercase; letter-spacing: 1px;">Your Role</p>
          <p style="margin: 6px 0 0 0; color: #FF6B00; font-size: 18px; font-weight: bold;">${roleLabel}</p>
        </div>
        <p style="font-size: 15px; line-height: 1.6; color: #d0d0d0;">Click the button below to accept your invitation. This link expires in <strong>7 days</strong>.</p>
        <div style="text-align: center; margin: 30px 0;"><a href="${joinUrl}" style="background: linear-gradient(135deg, #FF6B00, #FFA366); color: #000; padding: 14px 36px; text-decoration: none; border-radius: 6px; font-weight: 800; font-size: 16px; display: inline-block; letter-spacing: 1px;">JOIN TEAM →</a></div>
      </div>
    </div>
  `;

  return await sendMail({ to: toEmail, subject: `You've been invited to join ${orgName} on FORTEXA`, html });
};

module.exports = {
  sendMail,
  generateOTP,
  sendOTPEmail,
  sendResetPasswordEmail,
  sendScanCompletionEmail,
  sendScanTriggeredEmail,
  sendScanFailedEmail,
  sendScheduleConfirmationEmail,
  sendInviteEmail
};