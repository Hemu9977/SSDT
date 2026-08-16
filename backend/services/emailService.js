const IS_AWS = process.env.NODE_ENV === 'production';
const FROM_EMAIL = process.env.SES_FROM_EMAIL;
const SENDER = `FORTEXA <${FROM_EMAIL}>`;
const { getFrontendBaseUrl } = require('../utils/frontendUrl');
const FRONTEND_URL = getFrontendBaseUrl();

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
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // STARTTLS
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

// Emails are sent in the recipient's `preferredLanguage` (User model, mirrors the
// frontend's LanguageContext). Falls back to 'ja' — the product default — for any
// caller that doesn't have a user record handy (e.g. pre-account OTP flows).
const resolveLang = (lang) => (lang === 'en' ? 'en' : 'ja');

const sendOTPEmail = async (email, otp, lang) => {
  const l = resolveLang(lang);
  const t = {
    en: {
      subject: 'Your FORTEXA Verification Code',
      title: 'Your Verification Code',
      hello: 'Hello,',
      intro: 'Your one-time password (OTP) for account verification is:',
      expiry: 'This code will expire in <strong style="color: #FFA366;">10 minutes</strong>.',
      footer: 'If you did not request this code, please ignore this email or contact support.',
    },
    ja: {
      subject: 'FORTEXA 認証コードのご案内',
      title: '認証コード',
      hello: 'こんにちは。',
      intro: 'アカウント確認用のワンタイムパスワード(OTP)は以下の通りです。',
      expiry: 'このコードの有効期限は<strong style="color: #FFA366;">10分間</strong>です。',
      footer: '心当たりがない場合は、このメールを無視するか、サポートまでご連絡ください。',
    },
  }[l];
  try {
    await sendEmail(email, t.subject, `
    <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0a0a; padding: 30px; border-radius: 8px; border: 1px solid #3a1a00;">
      <div style="text-align: center; margin-bottom: 20px;">
        <h1 style="color: #FF6B00; margin: 0; font-size: 36px; letter-spacing: 3px; font-weight: bold;">FORTEXA</h1>
        <p style="color: #999; font-size: 13px; margin: 5px 0 0 0; letter-spacing: 1px; text-transform: uppercase;">Security Scanner</p>
      </div>
      <div style="padding: 25px; background-color: #111111; border-radius: 6px; border: 1px solid #2a2a2a;">
        <h2 style="color: #ffffff; text-align: left; margin-top: 0; font-size: 20px;">${t.title}</h2>
        <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">${t.hello}</p>
        <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">${t.intro}</p>
        <div style="background-color: #1a0a00; border: 2px solid #FF6B00; border-radius: 6px; padding: 25px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #FF6B00; margin: 25px 0;">
          ${otp}
        </div>
        <p style="font-size: 15px; line-height: 1.6; color: #cccccc;">${t.expiry}</p>
        <p style="font-size: 13px; color: #777777;">${t.footer}</p>
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

const sendResetPasswordEmail = async (email, resetToken, lang) => {
  const l = resolveLang(lang);
  const resetUrl = `${FRONTEND_URL}/reset-password/${resetToken}`;
  const t = {
    en: {
      subject: 'Password Reset Request - FORTEXA',
      title: 'Password Reset Request',
      hello: 'Hello,',
      intro: 'You have requested to reset your FORTEXA password. Click the button below to set a new password:',
      button: 'Reset Password',
      expiry: 'This link will expire in <strong style="color: #FFA366;">1 hour</strong>.',
      footer: 'If you did not request this password reset, please ignore this email. Your password will remain unchanged.',
    },
    ja: {
      subject: 'FORTEXA パスワード再設定のご案内',
      title: 'パスワード再設定リクエスト',
      hello: 'こんにちは。',
      intro: 'FORTEXAのパスワード再設定がリクエストされました。以下のボタンから新しいパスワードを設定してください。',
      button: 'パスワードを再設定',
      expiry: 'このリンクの有効期限は<strong style="color: #FFA366;">1時間</strong>です。',
      footer: '心当たりがない場合は、このメールを無視してください。パスワードは変更されません。',
    },
  }[l];
  try {
    await sendEmail(email, t.subject, `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0a0a; padding: 30px; border-radius: 8px; border: 1px solid #3a1a00;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #FF6B00; margin: 0; font-size: 36px; letter-spacing: 3px; font-weight: bold;">FORTEXA</h1>
          <p style="color: #999; font-size: 13px; margin: 5px 0 0 0; letter-spacing: 1px; text-transform: uppercase;">Security Scanner</p>
        </div>
        <div style="padding: 25px; background-color: #111111; border-radius: 6px; border: 1px solid #2a2a2a;">
          <h2 style="color: #ffffff; text-align: left; margin-top: 0; font-size: 20px;">${t.title}</h2>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">${t.hello}</p>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">${t.intro}</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" style="background-color: #FF6B00; color: #ffffff; padding: 14px 32px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 15px; display: inline-block; letter-spacing: 0.5px;">${t.button}</a>
          </div>
          <p style="font-size: 15px; line-height: 1.6; color: #cccccc;">${t.expiry}</p>
          <p style="font-size: 13px; color: #777777;">${t.footer}</p>
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

const sendScanCompletionEmail = async (email, userName, scanDetails, lang) => {
  const l = resolveLang(lang);
  const t = {
    en: {
      subject: 'FORTEXA – Your Security Scan Results Are Ready',
      title: 'Scan Completed',
      hello: (n) => `Hello ${n},`,
      intro: 'Your security scan has completed successfully. Your vulnerability report and full analysis are ready to view.',
      detailsHeading: 'Scan Details',
      scanType: 'Scan Type',
      targetUrl: 'Target URL',
      scanId: 'Scan ID',
      completed: 'Completed',
      outro: 'Log in to FORTEXA and visit your <strong style="color: #FFA366;">Profile</strong> page to view the full report, download a PDF, or export raw scan data.',
      footer: 'Thank you for using FORTEXA.',
    },
    ja: {
      subject: 'FORTEXA – セキュリティスキャン結果のお知らせ',
      title: 'スキャン完了',
      hello: (n) => `${n} 様`,
      intro: 'セキュリティスキャンが正常に完了しました。脆弱性レポートと詳細な分析結果をご確認いただけます。',
      detailsHeading: 'スキャン詳細',
      scanType: 'スキャン種別',
      targetUrl: '対象URL',
      scanId: 'スキャンID',
      completed: '完了日時',
      outro: 'FORTEXAにログインし、<strong style="color: #FFA366;">プロフィール</strong>ページから詳細レポートの閲覧、PDFダウンロード、生データのエクスポートが行えます。',
      footer: 'FORTEXAをご利用いただきありがとうございます。',
    },
  }[l];
  const { scanType, targetUrl, scanId, completedAt, dashboardLink } = scanDetails;
  const dateObj = new Date(completedAt);
  const formattedIST = dateObj.toLocaleString('en-US', {
    timeZone: 'Asia/Kolkata',
    dateStyle: 'medium',
    timeStyle: 'short',
  });
  const formattedJST = dateObj.toLocaleString('en-US', {
    timeZone: 'Asia/Tokyo',
    dateStyle: 'medium',
    timeStyle: 'short',
  });
  const formattedUTC = dateObj.toLocaleString('en-US', {
    timeZone: 'UTC',
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZoneName: 'short',
  });
  const formattedTime = `${formattedIST} IST / ${formattedJST} JST (${formattedUTC})`;
  try {
    await sendEmail(email, t.subject, `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0a0a; padding: 30px; border-radius: 8px; border: 1px solid #3a1a00;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #FF6B00; margin: 0; font-size: 36px; letter-spacing: 3px; font-weight: bold;">FORTEXA</h1>
          <p style="color: #999; font-size: 13px; margin: 5px 0 0 0; letter-spacing: 1px; text-transform: uppercase;">Security Scanner</p>
        </div>
        <div style="padding: 25px; background-color: #111111; border-radius: 6px; border: 1px solid #2a2a2a;">
          <h2 style="color: #ffffff; text-align: left; margin-top: 0; font-size: 20px;">${t.title}</h2>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">${t.hello(userName)}</p>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">${t.intro}</p>
          <div style="background-color: #1a0a00; border: 1px solid #3a1a00; border-radius: 6px; padding: 20px; margin: 20px 0;">
            <h3 style="color: #FF6B00; margin-top: 0; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;">${t.detailsHeading}</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="color: #777; padding: 7px 0; font-size: 14px; border-bottom: 1px solid #2a2a2a;">${t.scanType}</td>
                <td style="color: #f0f0f0; padding: 7px 0; font-size: 14px; text-align: right; border-bottom: 1px solid #2a2a2a;">${scanType}</td>
              </tr>
              <tr>
                <td style="color: #777; padding: 7px 0; font-size: 14px; border-bottom: 1px solid #2a2a2a;">${t.targetUrl}</td>
                <td style="color: #FF6B00; padding: 7px 0; font-size: 14px; text-align: right; word-break: break-all; border-bottom: 1px solid #2a2a2a;">${targetUrl}</td>
              </tr>
              <tr>
                <td style="color: #777; padding: 7px 0; font-size: 14px; border-bottom: 1px solid #2a2a2a;">${t.scanId}</td>
                <td style="color: #f0f0f0; padding: 7px 0; font-size: 14px; text-align: right; font-family: monospace; border-bottom: 1px solid #2a2a2a;">${scanId}</td>
              </tr>
              <tr>
                <td style="color: #777; padding: 7px 0; font-size: 14px;">${t.completed}</td>
                <td style="color: #f0f0f0; padding: 7px 0; font-size: 14px; text-align: right;">${formattedTime}</td>
              </tr>
            </table>
          </div>
          <p style="font-size: 15px; line-height: 1.6; color: #cccccc;">${t.outro}</p>
        </div>
        <div style="text-align: center; padding-top: 20px; border-top: 1px solid #2a2a2a; margin-top: 20px;">
          <p style="font-size: 13px; color: #555555; margin: 0;">${t.footer}<br><span style="color: #FF6B00; font-weight: bold;">The FORTEXA Team</span></p>
        </div>
      </div>
    `);
    console.log(`Scan completion email sent to ${email}`);
  } catch (error) {
    console.error('Error sending scan completion email:', error);
    throw error;
  }
};

const sendScanTriggeredEmail = async (email, userName, scanDetails, lang) => {
  const l = resolveLang(lang);
  const { scanType, targetUrl } = scanDetails;
  const t = {
    en: {
      subject: `FORTEXA: Scheduled ${scanType} Started`,
      title: 'Scheduled Scan Started',
      hello: `Hello ${userName},`,
      body: `Your automated <strong style="color: #FFA366;">${scanType}</strong> for <strong style="color: #FF6B00;">${targetUrl}</strong> has just started executing.`,
      outro: 'You will receive another email once the scan is complete and the report is ready.',
    },
    ja: {
      subject: `FORTEXA: 予約スキャン(${scanType})を開始しました`,
      title: '予約スキャンを開始しました',
      hello: `${userName} 様`,
      body: `<strong style="color: #FF6B00;">${targetUrl}</strong> を対象とした自動<strong style="color: #FFA366;">${scanType}</strong>の実行を開始しました。`,
      outro: 'スキャンが完了し、レポートの準備ができ次第、改めてメールでお知らせします。',
    },
  }[l];
  try {
    await sendEmail(email, t.subject, `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0a0a; padding: 30px; border-radius: 8px; border: 1px solid #3a1a00;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #FF6B00; margin: 0; font-size: 36px; letter-spacing: 3px; font-weight: bold;">FORTEXA</h1>
          <p style="color: #999; font-size: 13px; margin: 5px 0 0 0; letter-spacing: 1px; text-transform: uppercase;">Security Scanner</p>
        </div>
        <div style="padding: 25px; background-color: #111111; border-radius: 6px; border: 1px solid #2a2a2a; border-left: 4px solid #FF6B00;">
          <h2 style="color: #ffffff; text-align: left; margin-top: 0; font-size: 20px;">${t.title}</h2>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">${t.hello}</p>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">${t.body}</p>
          <p style="font-size: 15px; line-height: 1.6; color: #cccccc;">${t.outro}</p>
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

const sendScanFailedEmail = async (email, userName, scanDetails, lang) => {
  const l = resolveLang(lang);
  const { scanType, targetUrl, failureReason } = scanDetails;
  const t = {
    en: {
      subject: `FORTEXA: Scheduled ${scanType} Failed`,
      title: 'Scan Failed',
      hello: `Hello ${userName},`,
      body: `Unfortunately, your automated <strong style="color: #FFA366;">${scanType}</strong> for <strong style="color: #FF6B00;">${targetUrl}</strong> failed to complete.`,
      reasonLabel: 'Reason:',
      defaultReason: 'An unexpected error occurred.',
      outro: 'Please check your FORTEXA dashboard to review your scan configuration or run the scan manually.',
    },
    ja: {
      subject: `FORTEXA: 予約スキャン(${scanType})が失敗しました`,
      title: 'スキャン失敗',
      hello: `${userName} 様`,
      body: `<strong style="color: #FF6B00;">${targetUrl}</strong> を対象とした自動<strong style="color: #FFA366;">${scanType}</strong>が完了しませんでした。`,
      reasonLabel: '理由:',
      defaultReason: '予期しないエラーが発生しました。',
      outro: 'FORTEXAダッシュボードでスキャン設定をご確認いただくか、手動でスキャンを実行してください。',
    },
  }[l];
  try {
    await sendEmail(email, t.subject, `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0a0a; padding: 30px; border-radius: 8px; border: 1px solid #3a1a00;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #FF6B00; margin: 0; font-size: 36px; letter-spacing: 3px; font-weight: bold;">FORTEXA</h1>
          <p style="color: #999; font-size: 13px; margin: 5px 0 0 0; letter-spacing: 1px; text-transform: uppercase;">Security Scanner</p>
        </div>
        <div style="padding: 25px; background-color: #111111; border-radius: 6px; border: 1px solid #2a2a2a; border-left: 4px solid #ef4444;">
          <h2 style="color: #ef4444; text-align: left; margin-top: 0; font-size: 20px;">${t.title}</h2>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">${t.hello}</p>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">${t.body}</p>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;"><strong>${t.reasonLabel}</strong> ${failureReason || t.defaultReason}</p>
          <p style="font-size: 15px; line-height: 1.6; color: #cccccc;">${t.outro}</p>
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

const sendScheduleConfirmationEmail = async (email, userName, scheduleDetails, lang) => {
  const l = resolveLang(lang);
  const { scanType, targetUrl, scheduleType, displayTime } = scheduleDetails;
  const t = {
    en: {
      subject: 'FORTEXA: Scan Scheduled Successfully',
      title: 'Scan Scheduled',
      hello: `Hello ${userName},`,
      body: `You have successfully scheduled a <strong style="color: #FFA366;">${scanType}</strong> for <strong style="color: #FF6B00;">${targetUrl}</strong>.`,
      detailsHeading: 'Schedule Details',
      typeLabel: 'Type:',
      executionLabel: 'Execution:',
      outro: 'FORTEXA will notify you when the scan starts and again when your results are ready.',
    },
    ja: {
      subject: 'FORTEXA: スキャンの予約が完了しました',
      title: 'スキャン予約完了',
      hello: `${userName} 様`,
      body: `<strong style="color: #FF6B00;">${targetUrl}</strong> を対象とした<strong style="color: #FFA366;">${scanType}</strong>の予約が完了しました。`,
      detailsHeading: '予約詳細',
      typeLabel: '種別:',
      executionLabel: '実行日時:',
      outro: 'スキャン開始時と結果準備完了時に、改めてメールでお知らせします。',
    },
  }[l];
  try {
    await sendEmail(email, t.subject, `
      <div style="font-family: Arial, Helvetica, sans-serif; max-width: 600px; margin: 20px auto; background-color: #0a0a0a; padding: 30px; border-radius: 8px; border: 1px solid #3a1a00;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #FF6B00; margin: 0; font-size: 36px; letter-spacing: 3px; font-weight: bold;">FORTEXA</h1>
          <p style="color: #999; font-size: 13px; margin: 5px 0 0 0; letter-spacing: 1px; text-transform: uppercase;">Security Scanner</p>
        </div>
        <div style="padding: 25px; background-color: #111111; border-radius: 6px; border: 1px solid #2a2a2a; border-left: 4px solid #10b981;">
          <h2 style="color: #10b981; text-align: left; margin-top: 0; font-size: 20px;">${t.title}</h2>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">${t.hello}</p>
          <p style="font-size: 16px; line-height: 1.6; color: #cccccc;">${t.body}</p>
          <div style="background-color: #1a0a00; border: 1px solid #3a1a00; border-radius: 6px; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; color: #777; font-size: 13px; text-transform: uppercase; letter-spacing: 1px;">${t.detailsHeading}</p>
            <p style="margin: 8px 0 0 0; color: #f0f0f0; font-size: 15px;"><strong>${t.typeLabel}</strong> ${scanType}</p>
            <p style="margin: 6px 0 0 0; color: #f0f0f0; font-size: 15px;"><strong>${t.executionLabel}</strong> ${displayTime}</p>
          </div>
          <p style="font-size: 15px; line-height: 1.6; color: #cccccc;">${t.outro}</p>
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

// Send organization invite email
const sendInviteEmail = async (toEmail, { orgName, inviterName, role, token }) => {
  const joinUrl = `${getFrontendBaseUrl()}/join?token=${token}`;
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

  await sendEmail(toEmail, `You've been invited to join ${orgName} on FORTEXA`, html);
  console.log(`Invite email sent to ${toEmail} (org=${orgName}, role=${roleLabel})`);
};

module.exports = {
  generateOTP,
  sendOTPEmail,
  sendResetPasswordEmail,
  sendScanCompletionEmail,
  sendScanTriggeredEmail,
  sendScanFailedEmail,
  sendScheduleConfirmationEmail,
  sendInviteEmail,
};
