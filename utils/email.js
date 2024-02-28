const nodemailer = require('nodemailer');
const pug = require('pug');
const htmlToText = require('html-to-text');

module.exports = class Email {
  constructor(user, url, emailOTP) {
    this.to = user.email;
    this.emailOTP = emailOTP || undefined;
    this.firstName = user.firstName;
    this.url = url;
    this.from = `Gradell Tech Ltd <${process.env.EMAIL_FROM}>`;
  }

  newTransport() {
    if (process.env.NODE_ENV === 'production') {
      // Sendgrid
      //   return nodemailer.createTransport({
      //     service: 'SendGrid',
      //     auth: {
      //       user: process.env.SENDGRID_USERNAME,
      //       pass: process.env.SENDGRID_PASSWORD
      //     }
      //   });
      // }

      // Brevo
      return nodemailer.createTransport({
        host: process.env.BREVO_HOST,
        port: process.env.BREVO_PORT,
        secure: false, // true for 465, false for other ports
        auth: {
          user: process.env.BREVO_USERNAME,
          pass: process.env.BREVO_PASSWORD
        }
      });
    }

    return nodemailer.createTransport({
      host: process.env.EMAILTRAP_HOST,
      port: process.env.EMAILTRAP_PORT,
      auth: {
        user: process.env.EMAILTRAP_USERNAME,
        pass: process.env.EMAILTRAP_PASSWORD
      }
    });
  }

  // Send the actual email
  async send(template, subject) {
    // 1) Render HTML based on a pug template
    const html = pug.renderFile(`${__dirname}/../views/email/${template}.pug`, {
      firstName: this.firstName,
      emailOTP: this.emailOTP,
      url: this.url,
      subject
    });

    // 2) Define email options
    const mailOptions = {
      from: this.from,
      to: this.to,
      subject,
      html,
      text: htmlToText.fromString(html)
    };

    // 3) Create a transport and send email
    await this.newTransport().sendMail(mailOptions);
  }

  async sendWelcome() {
    await this.send('welcome', 'Welcome');
  }

  async sendEmailOTP() {
    await this.send(
      'emailOtpToken',
      'Gradell Tech Ltd: Confirm your email address'
    );
  }

  async sendEmailVerifySuccess() {
    await this.send('emailVerifySuccess', 'Email successfully verified');
  }

  async sendPinReset() {
    await this.send('pinReset', 'Pin reset token');
  }

  async sendPinResetSuccess() {
    await this.send('pinResetSuccess', 'Pin successfully changed');
  }

  async sendTransctionSuccess() {
    await this.send('transactionSuccess', 'Transaction successful');
  }
};
