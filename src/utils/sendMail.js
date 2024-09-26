
import nodemailer from "nodemailer";

let transporterInfo = {
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: "9864226384s@gmail.com",
    pass: "abjy fgvm zadp scms",
  },
};

export let sendMail = async (mailInfo) => {
  try {
    let transporter = nodemailer.createTransport(transporterInfo);
    let info = await transporter.sendMail(mailInfo);
  } catch (error) {
    console.log("error has occurred", error.message);
  }
};

//to send mail
