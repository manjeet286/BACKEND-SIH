
import nodemailer from "nodemailer"
const sendEmail= async(option)=>{
   // create a transporter 
   const transporter= nodemailer.createTransport({
        host:process.env.EMAIL_HOST,
        port:process.env.EMAIL_PORT,
        secure: false,
        auth:{
             user:process.env.EMAIL_USER,
             pass:process.env.EMAIL_PASSWORD
        }

   })
     const emailOptions= {
         from:"Cineflix support<support@Cineflix.cm>",
         to:option.email,
         subject:option.subject,
         text:option.message
     }
    await  transporter.sendMail(emailOptions)

}
export default sendEmail