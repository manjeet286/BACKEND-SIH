import mongoose ,{Schema} from "mongoose";
import jwt from "jsonwebtoken"
import  bcrypt from "bcrypt"
import  crypto from "crypto"
import { type } from "os";

const userSchema= new Schema({
      username:{
            type:String ,
            required:true,
            index:true,
            lowercase:true,
            trim:true,
      },
      password:{
        type:String,
        required:[true ,"Password is Required"]

      }
      ,
      confirmPassword:{
        type:String,
        required:[true ,"Password is Required"]
      },
      fullname:{
        type:String ,
        required:true,
        index:true,
       
        trim:true,
  },
  email:{
    type:String ,
    required:true,
    unique:true,
    lowercase:true,
    trime:true,
},
  avatar:{
    type:String,    
    required:true,

  },
  coverImage:{
        type:String
  },
   refreshToken:{
       type:String,
   },
   passwordResetToken:{
     type:String,
   },
   passwordResetTokenExpiry:{
      type:Date,
   },
   passwordChangeAt:{
    type:Date,
   }
    
    

      
    },{timestamp:true})
userSchema.pre("save" , async function(next){
     if(!this.isModified("password")){
        return next()
     }
     this.password= await bcrypt.hash(this.password,10)
     next()

})
userSchema.methods.isPasswordCorrect= async function (password) {
    return bcrypt.compare( password, this.password)
    
}
userSchema.methods.generateAccessToken =async function () {
    return jwt.sign(
        {
        _id:this._id,
        email:this.email,
        username:this.username,
        fullname:this.fullname,
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
          expiresIn:process.env.ACCESS_TOKEN_EXPIRY
        }
        
)

    
}
userSchema.methods.createResetPasswordToken=  function() {
  const resetToken = crypto.randomBytes(32).toString("hex"); // Convert token to string
  this.passwordResetToken = crypto.createHash("sha256").update(resetToken).digest("hex");
  this. passwordResetTokenExpiry = Date.now() + 10 * 60 * 1000; // Set expiration to 10 minutes
  console.log("Generated Reset Token:", resetToken, this.passwordResetToken); // Debugging
  return resetToken;
 // passwordResetTokenExpiry
  
}

userSchema.methods.generateRefereshToken= async function () {
  
   return jwt.sign(
     {
         _id:this._id

     },
     process.env.REFRESH_TOKEN_SECRET,{
      expiresIn:process.env.REFRESH_TOKEN_EXPIRY
     }
   )

}
export const User= mongoose.model("User" , userSchema)
