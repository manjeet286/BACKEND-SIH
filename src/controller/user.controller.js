
import { asyncHandler } from "../utils/ayncHandler.js";
import {User} from "../models/user.model.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiError } from "../utils/ApiError.js";
import { Apiresponse } from "../utils/Apiresponse.js";
import jwt from "jsonwebtoken"
import { mongo } from "mongoose";
import sendEmail from "../utils/email.js";
import crypto from "crypto"
const generateAccessTokenAndRefreshToken= async(userId)=>{
    try {
        const user= await User.findById(userId)
        const accessToken= user.generateAccessToken()
        const refreshToken= user.generateRefereshToken()
        user.refreshToken=refreshToken
        await user.save({validateBeforeSave:false})
        return {accessToken ,refreshToken}


    } catch (error) {
        throw new ApiError(500, "Something went wrong when generating  access and refresh Token")
    } 
}
const RegisterUser= asyncHandler(async(req ,res)=>{
    const {fullname, email, username, password} = req.body
    if(
        [fullname ,email, username, password].some((field)=>field?.trim() === "")
        
    )
    {
        throw new ApiError(400 ,"all fields adre compulsory")
  }
    const ExistedUser= await User.findOne({
       $or: [ {email},{ username}

       ]})
    if(ExistedUser)
    {
          throw new ApiError(400 ,"User already exits")

    }
    const avatarPath= req.files?.avatar[0]?.path;
    let coverImagePath;
    if(req.files && Array.isArray(req.files.coverImage)&& req.files.coverImage.length>0)
    {
        coverImagePath= req.files.coverImage[0].path
    }
    if(!avatarPath)
    {
         throw new ApiError(400, "Avatar field is required");
    }
    const avatar =await uploadOnCloudinary(avatarPath)
    const coverImage= await uploadOnCloudinary(coverImagePath);
    if(!avatar)
    {
          throw new ApiError(401, "AVatar  field is required");
    }
    const user= await User.create({
         fullname, 
         username,
         email,
         password,
         avatar:avatar.url,
         coverImage:coverImage?.url || ""

    })
    const createdUser= await User.findById(user._id).select("-password  -refreshToken")
    if(!createdUser)
    {
          throw new ApiError(400 ,"Something went wrong");
    }
    return res.status(201).json(
         new Apiresponse(200 , createdUser , "User registeres Successfully")
    )

})
const loginUser= asyncHandler(async(req,res)=>{
      const {email, username, password}= req.body
      if(!username && !email)
      {
         throw new ApiError(400, "Username   or email required")
      }
      const user= await User.findOne({
        $or:[{username} , {email}]
      })
      if(!user)
      {
         throw new ApiError(400, "user does not exits");
      }
      const isPasswordCorrect= await user.isPasswordCorrect(password)
      if(!isPasswordCorrect)
      {
         throw new ApiError(400, " password is incorrect")
      }
      const {accessToken , refreshToken}= await generateAccessTokenAndRefreshToken(user._id)
      const loggedinUser = await User.findById(user._id).select("-password -refreshToken");

      const options={
        httpOnly:true,
        secure:true,
      }
      return res.status(200)
      .cookie("accessToken" , accessToken, options)
      .cookie("refreshToken" , refreshToken, options)
      .json(
         new Apiresponse(
             
            200,
            {
                     user:loggedinUser, accessToken, refreshToken
         }
        , "User Logged in Successfully"
    )
      )
})
const logOutUser = asyncHandler(async (req, res) => {
    // Fetch refresh token from cookies or body
    const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

    if (!refreshToken) {
        return res.status(200)
            .clearCookie("accessToken", { httpOnly: true, secure: true })
            .clearCookie("refreshToken", { httpOnly: true, secure: true })
            .json(new Apiresponse(200, {}, "User1 logged out successfully"));
    }

    // Find user based on the refresh token
    const user = await User.findOne({ refreshToken });

    if (!user) {
        return res.status(200)
            .clearCookie("accessToken", { httpOnly: true, secure: true })
            .clearCookie("refreshToken", { httpOnly: true, secure: true })
            .json(new Apiresponse(200, {}, "User1 logged out successfully"));
    }

    // Clear the user's refresh token in the database
    await User.findByIdAndUpdate(user._id, {
        $unset: { refreshToken: 1 }
    }, { new: true });

    return res.status(200)
        .clearCookie("accessToken", { httpOnly: true, secure: true })
        .clearCookie("refreshToken", { httpOnly: true, secure: true })
        .json(new Apiresponse(200, {}, "User1 logged out successfully"));
});

const refreshAccessToken= asyncHandler(async(req, res)=>{
    const inCommingRefreshToken=  req.cookies.refreshToken || req.body.refreshToken
    if(!inCommingRefreshToken)
    {
         throw new ApiError(400 ,"Unauthorized Request")

    }
    try {
          const decodedToken= jwt.verify(
              inCommingRefreshToken, 
              process.env.REFRESH_TOKEN_SECRET,
          )
          const user= await User.findById(decodedToken?._id)
          if(!user)
          {
              throw new ApiError(401, " Invalid refresh Token")
          }
          if(inCommingRefreshToken!==user?.refreshToken)
          {
               throw new ApiError(401, "Refresh Token expired")
          }
          const options={
             httpOnly:true,
             secure:true
          }
          const {accessToken , newrefreshToken}=await generateAccessTokenAndRefreshToken(user._id)
          return res
          .status(200)
          .cookie("accessToken" , accessToken)
          .cookie("refreshToken" , newrefreshToken)
          .json(
               new Apiresponse(200 ,{accessToken, newrefreshToken}),
               "Accesss Token Refreshed"
          )
    } catch (error) {
          throw   new Apiresponse(401 , error?.message || "Invalid refresh Token")
    }
    
})

const getCurrentUser= asyncHandler(async(req,res)=>{
    return res
    .status(200)
    .json(200 , new Apiresponse(200 , req.user ,"Current User fetched Succesfully"))
})

const updateUserAvatar =asyncHandler(async(req,res)=>{
    const avatarLocalPath= req.file?.path
    if(!avatarLocalPath)
    {
          throw new ApiError(401, "avatar fils is missing")
    }
    const avatar= await uploadOnCloudinary(avatarLocalPath)
    if(!avatar)
    {
        throw new ApiError(401, " Error while uploading avatar on  cloundinary")
    }
    const user =await User.findByIdAndUpdate(req.user?._id ,{
          $set:{
                 avatar:avatar.url,
          }
    },{
        new:true
    }).select("-paasword")
    return res
    .status(200)
    .json(new Apiresponse(200 , "Aavatr Changed Succesfully"))
})
const updateUserCoverImage= asyncHandler(async(req,res)=>{
    const CoverImageLocalPath= req.files?.path
    if(!CoverImageLocalPath)
    {
         throw new ApiError(401, "CoverImage is Missing")
    }
    const coverImage= await uploadOnCloudinary(CoverImageLocalPath)
    if(!coverImage)
    {
          throw new ApiError(401 ,"Erorr while uploading on the Cloudinary")
    }
    const user= await User.findByIdAndUpdate(req.user?._id ,{
         $set:{
            coverImage:coverImage.url
         }
    },
{
     new:true
}).select("-password")
 return res
 .status(200)
 .json( new Apiresponse(200  , "CoverImage Changed SuccessFully"))
})
const forgotPassword= asyncHandler(async(req,res)=>{
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
        throw new ApiError(401, "User with this email does not exist");
    }

    const resetToken = user.createResetPasswordToken(); // Generates token and sets passwordResetToken and expiry fields on user

    // Save the user to update the reset token and expiry fields in the database
    await user.save({ validateBeforeSave: false });

    const resetURL = `${req.protocol}://${req.get('host')}/api/v2/users/resetPassword/${resetToken}`;
    const message = `We have received a password reset request. Please click on the link below to reset your password:\n\n${resetURL}\n\nThis reset password link is valid for only 10 minutes.`;

    try {
        await sendEmail({
            email: user.email,
            subject: 'Password change request received',
            message: message,
        });
        return res.status(200).json(new Apiresponse(200, "URL for password reset sent successfully"));
    } catch (error) {
        user.passwordResetToken = undefined;
        user.passwordResetTokenExpiry = undefined;
        await user.save({ validateBeforeSave: false }); // Clear reset token and expiry on failure
        throw new ApiError(500, "Due to a server issue, reset password URL could not be sent. Please try again later.");
    }
 

})
const resetPassword= asyncHandler(async(req,res)=>{
     const token= crypto.createHash('sha256').update(req.params.token).digest('hex')
  const user=  await User.findOne({passwordResetToken: token , passwordResetTokenExpiry: {$gt:Date.now()}})  // greater than : gt
    if(!user)
    {
          throw new ApiError(400, "Token is invlaid or expire")
    }
    // reseting the user password
    user.password= req.body.password;
    user.confirmPassword= req.body.confirmPassword;
    user.passwordResetToken=undefined;
    user.passwordResetTokenExpiry=undefined;
    user.passwordChangeAt=Date.now();
     await   user.save();
     // login user automatically
     const{accessToken, refreshToken}= await generateAccessTokenAndRefreshToken(user._id)
      return res.status(200)
      .json(new Apiresponse(200,   {
         accessToken, refreshToken
}, "Password changed Succesfully"))


})   
export{
    generateAccessTokenAndRefreshToken,
    RegisterUser,
    loginUser,
    logOutUser,
    refreshAccessToken,
   forgotPassword,
   resetPassword,
    getCurrentUser,
   
    updateUserAvatar ,
    updateUserCoverImage




}