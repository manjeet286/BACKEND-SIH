import { Router } from "express";
import { logOutUser, loginUser ,refreshAccessToken ,RegisterUser,  resetPassword,forgotPassword ,updateUserCoverImage , updateUserAvatar, getCurrentUser } from "../controller/user.controller.js";
import {VerfiyJwt} from "../middleWare/auth.middleware.js"
import {upload} from "../middleWare/multer.middleware.js"
const router =Router()
router.route("/register").post(
    upload.fields([
         {
             name:"avatar"
             ,maxCount:1,
         },{
            name:"coverImage",
            maxCount:1,
         }
    ]),
    RegisterUser
)
router.route("/login").post(
     loginUser
)
router.route("/forgotPassword").post(
    forgotPassword
)
 router.route("/resetPassword/:token").patch(
    resetPassword
 )
router.route("/logout").post(
    logOutUser
)
router.route("/refresh-token").post(refreshAccessToken)

router.route("/current-user").get(VerfiyJwt, getCurrentUser)

router.route("/avatar").patch(VerfiyJwt, updateUserAvatar)
router.route("/coverImage").patch(VerfiyJwt , updateUserCoverImage)
export  default router