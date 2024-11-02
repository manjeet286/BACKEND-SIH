import jwt from "jsonwebtoken";
import { ApiError } from '../utils/ApiError.js';
import { asyncHandler } from "../utils/ayncHandler.js";
import { User } from "../models/user.model.js";

export const VerfiyJwt = asyncHandler(async (req, _, next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");
        console.log("Token:", token); // Log the token for debugging

        // Check if the token is valid
        if (!token) {
            throw new ApiError(401, "Unauthorized Request: Invalid token");
        }

        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken");
        
        if (!user) {
            throw new ApiError(401, "Invalid Access Token");
        }

        req.user = user;
        next();
    } catch (error) {
        console.error("Error in JWT verification:", error); // Log the error for debugging
        throw new ApiError(401, error.message || "Invalid Access");
    }
});
