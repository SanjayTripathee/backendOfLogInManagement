import { seceretekey } from "../../constant.js";
import jwt from "jsonwebtoken";
import expressAsyncHandler from "express-async-handler";
//isAuthenticated means it check token valid or not
const isAuthenticated = expressAsyncHandler(async (req, res, next) => {
  let tokenString = req.headers.authorization; //to get token
  let tokenArray = tokenString.split(" "); //convert token to array
  let token = tokenArray[1];
  //verify token
  let user = await jwt.verify(token, seceretekey);
  let _id = user._id;
  req._id = user._id;
  next(); //throwing id to next middlewire i.e middlewire infront of isAuthenticated in route
});

export default isAuthenticated;
