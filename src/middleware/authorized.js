import expressAsyncHandler from "express-async-handler";
import { WebUser } from "../schema/model.js";

//authorization =>to give permission for specefic person to see or change content
const authorized = (roles) => {
  return expressAsyncHandler(async (req, res, next) => {
    //to get detail
    let result = await WebUser.findById(req._id);
    // console.log(result);
    let takenRole = result.role; //we have pass admin

    if (roles.includes(takenRole)) {
      next();
    } else {
      res.status(403).json({
        success: false,
        message: "user not authroized ",
      });
    }
  });
};

export default authorized;
