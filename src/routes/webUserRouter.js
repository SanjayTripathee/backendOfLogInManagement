import { Router } from "express";
import {
  createWebUserController,
  deleteSpeceficUser,
  forgotPassword,
  loginUser,
  myProfile,
  readAllUsers,
  readSpeceficUser,
  resetPassword,
  updatePassword,
  updateProfile,
  updateSpeceficUser,
  verifyEmail,
} from "../controller/webUserController.js";
import authorized from "../middleware/authorized.js";
import isAuthenticated from "../middleware/isAuthenticated.js";

let webUserRouter = Router();
webUserRouter.route("/").post(createWebUserController);

webUserRouter.route("/verify-email").patch(verifyEmail);

webUserRouter.route("/login").post(loginUser);

webUserRouter.route("/my-profile").get(isAuthenticated, myProfile);

webUserRouter.route("/update-profile").patch(isAuthenticated, updateProfile);

webUserRouter.route("/update-password").patch(isAuthenticated, updatePassword);  

webUserRouter.route("/").get(readAllUsers);

webUserRouter.route("/forgot-password").post(forgotPassword);

webUserRouter.route("/reset-password").patch(isAuthenticated, resetPassword);

//always put => ("/:id") at last because it might confuse and let id is the thing which you want to perform and might run and you will get error ok..

webUserRouter
  .route("/:id")
  .get(isAuthenticated, authorized(["admin", "superadmin"]), readSpeceficUser); //admin,superAdmin

webUserRouter
  .route("/:id")
  .patch(
    isAuthenticated,
    authorized(["admin", "superadmin"]),
    updateSpeceficUser
  ); //admin,superAdmin

webUserRouter
  .route("/:id")
  .delete(isAuthenticated, authorized(["superadmin"]), deleteSpeceficUser); //superAdmin

export default webUserRouter;
