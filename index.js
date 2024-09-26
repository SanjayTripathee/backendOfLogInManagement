import express, { json } from "express";
import errorMiddleware from "./src/middleware/errorMiddlewire.js";
import connectToMongoDb from "./src/connectToDb/connectToMongooDb.js";
import cors from "cors";
import webUserRouter from "./src/routes/webUserRouter.js";
import notFoundMiddleware from "./src/middleware/notFoundMiddleware.js";


let expressApp = express();
expressApp.use(cors()); //! cors is enable so that we could hit api from browser(it is always put on top)
expressApp.use(json()); //dont forget to import json

expressApp.listen(8000, () => {
  console.log("Server is running on port 8000");
  connectToMongoDb();
});

expressApp.use("/web-users", webUserRouter);//write kabab case on sending part ok


expressApp.use("*", notFoundMiddleware); //! always put it after all route is decleare ..put down after route ok...

expressApp.use(errorMiddleware); 



