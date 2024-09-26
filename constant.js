import { config } from "dotenv";

config(); //for .env

export const seceretekey = process.env.SECRET_KEY;

export const url = `mongodb+srv://sanjay:sanjay@codersanjay.jknb2.mongodb.net/dw18project`
