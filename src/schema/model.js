import { model } from "mongoose";
import webUserSchema from "./webUserSchema.js";


export let WebUser = model("WebUser", webUserSchema);

