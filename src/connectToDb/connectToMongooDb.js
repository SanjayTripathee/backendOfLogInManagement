import mongoose from "mongoose";

const connectToMongoDb = () => {
  // mongoose.connect( "mongodb+srv://sanjay:sanjay@codersanjay.jknb2.mongodb.net/dw18project");
  mongoose.connect("mongodb://0.0.0.0:27017/dw18project");
  console.log("application is connected to MongoDB successfully");
};

export default connectToMongoDb;
