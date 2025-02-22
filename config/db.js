import mongoose from "mongoose";

export const connectDB = async() => {
        await mongoose.connect('mongodb+srv://Caravan:project123@cluster0.l8ms4op.mongodb.net/Caravan');
        console.log("DB Connected");
}