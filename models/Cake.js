import mongoose from "mongoose";

const CakeSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  price: { type: Number, required: true },
  image: String, // image URL
});

export default mongoose.model("Cake", CakeSchema);