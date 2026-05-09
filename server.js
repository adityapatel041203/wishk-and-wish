import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import Cake from './models/Cake.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Get current directory name for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(cors());
app.use(express.json()); 

// Serve static files from images directory
app.use('/images', express.static(path.join(__dirname, 'images')));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/wishkandwish');

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// ========================
// Authentication Middleware
// ========================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Access token required' 
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid or expired token' 
      });
    }
    req.user = user;
    next();
  });
};

// ========================
// Admin Authentication Middleware (FIXED)
// ========================

const authenticateAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: 'Access token required' 
      });
    }

    // Verify token and get user data
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Find user in database to check admin status
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(403).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // Check if user is admin using the isAdmin field
    if (!user.isAdmin) {
      return res.status(403).json({ 
        success: false, 
        message: 'Admin access required' 
      });
    }
    
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid token' 
      });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({ 
        success: false, 
        message: 'Token expired' 
      });
    }
    res.status(500).json({ 
      success: false, 
      message: 'Server error during authentication' 
    });
  }
};

// ========================
// Schemas & Models
// ========================

// User Schema
// User Schema with admin role
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Order Schema - UPDATED to include userId
const orderSchema = new mongoose.Schema({
  // Customer Information
  name: { type: String, required: true },
  email: { type: String, required: true },
  dateNeeded: { type: Date, required: true },
  
  // User reference
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  
  // Cake Information
  cakeId: { type: String },
  cakeName: { type: String, required: true },
  cakePrice: { type: Number, required: true },
  
  // Order Details
  cakeFlavor: { type: String, required: true },
  cakeMessage: { type: String },
  cakeSize: { type: String, required: true },
  designPreferences: { type: String },
  
  // Order Metadata
  orderDate: { type: Date, default: Date.now },
  status: { type: String, default: 'pending' }, // pending, confirmed, completed, cancelled
  orderNumber: { type: String, unique: true },
});

const Order = mongoose.model('Order', orderSchema);

// Helper function to convert image path to full URL
const getFullImageUrl = (imagePath) => {
  if (!imagePath) return null;
  if (imagePath.startsWith('http')) return imagePath;
  return `http://localhost:${PORT}${imagePath.startsWith('/') ? imagePath : '/' + imagePath}`;
};

// Helper function to generate order number
const generateOrderNumber = () => {
  return 'ORD' + Date.now().toString() + Math.floor(Math.random() * 1000).toString().padStart(3, '0');
};

// ========================
// Routes
// ========================

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user
    const newUser = new User({
      name,
      email,
      password: hashedPassword
    });

    await newUser.save();
    
    // Generate JWT token
    const token = jwt.sign(
      { id: newUser._id, email: newUser.email }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    res.status(201).json({ 
      message: 'User created successfully',
      token,
      user: { id: newUser._id, name: newUser.name, email: newUser.email, isAdmin: newUser.isAdmin }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Login endpoint - UPDATED to return JWT token
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { 
        id: user._id, 
        name: user.name, 
        email: user.email,
        isAdmin: user.isAdmin 
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Admin login endpoint
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid credentials' 
      });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid credentials' 
      });
    }

    // Check if user is admin
    if (!user.isAdmin) {
      return res.status(403).json({ 
        success: false,
        message: 'Admin access required' 
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, email: user.email, isAdmin: true }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Admin login successful',
      token,
      user: { 
        id: user._id, 
        name: user.name, 
        email: user.email,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      message: 'Server error', 
      error: error.message 
    });
  }
});

// Verify admin status
app.get('/api/admin/verify', authenticateAdmin, async (req, res) => {
  res.json({
    success: true,
    message: 'Admin access verified',
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      isAdmin: req.user.isAdmin
    }
  });
});

// ========================
// Admin Routes
// ========================

// Get all orders (Admin only)
app.get('/api/admin/orders', authenticateAdmin, async (req, res) => {
  try {
    const orders = await Order.find().sort({ orderDate: -1 }).populate('userId', 'name email');
    res.json({
      success: true,
      orders
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching orders',
      error: error.message
    });
  }
});

// Get order statistics (Admin only)
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const totalOrders = await Order.countDocuments();
    const pendingOrders = await Order.countDocuments({ status: 'pending' });
    const completedOrders = await Order.countDocuments({ status: 'completed' });
    const totalRevenue = await Order.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$cakePrice' } } }
    ]);

    res.json({
      success: true,
      stats: {
        totalOrders,
        pendingOrders,
        completedOrders,
        totalRevenue: totalRevenue[0]?.total || 0
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching statistics',
      error: error.message
    });
  }
});

// Update order status (Admin only)
app.put('/api/admin/orders/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    
    const validStatuses = ['pending', 'confirmed', 'completed', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status'
      });
    }

    const updatedOrder = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).populate('userId', 'name email');

    if (!updatedOrder) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    res.json({
      success: true,
      message: 'Order status updated successfully',
      order: updatedOrder
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating order status',
      error: error.message
    });
  }
});

// Get all cakes (Admin with full control)
app.get('/api/admin/cakes', authenticateAdmin, async (req, res) => {
  try {
    const cakes = await Cake.find();
    res.json({
      success: true,
      cakes
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching cakes',
      error: error.message
    });
  }
});

// Add new cake (Admin only)
app.post('/api/admin/cakes', authenticateAdmin, async (req, res) => {
  try {
    const { name, description, price, image, category, flavors } = req.body;
    
    const imageUrl = getFullImageUrl(image);
    
    const newCake = new Cake({ 
      name, 
      description, 
      price, 
      image: imageUrl,
      category,
      flavors: flavors || []
    });
    
    await newCake.save();
    
    res.status(201).json({ 
      success: true,
      message: 'Cake added successfully', 
      cake: newCake 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      message: 'Error adding cake', 
      error: error.message 
    });
  }
});

// Update cake (Admin only)
app.put('/api/admin/cakes/:id', authenticateAdmin, async (req, res) => {
  try {
    const { name, description, price, image, category, flavors } = req.body;
    
    const imageUrl = getFullImageUrl(image);
    
    const updatedCake = await Cake.findByIdAndUpdate(
      req.params.id,
      { name, description, price, image: imageUrl, category, flavors },
      { new: true }
    );
    
    if (!updatedCake) {
      return res.status(404).json({ 
        success: false,
        message: 'Cake not found' 
      });
    }
    
    res.json({ 
      success: true,
      message: 'Cake updated successfully', 
      cake: updatedCake 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      message: 'Error updating cake', 
      error: error.message 
    });
  }
});

// Delete cake (Admin only)
app.delete('/api/admin/cakes/:id', authenticateAdmin, async (req, res) => {
  try {
    const deletedCake = await Cake.findByIdAndDelete(req.params.id);
    if (!deletedCake) {
      return res.status(404).json({ 
        success: false,
        message: 'Cake not found' 
      });
    }
    res.json({ 
      success: true,
      message: 'Cake deleted successfully' 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      message: 'Error deleting cake', 
      error: error.message 
    });
  }
});

// ========================
// Cake Routes
// ========================

// Add new cake
app.post('/api/cakes', async (req, res) => {
  try {
    const { name, description, price, image } = req.body;
    
    // Convert image path to full URL if needed
    const imageUrl = getFullImageUrl(image);
    
    const newCake = new Cake({ name, description, price, image: imageUrl });
    await newCake.save();
    
    res.status(201).json({ 
      message: 'Cake added successfully', 
      cake: newCake 
    });
  } catch (error) {
    res.status(500).json({ message: 'Error adding cake', error: error.message });
  }
});

// Get all cakes
app.get('/api/cakes', async (req, res) => {
  try {
    const cakes = await Cake.find();
    
    // Convert image paths to full URLs
    const cakesWithFullUrls = cakes.map(cake => ({
      ...cake.toObject(),
      image: getFullImageUrl(cake.image)
    }));
    
    res.json(cakesWithFullUrls);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching cakes', error: error.message });
  }
});

// Get single cake by ID
app.get('/api/cakes/:id', async (req, res) => {
  try {
    const cake = await Cake.findById(req.params.id);
    if (!cake) {
      return res.status(404).json({ message: 'Cake not found' });
    }
    
    // Convert image path to full URL
    const cakeWithFullUrl = {
      ...cake.toObject(),
      image: getFullImageUrl(cake.image)
    };
    
    res.json(cakeWithFullUrl);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching cake', error: error.message });
  }
});

// Update cake
app.put('/api/cakes/:id', async (req, res) => {
  try {
    const { name, description, price, image } = req.body;
    
    // Convert image path to full URL if needed
    const imageUrl = getFullImageUrl(image);
    
    const updatedCake = await Cake.findByIdAndUpdate(
      req.params.id,
      { name, description, price, image: imageUrl },
      { new: true }
    );
    
    if (!updatedCake) {
      return res.status(404).json({ message: 'Cake not found' });
    }
    
    res.json({ 
      message: 'Cake updated successfully', 
      cake: updatedCake 
    });
  } catch (error) {
    res.status(500).json({ message: 'Error updating cake', error: error.message });
  }
});

// Delete cake
app.delete('/api/cakes/:id', async (req, res) => {
  try {
    const deletedCake = await Cake.findByIdAndDelete(req.params.id);
    if (!deletedCake) {
      return res.status(404).json({ message: 'Cake not found' });
    }
    res.json({ message: 'Cake deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting cake', error: error.message });
  }
});

// Improved admin user creation
const createAdminUser = async () => {
  try {
    const adminEmail = 'admin@wishkandwish.com';
    const adminPassword = 'admin123'; // Change this in production!
    
    let adminUser = await User.findOne({ email: adminEmail });
    
    if (!adminUser) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      adminUser = new User({
        name: 'Administrator',
        email: adminEmail,
        password: hashedPassword,
        isAdmin: true
      });
      await adminUser.save();
      console.log('Admin user created successfully');
    } else if (!adminUser.isAdmin) {
      // Update existing user to admin if needed
      adminUser.isAdmin = true;
      await adminUser.save();
      console.log('Existing user updated to admin');
    } else {
      console.log('Admin user already exists');
    }
    
    console.log('Admin login credentials:');
    console.log('Email:', adminEmail);
    console.log('Password:', adminPassword);
    
  } catch (error) {
    console.error('Error creating admin user:', error);
  }
};

// Call this function when server starts
createAdminUser();

// ========================
// Order Routes - UPDATED with authentication
// ========================

// Create new order - UPDATED to include userId
app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const {
      name,
      email,
      dateNeeded,
      cakeId,
      cakeName,
      cakePrice,
      cakeFlavor,
      cakeMessage,
      cakeSize,
      designPreferences
    } = req.body;

    // Validate required fields
    if (!name || !email || !dateNeeded || !cakeName || !cakePrice || !cakeFlavor || !cakeSize) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields'
      });
    }

    // Generate unique order number
    const orderNumber = generateOrderNumber();

    // Create new order with userId from authenticated user
    const newOrder = new Order({
      name,
      email,
      dateNeeded: new Date(dateNeeded),
      userId: req.user.id, // Add user ID from authentication
      cakeId,
      cakeName,
      cakePrice: Number(cakePrice),
      cakeFlavor,
      cakeMessage,
      cakeSize,
      designPreferences,
      orderNumber
    });

    await newOrder.save();

    res.status(201).json({
      success: true,
      message: 'Order submitted successfully!',
      orderId: newOrder._id,
      orderNumber: newOrder.orderNumber,
      order: newOrder
    });

  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating order',
      error: error.message
    });
  }
});

// Get all orders for authenticated user - FIXED
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    // Get user ID from the authenticated request
    const userId = req.user.id;
    
    // Only fetch orders for this specific user
    const orders = await Order.find({ userId: userId }).sort({ orderDate: -1 });
    
    res.json({ success: true, orders });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get order by ID - UPDATED with user validation
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    // Check if the order belongs to the authenticated user
    if (order.userId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    res.json({
      success: true,
      order
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching order',
      error: error.message
    });
  }
});

// Update order status - UPDATED with user validation
app.put('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body;
    
    const order = await Order.findById(req.params.id);
    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    // Check if the order belongs to the authenticated user
    if (order.userId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }
    
    const updatedOrder = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    
    res.json({
      success: true,
      message: 'Order updated successfully',
      order: updatedOrder
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating order',
      error: error.message
    });
  }
});

// Cancel order endpoint - UPDATED with user validation
app.put('/api/orders/:id/cancel', authenticateToken, async (req, res) => {
  try {
    const orderId = req.params.id;
    
    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    // Check if the order belongs to the authenticated user
    if (order.userId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Access denied'
      });
    }

    // Check if order can be cancelled
    if (order.status === 'cancelled') {
      return res.status(400).json({
        success: false,
        message: 'Order is already cancelled'
      });
    }

    if (order.status === 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Completed orders cannot be cancelled'
      });
    }

    // Update order status to cancelled
    const updatedOrder = await Order.findByIdAndUpdate(
      orderId,
      { 
        status: 'cancelled',
        cancelledAt: new Date().toISOString()
      },
      { new: true }
    );

    res.json({
      success: true,
      message: 'Order cancelled successfully',
      order: updatedOrder
    });

  } catch (error) {
    console.error('Error cancelling order:', error);
    res.status(500).json({
      success: false,
      message: 'Error cancelling order',
      error: error.message
    });
  }
});

// ========================
// Start Server
// ========================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Static images served from: http://localhost:${PORT}/images/`);
  console.log(`Orders API available at: http://localhost:${PORT}/api/orders`);
});