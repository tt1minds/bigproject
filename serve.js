const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const NodeGeocoder = require('node-geocoder');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/transitfinder', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// Database Models
const User = require('./models/User');
const Vehicle = require('./models/Vehicle');
const Booking = require('./models/Booking');
const Payment = require('./models/Payment');
const Route = require('./models/Route');

// Geocoder setup
const geocoder = NodeGeocoder({
    provider: 'openstreetmap'
});

// Authentication Middleware
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) throw new Error();
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findOne({ _id: decoded._id, 'tokens.token': token });
        
        if (!user) throw new Error();
        
        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};

// 1. User Authentication Routes
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, name, phone, userType } = req.body;
        
        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const user = new User({
            email,
            password: hashedPassword,
            name,
            phone,
            userType: userType || 'passenger',
            favorites: [],
            paymentMethods: []
        });
        
        await user.save();
        
        // Generate token
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
        user.tokens.push({ token });
        await user.save();
        
        res.status(201).json({ user, token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate token
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
        user.tokens.push({ token });
        await user.save();
        
        res.json({ user, token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/logout', authMiddleware, async (req, res) => {
    try {
        req.user.tokens = req.user.tokens.filter(token => token.token !== req.token);
        await req.user.save();
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 2. Vehicle Management
app.get('/api/vehicles', async (req, res) => {
    try {
        const { type, lat, lng, radius = 5000 } = req.query;
        let filter = {};
        
        if (type && type !== 'all') {
            filter.type = type;
        }
        
        if (lat && lng) {
            filter.location = {
                $near: {
                    $geometry: {
                        type: "Point",
                        coordinates: [parseFloat(lng), parseFloat(lat)]
                    },
                    $maxDistance: parseInt(radius)
                }
            };
        }
        
        filter.status = 'available';
        
        const vehicles = await Vehicle.find(filter).populate('driver', 'name rating avatar');
        res.json(vehicles);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/vehicles/:id', async (req, res) => {
    try {
        const vehicle = await Vehicle.findById(req.params.id).populate('driver', 'name rating avatar');
        if (!vehicle) {
            return res.status(404).json({ error: 'Vehicle not found' });
        }
        res.json(vehicle);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 3. Route Planning
app.post('/api/plan-route', async (req, res) => {
    try {
        const { pickup, destination, vehicleType, preferences } = req.body;
        
        // Geocode pickup and destination
        const [pickupResult, destResult] = await Promise.all([
            geocoder.geocode(pickup),
            geocoder.geocode(destination)
        ]);
        
        if (!pickupResult.length || !destResult.length) {
            return res.status(400).json({ error: 'Could not geocode locations' });
        }
        
        // Calculate distance (simplified - in production use routing API)
        const pickupCoords = [pickupResult[0].longitude, pickupResult[0].latitude];
        const destCoords = [destResult[0].longitude, destResult[0].latitude];
        const distance = calculateDistance(pickupCoords, destCoords);
        
        // Calculate estimated time and fare
        const estimatedTime = calculateEstimatedTime(distance, vehicleType);
        const fare = calculateFare(distance, vehicleType, preferences);
        
        // Find available vehicles near pickup
        const vehicles = await Vehicle.find({
            type: vehicleType,
            status: 'available',
            location: {
                $near: {
                    $geometry: {
                        type: "Point",
                        coordinates: pickupCoords
                    },
                    $maxDistance: 5000
                }
            }
        }).limit(5);
        
        res.json({
            route: {
                pickup: {
                    address: pickup,
                    coordinates: pickupCoords
                },
                destination: {
                    address: destination,
                    coordinates: destCoords
                },
                distance: distance.toFixed(2),
                estimatedTime,
                fare
            },
            availableVehicles: vehicles
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 4. Booking System
app.post('/api/bookings', authMiddleware, async (req, res) => {
    try {
        const { vehicleId, pickupTime, passengers, routeId, paymentMethodId } = req.body;
        
        const vehicle = await Vehicle.findById(vehicleId);
        if (!vehicle || vehicle.status !== 'available') {
            return res.status(400).json({ error: 'Vehicle not available' });
        }
        
        const booking = new Booking({
            user: req.user._id,
            vehicle: vehicleId,
            driver: vehicle.driver,
            pickupTime: new Date(pickupTime),
            passengers,
            route: routeId,
            status: 'confirmed',
            totalAmount: vehicle.pricePerKm * 10 // Simplified calculation
        });
        
        // Mark vehicle as booked
        vehicle.status = 'booked';
        await vehicle.save();
        
        await booking.save();
        
        // Process payment
        if (paymentMethodId) {
            await processPayment(booking, paymentMethodId, req.user);
        }
        
        res.status(201).json(booking);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 5. Payment Integration
app.post('/api/create-payment-intent', authMiddleware, async (req, res) => {
    try {
        const { amount, currency = 'usd' } = req.body;
        
        const paymentIntent = await stripe.paymentIntents.create({
            amount: Math.round(amount * 100), // Convert to cents
            currency,
            metadata: {
                userId: req.user._id.toString()
            }
        });
        
        res.json({
            clientSecret: paymentIntent.client_secret
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/save-payment-method', authMiddleware, async (req, res) => {
    try {
        const { paymentMethodId } = req.body;
        
        // Attach payment method to customer
        const customer = await getOrCreateCustomer(req.user);
        await stripe.paymentMethods.attach(paymentMethodId, {
            customer: customer.id
        });
        
        // Add to user's payment methods
        req.user.paymentMethods.push({
            paymentMethodId,
            isDefault: req.user.paymentMethods.length === 0
        });
        
        await req.user.save();
        
        res.json({ message: 'Payment method saved successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 6. User Profile & History
app.get('/api/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user._id)
            .select('-password -tokens');
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/bookings', authMiddleware, async (req, res) => {
    try {
        const { status, limit = 10, page = 1 } = req.query;
        const query = { user: req.user._id };
        
        if (status) {
            query.status = status;
        }
        
        const bookings = await Booking.find(query)
            .populate('vehicle', 'type name licensePlate')
            .populate('driver', 'name phone rating')
            .sort('-createdAt')
            .limit(parseInt(limit))
            .skip((parseInt(page) - 1) * parseInt(limit));
        
        const total = await Booking.countDocuments(query);
        
        res.json({
            bookings,
            pagination: {
                total,
                page: parseInt(page),
                pages: Math.ceil(total / parseInt(limit))
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 7. Favorites System
app.post('/api/favorites', authMiddleware, async (req, res) => {
    try {
        const { vehicleId, driverId } = req.body;
        
        if (vehicleId) {
            req.user.favorites.vehicles.push(vehicleId);
        }
        if (driverId) {
            req.user.favorites.drivers.push(driverId);
        }
        
        await req.user.save();
        res.json({ message: 'Added to favorites' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 8. Real-time Location Updates
app.post('/api/update-location', authMiddleware, async (req, res) => {
    try {
        const { vehicleId, coordinates } = req.body;
        
        await Vehicle.findByIdAndUpdate(vehicleId, {
            'location.coordinates': coordinates,
            lastUpdated: new Date()
        });
        
        res.json({ message: 'Location updated' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// WebSocket for real-time updates
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });

const clients = new Map();

wss.on('connection', (ws, req) => {
    const userId = req.url.split('=')[1];
    if (userId) {
        clients.set(userId, ws);
    }
    
    ws.on('close', () => {
        clients.delete(userId);
    });
});

// Helper functions
function calculateDistance(coords1, coords2) {
    const [lng1, lat1] = coords1;
    const [lng2, lat2] = coords2;
    const R = 6371; // Earth's radius in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLng = (lng2 - lng1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLng/2) * Math.sin(dLng/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
}

function calculateEstimatedTime(distance, vehicleType) {
    const speeds = { bus: 30, taxi: 40, cab: 45 }; // km/h
    const speed = speeds[vehicleType] || 35;
    return Math.round((distance / speed) * 60); // minutes
}

function calculateFare(distance, vehicleType, preferences) {
    const rates = { bus: 0.5, taxi: 1.5, cab: 2.0 }; // $ per km
    const baseRate = rates[vehicleType] || 1.0;
    let fare = distance * baseRate;
    
    if (preferences?.premium) fare *= 1.5;
    if (preferences?.shared) fare *= 0.7;
    
    return Math.round(fare * 100) / 100;
}

async function getOrCreateCustomer(user) {
    if (user.stripeCustomerId) {
        return await stripe.customers.retrieve(user.stripeCustomerId);
    }
    
    const customer = await stripe.customers.create({
        email: user.email,
        name: user.name,
        metadata: {
            userId: user._id.toString()
        }
    });
    
    user.stripeCustomerId = customer.id;
    await user.save();
    
    return customer;
}

async function processPayment(booking, paymentMethodId, user) {
    const customer = await getOrCreateCustomer(user);
    
    const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(booking.totalAmount * 100),
        currency: 'usd',
        customer: customer.id,
        payment_method: paymentMethodId,
        confirm: true,
        metadata: {
            bookingId: booking._id.toString()
        }
    });
    
    if (paymentIntent.status === 'succeeded') {
        const payment = new Payment({
            booking: booking._id,
            user: user._id,
            amount: booking.totalAmount,
            currency: 'usd',
            stripePaymentId: paymentIntent.id,
            status: 'completed'
        });
        
        await payment.save();
        booking.paymentStatus = 'paid';
        await booking.save();
    }
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
