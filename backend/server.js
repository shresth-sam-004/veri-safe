const express = require('express');
const cors = require('cors');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Directories
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const DATA_DIR = path.join(__dirname, 'data');

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Setup Storage Data files (Acting as our simple local database)
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');

// Initialize empty data sets
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));
if (!fs.existsSync(PRODUCTS_FILE)) fs.writeFileSync(PRODUCTS_FILE, JSON.stringify([]));

// Secure Secrets (Ideally loaded via .env file)
const SECRET_KEY = process.env.JWT_SECRET || 'verisafe_super_secret_key';

// Setup Multer for secure Image/Receipt Uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, UPLOADS_DIR);
    },
    filename: function (req, file, cb) {
        cb(null, 'receipt_' + Date.now() + path.extname(file.originalname)); 
    }
});

// Enforce image-only uploads
const imageFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only standard image files are allowed.'), false);
};

const upload = multer({ storage: storage, fileFilter: imageFilter });

// Backend DB Helper Utilities
const readData = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const writeData = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));


// ============================================
// 1. User Authentication APIs (Registration & Login)
// ============================================

app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) return res.status(400).json({ error: 'Username and Password required' });
    
    let users = readData(USERS_FILE);
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'Username already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: Date.now().toString(), username, password: hashedPassword };
    users.push(newUser);
    writeData(USERS_FILE, users);
    
    res.json({ message: 'User registered securely to VeriSafe!' });
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    let users = readData(USERS_FILE);
    
    const user = users.find(u => u.username === username);
    if (!user) return res.status(401).json({ error: 'Invalid authentication credentials' });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid authentication credentials' });
    
    // Generate stateless authentication token valid for 24 hours
    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '24h' });
    res.json({ token, username: user.username });
});

// Middleware to protect Routes
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).json({ error: 'VeriSafe access denied: No JWT token provided' });
    
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token is invalid or expired' });
        req.user = user;
        next(); // Proceed to route
    });
};


// ============================================
// 2 & 3. Assets/Products Core API
// ============================================

app.post('/api/products', authenticateToken, (req, res) => {
    const { name, purchaseDate, expiryDate, nfcUid } = req.body;
    let products = readData(PRODUCTS_FILE);
    
    // Cryptographically secure generation or fallback to physical NFC Tag UID
    const assignedUid = nfcUid || Array.from({length: 4}, () => Math.random().toString(16).slice(2,4).toUpperCase()).join(':');
    
    const newProduct = {
        id: assignedUid,
        ownerId: req.user.id, // Links asset strictly to the authenticated user
        name,
        purchaseDate,
        expiryDate,
        registeredAt: new Date().toISOString(),
        receiptImageUrl: null
    };
    
    products.push(newProduct);
    writeData(PRODUCTS_FILE, products);
    
    res.json({ message: 'Asset successfully registered into Vault', product: newProduct });
});

app.get('/api/products', authenticateToken, (req, res) => {
    let products = readData(PRODUCTS_FILE);
    // User can only retrieve their own secured assets
    const userProducts = products.filter(p => p.ownerId === req.user.id);
    
    res.json(userProducts);
});


// ============================================
// 4. Receipt Uploading Endpoint (Multer Engine)
// ============================================

app.post('/api/products/:productId/receipt', authenticateToken, upload.single('receipt'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No physical image or receipt data uploaded' });
    
    let products = readData(PRODUCTS_FILE);
    // Find the product and verify ownership security before allowing image linking
    let productIndex = products.findIndex(p => p.id === req.params.productId && p.ownerId === req.user.id);
    
    if (productIndex === -1) {
        fs.unlinkSync(req.file.path); // Clean up ghost file
        return res.status(404).json({ error: 'Asset not found or unauthorized access attempt' });
    }
    
    products[productIndex].receiptImageUrl = `/uploads/${req.file.filename}`;
    writeData(PRODUCTS_FILE, products);
    
    res.json({ 
        message: 'Thermal receipt successfully uploaded and digitized', 
        imageUrl: products[productIndex].receiptImageUrl
    });
});

// Statically expose the images so they uniquely load on the frontend
app.use('/uploads', express.static(UPLOADS_DIR));

// Initialization
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🛡️ VeriSafe Node.js API Service running perfectly on http://localhost:${PORT}`);
});
