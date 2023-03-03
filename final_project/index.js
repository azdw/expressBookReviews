const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session')
const customer_routes = require('./router/auth_users.js').authenticated;
const genl_routes = require('./router/general.js').general;

const app = express();

app.use(express.json());

app.use("/customer",session({secret:"fingerprint_customer",resave: true, saveUninitialized: true}))

app.use("/customer/auth/*", function auth(req,res,next){
//Write the authenication mechanism here


    function auth(req, res, next) {
        // Check for a JWT in the Authorization header
        const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
        if (!token) {
            // No token provided, so send a 401 Unauthorized response
            return res.status(401).json({ message: 'Authorization token missing' });
        }

        try {
            // Verify the JWT using a secret key
            const decoded = jwt.verify(token, 'my-secret-key');
            // Store the decoded user information on the request object for later use
            req.user = decoded;
            // Call the next middleware function
            next();
        } catch (err) {
            // JWT verification failed, so send a 401 Unauthorized response
            return res.status(401).json({ message: 'Invalid authorization token' });
        }
        }

});
 
const PORT =5000;

app.use("/customer", customer_routes);
app.use("/", genl_routes);

app.listen(PORT,()=>console.log("Server is running"));
