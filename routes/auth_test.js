const express = require('express');
const router = express.Router();
const pool = require('../config'); 

const checkNotLoggedIn = (req, res, next) => {
    if (req.session.userId) {
        return res.redirect(req.session.role === 'admin' ? '/admin' : '/user');
    }
    next();
};

const preventBackButtonCache = (req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
};


router.get('/login', checkNotLoggedIn, preventBackButtonCache, (req, res) => {
    res.render('login', { error: null });
});


// // SQL Injection Prevention Functions
// function checkVulnerability(input) {
//     const specialChars = /['"&+=<>]/;
//     if (specialChars.test(input)) {
//         console.log('Input contains special characters.');
//         return 'attack';
//     }

//     const sqlKeywords = /(union|select|intersect|insert|update|delete|drop|truncate)/i;
//     if (sqlKeywords.test(input)) {
//         console.log('Input contains SQL keywords.');
//         return 'attack';
//     }

//     const booleanKeywords = /\b(or|and)\b/i;
//     if (booleanKeywords.test(input)) {
//         console.log('Input contains Boolean keywords.');
//         return 'attack';
//     }
//     return 'free';

// }


// function monitorQuery(params) { // Returns false when potential SQL injection detected
//     const pattern = /(--|;|\\|drop|alter|delete|union)/gi;
//     console.log(params)

//     if (pattern.test(params)) {
//         console.log('Potential SQL Injection attack detected:', query);
//         return false;
//     }
//     return true;

// }

// SQL Injection Detection and Prevention Algorithm in JavaScript


// Regular expressions for special characters, SQL keywords, and Boolean operators
const specialCharacters = /['"&+=<>]/;
const sqlKeywords = /(union|select|intersect|insert|update|delete|drop|truncate)/i;
const booleanKeywords = /\b(or|and)\b/i;

// Vulnerability detection function (CheckVulnerability)
function checkVulnerability(field) {
    if (field && typeof field === 'string') {
        // Check for special characters
        if (specialCharacters.test(field)) {
            console.log("Special characters detected in input.");
            return "attack";
        }

        // Check for SQL keywords
        if (sqlKeywords.test(field)) {
            console.log("SQL keyword detected in input.");
            return "attack";
        }

        // Check for Boolean operators
        if (booleanKeywords.test(field)) {
            console.log("Boolean operator detected in input.");
            return "attack";
        }
    }
    return "free";
}

// Main SQL Injection Detection Algorithm (SQLIAD)
function SQLIAD(forms) {
    let formStatus = "free"; // Default form status

    for (let form of forms) {
        for (let fieldName in form) {
            const fieldValue = form[fieldName];

            // Call CheckVulnerability on each field
            formStatus = checkVulnerability(fieldValue);

            // If an attack is detected, log it and reset the request
            if (formStatus === "attack") {
                console.log(`Potential SQL Injection detected in field '${fieldName}' with value: ${fieldValue}`);
                // Reset request or take necessary action (like blocking the request or showing a warning)
                return formStatus;
            }
        }
    }
    return formStatus; // Return form status ("free" if safe, "attack" if injection detected)
}

router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Check for SQL injection vulnerabilities
    const forms = [{ username, password }];
    const vulnerabilityStatus = SQLIAD(forms);

    if (vulnerabilityStatus === "attack") {
        return res.status(400).send('Potential SQL Injection is detected.');
    }

    try {
        // Use parameterized query to prevent SQL injection
        const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
        const params = [username, password];
        const rows = await pool.query(query, params);

        if (rows.length > 0) {
            const user = rows[0];

            const match_pass = password === user.password; 
            const match_user = username === user.username;
            console.log(String(match_user))
            console.log(String(match_pass))


            if (match_pass&match_user) { 
                req.session.userId = user.id;
                req.session.role = user.role;

                if (user.role === 'admin') {
                    return res.redirect('/admin');
                } else {
                    return res.redirect('/user');
                }
            } 
            if (match_user & !match_pass){
                return res.render('login', {error:"Incorrect password"});
            }
                return res.render('login', { error: 'User not found' });
        } else {
            return res.render('login', { error: 'User not found' });
        }
    } catch (err) {
        console.error('Login error:', err); 
        res.status(500).send('Server error');
    }
});

module.exports = router;


// Logout route
router.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Could not log out');
        }
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        res.redirect('/login');
    });
});


