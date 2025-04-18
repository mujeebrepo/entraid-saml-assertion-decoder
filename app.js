// app.js
require('dotenv').config();
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const SamlStrategy = require('passport-saml').Strategy;
const xmldom = require('@xmldom/xmldom');
const xpath = require('xpath');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const app = express();
const port = process.env.PORT || 3000;

// Configure express
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Explicitly set views directory

// Add body parser middleware to handle POST requests
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Set up session
app.use(session({
  secret: process.env.SESSION_SECRET || 'saml-decoder-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Register namespaces for XPath
const select = xpath.useNamespaces({
  samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
  saml: 'urn:oasis:names:tc:SAML:2.0:assertion'
});

// Configure SAML Strategy
const samlStrategy = new SamlStrategy({
  callbackUrl: process.env.CALLBACK_URL || `http://localhost:${port}/login/callback`,
  entryPoint: `https://login.microsoftonline.com/${process.env.TENANT_ID}/saml2`,
  issuer: process.env.SAML_ISSUER || 'urn:example:saml-decoder',
  cert: process.env.SAML_CERT || (fs.existsSync(path.join(__dirname, 'certs', 'idp-cert.pem')) ? 
         fs.readFileSync(path.join(__dirname, 'certs', 'idp-cert.pem'), 'utf8') : undefined),
  identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  validateInResponseTo: true,
  disableRequestedAuthnContext: true,
  acceptedClockSkewMs: 300000, // 5 minutes clock skew acceptable
  
  // === Request Signing Configuration (Uncomment to enable) ===
  // privateCert: process.env.SAML_SIGNING_KEY || fs.readFileSync(path.join(__dirname, 'certs', 'sp-key.pem'), 'utf8'),
  // signatureAlgorithm: 'sha256',
}, function(profile, done) {
  // Store the SAML response for later extraction
  if (profile) {
    // Store the raw SAML response if available in the profile
    profile._samlRaw = profile._saml || {};
  }
  return done(null, profile);
});

passport.use(samlStrategy);

// Serialize and deserialize user
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

// Function to decode SAML assertion
function decodeSamlAssertion(samlResponse) {
  try {
    console.log("Decoding SAML response...");
    
    // Parse the XML
    const doc = new xmldom.DOMParser().parseFromString(samlResponse);
    
    // Extract the assertion
    const assertion = select("//saml:Assertion", doc)[0];
    
    if (!assertion) {
      console.error("No SAML assertion found in response");
      return { error: "No assertion found in SAML response" };
    }
    
    // Extract all attributes
    const attributes = {};
    const attributeNodes = select("//saml:Attribute", doc);
    
    attributeNodes.forEach(attr => {
      const name = attr.getAttribute('Name');
      const valueNodes = select("saml:AttributeValue/text()", attr);
      
      if (valueNodes.length === 1) {
        attributes[name] = valueNodes[0].nodeValue;
      } else if (valueNodes.length > 1) {
        attributes[name] = valueNodes.map(node => node.nodeValue);
      }
    });
    
    // Extract subject information
    const subject = select("string(//saml:Subject/saml:NameID)", doc);
    
    // Extract groups specifically
    const groupsAttribute = select("//saml:Attribute[@Name='http://schemas.microsoft.com/ws/2008/06/identity/claims/groups' or @Name='groups']", doc);
    let groups = [];
    
    if (groupsAttribute.length > 0) {
      const groupValues = select("saml:AttributeValue/text()", groupsAttribute[0]);
      groups = groupValues.map(node => node.nodeValue);
    }
    
    // Format the decoded data
    return {
      subject,
      attributes,
      groups,
      raw: assertion ? assertion.toString() : 'No assertion found'
    };
  } catch (error) {
    console.error('Error decoding SAML assertion:', error);
    return { error: 'Failed to decode SAML assertion: ' + error.message };
  }
}

// Check if user is authenticated
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/');
}

// Routes
app.get('/', (req, res) => {
  res.render('index', { isAuthenticated: req.isAuthenticated() });
});

// Initiate SAML authentication
app.get('/login', passport.authenticate('saml', {
  failureRedirect: '/',
  failureFlash: true
}));

// Handle SAML callback
app.post('/login/callback', 
  passport.authenticate('saml', { 
    failureRedirect: '/',
    failureFlash: true,
    session: true
  }),
  function(req, res) {
    console.log("Authentication successful");
    
    // Store the SAML response for decoding
    if (req.body.SAMLResponse) {
      try {
        // Base64 decode the SAML response
        const decodedString = Buffer.from(req.body.SAMLResponse, 'base64').toString();
        
        // Parse and extract information from the SAML assertion
        const decodedAssertion = decodeSamlAssertion(decodedString);
        
        // Store in session
        req.session.decodedAssertion = decodedAssertion;
        
        console.log("Decoded SAML assertion and stored in session");
      } catch (err) {
        console.error("Error processing SAML response:", err);
      }
    } else {
      console.error("No SAMLResponse found in request body");
    }
    
    // Save the session before redirecting
    req.session.save((err) => {
      if (err) {
        console.error("Error saving session:", err);
      }
      // Redirect to profile page after successful authentication
      res.redirect('/profile');
    });
  }
);

app.get('/profile', ensureAuthenticated, (req, res) => {
  console.log("Rendering profile page");
  
  const decodedAssertion = req.session.decodedAssertion || {};
  const groups = decodedAssertion.groups || [];
  const hasGroupClaim = Array.isArray(groups) && groups.length > 0;
  
  res.render('profile', {
    isAuthenticated: true,
    user: {
      name: req.user.nameID || req.user.displayName || 'User',
      username: req.user.nameID || req.user.email || 'Unknown'
    },
    token: {
      accessToken: 'SAML does not use access tokens',
      idToken: 'See decoded assertion below',
      decoded: JSON.stringify(decodedAssertion, null, 2)
    },
    hasGroupClaim: hasGroupClaim,
    groups: groups
  });
});

app.get('/logout', (req, res) => {
  req.logout(function(err) {
    if (err) { 
      console.error("Error during logout:", err);
      return res.status(500).send("Error during logout"); 
    }
    req.session.destroy(function(err) {
      if (err) {
        console.error("Error destroying session:", err);
      }
      res.redirect('/');
    });
  });
});

// Get SAML metadata for application registration
app.get('/metadata', function(req, res) {
  res.type('application/xml');
  
  try {
    const cert = process.env.SAML_SIGNING_CERT || 
                (fs.existsSync(path.join(__dirname, 'certs', 'sp-cert.pem')) ? 
                 fs.readFileSync(path.join(__dirname, 'certs', 'sp-cert.pem'), 'utf8') : undefined);
                 
    const key = process.env.SAML_SIGNING_KEY || 
               (fs.existsSync(path.join(__dirname, 'certs', 'sp-key.pem')) ? 
                fs.readFileSync(path.join(__dirname, 'certs', 'sp-key.pem'), 'utf8') : undefined);
    
    const metadata = samlStrategy.generateServiceProviderMetadata(cert, key);
    res.status(200).send(metadata);
  } catch (err) {
    console.error("Error generating metadata:", err);
    res.status(500).send("Error generating metadata: " + err.message);
  }
});

// Error handling
app.use(function(err, req, res, next) {
  console.error(err.stack);
  res.status(500).send('Something broke! ' + err.message);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});