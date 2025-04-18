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
const app = express();
const port = process.env.PORT || 3000;

// Configure express
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Set up session - USE A MORE ROBUST STORE FOR PRODUCTION
app.use(session({
  secret: process.env.SESSION_SECRET || 'saml-decoder-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    // More secure cookie settings
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));

// Configure SAML Strategy
const samlStrategy = new SamlStrategy({
  callbackUrl: process.env.CALLBACK_URL || `http://localhost:${port}/login/callback`,
  entryPoint: `https://login.microsoftonline.com/${process.env.TENANT_ID}/saml2`,
  issuer: process.env.SAML_ISSUER,
  cert: process.env.SAML_CERT || fs.readFileSync(path.join(__dirname, 'certs', 'idp-cert.pem'), 'utf8'),
  identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  validateInResponseTo: false, // Disable response validation to prevent redirect loops
  disableRequestedAuthnContext: true
}, function(profile, done) {
  // Process the SAML assertion here
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

// Function to decode SAML assertion with proper namespace handling
function decodeSamlAssertion(samlResponse) {
  try {
    // Parse the XML
    const doc = new xmldom.DOMParser().parseFromString(samlResponse);
    
    // Define the namespaces used in SAML documents
    const namespaces = {
      samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
      saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
      ds: 'http://www.w3.org/2000/09/xmldsig#',
      xenc: 'http://www.w3.org/2001/04/xmlenc#'
    };
    
    // Create a namespace resolver for xpath
    const select = xpath.useNamespaces(namespaces);
    
    // Extract the assertion element using namespaces
    const assertionNode = select("//saml:Assertion", doc)[0];
    
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
    
    // Extract subject information (nameID)
    const subjectNode = select("string(//saml:Subject/saml:NameID)", doc);
    
    // Extract groups specifically
    const groupsAttribute = select("//saml:Attribute[@Name='http://schemas.microsoft.com/ws/2008/06/identity/claims/groups' or @Name='groups']", doc);
    let groups = [];
    
    if (groupsAttribute.length > 0) {
      const groupValues = select("saml:AttributeValue/text()", groupsAttribute[0]);
      groups = groupValues.map(node => node.nodeValue);
    }
    
    // Format the decoded data
    return {
      subject: subjectNode,
      attributes,
      groups,
      raw: assertionNode ? assertionNode.toString() : 'No assertion found'
    };
  } catch (error) {
    console.error('Error decoding SAML assertion:', error);
    console.error('Error details:', error.stack);
    return { error: `Failed to decode SAML assertion: ${error.message}` };
  }
}

// Helper function to print the raw SAML response for debugging
function debugSamlResponse(samlResponse) {
  try {
    const decoded = Buffer.from(samlResponse, 'base64').toString();
    console.log('Decoded SAML Response:');
    console.log('--------------------------------------------------');
    console.log(decoded.substring(0, 1000) + '...'); // Print first 1000 chars to avoid overwhelming logs
    console.log('--------------------------------------------------');
    return decoded;
  } catch (error) {
    console.error('Error decoding base64 SAML response:', error);
    return null;
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

app.get('/login', passport.authenticate('saml', {
  failureRedirect: '/',
  failureFlash: true
}));

app.post('/login/callback',
  function(req, res, next) {
    // Log the incoming request to help with debugging
    console.log('Received callback with SAMLResponse present:', !!req.body.SAMLResponse);
    next();
  },
  passport.authenticate('saml', { 
    failureRedirect: '/',
    failureFlash: true 
  }),
  function(req, res) {
    console.log('Authentication successful, user:', req.user?.nameID);
    
    // Store the decoded assertion if SAMLResponse exists
    if (req.body && req.body.SAMLResponse) {
      try {
        // First debug the raw response
        const decodedSaml = debugSamlResponse(req.body.SAMLResponse);
        
        if (decodedSaml) {
          // Then decode the assertion
          req.session.decodedAssertion = decodeSamlAssertion(decodedSaml);
        }
      } catch (error) {
        console.error('Error processing SAML response:', error);
        req.session.decodedAssertion = { 
          error: 'Failed to process SAML response',
          errorDetails: error.message 
        };
      }
    }
    
    res.redirect('/profile');
  }
);

app.get('/profile', ensureAuthenticated, (req, res) => {
  const decodedAssertion = req.session.decodedAssertion || {};
  const groups = decodedAssertion.groups || [];
  const hasGroupClaim = Array.isArray(groups) && groups.length > 0;
  
  res.render('profile', {
    isAuthenticated: true,
    user: {
      name: req.user.displayName || req.user.nameID || 'User',
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
    if (err) { return next(err); }
    req.session.destroy();
    res.redirect('/');
  });
});

// Get SAML metadata for application registration
app.get('/metadata', function(req, res) {
  res.type('application/xml');
  res.status(200).send(
    samlStrategy.generateServiceProviderMetadata(
      process.env.SAML_SIGNING_CERT || fs.readFileSync(path.join(__dirname, 'certs', 'sp-cert.pem'), 'utf8'),
      process.env.SAML_SIGNING_KEY || fs.readFileSync(path.join(__dirname, 'certs', 'sp-key.pem'), 'utf8')
    )
  );
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});