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

// Set up session
app.use(session({
  secret: process.env.SESSION_SECRET || 'saml-decoder-secret',
  resave: false,
  saveUninitialized: false
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Configure SAML Strategy
const samlStrategy = new SamlStrategy({
  callbackUrl: process.env.CALLBACK_URL || `http://localhost:${port}/login/callback`,
  entryPoint: `https://login.microsoftonline.com/${process.env.TENANT_ID}/saml2`,
  issuer: process.env.SAML_ISSUER,
  cert: process.env.SAML_CERT || fs.readFileSync(path.join(__dirname, 'certs', 'idp-cert.pem'), 'utf8'),
  identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  validateInResponseTo: true,
  disableRequestedAuthnContext: true
}, function(profile, done) {
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
    // Parse the XML
    const doc = new xmldom.DOMParser().parseFromString(samlResponse);
    
    // Extract the base64 encoded assertion
    const assertion = xpath.select("//saml:Assertion", doc, true);
    
    // Extract all attributes
    const attributes = {};
    const attributeNodes = xpath.select("//saml:Attribute", doc);
    
    attributeNodes.forEach(attr => {
      const name = attr.getAttribute('Name');
      const valueNodes = xpath.select("saml:AttributeValue/text()", attr);
      
      if (valueNodes.length === 1) {
        attributes[name] = valueNodes[0].nodeValue;
      } else if (valueNodes.length > 1) {
        attributes[name] = valueNodes.map(node => node.nodeValue);
      }
    });
    
    // Extract subject information
    const subject = xpath.select("string(//saml:Subject/saml:NameID)", doc);
    
    // Extract groups specifically
    const groupsAttribute = xpath.select("//saml:Attribute[@Name='http://schemas.microsoft.com/ws/2008/06/identity/claims/groups' or @Name='groups']", doc);
    let groups = [];
    
    if (groupsAttribute.length > 0) {
      const groupValues = xpath.select("saml:AttributeValue/text()", groupsAttribute[0]);
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
    return { error: 'Failed to decode SAML assertion' };
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
  passport.authenticate('saml', { 
    failureRedirect: '/',
    failureFlash: true 
  }),
  function(req, res) {
    // Get the SAML response from the strategy
    const samlResponse = req.body.SAMLResponse;
    
    // Store the decoded assertion
    if (samlResponse) {
      req.session.decodedAssertion = decodeSamlAssertion(
        Buffer.from(samlResponse, 'base64').toString()
      );
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