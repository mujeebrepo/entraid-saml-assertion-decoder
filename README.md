# SAML Assertion Decoder for Entra ID Groups

A Node.js application that authenticates users with Microsoft Entra ID (formerly Azure AD) using SAML and decodes the SAML assertion to verify if group claims are being properly transmitted.

## Features

- Authenticate users with Microsoft Entra ID via SAML protocol
- Decode SAML assertions to inspect claims
- Specifically check for and display group claims in the assertion
- Simple web interface to view decoded assertion data
- Exposure of service provider metadata for easy configuration
- Optional SAML request signing for enhanced security

## Prerequisites

- Node.js (v14 or newer)
- NPM (v6 or newer)
- Microsoft Entra ID tenant with administrative access
- Groups configured in your Entra ID tenant

## Setup Instructions

### 1. Create Project Structure

```
saml-assertion-decoder/
├── app.js
├── .env
├── package.json
├── certs/                  # For storing certificates
│   ├── idp-cert.pem        # Entra ID signing certificate
│   ├── sp-cert.pem         # Service Provider certificate (if needed)
│   └── sp-key.pem          # Service Provider private key (if needed)
├── public/
└── views/
    ├── index.ejs
    └── profile.ejs
```

### 2. Register an Enterprise Application in Entra ID (SAML-based)

1. Go to the [Azure Portal](https://portal.azure.com) or directly visit [Entra ID](https://entra.microsoft.com)
2. Navigate to "Microsoft Entra ID" > "Enterprise applications" 
3. Click "New application"
4. Choose "Create your own application"
5. Enter a name for your application
6. Select "Integrate any other application you don't find in the gallery (Non-gallery)"
7. Click "Create"

### 3. Configure SAML Authentication

1. In your enterprise application, go to "Single sign-on"
2. Select "SAML" as the sign-on method
3. In "Basic SAML Configuration":
   - Set Identifier (Entity ID) to the value of your SAML_ISSUER (e.g., `urn:example:saml-decoder`)
   - Set Reply URL (Assertion Consumer Service URL) to your callback URL (e.g., `http://localhost:3000/login/callback`)
4. In "User Attributes & Claims":
   - Ensure your required attributes are configured
   - Add group claims by clicking "Edit" under Groups returned in claim
   - Select the appropriate options:
     - Security groups
     - Groups assigned to the application
     - All groups
   - Choose whether you want the groups to be represented by Object ID or Display name

### 4. Download Federation Metadata or Certificate

1. From the "SAML Certificates" section:
   - Download the "Federation Metadata XML" or the "Certificate (Base64)" file
2. If you downloaded the certificate, save it as `idp-cert.pem` in your `certs` directory

### 5. Generate Service Provider Certificates (if needed)

Generate a self-signed certificate for your service provider:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/sp-key.pem -out certs/sp-cert.pem -days 365 -nodes
```

### 6. Create .env File

Create a `.env` file in the root directory with the following content:

```
TENANT_ID=your_tenant_id
SAML_ISSUER=urn:example:saml-decoder
CALLBACK_URL=http://localhost:3000/login/callback
SESSION_SECRET=your_random_session_secret
PORT=3000
```

If you're not storing the certificates in files, you can also include them in the .env:

```
SAML_CERT=your_base64_encoded_certificate
SAML_SIGNING_CERT=your_base64_encoded_signing_certificate
SAML_SIGNING_KEY=your_base64_encoded_signing_key
```

### 7. Install Dependencies

```bash
npm install
```

### 8. Run the Application

```bash
npm start
```

### 9. Configure the Application in Entra ID

1. Access the application's metadata at: `http://localhost:3000/metadata`
2. Copy this XML data
3. In your Entra ID enterprise application:
   - Go to "Single sign-on"
   - Select "Upload metadata file" or directly paste the values from your metadata into the appropriate fields

### 10. Test the Application

1. Open your browser and navigate to `http://localhost:3000`
2. Click "Sign in with Microsoft"
3. After authentication, you'll see the decoded SAML assertion with group claims if configured properly

## Enabling SAML Request Signing

SAML request signing adds an extra layer of security by allowing Entra ID to verify that authentication requests are genuinely coming from your application. To enable this:

1. Uncomment the request signing configuration in app.js:
```javascript
// privateCert: process.env.SAML_SIGNING_KEY || fs.readFileSync(path.join(__dirname, 'certs', 'sp-key.pem'), 'utf8'),
// signatureAlgorithm: 'sha256',
```

2. Make sure your SP certificate and private key are available either as environment variables or in the certs directory

3. Update your application in Entra ID:
   - Go to "Enterprise applications" > Your App > "Single sign-on"
   - In the "SAML Signing Certificate" section, upload your service provider certificate (sp-cert.pem)
   - Enable the option "Sign SAML request" if available

The application will now sign all SAML requests with your private key, and Entra ID will verify the signature using your public certificate.

## Advanced Configuration: Encrypted Assertions

For additional security, you can configure Entra ID to encrypt SAML assertions:

1. Uncomment the encryption configuration in app.js:
```javascript
// decryptionPvk: process.env.SAML_SIGNING_KEY || fs.readFileSync(path.join(__dirname, 'certs', 'sp-key.pem'), 'utf8'),
// wantAssertionsEncrypted: true,
```

2. In Entra ID, configure assertion encryption:
   - Go to "Enterprise applications" > Your App > "Single sign-on"
   - In the SAML configuration, look for encryption options
   - Upload your service provider certificate for encryption

## Troubleshooting Group Claims in SAML

If your groups aren't showing up in the SAML assertion, check the following:

1. Verify you've configured the application to include group claims in the "User Attributes & Claims" section
2. Confirm the authenticated user is actually a member of the groups
3. Check the Entra ID application logs for any issues during authentication
4. For large numbers of groups, Microsoft may limit the number of groups or use a different format to include them
5. Verify your SAML configuration is correct by checking the raw assertion for errors

## Group Name vs. Group ID

By default, Entra ID sends group object IDs in SAML claims. To get group names instead:

1. Go to "Enterprise applications" > Your App > "Single sign-on"
2. Click on "User Attributes & Claims"
3. Edit the groups claim
4. Choose "Group ID" or "Group name" based on your preference
5. Save the changes

## Security Considerations

This application is for demonstration purposes only. In a production environment:

1. Always use HTTPS for all communications
2. Store certificates and keys securely
3. Use a robust session management strategy
4. Implement proper error handling and logging
5. Use secure, randomly generated secrets
6. Consider certificate rotation practices
7. Configure appropriate attribute encryption
8. Enable SAML request signing for authentication integrity

## License

MIT