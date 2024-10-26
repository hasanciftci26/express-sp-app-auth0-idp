import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as SamlStrategy, VerifiedCallback, Profile } from "passport-saml";
import bodyParser from "body-parser";
import path from "path";
import fs from "fs";
import xml2js from "xml2js";

const app = express();
const PORT = process.env.PORT || 3000;

// Configure session
app.use(session({
    secret: "95f1b3bebe023ef699e555847b231821c9d8ff2c8a32279430a24ca647d9fefd",
    resave: false,
    saveUninitialized: true,
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Path to the SAML Metadata XML file
const metadataPath = path.join(__dirname, "saml/auth0-idp-metadata.xml");

// Function to read the metadata and initialize Passport SAML strategy
function configureSamlStrategy() {
    fs.readFile(metadataPath, "utf-8", (err, data) => {
        if (err) {
            console.error("Error reading IdP metadata file:", err);
            return;
        }

        xml2js.parseString(data, (parseErr, result) => {
            if (parseErr) {
                console.error("Error parsing IdP metadata XML:", parseErr);
                return;
            }

            try {
                // Extract entryPoint and issuer from the metadata XML
                const entryPoint = result.EntityDescriptor.IDPSSODescriptor[0].SingleSignOnService[0].$.Location;
                const issuer = "https://yourapp.example.com/saml";

                // Configure SAML Strategy with dynamic entryPoint and issuer
                passport.use(new SamlStrategy({
                    path: "/login/callback",
                    entryPoint,
                    issuer,
                    cert: fs.readFileSync(path.join(__dirname, "saml/auth0-idp-cert.pem"), "utf-8"),
                    acceptedClockSkewMs: 5000
                }, (profile, done) => {
                    return (done as unknown as VerifiedCallback)(null, profile as unknown as Profile);
                }));

                console.log("SAML Strategy configured with dynamic entryPoint and issuer.");
            } catch (configErr) {
                console.error("Error extracting SingleSignOnService URL or issuer:", configErr);
            }
        });
    });
}

// Initialize SAML configuration
configureSamlStrategy();

// Serialize user into the session
passport.serializeUser((user, done) => {
    done(null, user);
});

// Deserialize user from the session
passport.deserializeUser((user, done) => {
    done(null, user as Express.User);
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public"))); // Serve static files

// Routes
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public/login.html"));
});

// Trigger SAML Authentication
app.post("/login", passport.authenticate("saml", { failureRedirect: "/" }), (req, res) => {
    res.redirect("/dashboard");
});

// SAML Callback
app.post("/login/callback", passport.authenticate("saml", { failureRedirect: "/" }), (req, res) => {
    res.redirect("/dashboard");
});

// Dashboard route
app.get("/dashboard", (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect("/");
    }
    res.sendFile(path.join(__dirname, "public/dashboard.html"));
});

// Logout
app.get("/logout", (req, res) => {
    // req.logout();
    res.redirect("/");
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
