import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import nodemailer from "nodemailer";
import bcrypt from "bcrypt";
import connectPgSimple from "connect-pg-simple";


const pgStore = connectPgSimple(session);

// for __dirname in ES Module
const __dirname = dirname(fileURLToPath(import.meta.url));

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

// PostgreSQL Database Connection
const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

db.connect()
    .then(() => console.log("Connected to PostgreSQL"))
    .catch((err) => console.error("Database Connection Error", err.stack));

db.on('error', (err) => {
  console.error('Unexpected error on PostgreSQL client', err);
  // Optional: handle reconnection logic or process exit here
});

// Middleware
app.use(express.static("public")); // Serve static files
app.use(express.json()); // Handle JSON data
app.use(bodyParser.urlencoded({ extended: true })); // Handle form data

// Only trust proxy on production (Render)
if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

app.use(session({
  store: new pgStore({ pool: db }),
  secret: process.env.SESSION_SECRET || "your-secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production", // ❗true for Render, false for localhost
    httpOnly: true,
    sameSite: process.env.NODE_ENV === "production" ? 'None' : 'Lax',
    maxAge: 86400000
  }
}));



// Set EJS as the templating engine
app.set("view engine", "ejs");
app.set("views", join(__dirname, "views"));

// Home Route
app.get("/", (req, res) => {
    res.sendFile(join(__dirname, "public", "index.html"));
});

// Signup Page Route
app.get("/signup", (req, res) => {
    res.sendFile(join(__dirname, "public", "signup.html"));
});

// Login Page Route
app.get("/login", (req, res) => {
    res.sendFile(join(__dirname, "public", "login.html"));
});


// Dashboard Route 
app.get("/dashboard", async (req, res) => {
    if (!req.session.user) {
        return res.redirect("/login"); // Redirect to login if user is not logged in
    }
    console.log("hi")
    try {
        const userId = req.session.user.id;
        const result = await db.query('SELECT id, firstname, lastname, email, dob, region FROM users WHERE id = $1', [userId]);

        if (result.rows.length === 0) {
            return res.status(404).send('User not found');
        }

        const user = result.rows[0];
        res.render('dashboard', { user });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// User Profile Details Route
app.get("/details", async (req, res) => {
    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect("/login"); // Redirect to login if user is not logged in
    }

    const userId = req.session.user.id; // User ID from session

    try {
        // Fetch user details from the database using the user ID from session
        const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);

        if (result.rows.length === 0) {
            console.log("No user found in the database for userId:", userId);
            return res.status(404).send('User not found');
        }

        // Extract the user data
        const user = result.rows[0];
        console.log("User data retrieved from DB:", user); // Log user data for verification
        
        const dob_result = user.dob.toISOString().slice(0,10)
        console.log(dob_result)
        
        // Render the user details page with the user data
        res.render('details', { user:user,dob:dob_result }); // Ensure 'user' is passed to the EJS template
    } catch (err) {
        console.error("Error fetching user details:", err);
        res.status(500).send('Server error');
    }
});
// Update user details
app.post('/user/update', async (req, res) => {
    const id = req.session.user.id;

    const { firstName, lastName, email, dob, region } = req.body;

    try {
        const result = await db.query(
            'UPDATE users SET firstname = $1, lastname = $2, email = $3, dob = $4, region = $5 WHERE id = $6 RETURNING *',
            [firstName, lastName, email, dob, region, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'User details updated successfully', user: result.rows[0] });
    } catch (error) {
        console.error('Error updating user details:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



// Handle Signup Form Submission
app.post("/signup", async (req, res) => {
    console.log("✅ Received signup request!");
    console.log("Request body:", req.body);

    // Extract values from JSON body (keys from frontend)
    const firstname = req.body["key1"];
    const lastname = req.body["key2"];
    const email = req.body["key3"];
    const dob = req.body["key4"];
    const region = req.body["key5"];
    const signupPassword = req.body["key6"];
    const signupConfirmPassword = req.body["key7"];
    const enteredOtp = req.body["key8"];

    console.log("Session OTP:", req.session.otp, "Entered OTP:", enteredOtp);
    
  
    // ✅ 1. OTP verification
    const generated_otp = req.session.otp;
    if (!generated_otp || generated_otp.toString() !== enteredOtp) {
        return res.status(400).send("Incorrect OTP");
    }

    // ✅ 2. Validate required fields
    if (!firstname || !lastname || !email || !signupPassword || !signupConfirmPassword) {
        return res.status(400).send("Missing required fields!");
    }

    // ✅ 3. Check if passwords match
    if (signupPassword !== signupConfirmPassword) {
        return res.status(400).send("Passwords do not match");
    }

    // const email_exist = await db.query('SELECT email FROM users WHERE email=$1').values[email];
  
    // if (email_exist){
    //   res.alert('User already exist. Kindly proceed to Login.');
    // }
  
    // ✅ 4. Encrypt password and insert into database
    bcrypt.hash(signupPassword, saltRounds, async (err, hashedPassword) => {
        if (err) {
            console.error("❌ Error hashing password:", err);
            return res.status(500).send("Password hashing failed");
        }

        try {
            const insertQuery = `
                INSERT INTO users (firstname, lastname, email, dob, region, password)
                VALUES ($1, $2, $3, $4, $5, $6)
            `;
            const values = [firstname, lastname, email, dob, region, hashedPassword];

          console.log("Inserting into DB:", values);
            await db.query(insertQuery, values);

            // Optional: fetch the user back
            const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
            console.log("✅ User inserted:", result.rows[0]);

             //Stores User Session (Going to dashboard directly)
             if(!req.session.user){
               const user = result.rows[0];
               req.session.user = user; 
             }
            res.json({ message: "Signup successful!" });
        } catch (error) {
            console.error("❌ Database insert error:", error);
            res.status(500).send("Error signing up.");
        }
    });
});

// Handle Login Form Submission
app.post("/login", async (req, res) => {
    console.log("Login request received with data:", req.body);
    const { email, password } = req.body;

    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        console.log("Query result:", result.rows);

        if (result.rows.length > 0) {
            const user = result.rows[0];
            console.log("User data from DB:", user);            
            console.log("encrypted password: ", password);
            console.log("user entered password: ", user.password)

            // Matching the encrypted password with user entered password
            bcrypt.compare(password, user.password, (err, same)=>{
               if(err){
                    console.log("Error Matching the encrypted password with entered password", err);
               } else{
                    if(same){
                        req.session.user = user;  // Store user in session
                        return res.redirect("/dashboard"); // Redirect to dashboard after successful login
                    }else{
                        return res.status(401).send("Invalid credentials");
                    }
               }
            })

        } else {
            return res.status(404).send("User not found");
        }
    } catch (error) {
        console.error(error);
        res.status(500).send("Error logging in");
  }
})


// Route for page 1 (Depression)
app.post('/submit-page1', async (req, res) => {
    const answers = req.body;
    console.log(answers);

    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect("/login");
    }

    const userId = req.session.user.id;

    if (!answers || Object.keys(answers).length === 0) {
        return res.status(400).send('No answers provided');
    }

    // Calculate depression score
    let depScore = Object.values(answers).map(Number).reduce((acc, val) => acc + val, 0);
    let depInterpretation = getDepressionInterpretation(depScore);

    try {
        // Insert a new result row and capture the new result ID
        const insertResult = await db.query(
            'INSERT INTO results (user_id, dep_score, anx_score, str_score, testtype, dep_interpretation) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
            [userId, depScore, -1, -1, 'Dass-21', depInterpretation]
        );

        // ✅ Save the inserted result ID into session for use in page 2 & 3
        req.session.newUserId = insertResult.rows[0].id;

        // Redirect to anxiety page
        res.redirect(`/dass21-anx.html`);
    } catch (error) {
        console.error('Error saving page 1 results:', error);
        res.status(500).send('Internal Server Error');
    }
});


// Route for page 2 (Anxiety)
app.post('/submit-page2', async (req, res) => {
    const  answers  = req.body;
    console.log(answers)
    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect("/login"); // Redirect to login if user is not logged in
    }
    const userId = req.session.user.id
    if (!answers) {
        return res.status(400).send('No answers provided');
    }

    // Calculate the score for page 2 (anxiety)
    let anxScore = Object.values(answers).map(Number).reduce((acc, val)=> acc+val, 0)

    try {
        // Check if the user already has an entry in the results table
        let result = await db.query(
            'SELECT * FROM results WHERE user_id = $1',
            [userId]
        );
        let anxInterpretation = getAnxietyInterpretation(anxScore);
        if (result.rows.length > 0) {
            // Update the existing entry with the anxiety score for page 2
            const newUserId = req.session.newUserId;
            await db.query(
                'UPDATE results SET anx_score = $1, anx_interpretation = $2 WHERE id = $3',
                [anxScore,anxInterpretation, newUserId]
            );
        } 

        // Redirect to page 3 (Stress)
        res.redirect(`/dass21-str.html`);
    } catch (error) {
        console.error('Error saving page 2 results:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Route for page 3 (Stress)
app.post('/submit-page3', async (req, res) => {
    const  answers  = req.body;
    console.log(answers)
    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect("/login"); // Redirect to login if user is not logged in
    }
    const userId = req.session.user.id
    if (!answers) {
        return res.status(400).send('No answers provided');
    }

    // Calculate the score for page 3 (stress)
    let strScore = Object.values(answers).map(Number).reduce((acc, val)=> acc+val, 0)
    
    console.log(strScore)
    try {
        // Check if the user already has an entry in the results table
        let result = await db.query(
            'SELECT * FROM results WHERE user_id = $1',
            [userId]
        );
        let strInterpretation = getStressInterpretation(strScore);
        if (result.rows.length > 0) {
            // Update the existing entry with the stress score for page 3
            const newUserId = req.session.newUserId;
            await db.query(
                'UPDATE results SET str_score = $1, str_interpretation = $2 WHERE id = $3',
                [strScore,strInterpretation,newUserId]
            );
        } 

        // Redirect to the results page
        res.redirect(`/results`);
    } catch (error) {
        console.error('Error saving page 3 results:', error);
        res.status(500).send('Internal Server Error');
    }
});
// Route for page 1 (Depression-long)
// Route for page 1 (Depression - DASS-42)
app.post('/submit-page11', async (req, res) => {
    const answers = req.body;  // Get answers from form submission
    console.log("Page 11 answers:", answers);

    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect("/login");
    }

    const userId = req.session.user.id;

    // Validate answers
    if (!answers || Object.keys(answers).length === 0) {
        return res.status(400).send('No answers provided');
    }

    // Calculate total depression score from form answers
    let depScore = Object.values(answers).map(Number).reduce((acc, val) => acc + val, 0);

    // Get interpretation based on score
    let depInterpretation = getDepressionInterpretation(depScore);

    try {
        // ✅ Insert new row into 'results' table and get the new ID using RETURNING
        const insertResult = await db.query(
            `INSERT INTO results (user_id, dep_score, anx_score, str_score, testtype, dep_interpretation) 
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
            [userId, depScore, -1, -1, 'Dass-42', depInterpretation]
        );

        // ✅ Save newly inserted result ID in session to update it later in page22 and page33
        const newUserId = insertResult.rows[0].id;
        req.session.newUserId = newUserId;

        // Redirect to page 2 (Anxiety section)
        res.redirect(`/dass42-anx.html`);
    } catch (error) {
        console.error('❌ Error saving page 1 (Depression) results:', error);
        res.status(500).send('Internal Server Error');
    }
});
// Route for page 2 (Anxiety-long)
app.post('/submit-page22', async (req, res) => {
    const  answers  = req.body;
    console.log(answers)
    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect("/login"); // Redirect to login if user is not logged in
    }
    const userId = req.session.user.id
    if (!answers) {
        return res.status(400).send('No answers provided');
    }

    // Calculate the score for page 2 (anxiety)
    let anxScore = Object.values(answers).map(Number).reduce((acc, val)=> acc+val, 0)

    try {
        // Check if the user already has an entry in the results table
        let result = await db.query(
            'SELECT * FROM results WHERE user_id = $1',
            [userId]
        );
        let anxInterpretation = getAnxietyInterpretation(anxScore);
        if (result.rows.length > 0) {
            // Update the existing entry with the anxiety score for page 2
            const newUserId = req.session.newUserId;
            await db.query(
                'UPDATE results SET anx_score = $1, anx_interpretation = $2 WHERE id = $3',
                [anxScore,anxInterpretation, newUserId]
            );
        } 

        // Redirect to page 3 (Stress)
        res.redirect(`/dass42-str.html`);
    } catch (error) {
        console.error('Error saving page 2 results:', error);
        res.status(500).send('Internal Server Error');
    }
});
// Route for page 3 (Stress-Long)
app.post('/submit-page33', async (req, res) => {
    const  answers  = req.body;
    console.log(answers)
    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect("/login"); // Redirect to login if user is not logged in
    }
    const userId = req.session.user.id
    if (!answers) {
        return res.status(400).send('No answers provided');
    }

    // Calculate the score for page 3 (stress)
    let strScore = Object.values(answers).map(Number).reduce((acc, val)=> acc+val, 0)
    
    console.log(strScore)
    
    try {
        // Check if the user already has an entry in the results table
        let result = await db.query(
            'SELECT * FROM results WHERE user_id = $1',
            [userId]
        );
        let strInterpretation = getStressInterpretation(strScore);
        if (result.rows.length > 0) {
            // Update the existing entry with the stress score for page 3
            const newUserId = req.session.newUserId;
            await db.query(
                'UPDATE results SET str_score = $1, str_interpretation = $2 WHERE id = $3',
                [strScore,strInterpretation, newUserId]
            );
        } 

        // Redirect to the results page
        res.redirect(`/results`);
    } catch (error) {
        console.error('Error saving page 3 results:', error);
        res.status(500).send('Internal Server Error');
    }
});
// Route to display the results
app.get('/results', async (req, res) => {
    const userId = req.session.user.id;  // Access userId from the session
    console.log('User ID from session:', userId);

    if (!userId) {
        return res.status(401).send('User not logged in');  // Handle case where user is not logged in
    }

    try {
        // let result = await db.query('SELECT * FROM results WHERE user_id = $1', [userId]);
      let result = await db.query(
  'SELECT * FROM results WHERE user_id = $1 ORDER BY id DESC LIMIT 1',
  [userId]
);
        console.log('Query result:', result.rows);

        if (result.rows.length > 0) {
            const {anx_score, dep_score, str_score } = result.rows[0];
            const depInterpretation = getDepressionInterpretation(dep_score);
            const anxInterpretation = getAnxietyInterpretation(anx_score);
            const strInterpretation = getStressInterpretation(str_score);
            const testType = result.rows[0].testtype || 'DASS-21';
            // const result1 = await db.query(
            //     'UPDATE results SET (dep_interpretation, anx_interpretation, str_interpretation)=($2, $3, $4) where user_id = $1',
            //     [userId, depInterpretation, anxInterpretation, strInterpretation]
            // );
            res.render('results', {
                anx_score,
                dep_score,
                str_score,
                depInterpretation,
                anxInterpretation,
                strInterpretation,
                testType
            });
        } else {
            res.status(404).send('User results not found');
        }
    } catch (error) {
        console.error('Error retrieving results:', error);
        res.status(500).send('Internal Server Error');
    }
    
});


function getDepressionInterpretation(score) {
    if (score < 9) return "Normal";
    else if (score < 13) return "Mild";
    else if (score < 20) return "Moderate";
    else if (score < 27) return "Severe";
    else return "Extremely Severe";
}

function getAnxietyInterpretation(score) {
    if (score < 7) return "Normal";
    else if (score < 9) return "Mild";
    else if (score < 14) return "Moderate";
    else if (score < 19) return "Severe";
    else return "Extremely Severe";
}

function getStressInterpretation(score) {
    if (score < 14) return "Normal";
    else if (score < 18) return "Mild";
    else if (score < 25) return "Moderate";
    else if (score < 33) return "Severe";
    else return "Extremely Severe";
}


// Route to render past evaluations page
app.get('/past-evaluation', async (req, res) => {
    const userId = req.session.user.id;  // Access userId from the session
    console.log('User ID from session:', userId);

    if (!userId) {
        return res.status(401).send('User not logged in');  // Handle case where user is not logged in
    }

    try {
        // Query to fetch evaluations for the given user from the database
        const result = await db.query(
            'SELECT * FROM results WHERE user_id = $1 ORDER BY id DESC',

            [userId]
        );

        const evaluations = result.rows;  // Store the evaluations returned from the database

        // Render the results page with evaluations data
        res.render('past-evaluation', { evaluations });
    } catch (error) {
        console.error('Error fetching evaluations:', error);
        res.status(500).send('Internal Server Error');
    }
});

//logout route
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
    }
    res.redirect("/login");
  });
});


const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  }
});

app.post("/send-otp", async (req, res) => {
  const email = req.body.email;
  console.log("Email received for OTP:", email);

  const otp = Math.floor(100000 + Math.random() * 900000); // Generate OTP

  // Save OTP to session
  req.session.email = email;
  req.session.otp = otp;
  console.log("Generated OTP:", otp);

  const email_exists = await db.query('SELECT * FROM users WHERE email=$1', [email]);
console.log(email_exists.rowCount);
console.log(email);
  if(email_exists.rowCount>0){
    // Instead of .alert(), send a JSON response
res.json({message: "User already exists. Please try to login."});

  }else{
    try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your OTP Code for Neurocalm Signup",
      text: `Dear User,

Your One-Time Password (OTP) for Signup is: ${otp}

Please keep this code confidential and do not share it with anyone.
If you did not request this, please ignore this message.

Thank you,
Neurocalm`,
    });

    console.log(`✅ OTP ${otp} sent to ${email}`);
    res.json({ message: "OTP has been sent successfully!" });
  } catch (error) {
    console.error("❌ Failed to send OTP:", error);
    res.status(500).json({ message: "Failed to send OTP" });
  }
  }
  
});

app.post('/exercises', (req, res)=>{
  if(!req.session.user){res.redirect('/login');}
  res.redirect('/exercises.html');
});


app.post("/send-otp-forgot-password", async (req, res)=>{
  const email = req.body.email;
  //checking if the account already exists
  const check_user = await db.query('SELECT * FROM users WHERE email=$1', [email]);
  if(check_user.rowCount==0){
    res.json({message : "User doesn't have an account"});
    return;
  }

  const otp = Math.floor(100000 + Math.random() * 900000);
  req.session.reset_otp = otp;

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your OTP Code for Reset Password of Neurocalm Account",
      text: `Dear User,

Your One-Time Password (OTP) for Reset Password is: ${otp}

Please keep this code confidential and do not share it with anyone.
If you did not request this, please ignore this message.

Thank you,
Neurocalm`,
    });
    
    res.json({ message: "OTP has been sent successfully!" });
  }catch(error){
    console.error("❌ Failed to send OTP:", error);
    res.status(500).json({ message: "Failed to send OTP" });
  }
});

app.post("/verify-otp", (req, res)=>{
  const email = req.body["key1"];
  const enteredOtp = req.body["key2"];
  const sentOtp = req.session.reset_otp;
  
  if(enteredOtp !== sentOtp){
    res.json({message : "Incorrect OTP"});
  }

  res.status(200).json({message : "OTP has been verified successfully!"});
});
// Start Server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
