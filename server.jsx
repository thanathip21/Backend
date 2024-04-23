const express = require("express");
const bodyParser = require("body-parser");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");

dotenv.config();

const uri = process.env.MONGO_URI;
const saltRouds = process.envSALT_ROUNDS;

const app = express();

app.use(bodyParser.json());

// Register
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  const client = new MongoClient(uri, { useUnifiedTopology: true });
  try {
    await client.connect();
    const database = client.db("users");
    const collection = database.collection("users");

    const hashPassword = await bcrypt.hash(password, parseInt(saltRouds));

    const user = await collection.insertOne({
      username: username,
      email: email,
      password: hashPassword,
    });
    res.json({
      success: true,
      message: "Register successful!!",
    });
  } catch (err) {
    res.json({
      success: true,
      message: "Register failed!!",
    });
  } finally {
    await client.close();
  }
});

// login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const client = new MongoClient(uri, { useUnifiedTopology: true });
  try {
    await client.connect();
    const database = client.db("users");
    const collection = database.collection("users");

    const user = await collection.findOne({ email: email });

    if (user) {
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        const token = jwt.sign({ email: email }, process.env.SECRET, {
          expiresIn: "1h",
        });
        res.json({
          success: true,
          message: "Login Successful!!",
          token: token,
        });
      } else {
        res.json({
          success: true,
          message: "Login failed",
        });
      }
    } else {
      res.json({
        success: true,
        message: "Login failed",
      });
    }
  } catch (error) {
    res.json({
      success: true,
      message: "Login failed",
    });
  } finally {
    await client.close();
  }
});

// Verify Token
function VerifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (typeof token !== "undefined") {
    jwt.verify(token, process.env.SECRET, (err, authData) => {
      if (err) {
        res.sendStatus(403);
      } else {
        next();
      }
    });
  } else {
    res.sendStatus(403);
  }
}

// Get all users
app.get("/users", VerifyToken, async (req, res) => {
  const client = new MongoClient(uri, { useUnifiedTopology: true });
  try {
    await client.connect();
    const database = client.db("users");
    const collection = database.collection("users");

    const users = await collection.find({}).toArray();
    res.json({
      success: true,
      message: "Get users successful",
      data: users,
    });
  } catch (error) {
    res.json({
      success: false,
      message: "Get users failed",
    });
  } finally {
    await client.close();
  }
});

app.listen(3000, () => {
  console.log("Server is running on port http://localhost:3000");
});
