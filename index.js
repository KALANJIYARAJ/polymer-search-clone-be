const express = require("express");
const cors = require("cors");
const app = express();
const mongodb = require("mongodb");
const mongoclient = mongodb.MongoClient;
const dotenv = require("dotenv").config();
const URL = process.env.DB;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;
const nodemailer = require("nodemailer");
const EMAIL = process.env.EMAIL;
const PASSWORD = process.env.PASSWORD;
const FD = process.env.FD;

app.use(
  cors({
    orgin: FD,
  })
);

app.use(express.json());

let authorize = (req, res, next) => {
  try {
    // Check if authorization token present
    //   console.log(req.headers);
    if (req.headers.authorization) {
      // Check if the token is valid
      let decodedToken = jwt.verify(req.headers.authorization, JWT_SECRET);
      if (decodedToken) {
        next();
      } else {
        res.status(401).json({ message: "Unauthorized" });
      }
      // if valid say next()
      // if not valid say unauthorized
    }
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
  }
};

//user
//create_user
app.post("/user/register", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");

    //hash
    var salt = await bcrypt.genSalt(10);
    var hash = await bcrypt.hash(req.body.password, salt);

    req.body.password = hash;

    const user = await db.collection("users").insertOne(req.body);
    await connection.close();
    res.json({ message: "user created" });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
});

//user-login
app.post("/login", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");

    const user = await db
      .collection("users")
      .findOne({ email: req.body.email });
    await connection.close();

    if (user) {
      const compare = await bcrypt.compare(req.body.password, user.password);
      if (compare) {
        const token = jwt.sign({ _id: user._id }, JWT_SECRET, {
          expiresIn: "30m",
        });
        delete user.password;
        res.json({ message: "login successfully", token, user });
      } else {
        res.json({ message: "username or password incorrect" });
      }
    } else {
      res.json({ message: "username or password incorrect" });
    }
  } catch (error) {
    res.status(400).json({ message: "Something went wrong" });
  }
});

//sent msg to register email id
app.post("/forgot", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");

    const user = await db
      .collection("users")
      .findOne({ email: req.body.email });
    await connection.close();

    var transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: EMAIL,
        pass: PASSWORD,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });
    var mailOptions = {
      from: EMAIL,
      to: user.email,
      subject: "Rest Password",
      text: "Hi Raj",
      html: `<h1>Hiii ${user.email} <a href="${FD}/reset/${user._id}">please click the link and reset your password</a> </h1>`,
    };
    transporter.sendMail(mailOptions, function (error, response) {
      if (error) {
        console.log(error);
        return;
      }
      transporter.close();
    });

    res.json({ message: "Message sent" });
  } catch (error) {
    res.status(400).send({ sucess: false, msg: error.message });
  }
});

//update password from link
app.post("/reset/:userId", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");

    var salt = await bcrypt.genSalt(10);
    var hash = await bcrypt.hash(req.body.password, salt);
    req.body.password = hash;

    const user = await db
      .collection("users")
      .updateOne(
        { _id: mongodb.ObjectId(req.params.userId) },
        { $set: { password: req.body.password } }
      );
    await connection.close();
    res.json(user);
  } catch (error) {
    res.status(400).json({ message: "Something went wrong" });
  }
});

app.get("/user/:userId", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");
    const user = await db
      .collection("users")
      .find({ _id: mongodb.ObjectId(req.params.userId) })
      .toArray();
    await connection.close();
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Something went wrong for get user" });
  }
});

//edit user
app.post("/edituser/:userId", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");

    const user = await db
      .collection("users")
      .updateOne(
        { _id: mongodb.ObjectId(req.params.userId) },
        { $set: req.body }
      );
    await connection.close();
    res.json(user);
  } catch (error) {
    res.status(400).json({ message: "Something went wrong" });
  }
});

//delete user
app.delete("/deleteuser/:userId", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");

    const user = await db
      .collection("users")
      .deleteOne({ _id: mongodb.ObjectId(req.params.userId) });
    await connection.close();
    res.json({ message: "user delete successfully" });
  } catch (error) {
    res.status(400).json({ message: "Something went wrong" });
  }
});

//workSpace
app.post("/workspace", authorize, async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");
    const workSpace = await db.collection("work-space").insertOne(req.body);
    await connection.close();
    res.json({ message: "work-space created" });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
});

//workSpace get
app.get("/workspace/:userId", authorize, async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");
    const workSpace = await db
      .collection("work-space")
      .find({ user_id: req.params.userId })
      .toArray();
    await connection.close();
    res.json(workSpace);
  } catch (error) {
    res.status(500).json({ message: "Something went wrong for get user" });
  }
});

//upload post
app.post("/upload", authorize, async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");
    await db
      .collection("upload")
      .insertOne(req.body);
    await connection.close();
    res.status(201).json({ message: "xlsx created" });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
});

//upload get all sourece
app.get("/upload/:userId",authorize, async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");
    const xlxsdata = await db
      .collection("upload")
      .find({ user_id: (req.params.userId) })
      // .aggregate([
      //   {
      //     $match: {
      //       user_id: req.params.userId,
      //     },
      //   },
      //   {
      //     $project: {
      //       source: 1,
      //       _id: 0,
      //     },
      //   },
      // ])
      .toArray();
    await connection.close();
    res.json(xlxsdata);
  } catch (error) {
    res.status(500).json({ message: "Something went wrong for get Data" });
  }
});

//upload get a single source
app.get("/upload/:file_id",authorize, async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");
    const xlxsdata = await db
      .collection("upload")
      .find({ _id : mongodb.ObjectId(req.params.file_id)})
      .toArray();
    await connection.close();
    res.json(xlxsdata);
  } catch (error) {
    res.status(500).json({ message: "Something went wrong for get Data" });
  }
});

//Type Change
app.post("/type/:file_id",authorize, async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");
    const type = await db
      .collection("upload")
      .updateOne({ _id : mongodb.ObjectId(req.params.file_id)},
                 { $set: { type: req.body.type } });
    await connection.close();
    res.status(200).json({ message: "Type Change Successfully" });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong for get Data" });
  }
});

//Delete file

app.delete("/deletefile/:file_id", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("polymer_search_clone");

    const user = await db
      .collection("upload")
      .deleteOne({ _id: mongodb.ObjectId(req.params.file_id) });
    await connection.close();
    res.status(201).json({ message: "file delete successfully" });
  } catch (error) {
    res.status(400).json({ message: "Something went wrong" });
  }
});

app.listen(process.env.PORT || 3003);
