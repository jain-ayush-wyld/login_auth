const express = require("express");
const path = require('path');
const bcrypt = require("bcryptjs");
const jwt  = require('jsonwebtoken');
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");

const db = require('./db');

const app= express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.get("/",(req,res)=>{
    res.sendFile(path.join(__dirname, "public", "login.html"));
}
)

app.get("/login",(req,res)=>{
    res.send("this is my login page");
})

app.post("/login",async (req,res)=>{
    const{email,password} = req.body;
    // console.log(email,password);
    const [rows] = await db.execute('SELECT * FROM userid WHERE email = ?', [email]);
    // console.log(rows[0].password);
    if (rows.length==0)
    {
        console.log("user not found");
        return res.redirect("/");
    }
    const isMatch = await bcrypt.compare(password, rows[0].password);
    if (!isMatch)
    {
        console.log("password is incorrect");
        return res.redirect("/");
    }
    const user = {name : email};
    // console.log(user);
    const accesstoken = jwt.sign(user,process.env.ACCESS_SECRET_KEY,{
  expiresIn: '30s' // Token expires in 30 seconds
});
    res.cookie("accessToken", accesstoken, {
    httpOnly: true,
    secure: false,         // use only over HTTPS
    sameSite: 'Strict'
    });
    // res.redirect("/profile.html");
    console.log("welcome");
    res.redirect("/profile");
    
})

function authen_token(req,res,next)
{
    // const authheader = req.headers['authorization'];
    
    // const token = authheader && authheader.split(' ')[1];
    // console.log(token);
    // if (token==null)
    // {
    //     return res.redirect("/");
    // }
    // jwt.verify(token,process.env.ACCESS_SECRET_KEY,(err,user)=>{
    //     if (err){return res.redirect("/");}
    //     req.user = user;
    //     next();
    // })
    const token = req.cookies.accessToken;
    if (!token){
        console.log("no token present");
        return res.redirect("/");

    }

    try {
        const decoded = jwt.verify(token, process.env.ACCESS_SECRET_KEY);
        req.user = decoded; // store user info for later routes
        next();
    } catch (err) {
        console.log("invalid token/ expired");
        return res.redirect("/");
    }
}

app.get("/signup",(req,res)=>{
    // res.send("this is my signup page");
    res.sendFile(path.join(__dirname, "public", "signup.html"));
})

app.post("/signup",async (req,res)=>{
    const { username, email, password } = req.body;
    // console.log(username,email,password);
    const [rows] = await db.execute('SELECT * FROM userid WHERE email = ?', [email]);

    if (rows.length > 0) {
        // req.error = "User already exists";
        console.log("user already exists");
        return res.redirect("/signup");
    }
    const hasdPsw = await bcrypt.hash(password, 12);
    await db.execute(
      'INSERT INTO userid (name, email, password) VALUES (?, ?, ?)',
      [username, email,hasdPsw]
    );
    console.log("user added");
    res.redirect("/");
})

app.get("/profile",authen_token,(req,res)=>{
    res.send(req.user.name);
    // res.send("this is my profile page");
})


app.listen(3000,()=>{
    console.log("server listening on port 3000");
})