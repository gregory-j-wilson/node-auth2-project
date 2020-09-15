const express = require("express")
const helmet = require("helmet")
const cors = require("cors")
const bcryptjs = require("bcryptjs")

const server = express()

const Users = require("./users/users-model.js");
const restricted = require("./auth/restricted-middleware");

server.use(helmet())
server.use(express.json())
server.use(cors())





server.post("/api/register", (req, res) => {

    const credentials = req.body

    if (isValid(credentials)) {

        const rounds = process.env.BCRYPT_ROUNDS || 8;

        const hash = bcryptjs.hashSync(credentials.password, rounds)

        credentials.password = hash

        Users.add(credentials)
            .then(user => {
                res.status(201).json({data: user})
            })
            .catch(error => {
                res.status(500).json({error: error.message})
            })
    } else {
        res.status(400).json({message: "please provide username and password - password should be alphanumeric"})
    }
})


server.post("/api/login", (req, res) => {
  
    const { username, password } = req.body

    if (isValid(req.body)) {
        Users.findBy({username: username})
            .then(([user]) => {
                if (user && bcryptjs.compareSync(password, user.password)) {

                    const token = makeJwt(user)
                    res.status(200).json({ token })

                } else {
                    res.status(401).json({message: "Invalid credentials"})
                }
            })
            .catch(error => {
                res.status(500).json({error: "You are not in the system"})
            })
    } else {
        res.status(400).json({message: "Please provide your username and password."})
    }
})


server.get("/api/users", restricted, (req, res) => {

    Users.find()
        .then(users => {
            res.status(200).json(users)
        })
        .catch(err => res.send(err))
})


//----------------

function makeJwt(user) {

    const payload = {
        username: user.username
    }

    const config = {
        jwtSecret: process.env.JWT_SECRET || 'is it secret, is it safe?'
    }

    const options = {
        expiresIn: '1 hour'
    }

    return jwt.sign(payload, config.jwtSecret, options)
}


function isValid(user) {
    return Boolean(user.username && user.password && typeof user.password === "string");
  }


module.exports = server;