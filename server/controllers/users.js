const User = require('../models').User;
const TokenStore = require('../models').TokenStore;
const { jwtConfig } = require('../config/main-config');
const { sign } = require('jsonwebtoken');

const generateToken = (user) => {
    // Return Json Token for login
    return sign({user}, jwtConfig.jwtSecret, {
        expiresIn: jwtConfig.jwtLifeTime
    });
}


module.exports = {
    async create (req, res) {
        try {
            const { username, password } = req.body;
            const response = await User.create({username, password});

            return res.status(200).send(response);
        } catch (error) {
            return res.status(400).send({ message: error.message });
        }
    },

    async login (req, res) {
        try {
            const { username, password } = req.body;
            const user = await User.findOne({
                where: {
                    username
                }
            });
            
            // User doesn't exists or password is invalid
            if (!user) {
                return res.status(400).send({message: 'Invalid Username or Password'});
            }

            const checkPassword = await user.validatePassword(password);
            if (!checkPassword) {
                return res.status(400).send({message: 'Invalid Username or Password'});
            }

            const token = generateToken(user);

            // Store the token
            const createToken = await TokenStore.create({ token, userId: user.id });

            return res.status(200).send({ token: token });

        } catch (error) {
            console.log(error);
            return res.status(400).send({ message: error.message });
        }
    },

    async updatePassword (req, res) {
        try {
            const { old_password, new_password } = req.body;
            const user = req.user;

            const checkPassword = await user.validatePassword(old_password);
            if (!checkPassword) {
                return res.status(400).send({message: 'Incorrect Old Password'});
            }

            // delete all the tokens of this user from db
            const deleteToken = await TokenStore.destroy({ 
                where: {
                    userId: user.id,
                }
             });


            // Update Password
            const update = await user.update({ password: new_password });

            return res.status(200).send(user);

        } catch (error) {
            return res.status(400).send({ message: error.message });
        }
    },

    async logout (req, res) {
        try {

            const user = req.user;

            // delete all the tokens of this user from db
            const deleteToken = await TokenStore.destroy({ 
                where: {
                    userId: user.id,
                    token: req.headers['authorization'].split(' ')[1],
                }
             });

            return res.status(200).send(user);

        } catch (error) {
            return res.status(400).send({ message: error.message });
        }
    }
};