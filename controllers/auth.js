const { connect } = require('getstream');
const bcrypt = require('bcrypt');
const StreamChat = require('stream-chat').StreamChat;
const crypto = require('crypto');

require('dotenv').config();

const api_key = process.env.STREAM_API_KEY;
const api_secret = process.env.STREAM_API_SECRET;
const app_id = process.env.STREAM_APP_ID;

const signup = async (req, res) => {
    try {
        const { fullName, username, password, phoneNumber } = req.body;

        const userId = crypto.randomBytes(16).toString('hex');

        const serverClient = connect(api_key, api_secret, app_id);  // connects to getstream.io

        const hashedPassword = await bcrypt.hash(password, 10) // 10 specifies the 'salt'(password ) the level on encryption

        const token = serverClient.createUserToken(userId);

        res.status(200).json({ token, fullName, username, userId, hashedPassword, phoneNumber});
        
    } catch (error) {
        console.log(error);

        res.status(500).json({ message: error});

    }

};


const login = async (req, res) => {
    try {
        const { username, password } = req.body;

        const serverClient = connect(api_key, api_secret, app_id); 

        const client = StreamChat.getInstance(api_key, api_secret);  // created an instance of stream chat to query for the user with the provided username

        const { users } = await client.queryUsers({ name: username });  // search for the user with given username in the database

        if(!users.length) return res.status(400).json({ message: 'User not found'});

        const success = await bcrypt.compare(password, users[0].hashedPassword);  // if the user is found then his password is compared to the hashed password we generated while signing them up

        const token = serverClient.createUserToken(users[0].id);  // create a token using the logging in user's user id

        if(success){  // if the entered password matches with the password in database then we send back all the data of that particular user
            res.status(200).json({ token, fullName: users[0].fullName, username, userId: users[0].id}); 
        } else{
            res.status(500).json({ message: 'Incorrect Password'});
        }

    } catch (error) {
        console.log(error);

        res.status(500).json({ message: error});

    }
};



module.exports = { login, signup}