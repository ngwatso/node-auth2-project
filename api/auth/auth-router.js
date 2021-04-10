const router = require('express').Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const jwt = require('jsonwebtoken');
const /*{ JWT_SECRET }*/ secret = require('../secrets'); // !! use this secret!
const bcrypt = require('bcryptjs');
const Users = require('../users/users-model');
const ExpressError = require('./ExpressError');

router.post('/register', validateRoleName, async (req, res, next) => {
	/*
    * [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    * response:
    * status 201
    * {
    *   "user"_id: 3,
    *   "username": "anna",
    *   "role_name": "angel"
    * }
   */
	const credentials = req.body;

	try {
		const hash = bcrypt.hashSync(credentials.password, 10);
		credentials.password = hash;

		const user = await Users.add(credentials);
		res.status(201).json(user);
	} catch (err) {
		next(err);
	}
});

router.post('/login', checkUsernameExists, async (req, res, next) => {
	/*
    * [POST] /api/auth/login { "username": "sue", "password": "1234" }

    * response:
    * status 200
    * {
    *   "message": "sue is back!",
    *   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    * }

    * The token must expire in one day, and must provide the following information
    * in its payload:

    * {
    *   "subject"  : 1       // the user_id of the authenticated user
    *   "username" : "bob"   // the username of the authenticated user
    *   "role_name": "admin" // the role of the authenticated user
    * }
   */
	const { username, password } = req.body;

	try {
		const [user] = await Users.findBy({ username: username });
		if (user && bcrypt.compareSync(password, user.password)) {
			const token = generateToken(user);
			res.status(200).json({
				message: `${user.username} is back!`,
				token,
			});
		} else {
			next(new ExpressError('Invalid credentials', 401));
		}
	} catch (err) {
		next(err);
	}
});

function generateToken(user) {
	const payload = {
		subject: user.user_id,
		username: user.username,
		role_name: user.role_name,
	};
	const options = {
		expiresIn: '1 day',
	};
	const token = jwt.sign(payload, secret.jwtSecret, options);

	return token;
}

module.exports = router;
