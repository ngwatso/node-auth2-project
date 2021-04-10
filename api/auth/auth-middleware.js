const jwt = require('jsonwebtoken');
const /*{ JWT_SECRET }*/ secret = require('../secrets'); // !! use this secret!
const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');
const restricted = (req, res, next) => {
	/*
    * If the user does not provide a token in the Authorization header:
    * status 401
    * {
    *   "message": "Token required"
    * }

    * If the provided token does not verify:
    * status 401
    * {
    *   "message": "Token invalid"
    * }

    * Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
	try {
		const token = req.headers.authorization?.split(' ')[0];

		if (token) {
			jwt.verify(token, secret.jwtSecret, (err, decodedToken) => {
				if (err) {
					res.status(401).json({ message: 'Token invalid' });
				} else {
					req.decodedToken = decodedToken;
					next();
				}
			});
		} else {
			next({ statusCode: 401, message: 'Token required' });
		}
	} catch (err) {
		next({
			statusCode: 500,
			message: 'Error validating credentials',
			...err,
		});
	}
};

const only = (role_name) => (req, res, next) => {
	/*
    * If the user does not provide a token in the Authorization header with a role_name
    * inside its payload matching the role_name passed to this function as its argument:
    * status 403
    * {
    *   "message": "This is not for you"
    * }

    * Pull the decoded token from the req object, to avoid verifying it again!
  */
	if ((req?.decodedToken?.role_name || ' ') === role_name) {
		next();
	} else {
		res.status(403).json({ message: 'This is not for you' });
	}
};

const checkUsernameExists = async (req, res, next) => {
	/*
	 * If the username in req.body does NOT exist in the database
	 * status 401
	 * {
	 *   "message": "Invalid credentials"
	 * }
	 */
	try {
		let { username, password } = req.body;
		const user = await Users.findBy({ username }).first();
		if (user && bcrypt.compareSync(password, user.password)) {
			next();
		} else {
			res.status(401).json({ message: 'Invalid credentials' });
		}
	} catch (err) {
		next(err);
	}
};

const validateRoleName = async (req, res, next) => {
	/*
    * If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    * If role_name is missing from req.body, or if after trimming it is just an empty string,
    * set req.role_name to be 'student' and allow the request to proceed.

    * If role_name is 'admin' after trimming the string:
    * status 422
    * {
    *   "message": "Role name can not be admin"
    * }

    * If role_name is over 32 characters after trimming the string:
    * status 422
    * {
    *   "message": "Role name can not be longer than 32 chars"
    * }
  */

	try {
		let { role_name } = req.body;
		const isValid = (role_name) => {
			return Boolean(role_name && typeof role_name === 'string');
		};

		if (!req.body.role_name || req.body.role_name === ' ') {
			req.body.role_name = 'student';

			next();
		} else if (isValid(role_name)) {
			req.body.role_name = role_name.trim();

			if (req.body.role_name === 'admin') {
				res.status(422).json({ message: 'Role can not be admin' });
			} else if (req.body.role_name.length > 32) {
				res.status(422).json({
					message: 'Role name can not be longer than 32 chars',
				});
			}

			next();
		}
	} catch (err) {
		next(err);
	}
};

module.exports = {
	restricted,
	checkUsernameExists,
	validateRoleName,
	only,
};
