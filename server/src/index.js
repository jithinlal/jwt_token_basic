require('dotenv/config');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { verify } = require('jsonwebtoken');
const { hash, compare } = require('bcryptjs');

const { fakeDB } = require('./fakeDB');
const { isAuth } = require('./isAuth');
const {
	createAccessToken,
	createRefreshToken,
	sendAccessToken,
	sendRefreshToken,
} = require('./tokens');

const server = express();
server.use(cookieParser());

server.use(
	cors({
		origin: 'http://localhost:3000',
		credentials: true,
	})
);

server.use(express.json());
server.use(express.urlencoded({ extended: true }));

server.post('/register', async (req, res) => {
	const { email, password } = req.body;

	try {
		if (email === '' || email === null || password === '' || password === null)
			throw new Error('Invalid email or password');
		const user = fakeDB.find(user => user.email === email);
		if (user) throw new Error('User Already Exist');
		const hashedPassword = await hash(password, 10);
		fakeDB.push({
			id: fakeDB.length,
			email,
			password: hashedPassword,
		});
		res.send({
			message: 'User created',
		});
		console.log(fakeDB);
	} catch (err) {
		res.send({
			error: `${err.message}`,
		});
	}
});

server.post('/login', async (req, res) => {
	const { email, password } = req.body;

	try {
		const user = fakeDB.find(user => user.email === email);
		if (!user) throw new Error('User does not exist');
		const valid = await compare(password, user.password);
		if (!valid) throw new Error('Password not correct');
		const accessToken = createAccessToken(user.id);
		const refreshToken = createRefreshToken(user.id);
		user.refreshToken = refreshToken;
		console.log(fakeDB);
		sendRefreshToken(res, refreshToken);
		sendAccessToken(res, req, accessToken);
	} catch (err) {
		res.send({
			error: `${err.message}`,
		});
	}
});

server.post('/logout', async (_req, res) => {
	res.clearCookie('refreshtoken', { path: '/refresh_token' });
	return res.send({
		message: 'Logged out',
	});
});

server.post('/protected', async (req, res) => {
	try {
		const userId = isAuth(req);
		if (userId !== null) {
			res.send({
				data: 'This is protected data',
			});
		}
	} catch (err) {
		res.send({
			error: `${err.message}`,
		});
	}
});

server.post('/refresh_token', (req, res) => {
	const token = req.cookies.refreshtoken;
	if (!token) {
		return res.send({
			accessToken: '',
		});
	}
	let payload = null;
	try {
		payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
	} catch (err) {
		return res.send({
			accessToken: '',
		});
	}
	const user = fakeDB.find(user => user.id === payload.userId);
	if (!user) {
		return res.send({
			accessToken: '',
		});
	}
	if (user.refreshToken !== token) {
		return res.send({
			accessToken: '',
		});
	}
	const accessToken = createAccessToken(user.id);
	const refreshToken = createRefreshToken(user.id);
	user.refreshToken = refreshToken;

	sendRefreshToken(res, refreshToken);
	return res.send({
		accessToken,
	});
});

server.listen(process.env.PORT, () => {
	console.log(`Server listening on ${process.env.PORT}`);
});
