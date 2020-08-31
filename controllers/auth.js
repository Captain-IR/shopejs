const crypto = require('crypto')
const bcrypt = require('bcryptjs')
const nodemailer = require('nodemailer')
const sendgridTransport = require('nodemailer-sendgrid-transport')
const { validationResult } = require('express-validator')

const User = require('../models/user')

const transporter = nodemailer.createTransport(
	sendgridTransport({
		auth: {
			api_key: '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',
		},
	})
)

exports.getLogin = (req, res, next) => {
	let message = req.flash('error')
	if (message.length > 0) {
		message = message[0]
	} else {
		message = null
	}

	res.render('auth/login', {
		path: '/login',
		pageTitle: 'Login',
		errorMessage: message,
		oldInput: {
			email: '',
			password: '',
		},
		validationErrors: [],
	})
}

exports.getSignup = (req, res, next) => {
	let message = req.flash('error')
	if (message.length > 0) {
		message = message[0]
	} else {
		message = null
	}
	res.render('auth/signup', {
		path: '/signup',
		pageTitle: 'Signup',
		errorMessage: message,
		oldInput: {
			email: '',
			password: '',
			confirmPassword: '',
		},
		validationErrors: [],
	})
}

exports.postLogin = (req, res, next) => {
	const email = req.body.email
	const password = req.body.password

	const errors = validationResult(req)
	if (!errors.isEmpty()) {
		console.log(errors.array())
		return res.status(422).render('auth/login', {
			path: '/login',
			pageTitle: 'Login',
			errorMessage: errors.array()[0].msg,
			oldInput: {
				email,
				password,
			},
			validationErrors: errors.array(),
		})
	}

	User.findOne({ email })
		.then(user => {
			if (!user) {
				return res.status(422).render('auth/login', {
					path: '/login',
					pageTitle: 'Login',
					errorMessage: 'Invalid email or password',
					oldInput: {
						email,
						password,
					},
					validationErrors: [],
				})
			}

			bcrypt
				.compare(password, user.password)
				.then(doMatch => {
					if (doMatch) {
						req.session.isLoggedIn = true
						req.session.user = user
						return req.session.save(err => {
							console.log(err)
							res.redirect('/')
						})
					}
					return res.status(422).render('auth/login', {
						path: '/login',
						pageTitle: 'Login',
						errorMessage: 'Invalid email or password',
						oldInput: {
							email,
							password,
						},
						validationErrors: [],
					})
				})
				.catch(err => {
					console.error(err)
					res.redirect('/login')
				})
		})
		.catch(err => {
			const error = new Error(err)
			error.httpStatusCode = 500
			return next(error)
		})
}

exports.postSignup = (req, res, next) => {
	const email = req.body.email
	const password = req.body.password

	const errors = validationResult(req)
	if (!errors.isEmpty()) {
		console.log(errors.array())
		return res.status(422).render('auth/signup', {
			path: '/signup',
			pageTitle: 'Signup',
			errorMessage: errors.array()[0].msg,
			oldInput: {
				email,
				password,
				confirmPassword: req.body.confirmPassword,
			},
			validationErrors: errors.array(),
		})
	}

	return bcrypt
		.hash(password, 12)
		.then(hashedPassword => {
			const user = new User({
				email,
				password: hashedPassword,
				cart: { items: [] },
			})
			return user.save()
		})

		.then(result => {
			res.redirect('/login')
			return transporter.sendMail({
				to: email,
				from: 'SINDBAD@CRIPTEXT.COM',
				subject: 'Signup Succeeded',
				html: '<h1>Your account has been created please Login</h1>',
			})
		})
		.catch(err => {
			const error = new Error(err)
			error.httpStatusCode = 500
			return next(error)
		})
}

exports.postLogout = (req, res, next) => {
	req.session.destroy(err => {
		console.log(err)
		res.redirect('/')
	})
}

exports.getReset = (req, res, next) => {
	let message = req.flash('error')
	if (message.length > 0) {
		message = message[0]
	} else {
		message = null
	}

	res.render('auth/reset', {
		path: '/reset',
		pageTitle: 'Reset Password',
		errorMessage: message,
	})
}

exports.postReset = (req, res, next) => {
	crypto.randomBytes(32, (err, buffer) => {
		if (err) {
			console.error(err)
			return res.redirect('/reset')
		}
		const token = buffer.toString('hex')
		User.findOne({ email: req.body.email })
			.then(user => {
				if (!user) {
					req.flash('error', 'No account found')
					return res.redirect('/reset')
				}
				user.resetToken = token
				user.resetTokenExpiration = Date.now() + 3600000
				return user.save()
			})
			.then(() => {
				res.redirect('/')
				return transporter.sendMail({
					to: req.body.email,
					from: 'SINDBAD@CRIPTEXT.COM',
					subject: 'Password reset',
					html: ` <p>Click this <a href="http://localhost:5000/reset/${token}">link</a> to set a new password /p> `,
				})
			})
			.catch(err => {
				const error = new Error(err)
				error.httpStatusCode = 500
				return next(error)
			})
			.catch(err => {
				const error = new Error(err)
				error.httpStatusCode = 500
				return next(error)
			})
	})
}

exports.getNewPassword = (req, res, next) => {
	const token = req.params.token
	User.findOne({
		resetToken: token,
		resetTokenExpiration: { $gt: Date.now() },
	})
		.then(user => {
			let message = req.flash('error')
			if (message.length > 0) {
				message = message[0]
			} else {
				message = null
			}

			res.render('auth/new-password', {
				path: '/reset',
				pageTitle: 'New Password',
				errorMessage: message,
				userId: user._id.toString(),
				passwordToken: token,
			})
		})
		.catch(err => {
			const error = new Error(err)
			error.httpStatusCode = 500
			return next(error)
		})
}

exports.postNewPassword = (req, res, next) => {
	const newPassword = req.body.password
	const userId = req.body.userId
	const passwordToken = req.body.token
	console.log(newPassword)
	console.log(userId)
	console.log(passwordToken)
	let resetUser

	User.findOne({
		resetToken: passwordToken,
		resetTokenExpiration: { $gt: Date.now() },
		_id: userId,
	})
		.then(user => {
			resetUser = user
			return bcrypt.hash(newPassword, 12)
		})
		.then(hashedPassword => {
			resetUser.password = hashedPassword
			resetUser.resetToken = undefined
			resetUser.resetTokenExpiration = undefined
			return resetUser.save()
		})
		.then(result => {
			res.redirect('/login')
		})
		.catch(err => {
			const error = new Error(err)
			error.httpStatusCode = 500
			return next(error)
		})
}
