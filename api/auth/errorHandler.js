module.exports = (err, req, res, next) => {
	console.log('express error: ', err);
	if (err.apiCode && err.apiCode >= 400) {
		err.apiMessage = err.apiMessage ? err.apiMessage : '';
		res.status(err.apiCode).json({
			apiCode: err.apiCode,
			apiMessage: err.apiMessage,
			...err,
		});
	} else {
		next();
	}
};
