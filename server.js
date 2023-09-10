/** @format */

const app = require("./app");
const http = require("http");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
dotenv.config({ path: "./config.env" });

process.on("uncaughtException", (err) => {
	console.log(err);
	process.exit(1);
});

mongoose
	.connect(process.env.MONGO_URI, {
		// useNewUrlParser: true,
		// useCreateIndex: true,
		// useFindAndModify: false,
		// useUnifiedTopology: true,
	})
	.then((conn) => {
		console.log(`Connected to Database`);
	})
	.catch((err) => {
		console.log(err);
	});

const server = http.createServer(app);
const port = process.env.PORT || 8000;

server.listen(port, () => {
	console.log(`App running on Port ${port}`);
});

process.on("unhandledRejection", (err) => {
	console.log(err);
	server.close(() => {
		process.exit(1);
	});
});
