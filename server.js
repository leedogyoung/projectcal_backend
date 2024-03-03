require("dotenv").config();
const express = require('express');
const app = express();
const morgan = require("morgan");
const bodyParser = require('body-parser');
const cors = require('cors');
const authRoute = require('./routes/auth');
//const memberRoute = require('./routes/member')
// const swaggerUi = require('swagger-ui-express');
// const swaggerFile = require('./swagger-output.json');


const port = 8000;

app.use(morgan("dev"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended : false}));
app.use(cors());

app.use('/auth', authRoute);
//app.use('/member', memberRoute);
// app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerFile, { explorer: true }));
const { createServer } = require("http");
const httpServer = createServer(app);

httpServer.listen(port, () => {
    console.log("서버 시작");
})
