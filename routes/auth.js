const mysql = require('mysql2');
require('dotenv').config();

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

module.exports = pool;

const express = require('express');
const router = express.Router();
const db = require('../db');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('../utils/jwt-util');
// const redisClient = require('../utils/redis');
// const refresh = require('./refresh');
// const cache = require('memory-cache');
// const path = require('path');
const authJWT = require('../middlewares/authJWT');
// const authMember = require('../middlewares/authmember');
// var appDir = path.dirname(require.main.filename);

// 회원가입
router.post('/signup', async(req, res) => {
    //redis 연결 for refresh token 저장
    //signToken 해체
    console.log(18)
    try {
        // const signInfoVerified = jwt.signVerify(req.body.signToken);
        // if (signInfoVerified === false) {
        //     return res.status(400).json({
        //         statusCode: 1020, 
        //         message: "invalid sign token" 
        //     })
        //}
        const salt = await bcrypt.genSalt(saltRounds);
        console.log(27)
        const encrypted = await bcrypt.hash(req.body.pwd, salt);
        console.log(29)

        await db.promise().query(`
            INSERT INTO member(member_name, member_email, member_pwd ,member_tel)
            VALUES('${req.body.name}','${req.body.email}', '${encrypted}','${req.body.tel}')
        `)
        res.status(201).send({ 
            message: "signup succeed"
        });
    } catch (err) {
        if(err.errno===1062){
            res.status(400).send({ 
                statusCode: 1062,
                message: "email already exists" 
            });
        }
        console.log(err);
    }
});

// //로그인 회원 존재 시 JWT발급, 존재 안하면 404에러 발생
// router.post('/login', async(req, res) => {
//     const [member] = await db.promise().query(`
//         SELECT * FROM member WHERE member_email = '${req.body.email}'
//     `);
//     if (member.length == 0) {
//         return res.status(404).json({
//             statusCode: 404,
//             message: "member not found" 
//         });
//     }
//     bcrypt.compare(req.body.pwd, member[0].member_pwd, (err, same) => {
//         if (same) {
//             const accessToken = jwt.login(member[0].member_email); // 수정된 부분
//             // refreshToken 발급 로직 제거
//             res.status(200).send({
//                 accessToken: accessToken,
//                 message: "login succeed"
//             });
//         } else {
//             res.status(401).send({
//                 statusCode: 1001,
//                 message: "invalid password"
//             });
//         }
//     });
// });

router.post('/login', async(req, res) => {
    try {
        const [member] = await db.promise().query(`
            SELECT * FROM member WHERE member_email = '${req.body.email}'
        `);
        if (member.length == 0) {
            return res.status(404).json({
                statusCode: 404,
                message: "member not found" 
            });
        }

        const same = await bcrypt.compare(req.body.pwd, member[0].member_pwd);
        if (same) {
            const accessToken = jwt.login(member[0].member_email);
            res.status(200).send({
                accessToken: accessToken,
                message: "login succeed"
            });
        } else {
            res.status(401).send({
                statusCode: 1001,
                message: "invalid password"
            });
        }
    } catch (err) {
        console.log(err);
        res.status(500).send("Server error");
    }
});

//로그아웃
router.post('/logout', authJWT, async (req, res, next) => {
    // 서버 측 로직 제거. 클라이언트에서 토큰 삭제로 처리
    res.status(200).send({
        isLogout: true,
        message: "logout succeed"
    });
});


module.exports = router;