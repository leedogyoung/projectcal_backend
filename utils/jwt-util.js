// const { promisify } = require('util');
// const redisClient = require('./redis');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
require("dotenv").config();
const secret = process.env.SECRET_KEY;

// 환경변수에서 데이터베이스 접속 정보를 로드합니다.
const dbConfig = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE
};

module.exports = {
  // 회원가입 시 사용자 정보를 DB에 저장하고 access token 발급
  // 비밀번호는 해싱하여 DB에 저장합니다. (DB 저장 로직은 이 예제에 포함되지 않음)
  register: async (name, tel, email, pwd) => {
    const saltRounds = 10;
    try {
      const hashedPassword = await bcrypt.hash(pwd, saltRounds); // 비밀번호 해싱
      const connection = await mysql.createConnection(dbConfig); // 데이터베이스 연결
      
      // 사용자 정보와 해시된 비밀번호를 데이터베이스에 저장
      const [rows, fields] = await connection.execute(
        'INSERT INTO member (name, tel, email, password) VALUES (?, ?, ?, ?)',
        [name, tel, email, hashedPassword]
      );
      
      // 비밀번호는 토큰에 포함시키지 않습니다.
      const payload = {
        name: name,
        tel: tel,
        email: email,
      };
      return jwt.sign(payload, secret, {
        algorithm: 'HS256',
        expiresIn: '1d',
      });
    } catch (error) {
      console.error('Error hashing password or saving to DB:', error);
      throw error;
    }
  },

  // // 로그인 시 이메일과 비밀번호 검증 후 access token 발급
  // // 이 함수는 비밀번호 검증 로직을 포함해야 합니다. (DB 조회 로직은 이 예제에 포함되지 않음)
  // login: async (email, pwd) => {
  //   try {
  //     // DB에서 사용자의 hashedPassword를 조회하는 로직을 추가하세요.

  //     const isMatch = await bcrypt.compare(pwd, hashedPassword); // DB에서 가져온 hashedPassword와 비교
  //     if (isMatch) {
  //       const payload = {
  //         email: email,
  //       };
  //       return jwt.sign(payload, secret, {
  //         algorithm: 'HS256',
  //         expiresIn: '1d',
  //       });
  //     } else {
  //       throw new Error('Authentication failed');
  //     }
  //   } catch (error) {
  //     console.error('Login error:', error);
  //     throw error;
  //   }
  // },

  login: async (email, pwd) => {
    try {
      const connection = await mysql.createConnection(dbConfig);
      const [users] = await connection.execute('SELECT * FROM member WHERE email = ?', [email]);
      if (users.length === 0) {
        throw new Error('User not found');
      }
      const user = users[0];
      
      const isMatch = await bcrypt.compare(pwd, user.password);
      if (isMatch) {
        const payload = { email: user.email };
        return jwt.sign(payload, secret, { algorithm: 'HS256', expiresIn: '1d', });
      } else {
        throw new Error('Authentication failed');
      }
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  },

  // 토큰 검증
  signVerify: (token) => {
    try {
      const decoded = jwt.verify(token, secret);
      return {
        ok: true,
        data: decoded,
      };
    } catch (err) {
      return {
        ok: false,
        message: err.message,
      };
    }
  },

  // 로그아웃 기능은 클라이언트 측에서 토큰을 삭제하거나 무효화하여 구현합니다.
};

