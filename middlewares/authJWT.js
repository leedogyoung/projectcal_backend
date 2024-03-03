const { signVerify } = require('../utils/jwt-util');

// const authJWT = (req, res, next) => {
//     console.log(req.headers.authorization)
//     if (req.headers.authorization) {
//       const token = req.headers.authorization.split('Bearer ')[1]; // header에서 access token을 가져옵니다.
//       const result = verify(token); // token을 검증합니다.
//       if (result.ok) { // token이 검증되었으면 req에 값을 세팅하고, 다음 콜백함수로 갑니다.
//         req.email = result.email.email.member_email;
//         next();
//       } else { // 검증에 실패하거나 토큰이 만료되었다면 클라이언트에게 메세지를 담아서 응답합니다.
//         res.status(401).send({
//           statusCode: 1000,
//           data: {},
//           message: result.message, // jwt가 만료되었다면 메세지는 'jwt expired'입니다.
//         });
//       }
//     }
//   };

const authJWT = (req, res, next) => {
  if (req.headers.authorization) {
      const token = req.headers.authorization.split('Bearer ')[1];
      const result = signVerify(token); // 수정된 함수명
      if (result.ok) {
          req.user = result.data; // 수정된 접근 방식
          next();
      } else {
          res.status(401).send({
              statusCode: 1000,
              message: result.message,
          });
      }
  } else {
      res.status(401).send({
          statusCode: 1000,
          message: "No authorization token provided",
      });
  }
};


module.exports = authJWT;