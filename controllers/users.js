const bcrypt = require("bcrypt");

const config = require("../config/index");
const { dataSource } = require("../db/data-source");
const logger = require("../utils/logger")("UsersController");
const generateJWT = require("../utils/generateJWT");

const passwordPattern = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,32}/;
const emailPattern = /^[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\.[A-Za-z]{2,}$/;

function isUndefined(value) {
  return value === undefined;
}

function isNotValidSting(value) {
  return typeof value !== "string" || value.trim().length === 0 || value === "";
}

class UsersController {
  // postSignup API 的內容
  static async postSignup(req, res, next) {
    try {
      const { name, email, password } = req.body;
      if (
        isUndefined(name) ||
        isNotValidSting(name) ||
        name.trim().length > 10 ||
        name.trim().length < 2 ||
        isUndefined(email) ||
        isNotValidSting(email) ||
        !emailPattern.test(email) ||
        isUndefined(password) ||
        isNotValidSting(password)
      ) {
        logger.warn("欄位未填寫正確");
        res.status(400).json({
          message: "欄位未填寫正確",
        });
        return;
      }
      if (!passwordPattern.test(password)) {
        logger.warn(
          "建立使用者錯誤: 密碼不符合規則，需要包含英文數字大小寫，最短8個字，最長32個字"
        );
        res.status(400).json({
          message:
            "密碼不符合規則，需要包含英文數字大小寫，最短8個字，最長32個字",
        });
        return;
      }
      const userRepository = dataSource.getRepository("users");
      const existingUser = await userRepository.findOne({
        where: { email },
      });

      if (existingUser) {
        logger.warn("註冊失敗，Email 已被使用");
        res.status(409).json({
          message: "註冊失敗，Email 已被使用",
        });
        return;
      }
      const salt = await bcrypt.genSalt(10);
      const hashPassword = await bcrypt.hash(password, salt);
      const newUser = userRepository.create({
        name,
        email,
        role: "USER",
        password: hashPassword,
      });
      const savedUser = await userRepository.save(newUser);
      logger.info("新建立的使用者ID:", savedUser.id);
      res.status(201).json({
        message: "註冊成功",
      });
    } catch (error) {
      logger.error("建立使用者錯誤:", error);
      next(error);
    }
  }
}

module.exports = UsersController;
