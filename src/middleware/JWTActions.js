const JWTService = require('../service/JWTService');
const { handleInsertTokeToCookies } = require('../utils');

const nonSecurePaths = [
    '/logout',
    '/forgot-password',
    '/login',
    '/register',
    '/verify-token',
    '/google',
    '/google/callback',
    '/send-otp',
    'another-user-account'];

const verifyJWT = async (req, res, next) => {
    if (nonSecurePaths.includes(req.path)) return next();

    const accessToken = req.cookies?.access_token
    const refreshToken = req.cookies?.refresh_token

    if (!refreshToken) {
        return res.status(405).json({
            EC: -1,
            EM: 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại!'
        })
    }

    const decoded = JWTService.verifyToken(accessToken)

    if (accessToken && decoded !== 'TokenExpiredError') {
        req.user = {
            ...decoded,
            access_token: accessToken,
            refresh_token: refreshToken
        }
        return next()
    } 

    const response = await JWTService.findUserByToken(refreshToken)

    if (+response?.EC === -1) {
        return res.status(401).json({
            EC: response?.EC,
            EM: response?.EM
        })
    }

    const payload = {
        id: response?.DT?.id,
        username: response?.DT?.username,
        email: response?.DT?.email,
        gender: response?.DT?.gender,
        phone_number: response?.DT?.phone_number,
        address: response?.DT?.address,
        type_account: response?.DT?.type_account,
    }

    const newAccessToken = JWTService.createJWT(payload)

    handleInsertTokeToCookies(res, newAccessToken, refreshToken)

    req.user = {
        ...payload,
        access_token: newAccessToken,
        refresh_token: refreshToken
    }

    return next()
}

module.exports = {
    verifyJWT
}