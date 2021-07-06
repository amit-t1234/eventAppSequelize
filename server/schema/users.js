const Joi = require('joi');

const createAuthSchema = Joi.object({
    username: Joi.string().min(5).max(100).regex(/^[a-zA-Z0-9-_]+$/).required(),
    password: Joi.string().min(6).max(100).regex(/^(?=.*\d)(?=.*[a-zA-Z])(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{6,}$/).required().messages({
        "object.regex": "Password must 6 to 100 characters long with atleast one number, one alphabet and one special character",
        "string.pattern.base": "Password must 6 to 100 characters long with atleast one number, one alphabet and one special character",
    }),
});

const updatePasswordSchema = Joi.object({
    old_password: Joi.string().min(1).required(),
    new_password: Joi.string().min(6).max(100).disallow(Joi.ref('old_password')).regex(/^(?=.*\d)(?=.*[a-zA-Z])(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{6,}$/).required().messages({
        "object.regex": "Password must 6 to 100 characters long with atleast one number, one alphabet and one special character",
        "string.pattern.base": "Password must 6 to 100 characters long with atleast one number, one alphabet and one special character",
        "any.invalid": "New password and old password cannot be same"
    }),
    

});

module.exports = { createAuthSchema, updatePasswordSchema }