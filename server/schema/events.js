const Joi = require('joi');

const createEventSchema = Joi.object({
    name: Joi.string().min(1).max(100).required(),
    description: Joi.string().min(1).max(255).required(),
});

const getEventSchema = Joi.object({
    offset: Joi.number().integer().min(0).required(),
    limit: Joi.number().integer().min(1).required(),
    name: Joi.string().min(1).max(100),
    description: Joi.string().min(1).max(100),
    created_from: Joi.date().raw(),
    created_to: Joi.date().raw(),

});

const inviteSchema = Joi.object({
    invites: Joi.array().items(Joi.string().min(5).max(100).regex(/^[a-zA-Z0-9-_]+$/)).min(1).required(),

});

module.exports = { createEventSchema, getEventSchema, inviteSchema }