const userSchema = require('./users');
const eventSchema = require('./events');

module.exports = {
    '/api/user': userSchema.createAuthSchema,
    '/api/user/login': userSchema.createAuthSchema,
    '/api/user/password': userSchema.updatePasswordSchema,

    '/api/event/': eventSchema.createEventSchema,
    '/api/event/:event_id/invite': eventSchema.inviteSchema,
}