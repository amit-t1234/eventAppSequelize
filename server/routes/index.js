const usersController = require('../controllers').users;
const eventsController = require('../controllers').events;
const { isLoggedIn } = require('../directives/isLoggedIn');
const SchemaValidator = require('../directives/schemaValidator');
const validateRequest = SchemaValidator(true);

module.exports = (app) => {
    app.get('/api', (req, res) => res.status(200).send({
        message: 'Welcome to the Events API!',
    }));
    
    app.post('/api/user', validateRequest, usersController.create);
    app.post('/api/user/login', validateRequest, usersController.login);
    app.put('/api/user/password', isLoggedIn, validateRequest, usersController.updatePassword);
    app.post('/api/user/logout', isLoggedIn, usersController.logout);


    app.post('/api/event', isLoggedIn, eventsController.create);
    app.get('/api/event', isLoggedIn, eventsController.get);
    app.post('/api/event/:event_id/invite', isLoggedIn, eventsController.invite);
}