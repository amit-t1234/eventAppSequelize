const _ = require('lodash');
const Joi = require('joi');
const Schemas = require('../schema');

module.exports = (useJoiError = false) => {
  // useJoiError determines if we should respond with the base Joi error
  // boolean: defaults to false
  const _useJoiError = _.isBoolean(useJoiError) && useJoiError;

  // enabled HTTP methods for request data validation
  const _supportedMethods = ['post', 'put'];

  // Joi validation options
  const _validationOptions = {
    abortEarly: false,  // abort after the last validation error
    allowUnknown: true, // allow unknown keys that will be ignored
    stripUnknown: false  // remove unknown keys from the validated data
  };

  // return the validation middleware
  return (req, res, next) => {
    const route = req.route.path;
    const method = req.method.toLowerCase();

    if (_.includes(_supportedMethods, method) && _.has(Schemas, route)) {
      // get schema for the current route
      const _schema = _.get(Schemas, route);

      if (_schema) {
        // Validate req.body using the schema and validation options
        const result =_schema.validate(req.body, _validationOptions);

        if (result.error) {
            // Joi Error
            const JoiError = {
                status: 'failed',
                error: {
                    original: result.error._original,
                    // fetch only message and type from each error
                    details: _.map(result.error.details, ({message, type}) => ({
                        message: message.replace(/['"]/g, ''),
                        type
                    }))
                }
            };

            // Custom Error
            const CustomError = {
                status: 'failed',
                error: 'Invalid request data. Please review request and try again.'
            };

            // Send back the JSON error response
            return res.status(422).json(_useJoiError ? JoiError : CustomError);
        } else {
            // Replace req.body with the data after Joi validation
            req.body = result.value;
            return next();
        }
      }
    }
    next();
  };
};