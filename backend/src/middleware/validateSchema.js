const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true });

const validateSchema = (schema) => {
  return (req, res, next) => {
    const validate = ajv.compile(schema);
    const valid = validate(req.body);

    if (!valid) {
      const errors = validate.errors.map(err => `${err.instancePath} ${err.message}`).join(', ');
      
      const error = new Error(`Validation Error: ${errors}`);
      error.statusCode = 400;
      return next(error);
    }
    
    next();
  };
};

module.exports = validateSchema;
