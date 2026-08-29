exports.getHealth = (req, res, next) => {
  try {
    res.status(200).json({
      status: 'UP',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    next(error);
  }
};
