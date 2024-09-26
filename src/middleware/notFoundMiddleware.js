const notFoundMiddleware = (req, res, next) => {
  res.status(404).json({
    sucess: false,
    message: "Route not Found",
  });
};

export default notFoundMiddleware;
