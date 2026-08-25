// Must run after verifyToken, which sets req.user from the verified JWT payload.
const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({
      message: `Forbidden: this account's role is "${req.user.role || "unknown"}", but this action requires ${roles.join(" or ")}. If you were just promoted, log out and back in to refresh your session.`,
    });
  }
  next();
};

module.exports = requireRole;
