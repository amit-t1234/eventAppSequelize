module.exports = (sequelize, DataTypes) => {
  const User_Event = sequelize.define('User_Event', {});

  User_Event.associate = (models) => {
    User_Event.belongsTo(models.User, {
      foreignKey: "userId",
      onDelete: "CASCADE"
    });
    
    User_Event.belongsTo(models.Event, {
      foreignKey: "eventId",
      onDelete: "CASCADE"
    });
  }
  return User_Event;
};