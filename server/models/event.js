module.exports = (sequelize, DataTypes) => {
  const Event = sequelize.define('Event', {
    name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    description: {
      type: DataTypes.STRING,
      allowNull: false,
    },
  });

  Event.associate = (models) => {
    Event.belongsTo(models.User, {
      foreignKey: "userId",
      onDelete: "CASCADE",
    });

    Event.belongsToMany(models.User, {
      through: models.User_Event,
      foreignKey: 'eventId'
    });
  }
  
  return Event;
};