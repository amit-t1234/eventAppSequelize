module.exports = (sequelize, DataTypes) => {
  const TokenStore = sequelize.define('TokenStore', {
    token: {
      type: DataTypes.STRING(1000),
      allowNull: false,
    },
  });

  TokenStore.associate = (models) => {
    TokenStore.belongsTo(models.User, {
      foreignKey: "userId",
      onDelete: "CASCADE"
    });
  }
  return TokenStore;
};