const { genSaltSync, hashSync, compareSync } = require('bcrypt');
module.exports = (sequelize, DataTypes) => {
  const User = sequelize.define('User', {
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
  }, {
    hooks: {
      beforeCreate: async (User) => {
        const salt = genSaltSync(10);
        User.password = hashSync(User.password, salt);
      },
      beforeUpdate: async (User) => {
        const salt = genSaltSync(10);
        User.password = hashSync(User.password, salt);
      }
    }
  });

  User.prototype.validatePassword = async function (password) {
    return compareSync(password, this.password);
  }

  User.associate = (models) => {
    User.hasMany(models.Event, {
      foreignKey: "userId",
      as: "events"
    });

    User.hasMany(models.TokenStore, {
      foreignKey: "userId",
      as: "tokens"
    });

    User.belongsToMany(models.Event, {
      through: models.User_Event,
      foreignKey: 'userId'
    });
  }

  return User;
};