const sequelize = require('../../config/sequelize');
const { DataTypes } = require('sequelize');

const model = () => sequelize.define('user', {
  'user_id': {
    type: DataTypes.INTEGER(20),
    allowNull: false,
    primaryKey: true,
    autoIncrement: true,
  },
  'username': {
    type: DataTypes.STRING(100),
    allowNull: false
  },
  'email': {
    type: DataTypes.STRING(100),
    allowNull: false
  },
  'password': {
    type: DataTypes.STRING(100),
    allowNull: false
  },
}, {
  timestamps: false,
  tableName: 'user'
});

module.exports = model;
