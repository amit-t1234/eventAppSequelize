const { User, Event, User_Event } = require('../models');
const { jwtConfig } = require('../config/main-config');
const { sign } = require('jsonwebtoken');
const { Op } = require("sequelize");
const sequelize = require("../models").sequelize;

module.exports = {
    async create (req, res) {
        // ! Creating Transaction
        const t = await sequelize.transaction();

        try {
            const { name, description } = req.body;
            const userId = req.user.id;

            const event = await Event.create({ name, description, userId}, { transaction: t });

            const linkUserEvent = await event.addUsers(userId, { transaction: t });

            // ! Transaction Commit
            await t.commit();
            return res.status(200).send(linkUserEvent);
        } catch (error) {
            console.log(error);

            // ! Transaction Rollback
            await t.rollback();
            return res.status(400).send({ message: error.message });
        }
    },

    async get (req, res) {
        try {
            const { offset, limit, name, description, created_from, created_to } = req.body;
            const user = req.user;

            // !Define Dynamic Where Clause
            let where = {};
            
            if (created_from && created_to && created_from.length && created_to.length) {
                where.createdAt = {
                    [Op.and]: {
                        [Op.gte]: new Date(created_from),
                        [Op.lte]: new Date(created_to),
                    }
                }
            }

            if (name && name.length) {
                where.name = {
                    [Op.eq]: name,
                }
            }

            if (description && description.length) {
                where.description = {
                    [Op.eq]: description,
                }
            }

            // ! Get Events Of User
            // TODO: Can be made simpler I think
            const events = await User_Event.findAll({
                where: {
                    userId: user.id,
                },
                include: [{
                    model: Event,
                    include: [ {
                        model: User,
                    }],
                    where,
                    order: ['createdAt'],
                }],
                limit,
                offset,
            });

            return res.status(200).send(events);

        } catch (error) {
            console.log(error);
            return res.status(400).send({ message: error.message });
        }
    },

    async invite (req, res) {
        try {
            let body = req.body;
            const event_id = req.params.event_id;

            // * Check if invite is array or jsonencoded array
            const invites = Array.isArray(body.invites)? body.invites: JSON.parse(body.invites);
            console.log(invites);
            // Get User Ids
            const users = await User.findAll({
                where: {
                    username: {
                        [Op.in]: invites
                    }
                },
                attributes: ['id'],
                raw: true,
            })

            // Get the Event
            const event = await Event.findByPk(event_id);

            // * Add Users to the Event
            const addToEvent = await event.addUsers(users.map(user => user.id));

            return res.status(200).send(event);

        } catch (error) {
            console.log(error);
            return res.status(400).send({ message: error.message });
        }
    }
};