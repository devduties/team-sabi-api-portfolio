# FinComm Backend

Backend API for a team communication prototype, built with Express, PostgreSQL, Socket.IO, and JWT authentication.

> This repository is an educational prototype. Review and harden authorization, validation, upload handling, database migrations, and deployment settings before using it with real users or data.

## Requirements

- Node.js and npm
- PostgreSQL

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create a PostgreSQL database, then apply the schema:

   ```bash
   psql -U postgres -d fintech_chat -f database.sql
   ```

3. Copy `env.template` to `.env` and set your database connection values. Generate a unique JWT secret, for example:

   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

4. Start the API:

   ```bash
   npm run dev
   ```

The API listens on port `5000` by default. Set `FRONTEND_URL` to the exact frontend origin. The `/health` endpoint reports service status.

## Available scripts

- `npm start` — start the server
- `npm run dev` — start with nodemon
- `npm run setup-db` — apply the schema using the local `postgres` role

## Configuration

See [env.template](env.template). Never commit `.env` or real credentials. The database script creates tables and indexes only; it does not insert demo users or personal data.
