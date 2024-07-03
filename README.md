## Auth Microservice
## CURRENTLY UNDER REWORK (07/24)

<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="200" alt="Nest Logo" /></a>
</p>

## Dev

1. Clone this Repository.

2. Install Dependencies:
```bash
npm install
```

3. Create an `.env` file at the root directory of the project (use the provided `.env.template` as a guide for the bare minimum required env variables needed since they are type safe checked using dotenv and joi).

4. Run NATS server (if you haven`t done it before). To do this execute the following command: 
```bash
docker run -d --name nats-server -p 4222:4222 -p 8222:8222 nats
```

5. Run all the other required microservices.

6. Start this project with:
```bash
npm run start:dev
```

## Prod

To build only this Microservice image, navigate to auth-ms root directory and run:

```bash
docker build -f dockerfile.prod -t auth-ms .
```