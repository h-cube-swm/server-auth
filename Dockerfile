FROM node:14

WORKDIR /app

COPY package.json ./
COPY yarn.lock ./

RUN yarn

COPY ./ ./

CMD [ "node", "index.js" ]

EXPOSE 80