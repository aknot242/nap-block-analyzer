FROM node:14

WORKDIR /home/node

# Bundle app source
COPY . .

RUN npm install
# If you are building your code for production
# RUN npm ci --only=production

RUN npm run postinstall

ENV PORT=5001
# EXPOSE 5001

CMD [ "node", "server" ]
