FROM node:22-alpine
LABEL "language"="nodejs"
LABEL "framework"="express"

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

# 创建 public 文件夹并复制静态文件
RUN mkdir -p public && \
    cp index.html public/ && \
    cp admin.html public/ && \
    cp logo.png public/ && \
    ls -la public/

EXPOSE 8080

CMD ["npm", "start"]
