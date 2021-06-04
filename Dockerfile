FROM alpine
MAINTAINER Pinecrypt Labs <info@pinecrypt.com>
RUN apk add --update npm nginx rsync bash
RUN npm install --silent --no-optional -g nunjucks@2.5.2 nunjucks-date@1.2.0 node-forge bootstrap@4.0.0-alpha.6 jquery timeago tether font-awesome qrcode-svg xterm
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80 443 8443
WORKDIR /var/lib/nginx/html/
RUN rsync -avq /usr/lib/node_modules/font-awesome/fonts/ fonts/
COPY static ./
COPY templates templates
RUN nunjucks-precompile --include snippets --include views templates >> js/bundle.js
RUN bash -c 'cat /usr/lib/node_modules/{jquery/dist/jquery.min.js,tether/dist/js/tether.min.js,bootstrap/dist/js/bootstrap.min.js,node-forge/dist/forge.all.min.js,qrcode-svg/dist/qrcode.min.js,timeago/jquery.timeago.js,nunjucks/browser/nunjucks-slim.min.js,xterm/lib/xterm.js} >> js/bundle.js'
RUN bash -c 'cat /usr/lib/node_modules/{tether/dist/css/tether.min.css,bootstrap/dist/css/bootstrap.min.css,font-awesome/css/font-awesome.min.css,xterm/css/xterm.css} >> css/bundle.css'
RUN mkdir /frontend-secrets
RUN ln -s ../server-secrets/self_cert.pem /frontend-secrets/cert.pem
RUN ln -s ../server-secrets/self_key.pem /frontend-secrets/key.pem
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT /entrypoint.sh
