module.exports=function(e){function t(r){if(n[r])return n[r].exports;var i=n[r]={i:r,l:!1,exports:{}};return e[r].call(i.exports,i,i.exports,t),i.l=!0,i.exports}var n={};return t.m=e,t.c=n,t.i=function(e){return e},t.d=function(e,n,r){t.o(e,n)||Object.defineProperty(e,n,{configurable:!1,enumerable:!0,get:r})},t.n=function(e){var n=e&&e.__esModule?function(){return e.default}:function(){return e};return t.d(n,"a",n),n},t.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},t.p="",t(t.s=11)}([function(e,t,n){"use strict";e.exports=n(4).config()},function(e,t){e.exports=require("auth0-extension-express-tools@1.1.6")},function(e,t){e.exports=require("express@4.12.4")},function(e,t,n){"use strict";var r=n(20);r.emitErrs=!0;var i=new r.Logger({transports:[new r.transports.Console({timestamp:!0,level:"debug",handleExceptions:!0,json:!1,colorize:!0})],exitOnError:!1});e.exports=i,e.exports.stream={write:function(e){i.info(e.replace(/\n$/,""))}}},function(e,t){e.exports=require("auth0-extension-tools@1.3.1")},function(e,t){e.exports=require("path")},function(e,t,n){"use strict";(function(t){var r=(n(19),n(5)),i=n(18),o=n(2),s=n(14),a=n(4),u=n(1),c=n(9),l=n(10),d=n(7),p=n(3),x=n(0);e.exports=function(e,n){x.setProvider(e);var f=n?new a.WebtaskStorageContext(n,{force:1}):new a.FileStorageContext(r.join(t,"./data.json"),{mergeWrites:!0}),E=new o;E.use(i(":method :url :status :response-time ms - :res[content-length]",{stream:p.stream}));var h=function(e){return function(t,n,r){return t.webtaskContext&&t.webtaskContext.body?(t.body=t.webtaskContext.body,r()):e(t,n,r)}};return E.use(h(s.json())),E.use(h(s.urlencoded({extended:!1}))),E.use(u.routes.dashboardAdmins({secret:x("EXTENSION_SECRET"),audience:"urn:extend-security-extension",rta:x("AUTH0_RTA").replace("https://",""),domain:x("AUTH0_DOMAIN"),baseUrl:x("PUBLIC_WT_URL")||x("WT_URL"),clientName:"Extend Security Extension",urlPrefix:"",sessionStorageKey:"extend-security-extension:apiToken"})),E.use("/meta",l()),E.use("/.extensions",d()),E.use("/app",o.static(r.join(t,"../dist"))),E.use("/",c(f)),E.use(u.middlewares.errorHandler(p.error.bind(p))),E}}).call(t,"/")},function(e,t,n){"use strict";var r=n(2).Router,i=n(1).middlewares,o=n(0),s=n(3),a=n(13);e.exports=function(){var e=r(),t=i.validateHookToken(o("AUTH0_DOMAIN"),o("WT_URL"),o("EXTENSION_SECRET"));return e.use("/on-uninstall",t("/.extensions/on-uninstall")),e.use("/on-install",t("/.extensions/on-install")),e.use(i.managementApiClient({domain:o("AUTH0_DOMAIN"),clientId:o("AUTH0_CLIENT_ID"),clientSecret:o("AUTH0_CLIENT_SECRET")})),e.post("/on-install",function(e,t){var n=e.auth0,r=o("API_AUDIENCE"),i=o("OWNER"),s=[n.clients.create({name:o("WEBSITE_CLIENT_NAME"),app_type:"regular_web"}),n.clients.create({name:o("EXTEND_DEPLOYMENT_CLIENT"),app_type:"non_interactive"}),n.resourceServers.create({name:o("API_NAME"),identifier:r}),n.rules.create({name:"Extend Authorization",order:1,enabled:!0,script:["function (user, context, callback) {",'  var crypto = require("crypto");',"",'  if (context.clientName !== "'+o("EXTEND_DEPLOYMENT_CLIENT")+'" && context.clientName !== "'+o("WEBSITE_CLIENT_NAME")+'") {',"    return callback(null, user, context);","  }","","  var audience = (context.request && context.request.query && context.request.query.audience);","",'  if (audience !== "'+r+'")',"    return callback(null, user, context);","","  if (!user.email || !user.email_verified) {",'    return callback(new UnauthorizedError("User must have verified e-mail address to log in."));',"  }","",'  if (user.email === "'+i+'") {','    var hash = crypto.createHash("md5").update(user.nickname);','    var container = hash.digest("hex");','    context.accessToken.scope = ["openid", "profile", "wt:owner:" + container];',"  }","","  return callback(null, user, context);","}"].join("\n")})];a.all(s).then(function(){t.sendStatus(204)}).catch(function(e){console.log(e),t.sendStatus(500)})}),e.delete("/on-uninstall",function(e,t){var n=o("AUTH0_CLIENT_ID");e.auth0.clients.delete({client_id:n}).then(function(){s.debug("Deleted client "+n),t.sendStatus(204)}).catch(function(e){s.debug("Error deleting client: "+o("AUTH0_CLIENT_ID")),s.error(e),t.sendStatus(204)})}),e}},function(e,t,n){"use strict";(function(t){var r=(n(16),n(15)),i=(n(5),n(1).urlHelpers),o=n(0);e.exports=function(){var e='\n  <!DOCTYPE html>\n  <html lang="en">\n  <head>\n    <title>Extend Security</title>\n    <meta charset="UTF-8" />\n    <meta http-equiv="X-UA-Compatible" content="IE=Edge" />\n    <meta name="viewport" content="width=device-width, initial-scale=1.0" />\n    <link rel="shortcut icon" href="https://cdn.auth0.com/styleguide/4.6.13/lib/logos/img/favicon.png">\n    <meta name="viewport" content="width=device-width, initial-scale=1">\n    <link rel="stylesheet" type="text/css" href="https://cdn.auth0.com/styles/zocial.min.css" />\n    <link rel="stylesheet" type="text/css" href="https://cdn.auth0.com/manage/v0.3.1672/css/index.min.css" />\n    <link rel="stylesheet" type="text/css" href="https://cdn.auth0.com/styleguide/4.6.13/index.min.css" />\n  </head>\n  <body>\n    Coming soon\n  </body>\n  </html>\n  ';return function(t,n,s){if(0===t.url.indexOf("/api"))return s();var a={AUTH0_DOMAIN:o("AUTH0_DOMAIN"),AUTH0_CLIENT_ID:o("EXTENSION_CLIENT_ID"),AUTH0_MANAGE_URL:o("AUTH0_MANAGE_URL")||"https://manage.auth0.com",BASE_URL:i.getBaseUrl(t),BASE_PATH:i.getBasePath(t)};return n.send(r.render(e,{config:a,assets:{version:"0.8.0"}}))}}}).call(t,"/")},function(e,t,n){"use strict";var r=(n(17),n(2).Router),i=n(1).middlewares,o=n(0),s=n(8);e.exports=function(e){var t=r();i.authenticateAdmins({credentialsRequired:!0,secret:o("EXTENSION_SECRET"),audience:"urn:extend-security-extension",baseUrl:o("PUBLIC_WT_URL")||o("WT_URL"),onLoginSuccess:function(e,t,n){return n()}});return t.get("/",s()),t}},function(e,t,n){"use strict";var r=n(2),i=n(12);e.exports=function(){var e=r.Router();return e.get("/",function(e,t){t.status(200).send(i)}),e}},function(e,t,n){"use strict";var r=n(1),i=n(6),o=n(0),s=n(3),a=r.createServer(function(e,t){return s.info("Starting Extend Security Extension - Version:","0.8.0"),i(e,t)});e.exports=function(e,t,n){o.setValue("PUBLIC_WT_URL",r.urlHelpers.getWebtaskUrl(t)),a(e,t,n)}},function(e,t){e.exports={title:"Extend Security",name:"extend-security",version:"0.8.0",author:"extend",description:"This extension helps to create the required artifacts at Auth0 for enabling Extend security model v2",type:"application",logoUrl:"https://goextend.io/images/rounded-logo.png",initialUrlPath:"/login",category:"Extend",repository:"https://github.com/goextend/extend-security-extension",keywords:["auth0","extension","extend","security"],auth0:{createClient:!0,onUninstallPath:"/.extensions/on-uninstall",onInstallPath:"/.extensions/on-install",scopes:"read:resource_servers create:resource_servers read:clients create:clients read:rules create:rules"},secrets:{OWNER:{description:"The email of the owner of the Extend deployment. It can modified on the authorization rule afterwards.",required:!0,example:"john.doe@acme.com"},API_NAME:{description:"The name for the API",required:!0,default:"Extend API"},API_AUDIENCE:{description:"Your Extend deployment URL",required:!0,example:"https://acme.auth0-extend.com"},WEBSITE_CLIENT_NAME:{description:"A client for identifying your website",required:!0,default:"Website",type:"text"},EXTEND_DEPLOYMENT_CLIENT:{description:"A client for identifying the Extend deployment",required:!0,type:"text",default:"Extend Deployment"}}}},function(e,t){e.exports=require("bluebird@3.4.6")},function(e,t){e.exports=require("body-parser@1.12.4")},function(e,t){e.exports=require("ejs@2.3.1")},function(e,t){e.exports=require("fs")},function(e,t){e.exports=require("lodash@3.10.1")},function(e,t){e.exports=require("morgan@1.5.3")},function(e,t){e.exports=require("url")},function(e,t){e.exports=require("winston@1.0.0")}]);