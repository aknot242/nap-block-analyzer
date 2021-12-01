const policyUtils = require("./policy-utils.js")
const Syslog = require("simple-syslog-server")
const http = require("http")
const WebSocket = require("ws")
const createError = require("http-errors")
const express = require("express")
const path = require("path")
const cookieParser = require("cookie-parser")
const logger = require("morgan")


// Create our syslog server with the given transport
const socktype = "TCP" // or "TCP" or "TLS"
const address = "" // Any
const syslogPort = 5144
const syslogServer = Syslog(socktype)

// State Information
let listening = false
let clients = []

const indexRouter = require("./routes/index")

const app = express()

const port = 6969
const server = http.createServer(app)
const wss = new WebSocket.Server({ server })

// view engine setup
app.set("views", path.join(__dirname, "views"))
app.set("view engine", "jade")

app.use(logger("dev"))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, "public")))

app.use("/", indexRouter)

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404))
})

// error handler;
app.use((err, req, res, next) => {
  // set locals, only providing error in development
  res.locals.message = err.message
  res.locals.error = req.app.get("env") === "development" ? err : {}

  // render the error page
  res.status(err.status || 500)
  res.render("error")
})

wss.on('connection', (ws) => {
  console.log("client connected to websocket server")
  ws.on('message', (message) => {
    switch (message) {
      case "clear":
        console.log("Clearing messages...")
        policyUtils.clearMessages()
        sendLog(policyUtils.sendMessages())
        break
      case "refresh":
        console.log("Refreshing messages...")
        sendLog(policyUtils.sendMessages())
        break
    }
  });
  sendLog(policyUtils.sendMessages())
})

server.listen(port, () => {
  console.log(`Server is listening on ${port}!`)
  policyUtils.loadPolicyResources()
})

syslogServer.on("msg", data => sendLog(policyUtils.parseNapMessage(data)))
  .on("invalid", err => {
    console.warn("Invalid message format received: %o\n", err)
  })
  .on("error", err => {
    console.warn("Client disconnected abruptly: %o\n", err)
  })
  .on("connection", s => {
    let addr = s.address().address
    console.log(`Client connected: ${addr}\n`)
    clients.push(s)
    s.on("end", () => {
      console.log(`Client disconnected: ${addr}\n`)
      let i = clients.indexOf(s)
      if (i !== -1) {
        clients.splice(i, 1)
      }
    })
  })
  .listen({ host: address, port: syslogPort })
  .then(() => {
    listening = true
    console.log(`Now listening on: ${address}:${port}`)
  })
  .catch(err => {
    if ((err.code == "EACCES") && (syslogPort < 1024)) {
      console.error("Cannot listen on ports below 1024 without root permissions. Select a higher port number: %o", err)
    }
    else { // Some other error so attempt to close server socket
      console.error(`Error listening to ${address}:${syslogPort} - %o`, err)
      try {
        if (listening)
          syslogServer.close()
      }
      catch (err) {
        console.warn(`Error trying to close server socket ${address}:${syslogPort} - %o`, err)
      }
    }
  })


const sendLog = (data) => {
  wss.clients.forEach(function each(client) {
    if (client !== WebSocket && client.readyState === WebSocket.OPEN) {
      client.send(data)
    }
  })
}

module.exports = app
