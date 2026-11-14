const express = require("express");
const config = require("./config");

const app = express();
app.get("/healthz", (_req, res) => res.json({ status: "ok" }));
app.listen(config.port);
