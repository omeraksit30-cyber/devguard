import { route, start } from "./router.js";
import { compare } from "./views/compare.js";
import { dashboard } from "./views/dashboard.js";
import { evaluation } from "./views/evaluation.js";
import { history } from "./views/history.js";
import { newScan } from "./views/newscan.js";
import { findingPage, scanDetail } from "./views/scan.js";

route(/^\/$/, dashboard, "dashboard");
route(/^\/scans\/new$/, newScan, "new");
route(/^\/scans\/(\d+)$/, scanDetail, "history");
route(/^\/findings\/(\d+)$/, findingPage, "history");
route(/^\/compare$/, compare, "compare");
route(/^\/history$/, history, "history");
route(/^\/evaluation$/, evaluation, "evaluation");
start();
