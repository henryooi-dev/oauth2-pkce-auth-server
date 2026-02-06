import { createApp } from "./createApp.js";

const app = await createApp();

app.listen(5000);
console.log("Resource server listening on http://localhost:5000");
