import { createApp } from "./createApp.js";

const app = await createApp();

app.listen(3000);
console.log("Authorization server listening on http://localhost:3000");
