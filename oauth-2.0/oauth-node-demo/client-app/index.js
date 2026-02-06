import { createApp } from "./createApp.js";

const app = await createApp();

app.listen(4000);
console.log("Client app listening on http://localhost:4000");
