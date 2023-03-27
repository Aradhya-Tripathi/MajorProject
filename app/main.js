const { app, BrowserWindow, session } = require("electron");
const { spawn } = require("child_process");

let mainWindow;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function createWindow() {
  const server = spawn("python", ["./server/main.py"]);
  await sleep(5000);

  mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: false,
    },
  });
  mainWindow.loadURL("http://localhost:8080");
  mainWindow.on("closed", function () {
    server.kill();
    mainWindow = null;
  });

  session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
    details.requestHeaders["X-Custom-Header"] =
      "This will be replaced by an external API call most likey";
    callback({ cancel: false, requestHeaders: details.requestHeaders });
  });
}

app.on("ready", createWindow);

app.on("window-all-closed", function () {
  app.quit();
});

app.on("activate", function () {
  if (mainWindow === null) createWindow();
});
