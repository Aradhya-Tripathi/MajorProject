const { app, BrowserWindow, session } = require("electron");
const { spawn } = require("child_process");

let mainWindow;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function createWindow() {
  const secretKey = "Secret";
  const server = spawn("python", ["./server/main.py", secretKey]);
  await sleep(5000);

  mainWindow = new BrowserWindow({
    width: 1000,
    height: 700,
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
    details.requestHeaders["X-Custom-Header"] = secretKey;
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
