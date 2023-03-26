const { app, BrowserWindow, session } = require("electron");
const path = require("path");
const { PythonShell } = require("python-shell");

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: false,
    },
  });
  mainWindow.loadURL("http://localhost:8080");
  mainWindow.on("closed", function () {
    mainWindow = null;
  });

  // To run python script from electron app
  // Will probably be useful during packaging and
  // distribution.
  // const options = {
  //   mode: 'text',
  //   pythonPath: 'python',
  //   scriptPath: path.join(__dirname, 'dash_app'),
  // }
  // PythonShell.run('main.py', options, function (err, results) {
  //   if (err) throw err
  //   console.log('Python script finished.')
  // })
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
