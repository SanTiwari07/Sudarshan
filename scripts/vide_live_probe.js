import Java from "frida-java-bridge";

Java.perform(function () {
  var WebView = Java.use("android.webkit.WebView");
  WebView.loadData.overload(
    "java.lang.String",
    "java.lang.String",
    "java.lang.String"
  ).implementation = function (data, mime, enc) {
    var preview = data ? data.substring(0, 500) : "";
    send({
      type: "event",
      payload: {
        category: "network",
        data: { hook: "WebView.loadData", html_preview: preview },
      },
    });
    return this.loadData(data, mime, enc);
  };

  Java.scheduleOnMainThread(function () {
    try {
      var AT = Java.use("android.app.ActivityThread");
      var act = AT.currentActivityThread().getCurrentActivity();
      var ctx = act ? act : AT.currentApplication().getApplicationContext();
      var html =
        "<html><body>\nMobile Banking\nUsername\nPassword\nOTP\nLogin\nContinue\n" +
        "Enter UPI PIN\nMPIN\nYONO\nUser ID\nForgot Password\nState Bank of India\n" +
        "Net Banking\nAccount Balance\n</body></html>";
      var wv = WebView.$new(ctx);
      wv.loadData(html, "text/html", "UTF-8");
      send({ type: "vide_live", msg: "loadData_triggered" });
    } catch (e) {
      send({ type: "vide_live", msg: "error", error: String(e) });
    }
  });
});
