// Appended to banking_trojan.bundle.js for live VIDE verification (same script / Java bridge).
setTimeout(function () {
  Java.perform(function () {
    Java.scheduleOnMainThread(function () {
      try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var activity = ActivityThread.currentActivityThread().getCurrentActivity();
        if (!activity) {
          send({ type: 'vide_live', msg: 'no_current_activity' });
          return;
        }
        var WebView = Java.use('android.webkit.WebView');
        var html =
          '<html><body>\nMobile Banking\nUsername\nPassword\nOTP\nLogin\nContinue\n' +
          'Enter UPI PIN\nMPIN\nYONO\nUser ID\nForgot Password\nState Bank of India\n' +
          'Net Banking\nAccount Balance\n</body></html>';
        var wv = WebView.$new(activity);
        wv.loadData(html, 'text/html', 'UTF-8');
        send({ type: 'vide_live', msg: 'loadData_triggered' });
      } catch (e) {
        send({ type: 'vide_live', msg: 'error', error: String(e) });
      }
    });
  });
}, 15000);
