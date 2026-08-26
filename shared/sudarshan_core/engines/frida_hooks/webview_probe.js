import JavaBridgeModule from 'frida-java-bridge';
var Java = (function () { var m = JavaBridgeModule; return (m && m.default) ? m.default : m; })();

Java.perform(function () {
  var views = [], seen = {};
  function remember(wv) {
    try {
      var h = wv.hashCode();
      send({ msg: 'hashCode_ok', h: h });
      if (seen[h]) return;
      seen[h] = 1;
      views.push(Java.retain(wv));
      send({ msg: 'retained', total: views.length });
    } catch (e) { send({ msg: 'remember_FAILED', error: e.message }); }
  }
  try {
    Java.choose('android.webkit.WebView', {
      onMatch: function (i) { remember(i); },
      onComplete: function () { send({ msg: 'sweep_done', held: views.length }); }
    });
  } catch (e) { send({ msg: 'choose_error', error: e.message }); }

  var CB = null;
  try {
    var VC = Java.use('android.webkit.ValueCallback');
    CB = Java.registerClass({
      name: 'com.sudarshan.probe.Cb2', implements: [VC],
      methods: { onReceiveValue: function (v) { send({ msg: 'DRAIN', value: v ? v.toString() : null }); } }
    });
    send({ msg: 'registerClass_ok' });
  } catch (e) { send({ msg: 'registerClass_FAILED', error: e.message }); }

  var SHIM = '(function(){if(window.__p){return window.__pd?window.__pd():"[]";}window.__p=1;window.__pq=[];'
    + 'function push(k,m,u,b){try{window.__pq.push({k:k,m:String(m||"GET"),u:String(u||""),b:b?String(b).substring(0,200):""});}catch(e){}}'
    + 'try{var of=window.fetch;if(of){window.fetch=function(i,o){try{push("fetch",(o&&o.method)||"GET",(i&&i.url)?i.url:i,(o&&o.body)||null);}catch(e){}return of.apply(this,arguments);};}}catch(e){}'
    + 'try{var xo=XMLHttpRequest.prototype.open,xs=XMLHttpRequest.prototype.send;'
    + 'XMLHttpRequest.prototype.open=function(m,u){this.__m=m;this.__u=u;return xo.apply(this,arguments);};'
    + 'XMLHttpRequest.prototype.send=function(b){try{push("xhr",this.__m,this.__u,b);}catch(e){}return xs.apply(this,arguments);};}catch(e){}'
    + 'window.__pd=function(){try{return JSON.stringify(window.__pq.splice(0));}catch(e){return "[]";}};'
    + 'return "INSTALLED";})()';

  var n = 0;
  setInterval(function () {
    n++;
    if (!views.length) { send({ msg: 'pump_skipped_no_views', tick: n }); return; }
    if (!CB) { send({ msg: 'pump_skipped_no_cb', tick: n }); return; }
    Java.scheduleOnMainThread(function () {
      for (var i = 0; i < views.length; i++) {
        try { views[i].evaluateJavascript(SHIM, CB.$new()); send({ msg: 'eval_dispatched', tick: n }); }
        catch (e) { send({ msg: 'eval_FAILED', error: e.message }); }
      }
    });
  }, 2500);
});
