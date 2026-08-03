import JavaBridgeModule from 'frida-java-bridge';

var Java = (function () {
  try {
    var mod = JavaBridgeModule;
    return (mod && mod.default) ? mod.default : mod;
  } catch (e) {
    return null;
  }
})();

send({ type: 'probe', msg: 'start', java_available: (Java ? Java.available : false) });

if (Java && Java.available) {
  try {
    Java.perform(function () {
      send({ type: 'probe', msg: 'in_java_perform' });
      var S = Java.use("java.lang.String");
      send({ type: 'probe', msg: 'string_class_ok' });
      var T = Java.use("java.lang.Thread");
      send({ type: 'probe', msg: 'thread_class_ok', current: String(T.currentThread()) });
    });
  } catch (e) {
    send({ type: 'probe', msg: 'java_perform_error', error: e.stack || String(e) });
  }
} else {
  send({ type: 'probe', msg: 'java_not_available' });
}
