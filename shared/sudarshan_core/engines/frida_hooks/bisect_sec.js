
    import JavaBridgeModule from 'frida-java-bridge';
    var Java = JavaBridgeModule.default || JavaBridgeModule;
    Java.perform(function() {
        send({type:'diag', msg:'start_Section X - Anti-Analysis'});
        
    try {
        var Process = Java.use('android.os.Process');
        send({type:'diag', msg:'Process_use_ok'});
        var Runtime = Java.use('java.lang.Runtime');
        send({type:'diag', msg:'Runtime_use_ok'});
    } catch(e) { send({type:'error', description: e.message}); }
    
        send({type:'diag', msg:'end_Section X - Anti-Analysis'});
    });
    