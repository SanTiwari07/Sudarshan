
    import JavaBridgeModule from 'frida-java-bridge';
    var Java = JavaBridgeModule.default || JavaBridgeModule;
    Java.perform(function() {
        send({type:'diag', msg:'start_acc_test'});
        try {
            var AccessibilityService = Java.use('android.accessibilityservice.AccessibilityService');
            AccessibilityService.onAccessibilityEvent.implementation = function (event) {
                return this.onAccessibilityEvent(event);
            };
            send({type:'diag', msg:'acc_hook_installed'});
        } catch(e) { send({type:'diag', msg:'acc_err', err: e.message}); }
    });
    