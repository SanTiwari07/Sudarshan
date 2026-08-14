/*
 * time_warp.js - in-process clock offset for dormancy defeat.
 *
 * Moving the device wall clock with `adb shell date` gets you most of the way,
 * but not all of it:
 *
 *   - SystemClock.elapsedRealtime() and uptimeMillis() are monotonic since
 *     boot. They do not move when the wall clock does, and a sample that
 *     measures a delay with them is unaffected by any amount of `date`.
 *   - A sample that captured System.currentTimeMillis() at install time and
 *     compares it against "now" will see the jump - but one that holds a
 *     Handler.postDelayed or a ScheduledExecutorService will not.
 *   - Setting the system clock is a device-wide, observable change. A sample
 *     that samples the clock twice a second sees it lurch, which is itself a
 *     sandbox tell.
 *
 * Hooking the accessors instead applies the offset only to the process under
 * analysis, keeps the rest of the device consistent, and moves the monotonic
 * clocks too.
 *
 * RPC:
 *   setTimeOffset(offsetMs)   - absolute offset applied to every clock read
 *   advanceHours(hours)       - additive convenience wrapper
 *   getTimeOffset()           - current offset in ms
 *   reset()                   - back to real time
 *
 * Portability: every hook is attempted independently inside its own try block,
 * because the exact overload set of Date and Calendar varies across Android 7
 * through 15+. A missing class must degrade to "that one clock is unhooked",
 * never to "the script failed to load".
 */

'use strict';

var timeOffsetMs = 0;
var hookState = {
    installed: [],
    skipped: [],
};

function log(message) {
    try {
        send({ hook: 'time_warp', type: 'info', message: message });
    } catch (e) {
        /* console-only fallback; send() is unavailable outside a session */
    }
}

function markInstalled(name) {
    hookState.installed.push(name);
}

function markSkipped(name, reason) {
    hookState.skipped.push(name + ': ' + reason);
}

function installHooks() {
    // java.lang.System.currentTimeMillis - the wall clock nearly every
    // "has enough time passed" check reads.
    try {
        var System = Java.use('java.lang.System');
        // `real` is a Java long wrapper under Frida's Java bridge, so the
        // offset is applied with .add() when that is available and with plain
        // arithmetic when the bridge has already marshalled it to a Number.
        System.currentTimeMillis.implementation = function () {
            var real = this.currentTimeMillis();
            return real.add ? real.add(timeOffsetMs) : real + timeOffsetMs;
        };
        markInstalled('System.currentTimeMillis');
    } catch (e) {
        markSkipped('System.currentTimeMillis', '' + e);
    }

    // SystemClock - the monotonic clocks. These are the ones `adb shell date`
    // cannot touch, which is the whole reason this script exists.
    try {
        var SystemClock = Java.use('android.os.SystemClock');

        SystemClock.elapsedRealtime.implementation = function () {
            var real = this.elapsedRealtime();
            return real.add ? real.add(timeOffsetMs) : real + timeOffsetMs;
        };
        markInstalled('SystemClock.elapsedRealtime');

        SystemClock.uptimeMillis.implementation = function () {
            var real = this.uptimeMillis();
            return real.add ? real.add(timeOffsetMs) : real + timeOffsetMs;
        };
        markInstalled('SystemClock.uptimeMillis');

        try {
            SystemClock.elapsedRealtimeNanos.implementation = function () {
                var real = this.elapsedRealtimeNanos();
                var deltaNanos = timeOffsetMs * 1000000;
                return real.add ? real.add(deltaNanos) : real + deltaNanos;
            };
            markInstalled('SystemClock.elapsedRealtimeNanos');
        } catch (inner) {
            markSkipped('SystemClock.elapsedRealtimeNanos', '' + inner);
        }
    } catch (e) {
        markSkipped('SystemClock', '' + e);
    }

    // java.util.Date - the no-arg constructor reads the clock. Overloads that
    // take an explicit timestamp must NOT be shifted: `new Date(someStoredMs)`
    // is the sample restating a value it already holds, and offsetting that
    // would corrupt its arithmetic rather than advance its timers.
    try {
        var DateClass = Java.use('java.util.Date');
        DateClass.$init.overload().implementation = function () {
            this.$init();
            this.setTime(this.getTime().add
                ? this.getTime().add(timeOffsetMs)
                : this.getTime() + timeOffsetMs);
        };
        markInstalled('java.util.Date.<init>()');
    } catch (e) {
        markSkipped('java.util.Date', '' + e);
    }

    // Calendar.getInstance() - same reasoning as Date.
    try {
        var Calendar = Java.use('java.util.Calendar');
        Calendar.getInstance.overload().implementation = function () {
            var cal = this.getInstance();
            try {
                var millis = cal.getTimeInMillis();
                cal.setTimeInMillis(
                    millis.add ? millis.add(timeOffsetMs) : millis + timeOffsetMs
                );
            } catch (inner) {
                /* leave the calendar untouched rather than throwing into the app */
            }
            return cal;
        };
        markInstalled('Calendar.getInstance()');
    } catch (e) {
        markSkipped('java.util.Calendar', '' + e);
    }

    // java.time.Instant.now() - used by anything built against desugared or
    // API 26+ java.time. Absent on older images, hence its own guard.
    try {
        var Instant = Java.use('java.time.Instant');
        Instant.now.overload().implementation = function () {
            var real = this.now();
            return real.plusMillis(timeOffsetMs);
        };
        markInstalled('java.time.Instant.now()');
    } catch (e) {
        markSkipped('java.time.Instant', '' + e);
    }
}

function bootstrap() {
    if (!Java || !Java.available) {
        log('Java runtime unavailable - time warp hooks not installed');
        return;
    }
    Java.perform(function () {
        installHooks();
        log(
            'time_warp installed: ' +
                hookState.installed.length +
                ' hook(s), skipped ' +
                hookState.skipped.length
        );
    });
}

rpc.exports = {
    /** Set the absolute offset, in milliseconds, added to every clock read. */
    setTimeOffset: function (offsetMs) {
        var value = parseInt(offsetMs, 10);
        timeOffsetMs = isNaN(value) ? 0 : value;
        log('time offset set to ' + timeOffsetMs + ' ms');
        return timeOffsetMs;
    },

    /** Add `hours` to the current offset. */
    advanceHours: function (hours) {
        var delta = parseFloat(hours);
        if (isNaN(delta)) {
            return timeOffsetMs;
        }
        timeOffsetMs += Math.round(delta * 3600000);
        log('time offset advanced to ' + timeOffsetMs + ' ms');
        return timeOffsetMs;
    },

    getTimeOffset: function () {
        return timeOffsetMs;
    },

    /** Hook installation report - which clocks are actually under control. */
    status: function () {
        return {
            offset_ms: timeOffsetMs,
            installed: hookState.installed,
            skipped: hookState.skipped,
        };
    },

    reset: function () {
        timeOffsetMs = 0;
        log('time offset cleared');
        return 0;
    },
};

bootstrap();
