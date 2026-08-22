/*
    SUDARSHAN - APK container / dropper packaging rules
    ===================================================

    These run against the APK on disk (YARAScanner.scan_file). What YARA can
    actually see there is narrower than it looks, and the rules below are built
    around that limit:

      * ZIP entry names ARE stored in plaintext, in both the local headers and
        the central directory. Verified on the corpus.
      * Entry CONTENT is deflated, so payload bytes are not matchable.
      * AndroidManifest.xml is binary, and permission strings are NOT present as
        plaintext. Permission analysis belongs to androguard, which already does
        it - not here.

    So these rules match on packaging: the names, locations and shapes of the
    files a dropper ships. That is deliberately a weaker signal than the runtime
    rules in banking_trojan_behaviour.yar, and the severities say so.

    Scope note, stated plainly: the corpus holds ONE sample per family, so a
    rule keyed to a specific asset directory would encode that one build rather
    than the family. Family attribution is left to threat intelligence, which
    already supplies it. The rules here describe dropper *shape*, which is what
    a single sample can honestly support.
*/

import "math"

rule apk_payload_disguised_by_extension
{
    meta:
        author      = "Sudarshan"
        description = "Asset shipped under a media or document extension inside a directory of otherwise unrelated files - observed carrying encrypted second stages"
        severity    = "MEDIUM"
        threat      = "concealed_payload_packaging"
        surface     = "apk_container"
        note        = "Corroborates the static analyser's has_concealed_payload; it does not replace it."

    strings:
        // Observed in the corpus: assets/Monoco/Zw6IGlco.ppt (FluBot),
        // assets/lmafo/mimlwef.qiv (Teabot), assets/ilyyp.mp3 (Anubis).
        // The shape is a nested assets directory holding a single randomly
        // named file whose extension does not describe its content.
        $rand_media = /assets\/[A-Za-z0-9_]{3,12}\/[A-Za-z0-9]{6,16}\.(ppt|mp3|avi|qiv|dat|bin|mp4|wav|doc)/ ascii
        $rand_root  = /assets\/[a-z]{4,8}\.(mp3|avi|ppt|qiv)/ ascii

    condition:
        // uint32(0) == 0x04034b50 is the ZIP local file header - i.e. this is
        // an APK/ZIP and not a loose file that happens to contain the pattern.
        uint32(0) == 0x04034b50 and any of them
}

/*
    A multi-DEX-plus-dense-assets rule was drafted here and removed. It fired on
    0 of 17 samples: the one corpus member with the shape it described (Hook,
    6 DEX files) also ships the androidx markers the rule required to be absent.
    A rule that never fires has not been validated by the corpus - it has only
    avoided being tested by it - so it was dropped rather than kept as a
    plausible-looking placeholder.
*/

rule apk_no_signature_block
{
    meta:
        author      = "Sudarshan"
        description = "APK carrying no v1 signature files - repackaged or stripped, and unusual for anything distributed through a store"
        severity    = "LOW"
        threat      = "repackaging_indicator"
        surface     = "apk_container"

    strings:
        $mf   = "META-INF/MANIFEST.MF" ascii
        $rsa  = ".RSA" ascii
        $dsa  = ".DSA" ascii
        $ec   = ".EC" ascii

    condition:
        uint32(0) == 0x04034b50 and not $mf and not ($rsa or $dsa or $ec)
}
