# Phase 3 Storage Audit

| Artifact | Current Location | Size Characteristics | Lifecycle | Must Persist? | GCS? |
| -------- | ---------------- | -------------------- | --------- | ------------- | ---- |
| Original APK | `_UPLOADS_DIR` (`/app/uploads`) | 5MB - 150MB | Upload -> Analysis -> Kept for cache/re-analysis | Yes | Yes |
| Batch Upload APKs | `_UPLOADS_DIR` (`/app/uploads`) | 5MB - 150MB | Upload -> Analysis -> Kept | Yes | Yes |
| Discovery APK | `_UPLOADS_DIR` (`/app/uploads`) | 5MB - 150MB | Download -> Analysis -> Kept | Yes | Yes |
| APKTool Decompiled | `/tmp/sudarshan_apktool_*` | 10MB - 300MB | Created -> Parsed -> Discarded | No | No |
| JADX Decompiled | `/tmp/sudarshan_jadx_*` | 10MB - 300MB | Created -> Parsed -> Discarded | No | No |
| Repaired APK | `/tmp/apktool_build_*` | 5MB - 150MB | Created -> Aligned -> Signed -> Discarded/Replaced | No | No |
| Frida `evidence.json` | `sudarshan_artifacts/{id}/evidence.json` | 10KB - 5MB | Created -> Indexed -> Kept for UI | Yes | Yes |
| Screenshots | `sudarshan_artifacts/{id}/screenshots/` | 100KB - 2MB per img | Copied from device `/data/local/tmp` -> Kept for UI | Yes | Yes |
| HTML Report | Generated on the fly / cached | 1MB - 5MB | Memory / Download | Yes (if we want to cache) | Yes |
| PCAP / Network | `sudarshan_artifacts/{id}/network.pcap` | 1MB - 50MB | Captured -> Kept for Analyst | Yes | Yes |
| Frida Scripts/Output | `sudarshan_artifacts/{id}/*.json` | 1KB - 1MB | Written by frida -> Parsed -> Kept | Yes | Yes |
| Logs (logcat) | `sudarshan_artifacts/{id}/logcat.txt` | 1MB - 10MB | Written by frida sandbox -> Kept | Yes | Yes |
| Device Temporary | `/data/local/tmp/` on emulator | Variable | Generated -> Copied -> Deleted | No | No |
| IOC Exports | Generated on the fly | < 1MB | Memory / Download | No | No |

## Analysis
- **APKs**: Currently rely on `/app/uploads` being shared between backend and worker. This breaks in multi-node. They must be streamed to GCS on upload, and the resulting `object_key` passed to workers.
- **Artifacts (evidence, screenshots)**: Currently rely on `sudarshan_artifacts` being shared. Workers write here, backend reads from here to serve `evidence.json` and images. These must be uploaded to GCS at the end of the analysis job.
- **Decompiled Code**: Created in `/tmp` during analysis. Can remain in local scratch since it is only needed during the job.
- **Reports**: Can be generated and saved to GCS or generated on the fly. If kept for long-term retention, should be uploaded to GCS.

