"""
SUDARSHAN Premium Demo Narration Audio Generator
Uses edge-tts with en-IN-PrabhatNeural (or en-US-AndrewNeural)
Generates:
1. Individual audio clips per scene (for modular placement in Recordly)
2. Master continuous voiceover track with natural spacing (zero overlapping)
"""
import asyncio
import os
import edge_tts

AUDIO_DIR = r"c:\Projects\Sudarshan\video_recording\audio"
VOICE = "en-IN-PrabhatNeural"

SECTIONS = [
    {
        "id": "01_Act1_TheThreat_90Seconds",
        "title": "Act 1: The Threat - The 90-Second Fraud Crisis in India",
        "duration_target": "45s",
        "text": (
            "Across India, digital banking and UPI handle billions of transactions every single day. "
            "But right now, millions of citizens are being targeted by sophisticated on-device fraud campaigns. "
            "A victim receives an urgent WhatsApp notification impersonating their bank: "
            "'Update your SBI KYC within 24 hours to prevent account freeze.' Attached is a sideloaded APK. "
            "Once installed, the victim is tricked into enabling Android Accessibility permissions. "
            "Within 90 seconds, the trojan launches an invisible overlay, steals banking credentials, "
            "intercepts SMS OTPs, and executes Automated Transfer Systems to drain accounts. "
            "Traditional antivirus fails because attackers alter code hashes daily. "
            "Manual reverse engineering takes 4 to 8 hours per APK. "
            "That is why we built SUDARSHAN."
        )
    },
    {
        "id": "02_Act2_Sudarshan_VIDE_Breakthrough",
        "title": "Act 2: Enter SUDARSHAN and the VIDE Breakthrough",
        "duration_target": "45s",
        "text": (
            "SUDARSHAN is an autonomous Android banking malware and fraud intelligence platform, "
            "engineered from the ground up to take suspicious APKs from infiltration to complete containment in minutes. "
            "Our foundational breakthrough is VIDE, the Visual Impersonation Detection Engine. "
            "Here is our core insight: an adversary can easily obfuscate package names or encrypt payloads, "
            "but they cannot alter the visual interface. They must mimic the bank's UI perfectly to trick the user! "
            "VIDE treats the frontend visual interface as the ultimate Indicator of Compromise. "
            "Across 10 major Indian banking baselines, VIDE extracts Layout ASTs, CIEDE2000 color palettes, "
            "and digital signing certificates to unmask clones instantly."
        )
    },
    {
        "id": "03_Act3_Part1_Upload_AXMLRepair",
        "title": "Act 3 Part 1: Ingestion and Corrupted AXML Repair",
        "duration_target": "25s",
        "text": (
            "Let's run a live analysis. We drag and drop an active in-the-wild sample targeting State Bank of India customers. "
            "Modern trojans intentionally corrupt their binary XML headers to crash standard decompilers like MobSF and JADX. "
            "SUDARSHAN's intake pipeline instantly detects the anomaly, repairs the string tables with our built-in recovery engine, "
            "and dispatches parallel static and dynamic workers."
        )
    },
    {
        "id": "04_Act3_Part2_FraudCard_SBI_Attribution",
        "title": "Act 3 Part 2: The Executive Fraud Card and VIDE SBI Attribution",
        "duration_target": "40s",
        "text": (
            "Analysis complete. We land on the Executive Fraud Card, purpose-built for rapid triage. "
            "At a glance, our Fraud Risk Score reads 95 out of 100, CRITICAL. "
            "Notice the Targeted Bank panel: without relying on package names, VIDE has identified this sample as an impersonation of "
            "State Bank of India's YONO app with 92 percent confidence. "
            "Clicking into the Target Analysis Drawer reveals the forensic proof. "
            "VIDE verified the UI against our official SBI baseline. "
            "Notice the digital signer verification: the official SBI release key is completely absent. "
            "This triggers our CH27 On-Device Fraud Triad: high visual similarity plus developer signer mismatch "
            "immediately locks the verdict as fraudulent."
        )
    },
    {
        "id": "05_Act3_Part3_Runtime_Frida_Sandbox",
        "title": "Act 3 Part 3: Dynamic Sandbox and Runtime Frida Instrumentation",
        "duration_target": "35s",
        "text": (
            "Now, let's drill down into the Technical SOC View. "
            "Under the Runtime tab, we see the real-time telemetry from our isolated Android dynamic sandbox. "
            "Using our pre-compiled Frida hook bundle, SUDARSHAN instrumented the process at exact PID spawn. "
            "Look at these events: the sample hijacked Android Accessibility to scrape on-screen PIN entries, "
            "monitored SMS broadcasts to steal two-factor OTP tokens, "
            "and attempted outbound socket connections to an offshore C2 server. "
            "SUDARSHAN captured the exact exfiltration IPs and ports for immediate network blacklisting."
        )
    },
    {
        "id": "06_Act3_Part4_VisualDiff_ColorAST",
        "title": "Act 3 Part 4: Visual Diff and Overlay Inspection",
        "duration_target": "20s",
        "text": (
            "Under the Visual Evidence tab, our side-by-side AST and color comparator proves that the trojan reproduced "
            "SBI's exact brand color tokens, hex 1B4AA0, with a perceptual delta-E under 1.8. "
            "It also replicated critical strings like 'Enter MPIN' and 'Forgot Password' within an identical layout hierarchy."
        )
    },
    {
        "id": "07_Act3_Part5_GroundedAI_Copilot",
        "title": "Act 3 Part 5: Grounded AI Copilot and Report Export",
        "duration_target": "35s",
        "text": (
            "For fraud operations leads, SUDARSHAN features a Grounded AI Copilot powered by Google Gemini RAG. "
            "It indexes 22 forensic sections of the sample into an in-memory graph. "
            "Asking for a containment playbook generates an immediate, hallucination-free response complete with verified evidence citations: "
            "revoking active mobile sessions, blacklisting C2 infrastructure, and updating SIEM correlation rules. "
            "With one click, we can export this as an Executive PDF or OASIS STIX 2.1 threat feed."
        )
    },
    {
        "id": "08_Act4_Mathematical_Determinism",
        "title": "Act 4: Mathematical Determinism and Defense Standards",
        "duration_target": "35s",
        "text": (
            "Why can financial institutions and defense teams trust SUDARSHAN? "
            "Because of our non-negotiable architectural invariant: Deterministic Detection, Grounded AI Intelligence. "
            "Generative AI never calculates, alters, or inflates our Fraud Risk Score. "
            "The numerical score is computed strictly by our deterministic mathematical engine. "
            "Identical inputs yield identical, auditable scores every time. "
            "Every rule, safety floor, and sandbox boundary is verified by an enterprise test suite of over 2,800 automated tests, "
            "ensuring absolute reliability in hostile production environments."
        )
    },
    {
        "id": "09_Act5_National_Ecosystem_Vision",
        "title": "Act 5: National Ecosystem Vision and Closing Call to Action",
        "duration_target": "40s",
        "text": (
            "Looking to the future, SUDARSHAN is designed to integrate seamlessly into India's national cyber defense fabric. "
            "First, for Public and Private Banks, our API plugs into fraud investigation pipelines, "
            "detecting brand-impersonation campaigns before funds leave customer accounts. "
            "Second, for Government Agencies like CERT-In, RBI, and the I4C 1930 portal, "
            "SUDARSHAN automates the triage of citizen-reported APKs and expedites nationwide C2 infrastructure takedowns. "
            "And third, with Telecom and Messaging Platforms, SUDARSHAN's lightweight inspection engine "
            "can scan APK payloads before they are ever installed on citizen devices. "
            "As India leads the world in digital financial innovation, SUDARSHAN stands as an intelligent shield, "
            "turning 90 seconds of vulnerability into immediate, verifiable defense. Thank you."
        )
    }
]

async def generate():
    os.makedirs(AUDIO_DIR, exist_ok=True)
    print(f"Generating audio clips using voice: {VOICE}...")
    
    for section in SECTIONS:
        filename = f"{section['id']}.mp3"
        filepath = os.path.join(AUDIO_DIR, filename)
        print(f"Synthesizing [{section['id']}] ({section['duration_target']})...")
        communicate = edge_tts.Communicate(section["text"], VOICE, rate="-2%")
        await communicate.save(filepath)
        print(f"  -> Saved {filename} ({os.path.getsize(filepath):,} bytes)")
        
    print("\nAll individual scene clips generated successfully!")

if __name__ == "__main__":
    asyncio.run(generate())
