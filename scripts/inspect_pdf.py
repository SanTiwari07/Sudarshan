import sys
import subprocess
from pathlib import Path

def install_and_import():
    try:
        import pdfplumber
    except ImportError:
        print("Installing pdfplumber...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pdfplumber"])
        import pdfplumber
    return pdfplumber

pdfplumber = install_and_import()

pdf_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("artifacts_qa/sudarshan_investigation_report_qa.pdf")

def inspect_pdf():
    print(f"Inspecting {pdf_path.name} for visual defects...\n")
    
    with pdfplumber.open(pdf_path) as pdf:
        for p0, page in enumerate(pdf.pages):
            page_num = p0 + 1
            words = page.extract_words()
            
            print(f"=== Analyzing Page {page_num} ===")
            if not words:
                print("  [DEFECT: Blank Page] No text found on this page.")
                continue

            # 1. Bounding Box Overlaps
            overlaps = []
            for i in range(len(words)):
                for j in range(i+1, len(words)):
                    w1 = words[i]
                    w2 = words[j]
                    
                    # Intersect check:
                    if not (w1['x1'] <= w2['x0'] or w1['x0'] >= w2['x1'] or w1['bottom'] <= w2['top'] or w1['top'] >= w2['bottom']):
                        # Thresholding slightly to avoid false positives on tight kerning
                        dx = min(w1['x1'], w2['x1']) - max(w1['x0'], w2['x0'])
                        dy = min(w1['bottom'], w2['bottom']) - max(w1['top'], w2['top'])
                        if dx > 1.0 and dy > 1.0:
                            overlaps.append((w1, w2))

            if overlaps:
                print(f"  [DEFECT: Overlap] Found {len(overlaps)} text overlaps.")
                for w1, w2 in overlaps[:3]:
                    print(f"    - '{w1['text']}' and '{w2['text']}' intersect at Y:{w1['top']:.1f}")
                if len(overlaps) > 3:
                    print(f"    ... and {len(overlaps)-3} more.")

            # 2. Giant Blank Spaces & Section Spacing
            words_sorted_y = sorted(words, key=lambda w: w['top'])
            max_gap = 0
            if words_sorted_y:
                last_bottom = words_sorted_y[0]['bottom']
                for w in words_sorted_y[1:]:
                    gap = w['top'] - last_bottom
                    if gap > max_gap:
                        max_gap = gap
                    if gap > 200: # Threshold for a "giant" blank space
                        print(f"  [DEFECT: Giant Blank Space] Gap of {gap:.1f} pts detected starting at Y={last_bottom:.1f}")
                    last_bottom = max(last_bottom, w['bottom'])

            # 3. Margins Consistency
            left_margins = [w['x0'] for w in words]
            right_margins = [w['x1'] for w in words]
            min_left = min(left_margins)
            max_right = max(right_margins)
            
            if min_left < 30:
                print(f"  [DEFECT: Margin] Content bleeds into left margin: X={min_left:.1f}")
            if max_right > page.width - 30:
                print(f"  [DEFECT: Margin] Content bleeds into right margin: X={max_right:.1f} (Page Width: {page.width:.1f})")

            # 4. Footer Collisions & Bad Page Breaks
            footer_y = page.height - 50
            footer_elements = [w for w in words if w['top'] > footer_y]
            
            # Filter standard footer artifacts if they exist
            footer_texts = " ".join([w['text'] for w in footer_elements])
            if footer_elements and not ("Page" in footer_texts or "Sudarshan" in footer_texts):
                print(f"  [DEFECT: Footer Collision] Non-footer content in footer area (Y > {footer_y}): {footer_texts[:50]}...")

            bottom_elements = [w for w in words if w['bottom'] > page.height - 10]
            if bottom_elements:
                 print(f"  [DEFECT: Bad Page Break] Text cut off at absolute bottom of page: {bottom_elements[0]['text']}")

            # 5. Tables & Font Weights (Heuristic checks based on lines)
            lines = page.lines
            rects = page.rects
            
            # Very basic check for rect overlapping text (broken tables)
            table_overlaps = 0
            for r in rects:
                r_top, r_bottom, r_x0, r_x1 = r['top'], r['bottom'], r['x0'], r['x1']
                for w in words:
                    # check intersection with rect bounds (often indicates text bleeding out of table cell)
                    # We look for text that crosses the table boundary
                    # if w's center is near the edge of a rect
                    wc_x = (w['x0'] + w['x1']) / 2
                    wc_y = (w['top'] + w['bottom']) / 2
                    
                    if abs(wc_y - r_top) < 2 or abs(wc_y - r_bottom) < 2 or abs(wc_x - r_x0) < 2 or abs(wc_x - r_x1) < 2:
                        table_overlaps += 1
                        
            if table_overlaps > 5:
                 print(f"  [DEFECT: Broken Table/Box] High number of elements overlapping with drawn rectangles ({table_overlaps}).")


if __name__ == '__main__':
    inspect_pdf()
