const fs = require('fs');
const path = require('path');

const srcDir = path.join(__dirname, 'src');

function walkDir(dir, callback) {
  fs.readdirSync(dir).forEach(f => {
    const dirPath = path.join(dir, f);
    const isDirectory = fs.statSync(dirPath).isDirectory();
    isDirectory ? walkDir(dirPath, callback) : callback(path.join(dir, f));
  });
}

walkDir(srcDir, function(filePath) {
  if (filepath.endsWith('.tsx') || filepath.endsWith('.ts')) {
    const originalContent = fs.readFileSync(filepath, 'utf8');
    let newContent = originalContent;
    
    // Convert all bg-slate-50 variants (opacities) to bg-surface-secondary
    newContent = newContent.replace(/bg-slate-50\/(50|40|60|80|30)/g, 'bg-surface-secondary');
    
    // Replace bg-slate-50 to bg-surface-secondary
    newContent = newContent.replace(/\bbg-slate-50\b/g, 'bg-surface-secondary');
    
    // Replace bg-slate-100 to bg-surface-secondary
    newContent = newContent.replace(/\bbg-slate-100\b/g, 'bg-surface-secondary');

    // Replace bg-gray-50 and bg-gray-100 to bg-surface-secondary
    newContent = newContent.replace(/\bbg-gray-(50|100)\b/g, 'bg-surface-secondary');

    // For cards, bg-white -> bg-surface-card
    newContent = newContent.replace(/\bbg-white\b/g, 'bg-surface-card');

    if (newContent !== originalContent) {
      fs.writeFileSync(filepath, newContent, 'utf8');
      console.log('Updated', filepath);
    }
  }
});
