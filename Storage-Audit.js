#!/usr/bin/env node

/**
 * ============================================================================
 * Storage-Audit.js - CLI Utility untuk Audit & Pembersihan Penyimpanan
 * ============================================================================
 * Sesuai Spesifikasi:
 * STG-01: Recursive Scan (Traversal mendalam, SHA-256 hash, ukuran byte)
 * STG-02: Duplicate Detection (Pengelompokan hash identik, deteksi 2+ file)
 * STG-03: Giant File Flagging (Ambang batas >= 2 MB / 2.048 KB)
 * STG-04: Terminal Report (Ringkasan stdout terstruktur, raksasa, duplikat, hemat ruang)
 * STG-05: Safe Cleanup Confirmation (Prompt interaktif Y/N, pertahankan 1 asli, hapus duplikat & .tmp)
 * STG-06: Zero-Dependency Portability (Hanya modul native: fs, path, crypto, readline)
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

// Konfigurasi Ambang Batas & Filter
const GIANT_FILE_THRESHOLD = 2 * 1024 * 1024; // 2 MB = 2.048 KB = 2.097.152 bytes
const SCRIPT_SELF_NAMES = new Set([
  'storage-audit.js',
  'storage_audit.js',
  'storage_audit.py'
]);
const EXCLUDED_DIRS = new Set([
  '.git',
  '.downloads_lab_backup',
  'node_modules',
  '.vscode',
  '.idea'
]);

// Deteksi Dukungan Warna Terminal
const isColorSupported = Boolean(
  process.stdout.isTTY &&
  !process.env.NO_COLOR &&
  process.env.TERM !== 'dumb'
);

const c = {
  reset: isColorSupported ? '\x1b[0m' : '',
  bold: isColorSupported ? '\x1b[1m' : '',
  dim: isColorSupported ? '\x1b[2m' : '',
  red: isColorSupported ? '\x1b[31m' : '',
  green: isColorSupported ? '\x1b[32m' : '',
  yellow: isColorSupported ? '\x1b[33m' : '',
  blue: isColorSupported ? '\x1b[34m' : '',
  magenta: isColorSupported ? '\x1b[35m' : '',
  cyan: isColorSupported ? '\x1b[36m' : '',
  white: isColorSupported ? '\x1b[37m' : '',
  gray: isColorSupported ? '\x1b[90m' : '',
  bgBlue: isColorSupported ? '\x1b[44m' : '',
  bgGreen: isColorSupported ? '\x1b[42m' : '',
  bgRed: isColorSupported ? '\x1b[41m' : ''
};

/**
 * Format ukuran byte menjadi representasi manusiawi (Bytes, KB, MB)
 */
function formatSizeMB(bytes) {
  const mb = bytes / (1024 * 1024);
  const kb = bytes / 1024;
  return `${mb.toFixed(2)} MB (${kb.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} KB)`;
}

function formatBytesCompact(bytes) {
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(2)} KB`;
  }
  return `${bytes} B`;
}

/**
 * Menghitung hash SHA-256 dari sebuah file secara efisien menggunakan streaming
 */
function computeSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', err => reject(err));
  });
}

/**
 * Menentukan skor keaslian file (semakin rendah skor, semakin besar kemungkinan file adalah file asli).
 * File dengan penanda salinan (Copy, Salinan, (1), _v2, _edit, _backup, dll.) diberi penalti skor.
 */
function scoreOriginalHeuristic(fileName) {
  const lower = fileName.toLowerCase();
  let penalty = 0;

  // File sementara/sampah diberi penalti paling tinggi
  if (lower.endsWith('.tmp')) penalty += 5000;

  // Penanda salinan umum
  if (/ - copy\./i.test(lower)) penalty += 1000;
  if (/ - salinan\./i.test(lower)) penalty += 1000;
  if (/\(\d+\)\./i.test(lower)) penalty += 800;
  if (/_copy\./i.test(lower)) penalty += 700;
  if (/_backup\./i.test(lower)) penalty += 600;
  if (/_edit\d*\./i.test(lower)) penalty += 500;
  if (/_v\d+\./i.test(lower)) penalty += 400;
  if (/_final\./i.test(lower)) penalty += 300;
  if (/_fix\./i.test(lower)) penalty += 200;

  // Nama file yang lebih panjang cenderung merupakan modifikasi/salinan
  penalty += lower.length;
  return penalty;
}

/**
 * Memindai folder secara rekursif (STG-01)
 */
function scanFilesRecursively(dirPath, visitedDirs = new Set(), results = []) {
  let realDir;
  try {
    realDir = fs.realpathSync(dirPath);
  } catch (e) {
    realDir = dirPath;
  }

  // Cegah rekursi tak hingga akibat symbolic link / directory junction
  if (visitedDirs.has(realDir)) {
    return results;
  }
  visitedDirs.add(realDir);

  let entries = [];
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch (err) {
    console.error(`${c.red}Gagal membaca direktori: ${dirPath} (${err.message})${c.reset}`);
    return results;
  }

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    const lowerName = entry.name.toLowerCase();

    // Abaikan direktori sistem dan folder backup pengujian
    if (EXCLUDED_DIRS.has(lowerName)) {
      continue;
    }

    // Abaikan skrip audit itu sendiri
    if (SCRIPT_SELF_NAMES.has(lowerName)) {
      continue;
    }

    try {
      if (entry.isDirectory()) {
        scanFilesRecursively(fullPath, visitedDirs, results);
      } else if (entry.isFile()) {
        const stats = fs.statSync(fullPath);
        results.push({
          name: entry.name,
          fullPath: fullPath,
          relativePath: path.relative(process.cwd(), fullPath),
          size: stats.size,
          mtime: stats.mtimeMs,
          birthtime: stats.birthtimeMs
        });
      }
    } catch (err) {
      // Abaikan file yang terkunci atau tidak memiliki izin akses
    }
  }

  return results;
}

/**
 * Membantu resolusi folder target fleksibel
 */
function resolveTargetDirectory(userArg) {
  if (userArg && userArg !== '.' && userArg !== './') {
    const directPath = path.resolve(userArg);
    if (fs.existsSync(directPath) && fs.statSync(directPath).isDirectory()) {
      return directPath;
    }

    // Cek di direktori parent (misal jika dieksekusi di dalam subfolder)
    const parentPath = path.resolve('..', userArg);
    if (fs.existsSync(parentPath) && fs.statSync(parentPath).isDirectory()) {
      return parentPath;
    }

    // Cek khusus Bahan Latihan P12 di lokasi unduhan standar
    const knownLocations = [
      path.resolve('Bahan Latihan P12'),
      path.resolve('..', 'Bahan Latihan P12'),
      path.resolve('C:\\Users\\Student\\Downloads\\Bahan Latihan P12'),
      path.resolve('C:\\Users\\Student\\Downloads\\Downloads_Lab')
    ];

    for (const loc of knownLocations) {
      if (fs.existsSync(loc) && fs.statSync(loc).isDirectory()) {
        return loc;
      }
    }

    return directPath;
  }

  // Jika tanpa argumen: prioritaskan "Bahan Latihan P12" jika ada, jika tidak gunakan current working directory
  const localTarget = path.resolve('Bahan Latihan P12');
  if (fs.existsSync(localTarget) && fs.statSync(localTarget).isDirectory()) {
    return localTarget;
  }

  const parentTarget = path.resolve('..', 'Bahan Latihan P12');
  if (fs.existsSync(parentTarget) && fs.statSync(parentTarget).isDirectory()) {
    // Jika current directory dan parentTarget mengarah ke data yang sama, gunakan cwd
    try {
      if (fs.realpathSync(parentTarget) === fs.realpathSync(process.cwd())) {
        return process.cwd();
      }
    } catch (e) {}
  }

  return process.cwd();
}

/**
 * Prompt konfirmasi interaktif (STG-05)
 */
function askConfirmation(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/**
 * Fungsi Utama Eksekusi Audit Penyimpanan
 */
async function main() {
  const args = process.argv.slice(2);
  let targetArg = null;
  let autoYes = false;
  let autoNo = false;
  let dryRun = false;

  for (const arg of args) {
    if (arg === '-y' || arg === '--yes') {
      autoYes = true;
    } else if (arg === '-n' || arg === '--no') {
      autoNo = true;
    } else if (arg === '--dry-run') {
      dryRun = true;
    } else if (arg === '-h' || arg === '--help') {
      console.log(`
${c.bold}${c.cyan}Storage-Audit.js - CLI Utility Audit Penyimpanan${c.reset}
Penggunaan:
  node Storage-Audit.js [folder_target] [opsi]

Opsi:
  -y, --yes      Otomatis menyetujui pembersihan file duplikat (non-interaktif)
  -n, --no       Otomatis membatalkan pembersihan (hanya audit)
  --dry-run      Simulasi pembersihan tanpa benar-benar menghapus file
  -h, --help     Menampilkan bantuan ini

Contoh:
  node Storage-Audit.js
  node Storage-Audit.js "Bahan Latihan P12"
  node Storage-Audit.js . --yes
`);
      process.exit(0);
    } else if (!arg.startsWith('-') && !targetArg) {
      targetArg = arg;
    }
  }

  const targetDir = resolveTargetDirectory(targetArg);

  if (!fs.existsSync(targetDir)) {
    console.error(`${c.red}${c.bold}Error:${c.reset} Direktori target tidak ditemukan: ${targetDir}`);
    process.exit(1);
  }

  console.log(`\n${c.cyan}================================================================================${c.reset}`);
  console.log(`${c.bold}${c.white}                 SISTEM AUDIT PENYIMPANAN (STORAGE-AUDIT CLI)${c.reset}`);
  console.log(`${c.cyan}================================================================================${c.reset}`);
  console.log(`${c.bold}Target Folder :${c.reset} ${targetDir}`);
  console.log(`${c.bold}Waktu Audit   :${c.reset} ${new Date().toLocaleString('id-ID')}`);
  console.log(`${c.gray}Memindai seluruh struktur folder secara rekursif...${c.reset}\n`);

  // STG-01: Recursive Scan
  const fileList = scanFilesRecursively(targetDir);

  if (fileList.length === 0) {
    console.log(`${c.yellow}Tidak ada file yang ditemukan untuk diaudit di folder target.${c.reset}`);
    return;
  }

  // Hitung Hash SHA-256 untuk semua file
  process.stdout.write(`${c.dim}Menghitung hash SHA-256 untuk ${fileList.length} file... ${c.reset}`);
  let totalFolderBytes = 0;
  for (let i = 0; i < fileList.length; i++) {
    const file = fileList[i];
    totalFolderBytes += file.size;
    file.hash = await computeSha256(file.fullPath);
  }
  process.stdout.write(`${c.green}${c.bold}[SELESAI]${c.reset}\n\n`);

  // STG-02: Duplicate Detection
  const hashMap = new Map();
  for (const file of fileList) {
    if (!hashMap.has(file.hash)) {
      hashMap.set(file.hash, []);
    }
    hashMap.get(file.hash).push(file);
  }

  const duplicateGroups = [];
  let totalRedundantFiles = 0;
  let totalSavingsBytes = 0;

  for (const [hash, files] of hashMap.entries()) {
    if (files.length > 1) {
      // Urutkan file untuk menentukan file asli (original) dan file salinan (duplicate)
      files.sort((a, b) => {
        const scoreA = scoreOriginalHeuristic(a.name);
        const scoreB = scoreOriginalHeuristic(b.name);
        if (scoreA !== scoreB) return scoreA - scoreB;
        // Jika skor sama, dahulukan yang dibuat lebih awal (mtime lebih lama)
        return a.mtime - b.mtime;
      });

      const originalFile = files[0];
      const duplicatesToDelete = files.slice(1);
      const groupSavings = duplicatesToDelete.reduce((acc, f) => acc + f.size, 0);

      totalRedundantFiles += duplicatesToDelete.length;
      totalSavingsBytes += groupSavings;

      duplicateGroups.push({
        hash,
        fileSize: originalFile.size,
        original: originalFile,
        duplicates: duplicatesToDelete,
        allFiles: files,
        savingsBytes: groupSavings
      });
    }
  }

  // Urutkan kelompok duplikat berdasarkan potensi penghematan ruang (terbesar ke terkecil)
  duplicateGroups.sort((a, b) => b.savingsBytes - a.savingsBytes);

  // STG-03: Giant File Flagging (>= 2 MB / 2.048 KB)
  const giantFiles = fileList
    .filter(f => f.size >= GIANT_FILE_THRESHOLD)
    .sort((a, b) => b.size - a.size);

  // Identifikasi File Sampah .tmp tambahan (jika ada file .tmp yang berdiri sendiri)
  const tmpJunkFiles = fileList.filter(f => {
    const lower = f.name.toLowerCase();
    if (!lower.endsWith('.tmp')) return false;
    // Cek jika sudah masuk dalam daftar file duplikat yang akan dihapus
    for (const group of duplicateGroups) {
      if (group.duplicates.some(d => d.fullPath === f.fullPath)) {
        return false;
      }
    }
    return true;
  });

  for (const tmpFile of tmpJunkFiles) {
    totalSavingsBytes += tmpFile.size;
  }

  // STG-04: Terminal Report
  console.log(`${c.cyan}--------------------------------------------------------------------------------${c.reset}`);
  console.log(`${c.bold}${c.yellow}1. RINGKASAN AUDIT PENYIMPANAN (STORAGE SUMMARY)${c.reset}`);
  console.log(`${c.cyan}--------------------------------------------------------------------------------${c.reset}`);
  console.log(`• Total File Di-scan        : ${c.bold}${c.white}${fileList.length} file${c.reset}`);
  console.log(`• Total Ukuran Folder       : ${c.bold}${c.white}${formatSizeMB(totalFolderBytes)}${c.reset} (${totalFolderBytes.toLocaleString()} bytes)`);
  console.log(`• Jumlah File Raksasa       : ${c.bold}${c.magenta}${giantFiles.length} file${c.reset} ${c.dim}(ambang batas >= 2 MB / 2.048 KB)${c.reset}`);
  console.log(`• Kelompok Duplikat Ditemukan: ${c.bold}${c.red}${duplicateGroups.length} kelompok${c.reset} (${duplicateGroups.reduce((acc, g) => acc + g.allFiles.length, 0)} file terikat)`);
  console.log(`• File Salinan Redundan     : ${c.bold}${c.red}${totalRedundantFiles} file salinan${c.reset}`);
  if (tmpJunkFiles.length > 0) {
    console.log(`• File Sampah Sementara (.tmp): ${c.bold}${c.red}${tmpJunkFiles.length} file sampah${c.reset}`);
  }
  console.log(`• ${c.bold}${c.green}Estimasi Hemat Ruang Bersih : ${formatSizeMB(totalSavingsBytes)}${c.reset}`);

  // Tampilkan Daftar File Raksasa (STG-03)
  console.log(`\n${c.cyan}--------------------------------------------------------------------------------${c.reset}`);
  console.log(`${c.bold}${c.yellow}2. DAFTAR FILE RAKSASA (GIANT FILES - UKURAN >= 2 MB / 2.048 KB)${c.reset}`);
  console.log(`${c.cyan}--------------------------------------------------------------------------------${c.reset}`);
  if (giantFiles.length === 0) {
    console.log(`${c.dim}Tidak ada file yang melebihi ambang batas 2 MB.${c.reset}`);
  } else {
    giantFiles.forEach((file, idx) => {
      const num = String(idx + 1).padStart(2, '0');
      const formattedSize = formatSizeMB(file.size);
      console.log(`  [${c.bold}${num}${c.reset}] ${c.bold}${c.magenta}${file.name}${c.reset}`);
      console.log(`       Ukuran: ${formattedSize}`);
      console.log(`       Lokasi: ${c.dim}${file.fullPath}${c.reset}`);
    });
  }

  // Tampilkan Daftar Kelompok Duplikat (STG-02)
  console.log(`\n${c.cyan}--------------------------------------------------------------------------------${c.reset}`);
  console.log(`${c.bold}${c.yellow}3. DAFTAR KELOMPOK DUPLIKAT (DUPLICATE GROUPS - SHA-256 IDENTIK)${c.reset}`);
  console.log(`${c.cyan}--------------------------------------------------------------------------------${c.reset}`);
  if (duplicateGroups.length === 0) {
    console.log(`${c.green}Tidak ditemukan file duplikat dalam folder ini.${c.reset}`);
  } else {
    duplicateGroups.forEach((group, idx) => {
      const num = String(idx + 1).padStart(2, '0');
      console.log(`\n  ${c.bold}[Grup Duplikat ${num}]${c.reset} ${c.dim}SHA-256: ${group.hash.substring(0, 16)}...${c.reset}`);
      console.log(`  Ukuran per file : ${formatSizeMB(group.fileSize)}`);
      console.log(`  Potensi hemat   : ${c.green}${formatSizeMB(group.savingsBytes)}${c.reset} (${group.duplicates.length} salinan)`);
      console.log(`  ${c.green}✓ [FILE ASLI]    ${group.original.name}${c.reset} ${c.dim}(dipertahankan)${c.reset}`);
      for (const dup of group.duplicates) {
        console.log(`  ${c.red}✗ [SALINAN DUP]  ${dup.name}${c.reset} ${c.dim}(siap dibersihkan)${c.reset}`);
      }
    });
  }

  // STG-05: Safe Cleanup Confirmation
  console.log(`\n${c.cyan}================================================================================${c.reset}`);
  console.log(`${c.bold}${c.white}                  KONFIRMASI PEMBERSIHAN AMAN (SAFE CLEANUP)${c.reset}`);
  console.log(`${c.cyan}================================================================================${c.reset}`);

  const totalFilesToClean = totalRedundantFiles + tmpJunkFiles.length;

  if (totalFilesToClean === 0) {
    console.log(`${c.green}Penyimpanan sudah bersih! Tidak ada file duplikat atau file sampah .tmp.${c.reset}\n`);
    return;
  }

  console.log(`Total file yang dapat dibersihkan : ${c.bold}${c.red}${totalFilesToClean} file${c.reset} (${totalRedundantFiles} duplikat, ${tmpJunkFiles.length} sampah .tmp)`);
  console.log(`Total ruang yang akan dihemat     : ${c.bold}${c.green}${formatSizeMB(totalSavingsBytes)}${c.reset}`);
  console.log(`${c.dim}Prinsip keamanan: Tepat 1 file asli per kelompok duplikat AKAN SELALU DIPERTAHANKAN.${c.reset}`);

  let proceed = false;

  if (dryRun) {
    console.log(`\n${c.yellow}[SIMULASI / DRY-RUN] Menampilkan daftar file yang akan dihapus:${c.reset}`);
    for (const group of duplicateGroups) {
      for (const dup of group.duplicates) {
        console.log(`  [AKAN DIHAPUS] ${dup.fullPath} (${formatBytesCompact(dup.size)})`);
      }
    }
    for (const tmp of tmpJunkFiles) {
      console.log(`  [AKAN DIHAPUS] ${tmp.fullPath} (${formatBytesCompact(tmp.size)})`);
    }
    console.log(`\n${c.yellow}Mode dry-run selesai. Tidak ada perubahan file di disk.${c.reset}\n`);
    return;
  }

  if (autoYes) {
    console.log(`\n${c.yellow}Opsi -y / --yes terdeteksi: Konfirmasi pembersihan otomatis diterima.${c.reset}`);
    proceed = true;
  } else if (autoNo) {
    console.log(`\n${c.yellow}Opsi -n / --no terdeteksi: Pembersihan dibatalkan.${c.reset}`);
    proceed = false;
  } else {
    const promptText = `\n${c.bold}Apakah kamu ingin menghapus file duplikat yang tidak terpakai? (Y/N): ${c.reset}`;
    const answer = await askConfirmation(promptText);
    if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'ya' || answer.toLowerCase() === 'yes') {
      proceed = true;
    } else {
      proceed = false;
    }
  }

  if (!proceed) {
    console.log(`\n${c.yellow}>> Operasi pembersihan dibatalkan. Tidak ada file yang dihapus. Data tetap aman.${c.reset}\n`);
    return;
  }

  // Proses Penghapusan File Terkendali
  console.log(`\n${c.bold}${c.cyan}Memulai proses pembersihan file duplikat dan sampah .tmp...${c.reset}`);
  let deletedCount = 0;
  let deletedBytes = 0;
  let failedCount = 0;

  for (const group of duplicateGroups) {
    for (const dup of group.duplicates) {
      try {
        fs.unlinkSync(dup.fullPath);
        deletedCount++;
        deletedBytes += dup.size;
        console.log(`  ${c.green}✔ Terhapus:${c.reset} ${dup.name} ${c.dim}(hemat ${formatBytesCompact(dup.size)})${c.reset}`);
      } catch (err) {
        failedCount++;
        console.error(`  ${c.red}✖ Gagal menghapus:${c.reset} ${dup.name} (${err.message})`);
      }
    }
  }

  for (const tmp of tmpJunkFiles) {
    try {
      fs.unlinkSync(tmp.fullPath);
      deletedCount++;
      deletedBytes += tmp.size;
      console.log(`  ${c.green}✔ Terhapus (Sampah .tmp):${c.reset} ${tmp.name} ${c.dim}(hemat ${formatBytesCompact(tmp.size)})${c.reset}`);
    } catch (err) {
      failedCount++;
      console.error(`  ${c.red}✖ Gagal menghapus:${c.reset} ${tmp.name} (${err.message})`);
    }
  }

  console.log(`\n${c.green}================================================================================${c.reset}`);
  console.log(`${c.bold}${c.green}                     PEMBERSIHAN SELESAI DENGAN SUKSES!${c.reset}`);
  console.log(`${c.green}================================================================================${c.reset}`);
  console.log(`• Berhasil Dihapus    : ${c.bold}${c.white}${deletedCount} file${c.reset}`);
  if (failedCount > 0) {
    console.log(`• Gagal Dihapus       : ${c.bold}${c.red}${failedCount} file${c.reset}`);
  }
  console.log(`• Ruang Dibebaskan    : ${c.bold}${c.green}${formatSizeMB(deletedBytes)}${c.reset}`);
  console.log(`• File Asli Tersisa   : ${c.bold}${c.white}${fileList.length - deletedCount} file${c.reset} ${c.dim}(1 file original per kelompok dipertahankan)${c.reset}\n`);
}

// Jalankan program utama
main().catch(err => {
  console.error(`\n${c.red}${c.bold}Fatal Error:${c.reset} ${err.message}`);
  process.exit(1);
});
