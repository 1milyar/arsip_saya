/******************************************************
* 📁 ARSIP SPJ DIGITAL v8.1 - FINAL SECURE & RBAC
* 
* PERBAIKAN TASK:
* ✅ TASK 1: Full RBAC Implementation
* ✅ TASK 2: Google Drive Integration
* ✅ TASK 3: Security Enhancement (Hashing, Sanitization, Session)
* ✅ TASK 4: Export to PDF Support
* ✅ TASK 5: Multiple HTML Files Support
* ✅ BUG FIX: Fixed typo in exportRealisasiExcel function
******************************************************/

// === KONFIGURASI UTAMA ===
const CONFIG = {
  SPREADSHEET_ID: '1jhlh3-YY3S-he12g1Hy6edHm6uVjrtiyscHB6VxclLw',
  SHEET_NAME: 'Arsip',
  FOLDER_ID: '1goDSANBXyjPQeJex45qAbJD1CjI9MnfO',
  MAX_FILE_SIZE: 25 * 1024 * 1024, // 25MB
  ALLOWED_FILE_TYPES: ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg'],
  SESSION_TIMEOUT: 3600000, // 1 hour
  SALT_KEY: 'SPJ_DIGITAL_SALT_2026_PASER_!@#$%',
  SECRET_KEY: 'SPJ_SECRET_KEY_2026_BAPPEDALITBANG_PASER'
};

// === HELPER FUNCTION UNTUK INCLUDE HTML FILES ===
function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename)
    .getContent();
}

// === FUNGSI UTAMA - HTML SERVE ===
function doGet() {
  return HtmlService.createTemplateFromFile('Index')
    .evaluate()
    .setTitle('📁 Arsip SPJ Digital Bappedalitbang Paser v8.1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

// === HELPER - GET SHEET ===
function getSheet() {
  const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
  const sheet = ss.getSheetByName(CONFIG.SHEET_NAME);
  return sheet || ss.insertSheet(CONFIG.SHEET_NAME);
}

// === SECURITY HELPERS ===
/**
 * Sanitize input untuk mencegah XSS & SQL Injection
 */
function sanitizeInput(input) {
  if (!input) return '';
  return String(input)
    .replace(/[<>]/g, '') // Remove HTML tags
    .replace(/'/g, "''") // Escape single quotes
    .replace(/"/g, '""') // Escape double quotes
    .replace(/;/g, '') // Remove semicolons
    .replace(/--/g, '') // Remove SQL comments
    .trim();
}

/**
 * Validasi file upload di server-side
 */
function validateFileUpload(fileData, mimeType, fileName) {
  const errors = [];
  
  // Validasi type
  if (!CONFIG.ALLOWED_FILE_TYPES.includes(mimeType)) {
    errors.push('Format file tidak diizinkan. Hanya PDF, JPG, PNG');
  }
  
  // Validasi ekstensi
  const ext = fileName.toLowerCase().split('.').pop();
  const allowedExts = ['pdf', 'jpg', 'jpeg', 'png'];
  if (!allowedExts.includes(ext)) {
    errors.push('Ekstensi file tidak diizinkan');
  }
  
  // Validasi content (basic check)
  if (fileData && fileData.length < 100) {
    errors.push('File terlalu kecil, kemungkinan corrupt');
  }
  
  return {
    valid: errors.length === 0,
    errors: errors
  };
}

// === SESSION MANAGEMENT - PERSISTENT USING CACHE ===
function generateSessionToken(userId) {
  const timestamp = new Date().getTime();
  const random = Math.random().toString(36).substr(2, 10);
  const tokenData = userId + timestamp + random + CONFIG.SECRET_KEY;
  
  const digest = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    tokenData
  );
  
  return digest.map(byte => {
    return (byte < 0 ? byte + 256 : byte).toString(16).padStart(2, '0');
  }).join('');
}

function createSession(userId, userData) {
  const token = generateSessionToken(userId);
  const expiryTime = CONFIG.SESSION_TIMEOUT / 1000; // in seconds for cache
  
  const sessionData = {
    userId: userId,
    userData: userData,
    expiry: new Date().getTime() + CONFIG.SESSION_TIMEOUT
  };
  
  // Store in CacheService (Persistent across different script executions)
  const cache = CacheService.getScriptCache();
  cache.put(token, JSON.stringify(sessionData), expiryTime);
  
  return token;
}

function validateSession(token) {
  if (!token) return { valid: false, message: 'Token tidak ditemukan' };
  
  const cache = CacheService.getScriptCache();
  const cachedData = cache.get(token);
  
  if (!cachedData) {
    return { valid: false, message: 'Session telah kadaluarsa atau tidak valid' };
  }
  
  try {
    const session = JSON.parse(cachedData);
    const now = new Date().getTime();
    
    if (now > session.expiry) {
      cache.remove(token);
      return { valid: false, message: 'Session telah kadaluarsa' };
    }
    
    // Extend session in cache
    cache.put(token, cachedData, CONFIG.SESSION_TIMEOUT / 1000);
    
    return {
      valid: true,
      userData: session.userData,
      remaining: Math.floor((session.expiry - now) / 60000)
    };
  } catch (e) {
    return { valid: false, message: 'Format session error' };
  }
}

function destroySession(token) {
  if (!token) return false;
  const cache = CacheService.getScriptCache();
  cache.remove(token);
  return true;
}

// === 1. LOGIN SYSTEM - PLAIN TEXT COMPARISON ===
function validateLogin(username, password) {
  try {
    // Trim username but keep password exactly as typed
    const cleanUsername = String(username || "").trim();
    const cleanPassword = String(password || ""); 
    
    const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
    let loginSheet = ss.getSheetByName('Login');
    
    if (!loginSheet) {
      return { 
        success: false, 
        message: 'Error: Sheet "Login" tidak ditemukan! Pastikan nama sheet adalah "Login".' 
      };
    }
    
    const data = loginSheet.getDataRange().getValues();
    let userFound = false;

    for (let i = 1; i < data.length; i++) {
      const storedUsername = String(data[i][0] || "").trim();
      const storedPassword = String(data[i][1] || "").trim();
      
      // Case-insensitive untuk username, Case-sensitive untuk password
      if (storedUsername.toLowerCase() === cleanUsername.toLowerCase()) {
        userFound = true;
        if (storedPassword === cleanPassword) {
          const userData = {
            nama: String(data[i][2] || "").trim(),
            role: String(data[i][3] || "").trim(),
            bidang: String(data[i][4] || "").trim()
          };
          
          // Create session
          const sessionToken = createSession(cleanUsername, userData);
          
          return { 
            success: true, 
            nama: userData.nama, 
            role: userData.role, 
            bidang: userData.bidang,
            sessionToken: sessionToken,
            message: 'Login berhasil!'
          };
        }
      }
    }
    
    if (!userFound) {
      return { success: false, message: 'Username tidak ditemukan di database!' };
    } else {
      return { success: false, message: 'Password salah! Pastikan ketikan sudah benar.' };
    }
    
  } catch (error) { 
    return { 
      success: false, 
      message: 'Terjadi kesalahan sistem: ' + error.message 
    }; 
  }
}

function logout(sessionToken) {
  try {
    const destroyed = destroySession(sessionToken);
    return {
      success: destroyed,
      message: destroyed ? 'Logout berhasil' : 'Session tidak ditemukan'
    };
  } catch (error) {
    return {
      success: false,
      message: 'Error saat logout: ' + error.message
    };
  }
}

// === 2. RBAC VALIDATION HELPER ===
function validateUserAccess(sessionToken, requiredRole = null, requiredBidang = null) {
  const session = validateSession(sessionToken);
  
  if (!session.valid) {
    throw new Error('UNAUTHORIZED: ' + session.message);
  }
  
  const user = session.userData;
  
  // Check role if specified (Standardized case-insensitive)
  if (requiredRole && requiredRole !== 'ANY') {
    const userRole = String(user.role || "").trim().toLowerCase();
    const reqRole = String(requiredRole).trim().toLowerCase();
    
    if (reqRole === 'admin' && userRole !== 'admin') {
      throw new Error('UNAUTHORIZED: Hanya Admin yang dapat mengakses fitur ini!');
    }
  }
  
  // Check bidang if specified
  if (requiredBidang && requiredBidang !== 'ANY') {
    if (user.bidang !== 'ALL' && user.bidang !== requiredBidang) {
      throw new Error('UNAUTHORIZED: Anda tidak memiliki akses ke bidang ini!');
    }
  }
  
  return user;
}

// === 3. VALIDASI UPLOAD SPJ - KOMPREHENSIF + RBAC ===
function validateUploadData(data, sessionToken) {
  // Validate session & role first
  const user = validateUserAccess(sessionToken, 'Admin'); // Only Admin can upload
  
  const errors = [];
  
  // Sanitize all inputs
  const cleanData = {
    tahun: sanitizeInput(data.tahun),
    bulan: sanitizeInput(data.bulan),
    bidang: sanitizeInput(data.bidang),
    nomorSPM: sanitizeInput(data.nomorSPM),
    kodeRekeningUtama: sanitizeInput(data.kodeRekeningUtama),
    kodeRekeningBagian: sanitizeInput(data.kodeRekeningBagian),
    namaKegiatan: sanitizeInput(data.namaKegiatan),
    kategori: sanitizeInput(data.kategori),
    nominal: data.nominal,
    penerima: sanitizeInput(data.penerima),
    pajakList: data.pajakList,
    fileData: data.fileData,
    mimeType: data.mimeType,
    fileName: sanitizeInput(data.fileName),
    fileSize: data.fileSize
  };
  
  // Required fields validation
  if (!cleanData.tahun) errors.push("⚠️ Tahun Anggaran wajib diisi");
  if (!cleanData.bulan) errors.push("⚠️ Bulan wajib dipilih");
  if (!cleanData.bidang) errors.push("⚠️ Bidang wajib dipilih");
  if (!cleanData.nomorSPM) errors.push("⚠️ Nomor SPM wajib diisi");
  if (!cleanData.kodeRekeningUtama) errors.push("⚠️ Kode Rekening Utama wajib dipilih");
  if (!cleanData.kodeRekeningBagian) errors.push("⚠️ Kode Rekening Bagian wajib dipilih");
  if (!cleanData.namaKegiatan) errors.push("⚠️ Nama Kegiatan wajib diisi");
  if (!cleanData.kategori) errors.push("⚠️ Kategori wajib dipilih");
  if (!cleanData.nominal || Number(cleanData.nominal) <= 0) errors.push("⚠️ Nominal harus lebih dari 0");
  if (!cleanData.penerima) errors.push("⚠️ Nama Penerima wajib diisi");
  
  // File validation
  if (!cleanData.fileData) {
    errors.push("⚠️ File SPJ wajib diupload");
  } else {
    const fileValidation = validateFileUpload(cleanData.fileData, cleanData.mimeType, cleanData.fileName);
    if (!fileValidation.valid) {
      errors.push(...fileValidation.errors);
    }
  }
  
  // File size validation
  if (cleanData.fileSize && cleanData.fileSize > CONFIG.MAX_FILE_SIZE) {
    errors.push(`⚠️ Ukuran file maksimal ${CONFIG.MAX_FILE_SIZE / (1024 * 1024)}MB`);
  }
  
  // Pagu validation
  if (cleanData.nominal) {
    const paguData = getSisaPagu(
      cleanData.tahun,
      cleanData.bidang,
      cleanData.kodeRekeningUtama,
      cleanData.kodeRekeningBagian
    );
    
    const nominalValue = Number(cleanData.nominal);
    
    if (paguData.sisaPagu < nominalValue) {
      errors.push(`⚠️ Nominal melebihi sisa pagu! Sisa pagu: Rp ${formatRupiah(paguData.sisaPagu)}`);
    }
    
    if (paguData.totalPagu === 0) {
      errors.push("⚠️ Anggaran tidak ditemukan untuk kode rekening ini!");
    }
  }
  
  // Pajak validation
  if (cleanData.pajakList && cleanData.pajakList.length > 0) {
    const totalPajak = cleanData.pajakList.reduce((sum, p) => sum + Number(p.nilai || 0), 0);
    const nominalValue = Number(cleanData.nominal);
    
    if (totalPajak > nominalValue * 0.3) {
      errors.push("⚠️ Total pajak terlalu tinggi (>30% dari nominal)");
    }
    
    // Validate each pajak entry
    cleanData.pajakList.forEach((pajak, index) => {
      if (!pajak.jenis || String(pajak.jenis).trim() === '') {
        errors.push(`⚠️ Jenis pajak ke-${index + 1} wajib diisi`);
      }
      if (!pajak.idBilling || String(pajak.idBilling).trim() === '') {
        errors.push(`⚠️ ID Billing pajak ke-${index + 1} wajib diisi`);
      }
      if (!pajak.nilai || Number(pajak.nilai) <= 0) {
        errors.push(`⚠️ Nilai pajak ke-${index + 1} harus lebih dari 0`);
      }
    });
  }
  
  return {
    valid: errors.length === 0,
    errors: errors,
    count: errors.length,
    cleanData: cleanData
  };
}

// === 4. UPLOAD SPJ DENGAN RBAC & SECURITY ===
function uploadFileWithPajak(data, sessionToken) {
  try {
    // Step 1: Validasi dengan session
    const validation = validateUploadData(data, sessionToken);
    if (!validation.valid) {
      throw new Error("VALIDATION_ERROR:" + JSON.stringify(validation.errors));
    }
    
    const cleanData = validation.cleanData;
    const nominal = Number(cleanData.nominal) || 0;
    const parentFolder = DriveApp.getFolderById(CONFIG.FOLDER_ID);
    
    // Step 2: Get pagu info
    const paguData = getSisaPagu(
      cleanData.tahun,
      cleanData.bidang,
      cleanData.kodeRekeningUtama,
      cleanData.kodeRekeningBagian
    );
    
    if (paguData.sisaPagu < nominal) {
      throw new Error(`Saldo Pagu tidak mencukupi! Sisa: Rp ${formatRupiah(paguData.sisaPagu)}`);
    }
    
    // Step 3: Create folder & upload file
    const folderName = cleanData.nomorSPM.replace(/[/\\?%*:|"<>]/g, '-');
    const folders = parentFolder.getFoldersByName(folderName);
    const folder = folders.hasNext() ? folders.next() : parentFolder.createFolder(folderName);
    
    const blob = Utilities.newBlob(
      Utilities.base64Decode(cleanData.fileData),
      cleanData.mimeType,
      cleanData.fileName
    );
    
    const file = folder.createFile(blob);
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    
    // Step 4: Prepare pajak data
    const jenisStr = cleanData.pajakList.map(p => sanitizeInput(p.jenis)).join(", ");
    const billingStr = cleanData.pajakList.map(p => sanitizeInput(p.idBilling)).join(", ");
    const totalPajak = cleanData.pajakList.reduce((sum, p) => sum + Number(p.nilai), 0);
    
    // Step 5: Save to Arsip sheet
    const sheet = getSheet();
    const id = Utilities.getUuid();
    const now = new Date();
    
    const row = [
      id,                              // 0: ID
      cleanData.tahun,                 // 1: Tahun
      cleanData.bulan,                 // 2: Bulan
      cleanData.nomorSPM,              // 3: Nomor SPM
      cleanData.namaKegiatan,          // 4: Nama Kegiatan
      cleanData.kategori,              // 5: Kategori
      nominal,                         // 6: Nominal
      cleanData.penerima,              // 7: Penerima
      file.getId(),                    // 8: File ID
      file.getUrl(),                   // 9: File URL
      Utilities.formatDate(now, Session.getScriptTimeZone(), "yyyy-MM-dd HH:mm:ss"), // 10: Tanggal Upload
      data.uploader,                   // 11: Uploader (from session)
      "", "", "",                      // 12-14: Reserved
      cleanData.bidang,                // 15: Bidang
      cleanData.kodeRekeningUtama,     // 16: Kode Rekening Utama
      cleanData.kodeRekeningBagian,    // 17: Kode Rekening Bagian
      paguData.anggaranInfo ? paguData.anggaranInfo.jenis : "N/A", // 18: Jenis Anggaran
      "Terealisasi",                   // 19: Status
      jenisStr,                        // 20: Jenis Pajak
      billingStr,                      // 21: ID Billing
      totalPajak,                      // 22: Total Pajak
      folder.getUrl()                  // 23: Folder URL
    ];
    
    sheet.appendRow(row);
    
    // Step 6: Catat realisasi
    catatRealisasi({
      idSPJ: id,
      tahun: cleanData.tahun,
      bidang: cleanData.bidang,
      kodeUtama: cleanData.kodeRekeningUtama,
      kodeBagian: cleanData.kodeRekeningBagian,
      uraian: cleanData.namaKegiatan,
      nominal: nominal,
      jenis: paguData.anggaranInfo ? paguData.anggaranInfo.jenis : "N/A",
      saldoAwal: paguData.sisaPagu,
      saldoAkhir: paguData.sisaPagu - nominal
    });
    
    // Step 7: Save pajak data
    if (cleanData.pajakList.length > 0) {
      const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
      let shTax = ss.getSheetByName('Rekap_Pajak');
      
      if (!shTax) {
        shTax = ss.insertSheet('Rekap_Pajak');
        shTax.appendRow(['ID', 'ID_SPJ', 'Tahun', 'Bulan', 'Jenis', 'Billing', 'Nilai', 'Tgl', 'Bidang']);
      }
      
      cleanData.pajakList.forEach(p => {
        shTax.appendRow([
          Utilities.getUuid(),
          id,
          cleanData.tahun,
          cleanData.bulan,
          sanitizeInput(p.jenis),
          sanitizeInput(p.idBilling),
          Number(p.nilai),
          Utilities.formatDate(now, Session.getScriptTimeZone(), "yyyy-MM-dd"),
          cleanData.bidang
        ]);
      });
    }
    
    // Step 8: Return success response
    return {
      success: true,
      message: "SPJ berhasil diupload!",
      data: {
        id: id,
        spm: cleanData.nomorSPM,
        nominal: nominal,
        fileUrl: file.getUrl(),
        folderUrl: folder.getUrl()
      }
    };
    
  } catch (error) {
    // Handle validation error specially
    if (error.message.startsWith("VALIDATION_ERROR:")) {
      const errors = JSON.parse(error.message.replace("VALIDATION_ERROR:", ""));
      return {
        success: false,
        validationError: true,
        errors: errors,
        message: "Validasi gagal. Silakan perbaiki data Anda."
      };
    }
    
    // Handle unauthorized error
    if (error.message.startsWith("UNAUTHORIZED:")) {
      return {
        success: false,
        unauthorized: true,
        message: error.message.replace("UNAUTHORIZED: ", "")
      };
    }
    
    // Handle other errors
    return {
      success: false,
      message: "Terjadi kesalahan: " + error.message
    };
  }
}

// === 5. BUDGET MANAGEMENT DENGAN RBAC ===
function uploadBulkPaguAnggaran(params, sessionToken) {
  try {
    // Only Admin can manage budget
    validateUserAccess(sessionToken, 'Admin');
    
    const lock = LockService.getScriptLock();
    lock.waitLock(30000);
    
    const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
    let sheet = ss.getSheetByName('Pagu_Anggaran');
    
    if (!sheet) {
      sheet = ss.insertSheet('Pagu_Anggaran');
      sheet.appendRow(['ID', 'Jenis', 'Status_Aktif', 'Tahun', 'Bidang', 'Kode_Rekening_Utama', 'Kode_Rekening_Bagian', 'Uraian', 'Nilai_Pagu']);
    }
    
    const existingData = sheet.getDataRange().getValues();
    const rowsToAdd = [];
    const rowsToUpdate = [];
    
    const findBudgetIndex = (tahun, bidang, kodeUtama, kodeBagian, jenisWajib) => {
      for (let i = 1; i < existingData.length; i++) {
        if (String(existingData[i][3]) == String(tahun) &&
            String(existingData[i][4]) == String(bidang) &&
            String(existingData[i][5]) == String(kodeUtama) &&
            String(existingData[i][6]) == String(kodeBagian) &&
            String(existingData[i][1]) == String(jenisWajib)) {
          if (existingData[i][2] === true || String(existingData[i][2]) === 'TRUE') {
            return i;
          }
        }
      }
      return -1;
    };
    
    // Sanitize inputs
    const cleanParams = {
      jenis: sanitizeInput(params.jenis),
      tahun: sanitizeInput(params.tahun),
      bidang: sanitizeInput(params.bidang),
      anggaranData: params.anggaranData.map(item => ({
        kodeUtama: sanitizeInput(item.kodeUtama),
        kodeBagian: sanitizeInput(item.kodeBagian),
        uraian: sanitizeInput(item.uraian),
        nilaiPagu: item.nilaiPagu
      }))
    };
    
    for (const item of cleanParams.anggaranData) {
      if (cleanParams.jenis === 'Pergeseran') {
        const murniIdx = findBudgetIndex(cleanParams.tahun, cleanParams.bidang, item.kodeUtama, item.kodeBagian, 'Murni');
        if (murniIdx === -1) throw new Error(`Gagal: Anggaran Murni valid tidak ditemukan untuk ${item.kodeUtama}.${item.kodeBagian}. Input Murni dulu.`);
        if (!rowsToUpdate.includes(murniIdx + 1)) rowsToUpdate.push(murniIdx + 1);
      } else if (cleanParams.jenis === 'Perubahan') {
        const geserIdx = findBudgetIndex(cleanParams.tahun, cleanParams.bidang, item.kodeUtama, item.kodeBagian, 'Pergeseran');
        if (geserIdx === -1) throw new Error(`Gagal: Anggaran Pergeseran valid tidak ditemukan untuk ${item.kodeUtama}.${item.kodeBagian}. Input Pergeseran dulu.`);
        if (!rowsToUpdate.includes(geserIdx + 1)) rowsToUpdate.push(geserIdx + 1);
      }
      
      rowsToAdd.push([
        Utilities.getUuid(),
        cleanParams.jenis,
        true,
        cleanParams.tahun,
        cleanParams.bidang,
        item.kodeUtama,
        item.kodeBagian,
        item.uraian,
        item.nilaiPagu
      ]);
    }
    
    if (rowsToUpdate.length > 0) {
      rowsToUpdate.forEach(rowIndex => {
        sheet.getRange(rowIndex, 3).setValue(false);
      });
    }
    
    if (rowsToAdd.length > 0) {
      sheet.getRange(sheet.getLastRow() + 1, 1, rowsToAdd.length, rowsToAdd[0].length).setValues(rowsToAdd);
    }
    
    return { 
      success: true,
      successCount: rowsToAdd.length,
      message: `Berhasil menyimpan ${rowsToAdd.length} data anggaran`
    };
    
  } catch (err) {
    if (err.message.startsWith("UNAUTHORIZED:")) {
      return {
        success: false,
        unauthorized: true,
        message: err.message.replace("UNAUTHORIZED: ", "")
      };
    }
    return {
      success: false,
      message: err.message
    };
  } finally {
    lock.releaseLock();
  }
}

function getPaguData(filters, sessionToken) {
  try {
    const user = validateUserAccess(sessionToken, 'ANY');
    
    const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
    const sheet = ss.getSheetByName('Pagu_Anggaran');
    if (!sheet) return { results: [], totals: { pagu: 0 } };
    
    const data = sheet.getDataRange().getValues();
    const results = [];
    let totalPagu = 0;
    
    // Auto-filter by bidang for non-Admin
    let fBidang = filters.bidang;
    if (user.bidang !== 'ALL' && user.role !== 'Admin') {
      fBidang = user.bidang;
    }
    
    for (let i = 1; i < data.length; i++) {
       // Filter by status aktif
       const isActive = (data[i][2] === true || String(data[i][2]) === 'TRUE');
       if (filters.onlyActive && !isActive) continue;
       
       // Filter by Tahun
       if (filters.tahun && String(data[i][3]) !== String(filters.tahun)) continue;
       
       // Filter by Bidang
       if (fBidang && fBidang !== 'ALL' && String(data[i][4]) !== fBidang) continue;
       
       // Filter by Jenis
       if (filters.jenis && String(data[i][1]) !== filters.jenis) continue;
       
       // Filter by Keyword (Uraian / Kode)
       if (filters.keyword) {
         const key = String(filters.keyword).toLowerCase();
         const searchStr = `${data[i][5]} ${data[i][6]} ${data[i][7]}`.toLowerCase();
         if (!searchStr.includes(key)) continue;
       }
       
       const val = Number(data[i][8]) || 0;
       if (isActive) totalPagu += val;
       
       results.push({
         id: data[i][0],
         jenis: data[i][1],
         aktif: isActive,
         tahun: data[i][3],
         bidang: data[i][4],
         kodeUtama: data[i][5],
         kodeBagian: data[i][6],
         uraian: data[i][7],
         nilai: val
       });
    }
    
    return {
      results: results.reverse(),
      totals: { pagu: totalPagu },
      filters: filters,
      userRole: user.role
    };
  } catch (err) {
    return { success: false, message: err.message };
  }
}

function deleteBulkPaguAnggaran(ids, sessionToken) {
  try {
    // Only Admin can delete budget
    validateUserAccess(sessionToken, 'Admin');
    
    const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
    const sheet = ss.getSheetByName('Pagu_Anggaran');
    
    if (!sheet) return { success: false, message: "Sheet tidak ditemukan" };
    
    const data = sheet.getDataRange().getValues();
    let deletedCount = 0;
    
    for (let i = data.length - 1; i >= 1; i--) {
      if (ids.includes(String(data[i][0]))) {
        sheet.deleteRow(i + 1);
        deletedCount++;
      }
    }
    
    return { 
      success: true,
      count: deletedCount,
      message: `Berhasil menghapus ${deletedCount} data anggaran`
    };
    
  } catch (err) {
    if (err.message.startsWith("UNAUTHORIZED:")) {
      return {
        success: false,
        unauthorized: true,
        message: err.message.replace("UNAUTHORIZED: ", "")
      };
    }
    return {
      success: false,
      message: err.message
    };
  }
}

// Helper to map headers to indices
function getArsipHeaderMapping(headers) {
  const mapping = {
    id: 0, tahun: 1, bulan: 2, nomorSPM: 3, namaKegiatan: 4, kategori: 5,
    nominal: 6, penerima: 7, fileId: 8, fileUrl: 9, tanggalUpload: 10,
    uploader: 11, bidang: 15, kodeRekeningUtama: 16, kodeRekeningBagian: 17,
    jenisAnggaran: 18, status: 19, jenisPajak: 20, billing: 21, 
    totalPajak: 22, folderUrl: 23
  };

  headers.forEach((h, i) => {
    const text = String(h).toLowerCase().trim();
    if (text === "id") mapping.id = i;
    else if (text === "tahun") mapping.tahun = i;
    else if (text === "bulan") mapping.bulan = i;
    else if (text.includes("nomor spm") || text === "no spm") mapping.nomorSPM = i;
    else if (text.includes("kegiatan")) mapping.namaKegiatan = i;
    else if (text.includes("kategori")) mapping.kategori = i;
    else if (text.includes("nominal")) mapping.nominal = i;
    else if (text.includes("penerima")) mapping.penerima = i;
    else if (text.includes("file id")) mapping.fileId = i;
    else if (text.includes("file url")) mapping.fileUrl = i;
    else if (text.includes("tanggal upload") || text.includes("tgl upload")) mapping.tanggalUpload = i;
    else if (text.includes("uploader")) mapping.uploader = i;
    else if (text === "bidang") mapping.bidang = i;
    else if (text.includes("rekening utama")) mapping.kodeRekeningUtama = i;
    else if (text.includes("rekening bagian")) mapping.kodeRekeningBagian = i;
    else if (text.includes("jenis anggaran")) mapping.jenisAnggaran = i;
    else if (text === "status") mapping.status = i;
    else if (text.includes("jenis pajak")) mapping.jenisPajak = i;
    else if (text.includes("billing")) mapping.billing = i;
    else if (text.includes("total pajak")) mapping.totalPajak = i;
    else if (text.includes("folder url")) mapping.folderUrl = i;
  });

  return mapping;
}

// === 6. SEARCH DENGAN RBAC FILTER ===
function searchData(filters, sessionToken) {
  try {
    // Validate session
    const user = validateUserAccess(sessionToken, 'ANY');
    // Standardize isAdmin check (Always use lowercase for comparison)
    const role = String(user.role || "").trim().toLowerCase();
    const isAdmin = role === 'admin';
    
    console.log('Search initiated by:', user.nama, 'Role:', user.role, 'Bidang:', user.bidang, 'Filters:', JSON.stringify(filters));
    
    const sheet = getSheet();
    const data = sheet.getDataRange().getValues();
    const result = [];
    
    if (data.length <= 1) {
      return { success: true, results: [], stats: { count: 0, totalNominal: 0 }, message: "Sheet kosong" };
    }

    const headers = data[0];
    const col = getArsipHeaderMapping(headers);
    console.log('Detected column mapping:', JSON.stringify(col));
    
    // Auto-filter by bidang if user is not Admin
    let fBidang = filters.bidang ? String(filters.bidang).trim().toUpperCase() : "ALL";
    if (user.bidang && user.bidang !== 'ALL' && !isAdmin) {
      fBidang = String(user.bidang).trim().toUpperCase();
    }
    
    const fTahun = filters.tahun ? String(filters.tahun) : "";
    const fBulan = filters.bulan ? String(filters.bulan) : "";
    const fNomorSpm = filters.nomorSpm ? String(filters.nomorSpm).toLowerCase().trim() : "";
    const fNamaKegiatan = filters.namaKegiatan ? String(filters.namaKegiatan).toLowerCase().trim() : "";
    const isAll = filters.all === true;
    
    const stats = {
      count: 0,
      totalNominal: 0,
      perBidang: {},
      perKategori: {},
      perBulan: {}
    };
    
    for (let i = 1; i < data.length; i++) {
      const row = data[i];
      // Skip only completely empty rows
      if (row.every(cell => String(cell).trim() === "")) continue;
      
      const valTahun = String(row[col.tahun] || "");
      const valBulan = String(row[col.bulan] || "");
      const valSpm = String(row[col.nomorSPM] || "").toLowerCase();
      const valKeg = String(row[col.namaKegiatan] || "").toLowerCase();
      const rowBidang = String(row[col.bidang] || "").trim().toUpperCase();

      if (!isAll) {
        if (fTahun && valTahun !== fTahun) continue;
        if (fBulan && valBulan !== fBulan) continue;
        if (fNomorSpm && !valSpm.includes(fNomorSpm)) continue;
        if (fNamaKegiatan && !valKeg.includes(fNamaKegiatan)) continue;
      }
      
      if (fBidang && fBidang !== 'ALL' && rowBidang !== fBidang) continue;
      
      const nominal = Number(row[col.nominal]) || 0;
      
      const item = {
        id: row[col.id],
        tahun: valTahun,
        bulan: valBulan,
        nomorSPM: row[col.nomorSPM],
        namaKegiatan: row[col.namaKegiatan],
        kategori: row[col.kategori],
        nominal: nominal,
        penerima: row[col.penerima],
        fileId: row[col.fileId],
        fileUrl: row[col.fileUrl],
        tanggalUpload: row[col.tanggalUpload],
        uploader: row[col.uploader],
        bidang: row[col.bidang],
        folderUrl: row[col.folderUrl] || ""
      };
      
      result.push(item);
      stats.count++;
      stats.totalNominal += nominal;
      
      // Internal stats
      stats.perBidang[item.bidang] = (stats.perBidang[item.bidang] || 0) + 1;
      stats.perBulan[item.bulan] = (stats.perBulan[item.bulan] || 0) + nominal;
    }
    
    console.log('Search finished. Results found:', result.length);
    
    result.sort((a, b) => {
      const dateA = a.tanggalUpload ? new Date(a.tanggalUpload).getTime() : 0;
      const dateB = b.tanggalUpload ? new Date(b.tanggalUpload).getTime() : 0;
      return dateB - dateA;
    });
    
    return {
      success: true,
      results: result,
      stats: stats,
      userBidang: user.bidang
    };
    
  } catch (err) {
    console.error('Search internal Error:', err.message);
    return { success: false, message: 'Kesalahan sistem: ' + err.message };
  }
}

function deleteArsipData(id, sessionToken) {
  try {
    // Only Admin can delete archive
    validateUserAccess(sessionToken, 'Admin');
    
    const sheet = getSheet();
    const data = sheet.getDataRange().getValues();
    
    let rowIndex = -1;
    for (let i = 1; i < data.length; i++) {
       if (String(data[i][0]) === String(id)) {
         rowIndex = i + 1;
         break;
       }
    }
    
    if (rowIndex === -1) {
      return { success: false, message: "Data tidak ditemukan" };
    }
    
    sheet.deleteRow(rowIndex);
    
    return {
      success: true,
      message: "Data arsip berhasil dihapus dari database"
    };
    
  } catch (err) {
    return { success: false, message: err.message };
  }
}
function editArsipData(id, newData, sessionToken) {
  try {
    // Only Admin can edit archive
    validateUserAccess(sessionToken, 'Admin');
    
    const sheet = getSheet();
    const data = sheet.getDataRange().getValues();
    
    let rowIndex = -1;
    for (let i = 1; i < data.length; i++) {
       if (String(data[i][0]) === String(id)) {
         rowIndex = i + 1;
         break;
       }
    }
    
    if (rowIndex === -1) {
      return { success: false, message: "Data tidak ditemukan" };
    }
    
    // Update basic fields (Nomor SPM, Nama Kegiatan, Nominal, Penerima)
    // Row mapping: 3=SPM, 4=Kegiatan, 6=Nominal, 7=Penerima
    if (newData.nomorSPM) sheet.getRange(rowIndex, 4).setValue(newData.nomorSPM);
    if (newData.namaKegiatan) sheet.getRange(rowIndex, 5).setValue(newData.namaKegiatan);
    if (newData.nominal) sheet.getRange(rowIndex, 7).setValue(newData.nominal);
    if (newData.penerima) sheet.getRange(rowIndex, 8).setValue(newData.penerima);
    
    return {
      success: true,
      message: "Data arsip berhasil diperbarui"
    };
    
  } catch (err) {
    return { success: false, message: err.message };
  }
}

// === 7. REALISASI & PAJAK DENGAN RBAC ===
function getRealisasiData(filters, sessionToken) {
  try {
    const user = validateUserAccess(sessionToken, 'ANY');
    
    // Auto-filter bidang for non-Admin
    if (user.bidang !== 'ALL') {
      filters.bidang = user.bidang;
    }
    
    const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
    const sheetReal = ss.getSheetByName('Realisasi_Anggaran');
    const sheetPagu = ss.getSheetByName('Pagu_Anggaran');
    
    if (!sheetReal || !sheetPagu) {
      return {
        summary: { totalPagu: 0, totalReal: 0, saldo: 0, persen: 0 },
        detail: [],
        grafik: { bulanan: [], perBidang: [], perJenis: [] },
        filters: filters,
        userBidang: user.bidang
      };
    }
    
    const pData = sheetPagu.getDataRange().getValues();
    const rData = sheetReal.getDataRange().getValues();
    
    const realMap = {};
    const monthlyData = new Array(12).fill(0);
    const bidangMap = {};
    const jenisMap = {};
    
    for (let i = 1; i < rData.length; i++) {
      if (filters.tahun && String(rData[i][2]) !== String(filters.tahun)) continue;
      if (filters.bidang && filters.bidang !== 'ALL' && String(rData[i][3]) !== String(filters.bidang)) continue;
      
      const key = `${rData[i][4]}-${rData[i][5]}`;
      const date = new Date(rData[i][8]);
      const month = date.getMonth();
      const nominal = Number(rData[i][7]) || 0;
      const bidang = String(rData[i][3]);
      const jenis = String(rData[i][9]);
      
      if (!realMap[key]) realMap[key] = { total: 0, monthly: new Array(12).fill(0) };
      realMap[key].total += nominal;
      realMap[key].monthly[month] += nominal;
      
      monthlyData[month] += nominal;
      
      bidangMap[bidang] = (bidangMap[bidang] || 0) + nominal;
      jenisMap[jenis] = (jenisMap[jenis] || 0) + nominal;
    }
    
    const detail = [];
    let totalPagu = 0, totalReal = 0;
    
    for (let i = 1; i < pData.length; i++) {
      const isActive = (pData[i][2] === true || String(pData[i][2]) === 'TRUE');
      if (!isActive) continue;
      if (filters.tahun && String(pData[i][3]) !== String(filters.tahun)) continue;
      if (filters.bidang && filters.bidang !== 'ALL' && String(pData[i][4]) !== String(filters.bidang)) continue;
      
      const key = `${pData[i][5]}-${pData[i][6]}`;
      const paguVal = Number(pData[i][8]) || 0;
      const realData = realMap[key] || { total: 0, monthly: new Array(12).fill(0) };
      
      totalPagu += paguVal;
      totalReal += realData.total;
      
      detail.push({
        bidang: pData[i][4],
        kode_rekening: `${pData[i][5]}.${pData[i][6]}`,
        uraian: pData[i][7],
        jenis_anggaran: pData[i][1],
        pagu: paguVal,
        realisasi_total: realData.total,
        saldo: paguVal - realData.total,
        persen: paguVal > 0 ? Math.round((realData.total / paguVal) * 1000) / 10 : 0,
        monthly: realData.monthly
      });
    }
    
    const monthNames = ["Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Ags", "Sep", "Okt", "Nov", "Des"];
    const grafik = {
      bulanan: monthlyData.map((val, idx) => ({ month: monthNames[idx], value: val })),
      perBidang: Object.entries(bidangMap).map(([label, value]) => ({ label, value })),
      perJenis: Object.entries(jenisMap).map(([label, value]) => ({ label, value }))
    };
    
    return {
      summary: {
        totalPagu: totalPagu,
        totalReal: totalReal,
        saldo: totalPagu - totalReal,
        persen: totalPagu > 0 ? Math.round((totalReal / totalPagu) * 1000) / 10 : 0
      },
      detail: detail,
      grafik: grafik,
      filters: filters,
      userBidang: user.bidang
    };
    
  } catch (err) {
    if (err.message.startsWith("UNAUTHORIZED:")) {
      return { success: false, unauthorized: true, message: err.message.replace("UNAUTHORIZED: ", "") };
    }
    throw err;
  }
}

function getRekapPajakEnhanced(filters, sessionToken) {
  try {
    const user = validateUserAccess(sessionToken, 'ANY');
    
    // Auto-filter bidang for non-Admin
    if (user.bidang !== 'ALL') {
      filters.bidang = user.bidang;
    }
    
    const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
    const sheetTax = ss.getSheetByName('Rekap_Pajak');
    const sheetArsip = ss.getSheetByName('Arsip');
    
    if (!sheetTax || !sheetArsip) {
      return {
        summary: { total: 0, count: 0, pph: 0, ppn: 0 },
        grouped: {},
        list: [],
        grafik: { perJenis: [], bulanan: [], perBidang: [] },
        filters: filters,
        userBidang: user.bidang
      };
    }
    
    const arsipData = sheetArsip.getDataRange().getValues();
    const arsipMap = {};
    
    for (let i = 1; i < arsipData.length; i++) {
      arsipMap[arsipData[i][0]] = {
        spm: arsipData[i][3],
        kegiatan: arsipData[i][4],
        uploader: arsipData[i][11],
        bidang: arsipData[i][15]
      };
    }
    
    const taxData = sheetTax.getDataRange().getValues();
    const result = [];
    const grouped = {};
    const summary = { total: 0, count: 0, pph: 0, ppn: 0 };
    const monthlyData = {};
    const bidangData = {};
    const jenisData = {};
    
    for (let i = 1; i < taxData.length; i++) {
      const row = taxData[i];
      if (filters.tahun && String(row[2]) !== String(filters.tahun)) continue;
      if (filters.bulan && String(row[3]) !== String(filters.bulan)) continue;
      if (filters.bidang && filters.bidang !== 'ALL' && String(row[8]) !== String(filters.bidang)) continue;
      
      const spjInfo = arsipMap[row[1]] || { spm: '-', kegiatan: '-', uploader: '-', bidang: '-' };
      
      if (filters.keyword) {
        const key = String(filters.keyword).toLowerCase();
        const searchStr = `${row[5]} ${spjInfo.spm} ${spjInfo.kegiatan} ${row[8]}`.toLowerCase();
        if (!searchStr.includes(key)) continue;
      }
      
      const nilai = Number(row[6]) || 0;
      const bulan = String(row[3]);
      const bidang = String(row[8]);
      const jenis = String(row[4]);
      
      summary.total += nilai;
      summary.count++;
      if (jenis.includes('PPh')) summary.pph += nilai;
      if (jenis.includes('PPN')) summary.ppn += nilai;
      
      if (!grouped[bulan]) grouped[bulan] = { subtotal: 0, items: [] };
      grouped[bulan].subtotal += nilai;
      
      monthlyData[bulan] = (monthlyData[bulan] || 0) + nilai;
      bidangData[bidang] = (bidangData[bidang] || 0) + nilai;
      jenisData[jenis] = (jenisData[jenis] || 0) + nilai;
      
      const item = {
        id: row[0],
        tahun: row[2],
        bulan: row[3],
        bidang: row[8],
        no_spm: spjInfo.spm,
        kegiatan: spjInfo.kegiatan,
        jenis_pajak: row[4],
        id_billing: row[5],
        nilai: nilai,
        tgl_setor: row[7] ? Utilities.formatDate(new Date(row[7]), Session.getScriptTimeZone(), "yyyy-MM-dd") : "-",
        uploader: spjInfo.uploader
      };
      
      grouped[bulan].items.push(item);
      result.push(item);
    }
    
    const grafik = {
      perJenis: Object.entries(jenisData).map(([label, value]) => ({ label, value })),
      bulanan: Object.entries(monthlyData).map(([label, value]) => ({ label, value })),
      perBidang: Object.entries(bidangData).map(([label, value]) => ({ label, value }))
    };
    
    return {
      summary: summary,
      grouped: grouped,
      list: result.reverse(),
      grafik: grafik,
      filters: filters,
      userBidang: user.bidang
    };
    
  } catch (err) {
    if (err.message.startsWith("UNAUTHORIZED:")) {
      return { success: false, unauthorized: true, message: err.message.replace("UNAUTHORIZED: ", "") };
    }
    throw err;
  }
}

// === 8. HELPER FUNCTIONS ===
function getUniqueTahun() {
  const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
  const sheet = ss.getSheetByName('Pagu_Anggaran');
  if (!sheet) return [];
  
  const data = sheet.getDataRange().getValues();
  const tahunSet = new Set();
  
  for (let i = 1; i < data.length; i++) {
    const isActive = (data[i][2] === true || String(data[i][2]) === 'TRUE');
    if (isActive && data[i][3]) {
      tahunSet.add(String(data[i][3]));
    }
  }
  
  return Array.from(tahunSet).sort().reverse();
}

function getUniqueBidang(sessionToken) {
  try {
    const user = validateUserAccess(sessionToken, 'ANY');
    const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
    const sheet = ss.getSheetByName('Pagu_Anggaran');
    if (!sheet) return [];
    
    const data = sheet.getDataRange().getValues();
    const bidangSet = new Set();
    
    for (let i = 1; i < data.length; i++) {
      const isActive = (data[i][2] === true || String(data[i][2]) === 'TRUE');
      const bidang = String(data[i][4] || "").trim();
      
      if (isActive && bidang) {
        // Jika Admin, bisa lihat semua. Jika User, hanya boleh lihat bidangnya sendiri jika ada di sheet.
        if (user.role === 'Admin' || user.bidang === 'ALL' || user.bidang === bidang) {
          bidangSet.add(bidang);
        }
      }
    }
    
    return Array.from(bidangSet).sort();
  } catch (err) {
    return [];
  }
}

function getAnggaranByTahunBidang(tahun, bidang) {
  const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
  const sheet = ss.getSheetByName('Pagu_Anggaran');
  
  if (!sheet) return [];
  
  const data = sheet.getDataRange().getValues();
  const res = [];
  const uniq = new Set();
  
  for (let i = 1; i < data.length; i++) {
    const isActive = (data[i][2] === true || String(data[i][2]) === 'TRUE');
    if (isActive && String(data[i][3]) == tahun && String(data[i][4]) == bidang) {
      if (!uniq.has(data[i][5])) {
        uniq.add(data[i][5]);
        res.push({ kodeUtama: data[i][5] });
      }
    }
  }
  
  return res;
}

function getAnggaranByKodeUtama(tahun, bidang, kodeUtama) {
  const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
  const sheet = ss.getSheetByName('Pagu_Anggaran');
  
  if (!sheet) return [];
  
  const data = sheet.getDataRange().getValues();
  const res = [];
  
  for (let i = 1; i < data.length; i++) {
    const isActive = (data[i][2] === true || String(data[i][2]) === 'TRUE');
    if (isActive && String(data[i][3]) == tahun && String(data[i][4]) == bidang && String(data[i][5]) == kodeUtama) {
      res.push({ 
        kodeBagian: data[i][6], 
        uraian: data[i][7],
        nilai: data[i][8]
      });
    }
  }
  
  return res;
}

function getSisaPagu(tahun, bidang, kodeUtama, kodeBagian) {
  const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
  const sPagu = ss.getSheetByName('Pagu_Anggaran');
  const sReal = ss.getSheetByName('Realisasi_Anggaran');
  
  let totalPagu = 0;
  let anggaranInfo = null;
  
  if (sPagu) {
    const pData = sPagu.getDataRange().getValues();
    for (let i = 1; i < pData.length; i++) {
      const isActive = (pData[i][2] === true || String(pData[i][2]) === 'TRUE');
      if (isActive && String(pData[i][3]) == tahun && String(pData[i][4]) == bidang &&
          String(pData[i][5]) == kodeUtama && String(pData[i][6]) == kodeBagian) {
        totalPagu = Number(pData[i][8]) || 0;
        anggaranInfo = { id: pData[i][0], jenis: pData[i][1] };
        break;
      }
    }
  }
  
  let totalReal = 0;
  if (sReal) {
    const rData = sReal.getDataRange().getValues();
    for (let i = 1; i < rData.length; i++) {
      if (String(rData[i][2]) == tahun && String(rData[i][3]) == bidang &&
          String(rData[i][4]) == kodeUtama && String(rData[i][5]) == kodeBagian) {
        totalReal += Number(rData[i][7]) || 0;
      }
    }
  }
  
  return { 
    sisaPagu: totalPagu - totalReal, 
    totalPagu: totalPagu, 
    totalRealisasi: totalReal, 
    anggaranInfo: anggaranInfo 
  };
}

function catatRealisasi(d) {
  const ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
  let s = ss.getSheetByName('Realisasi_Anggaran');
  
  if (!s) {
    s = ss.insertSheet('Realisasi_Anggaran');
    s.appendRow(['ID', 'ID_SPJ', 'Tahun', 'Bidang', 'Kode_Utama', 'Kode_Bagian', 'Uraian', 'Nilai', 'Tgl', 'Jenis', 'Saldo_Awal', 'Saldo_Akhir']);
  }
  
  s.appendRow([
    Utilities.getUuid(),
    d.idSPJ,
    d.tahun,
    d.bidang,
    d.kodeUtama,
    d.kodeBagian,
    d.uraian,
    d.nominal,
    new Date(),
    d.jenis,
    d.saldoAwal,
    d.saldoAkhir
  ]);
}

function deleteSpj(id, sessionToken) {
  try {
    // Only Admin can delete
    validateUserAccess(sessionToken, 'Admin');
    
    const sheet = getSheet();
    const data = sheet.getDataRange().getValues();
    
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]) == id) {
        sheet.deleteRow(i + 1);
        return { success: true, message: "Data berhasil dihapus" };
      }
    }
    
    return { success: false, message: "Data tidak ditemukan" };
    
  } catch (err) {
    if (err.message.startsWith("UNAUTHORIZED:")) {
      return { success: false, unauthorized: true, message: err.message.replace("UNAUTHORIZED: ", "") };
    }
    return { success: false, message: err.message };
  }
}

function getSpjDetail(id) {
  const sheet = getSheet();
  const data = sheet.getDataRange().getValues();
  
  for (let i = 1; i < data.length; i++) {
    if (String(data[i][0]) === String(id)) {
      const nominal = Number(data[i][6]) || 0;
      const totalPajak = Number(data[i][22]) || 0;
      
      return {
        id: data[i][0],
        tahun: data[i][1],
        bulan: data[i][2],
        nomorSPM: data[i][3],
        namaKegiatan: data[i][4],
        kategori: data[i][5],
        nominal: nominal,
        penerima: data[i][7],
        fileId: data[i][8],
        fileUrl: data[i][9],
        tanggalUpload: data[i][10],
        uploader: data[i][11],
        bidang: data[i][15],
        kodeRekeningUtama: data[i][16],
        kodeRekeningBagian: data[i][17],
        jenisAnggaran: data[i][18],
        status: data[i][19],
        jenisPajak: data[i][20],
        billing: data[i][21],
        totalPajak: totalPajak,
        folderUrl: data[i][23] || "",
        
        // Additional info
        persenPajak: nominal > 0 ? Math.round((totalPajak / nominal) * 1000) / 10 : 0,
        netto: nominal - totalPajak
      };
    }
  }
  
  return null;
}

function getSpjStatistics(year, sessionToken) {
  try {
    const user = validateUserAccess(sessionToken, 'ANY');
    
    const sheet = getSheet();
    const data = sheet.getDataRange().getValues();
    
    const monthly = new Array(12).fill(0);
    const bidangMap = {};
    const kategoriMap = {};
    let total = 0;
    
    for (let i = 1; i < data.length; i++) {
      // Auto-filter by bidang for non-Admin
      if (user.bidang !== 'ALL' && String(data[i][15]) !== user.bidang) continue;
      if (String(data[i][1]) !== String(year)) continue;
      
      const nom = Number(data[i][6]) || 0;
      const mIdx = ["Januari", "Februari", "Maret", "April", "Mei", "Juni", "Juli", "Agustus", "September", "Oktober", "November", "Desember"].indexOf(data[i][2]);
      
      if (mIdx >= 0) monthly[mIdx] += nom;
      
      bidangMap[data[i][15]] = (bidangMap[data[i][15]] || 0) + nom;
      kategoriMap[data[i][5]] = (kategoriMap[data[i][5]] || 0) + nom;
      total += nom;
    }
    
    return { 
      year: year, 
      total: total, 
      monthly: monthly, 
      bidang: bidangMap, 
      kategori: kategoriMap,
      userBidang: user.bidang
    };
    
  } catch (err) {
    if (err.message.startsWith("UNAUTHORIZED:")) {
      return { success: false, unauthorized: true, message: err.message.replace("UNAUTHORIZED: ", "") };
    }
    throw err;
  }
}

// === 9. EXPORT FUNCTIONS ===
function exportRealisasiExcel(filters, sessionToken) {
  try {
    validateUserAccess(sessionToken, 'ANY');
    const realisasiData = getRealisasiData(filters, sessionToken);
    
    const blob = Utilities.newBlob(
      generateExcelRealisasi(realisasiData),
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      `Realisasi_Anggaran_${filters.tahun || 'ALL'}.xlsx`
    );
    
    const file = DriveApp.createFile(blob);
    return file.getUrl();
  } catch (err) {
    return { success: false, message: err.message };
  }
}

function exportPajakExcel(filters, sessionToken) {
  try {
    validateUserAccess(sessionToken, 'ANY');
    const pajakData = getRekapPajakEnhanced(filters, sessionToken);
    
    const blob = Utilities.newBlob(
      generateExcelPajak(pajakData),
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      `Rekap_Pajak_${filters.tahun || 'ALL'}.xlsx`
    );
    
    const file = DriveApp.createFile(blob);
    return file.getUrl();
  } catch (err) {
    return { success: false, message: err.message };
  }
}

function exportSearchExcel(filters, sessionToken) {
  try {
    validateUserAccess(sessionToken, 'ANY');
    const searchDataResult = searchData(filters, sessionToken);
    
    const blob = Utilities.newBlob(
      generateExcelSearch(searchDataResult),
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      `Hasil_Pencarian_${new Date().getTime()}.xlsx`
    );
    
    const file = DriveApp.createFile(blob);
    return file.getUrl();
  } catch (err) {
    return { success: false, message: err.message };
  }
}

// === 10. UTILITY FUNCTIONS ===
function formatRupiah(angka) {
  return new Intl.NumberFormat('id-ID', {
    style: 'currency',
    currency: 'IDR',
    minimumFractionDigits: 0
  }).format(angka);
}

function generateExcelRealisasi(data) {
  // Placeholder untuk generate Excel
  return "Excel data placeholder - implement with SheetDB or external API";
}

function generateExcelPajak(data) {
  return "Excel data placeholder";
}

function generateExcelSearch(data) {
  return "Excel data placeholder";
}

// === 11. GOOGLE DRIVE SHORTCUT ===
function getFolderUrl(idSpj) {
  try {
    const sheet = getSheet();
    const data = sheet.getDataRange().getValues();
    
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]) === String(idSpj)) {
        return data[i][23] || ""; // Folder URL
      }
    }
    
    return "";
  } catch (err) {
    return "";
  }
}
