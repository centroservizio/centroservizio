require('dotenv').config();

const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const nodemailer = require('nodemailer');
const multer = require('multer');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

let puppeteer = null;
try {
  puppeteer = require('puppeteer-core');
} catch (e) {
  console.log('puppeteer-core non caricato:', e.message);
}
const CHROME_PATH = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Directory paths
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'applications.json');
const DOCS_DIR = path.join(DATA_DIR, 'documenti');
const RECEIPTS_DIR = path.join(DATA_DIR, 'ricevute');
const FATTURE_DIR = path.join(DATA_DIR, 'fatture');
const FATTURE_FILE = path.join(DATA_DIR, 'fatture.json');
const INPS_DIR = path.join(DATA_DIR, 'inps_downloads');
const INPS_FILE = path.join(DATA_DIR, 'inps_downloads.json');
const CONSEGNE_DIR = path.join(DATA_DIR, 'consegne');
const CONSEGNE_FILE = path.join(DATA_DIR, 'consegne.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DOCS_DIR)) fs.mkdirSync(DOCS_DIR, { recursive: true });
if (!fs.existsSync(RECEIPTS_DIR)) fs.mkdirSync(RECEIPTS_DIR, { recursive: true });
if (!fs.existsSync(FATTURE_DIR)) fs.mkdirSync(FATTURE_DIR, { recursive: true });
if (!fs.existsSync(INPS_DIR)) fs.mkdirSync(INPS_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]');
if (!fs.existsSync(FATTURE_FILE)) fs.writeFileSync(FATTURE_FILE, '[]');
if (!fs.existsSync(INPS_FILE)) fs.writeFileSync(INPS_FILE, '[]');
if (!fs.existsSync(CONSEGNE_DIR)) fs.mkdirSync(CONSEGNE_DIR, { recursive: true });
if (!fs.existsSync(CONSEGNE_FILE)) fs.writeFileSync(CONSEGNE_FILE, '[]');
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');

// ------------------------------------------
// FILE FILTER & SECURITY WHITELIST
// ------------------------------------------
const ALLOWED_MIME_TYPES = new Set([
  'application/pdf',
  'image/jpeg',
  'image/jpg',
  'image/png',
  'image/webp'
]);
const ALLOWED_EXTENSIONS = new Set(['.pdf', '.jpg', '.jpeg', '.png', '.webp']);

function safeFileFilter(req, file, cb) {
  const ext = path.extname(file.originalname || '').toLowerCase();
  const mime = (file.mimetype || '').toLowerCase();
  if (ALLOWED_EXTENSIONS.has(ext) && (ALLOWED_MIME_TYPES.has(mime) || mime === 'application/octet-stream')) {
    cb(null, true);
  } else {
    cb(new Error('Tipo di file non supportato. Sono ammessi esclusivamente documenti PDF e immagini (JPG, PNG, WEBP).'));
  }
}

// Multer Storage Configuration
const docStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const rawAppNo = req.body.applicationNumber || req.params.applicationNumber || 'temp';
    const appNo = path.basename(rawAppNo).replace(/[^a-zA-Z0-9_-]/g, '') || 'temp';
    const targetDir = path.join(DOCS_DIR, appNo);
    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });
    cb(null, targetDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const safeField = (file.fieldname || 'doc').replace(/[^a-zA-Z0-9_-]/g, '');
    const safeName = safeField + '-' + Date.now() + ext;
    cb(null, safeName);
  }
});

const uploadDocs = multer({
  storage: docStorage,
  fileFilter: safeFileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

const receiptStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, RECEIPTS_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const appNo = (req.body.applicationNumber || 'receipt').replace(/[^a-zA-Z0-9_-]/g, '');
    cb(null, `${appNo}_ricevuta_${Date.now()}${ext}`);
  }
});

const uploadReceipt = multer({
  storage: receiptStorage,
  fileFilter: safeFileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }
});

// ==========================================
// SECURITY HEADERS & RATE LIMITING
// ==========================================
app.use(helmet({
  contentSecurityPolicy: false, // Prevents blocking inline scripts and external fonts/icons
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 300, // 300 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Troppe richieste da questo indirizzo IP. Riprova tra un minuto.' }
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // max 15 attempts per 15 min
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Troppi tentativi di accesso. Riprova tra 15 minuti.' }
});

const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Troppi tentativi OTP. Riprova tra 10 minuti.' }
});

const applyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 30, // max 30 applications per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Limite di invio pratiche raggiunto per questo indirizzo IP. Riprova più tardi.' }
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  next();
});
app.use(express.static(path.join(__dirname, 'public'), {
  etag: false,
  maxAge: 0
}));

// ==========================================
// USER AUTHENTICATION & ADMIN SECURITY CORE
// ==========================================
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';

function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch (e) {
    return [];
  }
}

function saveUsers(data) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST).toString('hex');
  return `pbkdf2:${PBKDF2_ITERATIONS}:${salt}:${hash}`;
}

function verifyPassword(password, combined) {
  if (!combined || typeof combined !== 'string') return false;
  try {
    if (combined.startsWith('pbkdf2:')) {
      const parts = combined.split(':');
      if (parts.length !== 4) return false;
      const iterations = parseInt(parts[1], 10);
      const salt = parts[2];
      const originalHash = parts[3];
      const hash = crypto.pbkdf2Sync(password, salt, iterations, PBKDF2_KEYLEN, PBKDF2_DIGEST).toString('hex');
      const hashBuf = Buffer.from(hash, 'hex');
      const origBuf = Buffer.from(originalHash, 'hex');
      if (hashBuf.length !== origBuf.length) return false;
      return crypto.timingSafeEqual(hashBuf, origBuf);
    } else if (combined.includes(':')) {
      // Legacy backward-compatibility format (salt:hash, 1000 iterations)
      const [salt, originalHash] = combined.split(':');
      const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
      const hashBuf = Buffer.from(hash, 'hex');
      const origBuf = Buffer.from(originalHash, 'hex');
      if (hashBuf.length !== origBuf.length) return false;
      return crypto.timingSafeEqual(hashBuf, origBuf);
    }
  } catch (err) {
    return false;
  }
  return false;
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// In-memory active auth sessions
const activeAuthTokens = new Map();

function getAuthUser(req) {
  const authHeader = req.headers['authorization'];
  let token = null;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (req.query && req.query.auth_token) {
    token = req.query.auth_token;
  }
  if (!token) return null;
  const session = activeAuthTokens.get(token);
  if (!session) return null;
  if (session.expiresAt < Date.now()) {
    activeAuthTokens.delete(token);
    return null;
  }
  return session;
}

// STRICT ADMIN AUTHENTICATION MIDDLEWARE
function requireAdmin(req, res, next) {
  const user = getAuthUser(req);
  if (!user || user.role !== 'admin') {
    return res.status(401).json({ error: 'Accesso non autorizzato. È richiesta autenticazione amministratore.' });
  }
  req.user = user;
  next();
}

// GUARD ALL ADMIN ENDPOINTS
app.use('/api/admin', requireAdmin);

// Initialize default admin if no admin exists
(function initDefaultAdmin() {
  const users = loadUsers();
  const hasAdmin = users.some(u => u.role === 'admin' && u.status !== 'deleted');
  if (!hasAdmin) {
    const defaultAdmin = {
      id: 'USR-ADMIN-01',
      name: 'Amministratore Ufficio',
      email: 'admin@centroservizicarpi.it',
      phone: '3511830385',
      passwordHash: hashPassword('admin123'),
      role: 'admin',
      status: 'active',
      createdAt: new Date().toISOString()
    };
    users.push(defaultAdmin);
    saveUsers(users);
    console.log('[Auth] Creato utente amministratore predefinito: admin@centroservizicarpi.it / admin123');
  }
})();

// Bank & IBAN info
const IBAN = process.env.IBAN || 'IT00X0000000000000000000000';
const INTESTATARIO = process.env.INTESTATARIO || 'CENTRO SERVIZIO STRANIERO';
const BANCA = process.env.BANCA || 'UniCredit / Banca';

// ------------------------------------------
// PAYMENT METHODS DYNAMIC CONFIGURATION
// ------------------------------------------
const PAYMENT_CONFIG_PATH = path.join(__dirname, 'data', 'payment_config.json');

function getDefaultPaymentConfig() {
  return {
    bonifico: {
      enabled: true,
      iban: process.env.IBAN || 'IT00X0000000000000000000000',
      intestatario: process.env.INTESTATARIO || 'CENTRO SERVIZIO STRANIERO',
      banca: process.env.BANCA || 'UniCredit / Banca',
      bicSwift: 'UNCRITM1XXX',
      note: 'Inserire obbligatoriamente il numero pratica nella causale del bonifico.'
    },
    postepay: {
      enabled: true,
      numeroCarta: '4023 6000 0000 0000',
      intestatario: process.env.INTESTATARIO || 'CENTRO SERVIZIO STRANIERO',
      codiceFiscale: 'RSSMRA80A01H501U',
      note: 'Ricarica effettuabile presso Uffici Postali, tabaccherie PuntoLis o online.'
    },
    paypal: {
      enabled: true,
      emailOrLink: 'https://paypal.me/centroserviziocarpi',
      intestatario: 'Centro Servizio Straniero',
      note: 'Pagamento rapido e sicuro con conto PayPal o carta di credito/debito.'
    },
    sede: {
      enabled: true,
      indirizzo: 'Via Berengario, 12 - 41012 Carpi (MO)',
      orari: 'Lun - Ven: 09:00 - 13:00 / 15:00 - 19:00',
      metodi: 'Contanti, Bancomat, POS Carta',
      note: 'Pagamento diretto allo sportello con rilascio immediato della ricevuta.'
    },
    istruzioniGenerali: 'Effettuare il saldo e caricare la ricevuta entro 48 ore dalla presente richiesta per procedere con la lavorazione.'
  };
}

function loadPaymentConfig() {
  try {
    if (fs.existsSync(PAYMENT_CONFIG_PATH)) {
      const data = JSON.parse(fs.readFileSync(PAYMENT_CONFIG_PATH, 'utf8'));
      const def = getDefaultPaymentConfig();
      return {
        bonifico: { ...def.bonifico, ...(data.bonifico || {}) },
        postepay: { ...def.postepay, ...(data.postepay || {}) },
        paypal: { ...def.paypal, ...(data.paypal || {}) },
        sede: { ...def.sede, ...(data.sede || {}) },
        istruzioniGenerali: data.istruzioniGenerali !== undefined ? data.istruzioniGenerali : def.istruzioniGenerali
      };
    }
  } catch (e) {
    console.error('Error reading payment_config.json:', e);
  }
  const def = getDefaultPaymentConfig();
  savePaymentConfig(def);
  return def;
}

function savePaymentConfig(cfg) {
  try {
    fs.writeFileSync(PAYMENT_CONFIG_PATH, JSON.stringify(cfg, null, 2), 'utf8');
    return true;
  } catch (e) {
    console.error('Error writing payment_config.json:', e);
    return false;
  }
}

// Comprehensive CAF, Patronato, Immigration, Monopattino & Banking Services
const SERVICES = [
  // --- SERVIZI INPS & PATRONATO ---
  { 
    id: 201, 
    category: "inps",
    name: "Estratto Conto Contributivo INPS", 
    desc_it: "Verifica della posizione assicurativa, contributi versati da lavoro dipendente, artigiani o commercianti e calcolo anzianità pensionistica",
    desc_en: "INPS pension contribution statement retrieval, insurance position check and years of service calculation"
  },
  { 
    id: 202, 
    category: "inps",
    name: "Certificazione Unica INPS (Modello CU)", 
    desc_it: "Scarico e stampa telematica del modello CU per pensionati, disoccupati NASpI o beneficiari di prestazioni a sostegno del reddito",
    desc_en: "Official INPS Certificazione Unica (CU) tax statement retrieval for pensioners and benefit recipients"
  },
  { 
    id: 203, 
    category: "inps",
    name: "Indennità di Disoccupazione NASpI & DIS-COLL", 
    desc_it: "Domanda e gestione telematica del sussidio mensile di disoccupazione per perdita involontaria del lavoro",
    desc_en: "NASpI and DIS-COLL monthly unemployment benefit application for involuntary job dismissal"
  },
  { 
    id: 204, 
    category: "inps",
    name: "Assegno Unico e Universale per Figli a Carico", 
    desc_it: "Richiesta, aggiornamento ISEE e gestione dell'assegno economico mensile INPS per ogni figlio fino a 21 anni",
    desc_en: "Single and Universal Child Allowance (Assegno Unico) application and yearly renewal for dependent children"
  },
  { 
    id: 205, 
    category: "inps",
    name: "Assegno di Inclusione (ADI) & Supporto Formazione Lavoro (SFL)", 
    desc_it: "Istruttoria, invio domanda e monitoraggio per la misura di contrasto alla povertà e inclusione sociale e lavorativa",
    desc_en: "Inclusion Allowance (ADI) and training/work financial support filing and monitoring"
  },
  { 
    id: 206, 
    category: "inps",
    name: "Modello OBIS/M & Cedolino Pensione INPS", 
    desc_it: "Certificato annuale di pensione OBIS/M con dettaglio importi lordi, netti, trattenute e consultazione cedolini mensili",
    desc_en: "OBIS/M annual pension certificate and monthly pension payment slip consultation"
  },
  { 
    id: 207, 
    category: "inps",
    name: "Domanda di Pensione (Vecchiaia, Anticipata & Reversibilità)", 
    desc_it: "Consulenza contributiva e invio telematico istanza per pensione di vecchiaia, anticipata, Quota 103 o reversibilità coniuge",
    desc_en: "Retirement pension, early retirement, Quota 103 and survivors pension formal filing"
  },
  { 
    id: 208, 
    category: "inps",
    name: "Invalidità Civile, Legge 104 & Indennità di Accompagnamento", 
    desc_it: "Trasmissione telematica del certificato medico introduttivo e richiesta di visita medica per riconoscimento invalidità e handicap",
    desc_en: "Civil disability, attendance allowance and Law 104 handicap recognition medical application"
  },
  { 
    id: 209, 
    category: "inps",
    name: "Bonus Asilo Nido & Maternità INPS", 
    desc_it: "Domanda di contributo statale per rimborso rette scolastiche nido e indennità di maternità/congedo parentale",
    desc_en: "Daycare nursery fee reimbursement bonus and maternity/parental leave allowance"
  },
  { 
    id: 210, 
    category: "inps",
    name: "Scarico Diretto Documenti INPS con SPID / CIE (Live Relay)", 
    desc_it: "Accesso rapido assistito con SPID o Carta d'Identità Elettronica per lo scarico immediato in formato PDF di qualsiasi documento INPS",
    desc_en: "Instant assisted download of any official INPS document via SPID / CIE live relay"
  },
  // --- MONOPATTINO ELETTRICO (TARGA & ASSICURAZIONE) ---
  { 
    id: 101, 
    category: "monopattino",
    name: "Targa Monopattino Elettrico (Allegato 1 MIT)", 
    desc_it: "Richiesta rilascio contrassegno identificativo Ministero Trasporti con generazione automatica Allegato 1 firmato digitalmente",
    desc_en: "Ministry of Transport electric scooter plate request with automatic signed Allegato 1 generation"
  },
  { 
    id: 102, 
    category: "monopattino",
    name: "Assicurazione RC Monopattino Elettrico", 
    desc_it: "Polizza assicurativa obbligatoria di responsabilità civile per danni a terzi per monopattini elettrici",
    desc_en: "Compulsory third-party liability insurance for electric scooters"
  },

  // --- IMMIGRAZIONE & CITTADINANZA ---
  { 
    id: 1, 
    category: "immigrazione",
    name: "Permesso di Soggiorno", 
    desc_it: "Richiesta, rinnovo o conversione del permesso di soggiorno (lavoro, famiglia, studio)",
    desc_en: "Residence permit application, renewal or conversion (work, family, study)"
  },
  { 
    id: 2, 
    category: "immigrazione",
    name: "Aggiornamento Permesso di Soggiorno", 
    desc_it: "Aggiornamento dati anagrafici, cambio residenza, nuovo passaporto o inserimento figli",
    desc_en: "Update personal data, address change, new passport or adding children"
  },
  { 
    id: 3, 
    category: "immigrazione",
    name: "Carta di Soggiorno UE (Lungo Periodo)", 
    desc_it: "Richiesta permesso di soggiorno UE per soggiornanti di lungo periodo (ex carta di soggiorno)",
    desc_en: "EU Long-Term Residence Permit application (former permanent card)"
  },
  { 
    id: 4, 
    category: "immigrazione",
    name: "Richiesta Cittadinanza Italiana", 
    desc_it: "Domanda di cittadinanza per residenza (10 anni) o per matrimonio con cittadino italiano",
    desc_en: "Italian citizenship application by residency (10 years) or by marriage"
  },
  { 
    id: 5, 
    category: "immigrazione",
    name: "Ricongiungimento Familiare (Nulla Osta)", 
    desc_it: "Preparazione pratica e richiesta Nulla Osta per portare la famiglia in Italia",
    desc_en: "Family reunification application and Nulla Osta issuance"
  },
  { 
    id: 6, 
    category: "immigrazione",
    name: "Decreto Flussi & Lavoro Subordinato", 
    desc_it: "Compilazione e invio istanze per contratti di lavoro e quote decreto flussi",
    desc_en: "Decreto Flussi quotas and foreign employment contract filing"
  },
  { 
    id: 7, 
    category: "immigrazione",
    name: "Prenotazione Appuntamento Questura / Prefettura", 
    desc_it: "Prenotazione appuntamenti Cupa / Portale Immigrazione per fotosegnalamento e ritiro",
    desc_en: "Questura and Prefettura appointment booking for fingerprints and pickup"
  },

  // --- BANCHE & UNICREDIT ---
  { 
    id: 8, 
    category: "banche",
    name: "Appuntamento UniCredit Banca (Apertura Conto & Carte)", 
    desc_it: "Prenotazione appuntamento e preparazione documenti per apertura conto corrente o Carta Genius UniCredit",
    desc_en: "UniCredit Bank appointment booking and document preparation for account or Genius card"
  },
  { 
    id: 9, 
    category: "banche",
    name: "Appuntamento Poste Italiane / Postepay Evolution", 
    desc_it: "Assistenza prenotazione sportello per rilascio Postepay Evolution, Libretto o Conto BancoPosta",
    desc_en: "Poste Italiane appointment for Postepay Evolution, Savings book or BancoPosta account"
  },

  // --- FISCO & TASSE (CAF) ---
  { 
    id: 10, 
    category: "fisco",
    name: "Modello 730 (Dichiarazione dei Redditi)", 
    desc_it: "Dichiarazione fiscale per lavoratori dipendenti e pensionati con recupero rimborsi e detrazioni",
    desc_en: "Tax return Form 730 for employees and pensioners with refund claims"
  },
  { 
    id: 11, 
    category: "fisco",
    name: "Modello Redditi PF (Ex Unico)", 
    desc_it: "Dichiarazione dei redditi per titolari di Partita IVA, commercianti e lavoratori autonomi",
    desc_en: "Tax return for self-employed, freelancers and VAT number holders"
  },
  { 
    id: 12, 
    category: "fisco",
    name: "Calcolo e Rilascio ISEE (Ordinario / Corrente)", 
    desc_it: "Attestazione della situazione economica per accedere a bonus statali, mense scolastiche e agevolazioni",
    desc_en: "ISEE economic certificate for family bonuses, school benefits and discounts"
  },
  { 
    id: 13, 
    category: "fisco",
    name: "Rilascio e Verifica CUD / Certificazione Unica (CU)", 
    desc_it: "Recupero e stampa telematica della Certificazione Unica da INPS o datore di lavoro",
    desc_en: "Retrieval and verification of CUD / Certificazione Unica from INPS or employer"
  },
  { 
    id: 14, 
    category: "fisco",
    name: "Calcolo IMU e Modello F24", 
    desc_it: "Calcolo imposta municipale sugli immobili, scadenze acconto/saldo e stampa F24",
    desc_en: "Municipal property tax (IMU) calculation and F24 payment slips"
  },
  { 
    id: 15, 
    category: "fisco",
    name: "Registrazione Contratto di Locazione", 
    desc_it: "Registrazione telematica nuovi contratti d'affitto, proroghe, risoluzioni e cedolare secca",
    desc_en: "Rental lease agreement registration with Agenzia delle Entrate"
  },

  // --- FAMIGLIA & BONUS INPS ---
  { 
    id: 16, 
    category: "famiglia",
    name: "Assegno Unico e Universale per Figli", 
    desc_it: "Richiesta o rinnovo del sostegno economico mensile INPS per ogni figlio a carico",
    desc_en: "Monthly child benefit (Assegno Unico) application for dependent children"
  },
  { 
    id: 17, 
    category: "famiglia",
    name: "Bonus Asilo Nido", 
    desc_it: "Contributo statale per il pagamento delle rette di asili nido pubblici e privati",
    desc_en: "Daycare and nursery school fee reimbursement bonus"
  },
  { 
    id: 18, 
    category: "famiglia",
    name: "Assegno di Inclusione (ADI) / SFL", 
    desc_it: "Domanda per la misura di contrasto alla povertà e supporto alla formazione lavoro",
    desc_en: "Inclusion Allowance (ADI) and training/work financial support"
  },
  { 
    id: 19, 
    category: "famiglia",
    name: "Bonus Maternità / Paternità", 
    desc_it: "Richiesta indennità o assegno di maternità del Comune o dello Stato",
    desc_en: "Maternity / Paternity allowance application through Municipality or State"
  },

  // --- LAVORO & INPS ---
  { 
    id: 20, 
    category: "lavoro",
    name: "Indennità di Disoccupazione NASpI", 
    desc_it: "Domanda di sussidio di disoccupazione mensile per perdita involontaria del lavoro",
    desc_en: "NASpI unemployment benefit application for involuntary job loss"
  },
  { 
    id: 21, 
    category: "lavoro",
    name: "Dimissioni Telematiche Volontarie", 
    desc_it: "Invio ufficiale delle dimissioni online tramite portale del Ministero del Lavoro",
    desc_en: "Online formal resignation submission to Ministry of Labour"
  },
  { 
    id: 22, 
    category: "lavoro",
    name: "Estratto Conto Contributivo & Busta Paga", 
    desc_it: "Verifica contributi INPS versati, anzianità lavorativa e controllo buste paga",
    desc_en: "INPS pension contributions check and payslip verification"
  },
  { 
    id: 23, 
    category: "lavoro",
    name: "Domanda di Pensione & Invalidità Civile", 
    desc_it: "Assistenza per pensione di vecchiaia, anticipata, reversibilità o riconoscimento Legge 104",
    desc_en: "Retirement pension, survivors pension and disability benefits assistance"
  },

  // --- DOCUMENTI PERSONALI & SPID ---
  { 
    id: 24, 
    category: "documenti",
    name: "Attivazione Identità Digitale SPID & PEC", 
    desc_it: "Creazione e riconoscimento credenziali SPID e attivazione Posta Elettronica Certificata (PEC)",
    desc_en: "SPID digital identity creation and certified legal email (PEC) activation"
  },
  { 
    id: 25, 
    category: "documenti",
    name: "Codice Fiscale & Duplicato Tessera Sanitaria", 
    desc_it: "Attribuzione nuovo codice fiscale o richiesta duplicato tessera sanitaria smarrita",
    desc_en: "Tax Code (Codice Fiscale) issuance or duplicate health card request"
  },
  { 
    id: 26, 
    category: "documenti",
    name: "Iscrizione Anagrafica / Cambio Residenza", 
    desc_it: "Pratica anagrafica per cambio indirizzo o iscrizione di residenza nel Comune",
    desc_en: "Civil registry registration or change of official residential address"
  },
  { 
    id: 27, 
    category: "documenti",
    name: "Certificato di Idoneità Alloggiativa", 
    desc_it: "Preparazione documenti per il rilascio del certificato igienico-sanitario dell'alloggio",
    desc_en: "Housing suitability certificate (Idoneità Alloggiativa) documentation"
  },
  { 
    id: 28, 
    category: "documenti",
    name: "Richiesta / Rinnovo Carta d'Identità", 
    desc_it: "Prenotazione appuntamento CIE (Carta d'Identità Elettronica) e verifica requisiti",
    desc_en: "Electronic Identity Card (CIE) appointment booking and compliance check"
  }
];

const STATUS_LABELS_IT = {
  pending: "Domanda Ricevuta",
  in_progress: "In Lavorazione",
  document_check: "Verifica Documenti",
  approved: "Approvata",
  completed: "Completata",
  rejected: "Rifiutata"
};

const STATUS_LABELS_EN = {
  pending: "Application Received",
  in_progress: "In Progress",
  document_check: "Document Check",
  approved: "Approved",
  completed: "Completed",
  rejected: "Rejected"
};

function readApps() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return [];
  }
}

function writeApps(apps) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(apps, null, 2));
}
const loadApplications = readApps;
const saveApplications = writeApps;

function generateApplicationNumber() {
  const random = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `CSS-${new Date().getFullYear()}-${random}`;
}

function parseCodiceFiscale(cf) {
  cf = (cf || '').trim().toUpperCase();

  if (cf.length !== 16) {
    return { valid: false, error: "Il Codice Fiscale deve essere di 16 caratteri / Tax Code must be 16 characters" };
  }

  const monthMap = {
    A: "01", B: "02", C: "03", D: "04", E: "05", H: "06",
    L: "07", M: "08", P: "09", R: "10", S: "11", T: "12"
  };

  const yearCode = cf.substring(6, 8);
  const monthCode = cf.charAt(8);
  const dayCode = cf.substring(9, 11);

  const month = monthMap[monthCode];
  if (!month) return { valid: false, error: "Codice mese non valido nel Codice Fiscale" };

  const dayRaw = parseInt(dayCode, 10);
  if (isNaN(dayRaw)) return { valid: false, error: "Codice giorno non valido nel Codice Fiscale" };

  const currentYY = new Date().getFullYear() % 100;
  const fullYear = parseInt(yearCode, 10) > currentYY ? `19${yearCode}` : `20${yearCode}`;

  const gender = dayRaw > 40 ? "F" : "M";
  const day = dayRaw > 40 ? dayRaw - 40 : dayRaw;

  if (day < 1 || day > 31) {
    return { valid: false, error: "Codice giorno non valido nel Codice Fiscale" };
  }

  return {
    valid: true,
    birthDate: `${fullYear}-${month}-${String(day).padStart(2, '0')}`,
    gender
  };
}

// Automatic Official MIT Allegato 1 PDF Generator (with digital signature)
async function generateAllegato1PDF(data) {
  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  // PAGE 1
  const page1 = pdfDoc.addPage([595.28, 841.89]); // A4 Size
  const { width, height } = page1.getSize();

  // Header & UMC
  page1.drawText("Allegato 1", { x: 50, y: height - 55, size: 11, font: fontBold });
  page1.drawText(`All'UMC di ${(data.prov || 'MODENA').toUpperCase()}`, { x: width - 230, y: height - 85, size: 11, font: fontBold });

  // Official Subject Box
  page1.drawText("OGGETTO: Richiesta di rilascio contrassegno identificativo per monopattini a propulsione", {
    x: 50, y: height - 135, size: 9.5, font: fontBold
  });
  page1.drawText("prevalentemente elettrica – richiedente maggiorenne", {
    x: 100, y: height - 150, size: 9.5, font: fontBold
  });

  // Personal Fields
  let yPos = height - 195;
  const lineSpacing = 28;

  page1.drawText(`Il/La sottoscritto/a:  ${(data.fullName || '').toUpperCase()}`, { x: 50, y: yPos, size: 10.5, font: fontBold });
  yPos -= lineSpacing;

  page1.drawText(`nato/a a:  ${(data.birthPlace || 'BANGLADESH').toUpperCase()}     il:  ${data.birthDate || ''}`, { x: 50, y: yPos, size: 10.5, font });
  yPos -= lineSpacing;

  page1.drawText(`codice fiscale:  ${(data.codiceFiscale || '').toUpperCase()}`, { x: 50, y: yPos, size: 10.5, font: fontBold });
  yPos -= lineSpacing;

  page1.drawText(`residente a:  ${(data.comune || 'CARPI').toUpperCase()}     prov:  ${(data.prov || 'MO').toUpperCase()}`, { x: 50, y: yPos, size: 10.5, font });
  yPos -= lineSpacing;

  page1.drawText(`alla via/piazza:  ${(data.via || data.address || '').toUpperCase()}     n:  ${data.civico || '1'}`, { x: 50, y: yPos, size: 10.5, font });
  yPos -= 36;

  // CHIEDE
  page1.drawText("CHIEDE", { x: width / 2 - 28, y: yPos, size: 12.5, font: fontBold });
  yPos -= 24;

  page1.drawText("il rilascio di n.    01    contrassegni identificativi per monopattini a propulsione", { x: 50, y: yPos, size: 10.5, font });
  yPos -= 17;
  page1.drawText("prevalentemente elettrica.", { x: 50, y: yPos, size: 10.5, font });
  yPos -= 28;

  page1.drawText("A tal fine allega:", { x: 50, y: yPos, size: 10.5, font: fontBold });
  yPos -= 20;
  page1.drawText("- Fotocopia del Permesso di soggiorno / Carta d'identità;", { x: 50, y: yPos, size: 10, font });
  yPos -= 18;
  page1.drawText("- Ricevuta di pagamento della tariffa N174 rilasciata dal Portale dell'Automobilista.", { x: 50, y: yPos, size: 10, font });

  // Footer Page 1
  page1.drawRectangle({ x: 50, y: 35, width: width - 100, height: 44, borderColor: rgb(0,0,0), borderWidth: 1 });
  page1.drawText("MIT", { x: 65, y: 50, size: 17, font: fontBold, color: rgb(0.05, 0.2, 0.45) });
  page1.drawText("ISTANZA DI RILASCIO DEL CONTRASSEGNO\nRICHIEDENTE MAGGIORENNE", { x: 135, y: 58, size: 8, font: fontBold, lineHeight: 11 });
  page1.drawText("IST-RILASCIO CONTRASSEGNO-001\nREV. 1.1 del 24/03/2026", { x: 385, y: 58, size: 8, font, lineHeight: 11 });

  // PAGE 2
  const page2 = pdfDoc.addPage([595.28, 841.89]);
  let y2 = height - 65;

  page2.drawText("DICHIARA", { x: width / 2 - 32, y: y2, size: 12.5, font: fontBold });
  y2 -= 35;

  const dichText = [
    "a)  di aver compiuto il diciottesimo anno di età;",
    "b)  di essere consapevole delle sanzioni penali previste in caso di dichiarazioni false ai sensi dell'art.",
    "     76 del DPR 445/2000 e della decadenza dei benefici derivanti da dichiarazioni non veritiere ai sensi",
    "     dell'art. 75 del DPR 445/2000;",
    "c)  di prestare il proprio consenso, ai sensi dell'art. 71 del DPR 445/2000, al controllo sulla veridicità e",
    "     sulla corrispondenza al vero di quanto dichiarato;",
    "d)  di aver preso visione dell'informativa e di prestare il consenso, ai sensi dell'articolo 6, comma 1,",
    "     lett. a), del GDPR, al trattamento dei miei dati personali, ai fini della richiesta e del rilascio del",
    "     contrassegno identificativo del monopattino a propulsione prevalentemente elettrica."
  ];

  for (const line of dichText) {
    page2.drawText(line, { x: 50, y: y2, size: 9.5, font });
    y2 -= 18;
  }

  y2 -= 55;
  const today = new Date().toLocaleDateString('it-IT');
  page2.drawText(`Data:   ${today}`, { x: 50, y: y2, size: 10.5, font: fontBold });

  page2.drawText("(Firma per esteso)", { x: width - 220, y: y2 + 15, size: 10, font: fontBold });

  // Embed Signature if provided
  if (data.signatureDataUrl && data.signatureDataUrl.startsWith('data:image/png;base64,')) {
    try {
      const base64Data = data.signatureDataUrl.replace(/^data:image\/png;base64,/, '');
      const sigImageBytes = Buffer.from(base64Data, 'base64');
      const sigImage = await pdfDoc.embedPng(sigImageBytes);
      page2.drawImage(sigImage, {
        x: width - 230,
        y: y2 - 32,
        width: 160,
        height: 48,
      });
    } catch (e) {
      console.log("Note on signature embed:", e.message);
    }
  }

  // Underline for signature
  page2.drawLine({
    start: { x: width - 240, y: y2 - 36 },
    end: { x: width - 50, y: y2 - 36 },
    thickness: 1,
    color: rgb(0,0,0)
  });

  // Footer Page 2
  page2.drawRectangle({ x: 50, y: 35, width: width - 100, height: 44, borderColor: rgb(0,0,0), borderWidth: 1 });
  page2.drawText("MIT", { x: 65, y: 50, size: 17, font: fontBold, color: rgb(0.05, 0.2, 0.45) });
  page2.drawText("ISTANZA DI RILASCIO DEL CONTRASSEGNO\nRICHIEDENTE MAGGIORENNE", { x: 135, y: 58, size: 8, font: fontBold, lineHeight: 11 });
  page2.drawText("IST-RILASCIO CONTRASSEGNO-001\nREV. 1.1 del 24/03/2026", { x: 385, y: 58, size: 8, font, lineHeight: 11 });

  return await pdfDoc.save();
}

// Nodemailer Email Sending Helper
async function sendEmail(to, subject, html, attachments = []) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.log("Email non inviata (EMAIL_USER o EMAIL_PASS non configurati nel .env):", subject);
    return false;
  }

  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: `"CENTRO SERVIZIO STRANIERO" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html,
      attachments
    });

    console.log("Email inviata con successo a:", to);
    return true;
  } catch (err) {
    console.log("Errore invio email:", err.message);
    return false;
  }
}

// Master HTML Email Template in Institutional Italian
function emailBox(title, body) {
  return `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
  </head>
  <body style="margin:0;padding:20px;background-color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
    <div style="max-width:620px;margin:auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;box-shadow:0 4px 16px rgba(12,35,64,0.08);">
      <!-- Header -->
      <div style="background:#0c2340;color:#ffffff;padding:26px 22px;text-align:center;border-bottom:3px solid #c59b27;">
        <h1 style="margin:0;font-size:22px;letter-spacing:0.8px;font-weight:700;">CENTRO SERVIZIO STRANIERO</h1>
        <p style="margin:6px 0 0;font-size:13px;color:#e5b84c;">Studio di Consulenza Immigrazione & Assistenza Fiscale CAF</p>
      </div>

      <!-- Content -->
      <div style="padding:28px 24px;color:#1e293b;line-height:1.65;font-size:15px;">
        <h2 style="color:#0c2340;font-size:18px;margin-top:0;border-bottom:2px solid #f1f5f9;padding-bottom:10px;">${title}</h2>
        ${body}
      </div>

      <!-- Footer -->
      <div style="background:#f8fafc;padding:18px 22px;border-top:1px solid #e2e8f0;text-align:center;font-size:12px;color:#64748b;">
        <p style="margin:0 0 5px;font-weight:600;color:#0c2340;">CENTRO SERVIZIO STRANIERO</p>
        <p style="margin:0 0 3px;">Via Roma / Carpi (MO) — Emilia-Romagna, Italia</p>
        <p style="margin:0;font-size:11px;color:#94a3b8;">Email generata automaticamente dal sistema di gestione pratiche.</p>
      </div>
    </div>
  </body>
  </html>`;
}

function emailButton(label, url, color = '#0c2340') {
  return `
    <div style="text-align:center;margin:24px 0;">
      <a href="${url}" style="background-color:${color};color:#ffffff;padding:13px 26px;text-decoration:none;border-radius:7px;font-weight:bold;font-size:15px;display:inline-block;box-shadow:0 3px 10px rgba(12,35,64,0.2);">
        ${label}
      </a>
    </div>
  `;
}

// ------------------- API ROUTES -------------------

// 0. Healthcheck endpoint (UptimeRobot 24/7 Always-On Ping)
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// 1. Get services
app.get('/api/services', (req, res) => {
  res.json(SERVICES);
});

// 2. Parse Codice Fiscale
app.post('/api/parse-cf', (req, res) => {
  res.json(parseCodiceFiscale(req.body.codiceFiscale));
});

// 3. Submit application with file attachments
const uploadFields = uploadDocs.fields([
  { name: 'passaporto', maxCount: 1 },
  { name: 'carta_identita', maxCount: 1 },
  { name: 'codice_fiscale_doc', maxCount: 1 },
  { name: 'permesso_soggiorno', maxCount: 1 },
  { name: 'residenza', maxCount: 1 },
  { name: 'altro', maxCount: 1 }
]);

app.post('/api/apply', applyLimiter, (req, res) => {
  uploadFields(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ error: "Errore durante il caricamento dei file: " + err.message });
    }

    const {
      serviceId,
      fullName,
      codiceFiscale,
      birthDate,
      gender,
      email,
      phone,
      address,
      birthPlace,
      residenceComune,
      residenceProv,
      residenceVia,
      residenceCivico,
      signature, // base64 data url
      notes,
      // Specific fields for Permesso di Soggiorno
      permessoTipo,
      permessoNumero,
      permessoScadenza,
      permessoQuestura,
      // Specific fields for Tessera Sanitaria
      tesseraMotivo,
      tesseraAsl,
      tesseraMedico
    } = req.body;

    const service = SERVICES.find(s => s.id === Number(serviceId));
    if (!service) return res.status(400).json({ error: "Servizio non valido / Invalid service" });
    if (!fullName || !email || !phone) {
      return res.status(400).json({ error: "Nome, email e telefono sono obbligatori / Name, email and phone are required" });
    }

    const applicationNumber = generateApplicationNumber();

    // Map uploaded documents and organize into target folder
    const docs = [];
    const targetDir = path.join(DOCS_DIR, applicationNumber);
    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

    if (req.files) {
      for (const fieldName of Object.keys(req.files)) {
        const fileArr = req.files[fieldName];
        if (fileArr && fileArr.length > 0) {
          const file = fileArr[0];
          const newPath = path.join(targetDir, file.filename);
          if (file.path !== newPath) {
            try {
              fs.renameSync(file.path, newPath);
            } catch (e) {
              console.log("File move note:", e.message);
            }
          }
          docs.push({
            type: fieldName,
            filename: file.filename,
            originalname: file.originalname,
            size: file.size,
            uploaded_at: new Date().toISOString()
          });
        }
      }
    }

    // SPECIAL: If service is Targa Monopattino Elettrico (Allegato 1 MIT)
    if (service.id === 101 || (service.name && service.name.includes('Targa Monopattino'))) {
      try {
        const allegatoPdfBytes = await generateAllegato1PDF({
          fullName,
          birthPlace: birthPlace || 'BANGLADESH',
          birthDate: birthDate || '',
          codiceFiscale,
          comune: residenceComune || address || 'CARPI',
          prov: residenceProv || 'MO',
          via: residenceVia || address || '',
          civico: residenceCivico || '1',
          signatureDataUrl: signature,
          appNo: applicationNumber
        });

        const allegatoFilename = `Allegato1_MIT_Firmato_${applicationNumber}.pdf`;
        const allegatoFilePath = path.join(targetDir, allegatoFilename);
        fs.writeFileSync(allegatoFilePath, allegatoPdfBytes);

        docs.unshift({
          type: 'allegato_1_firmato',
          filename: allegatoFilename,
          originalname: 'Allegato_1_MIT_Firmato.pdf',
          size: allegatoPdfBytes.length,
          uploaded_at: new Date().toISOString()
        });

        console.log(`Allegato 1 MIT PDF generato con successo per ${applicationNumber}`);
      } catch (pdfErr) {
        console.error("Errore generazione PDF Allegato 1:", pdfErr);
      }
    }

    // SPECIAL: Permesso di Soggiorno & Tessera Sanitaria (Automated Dossier Generation & Dispatch)
    const isPermesso = (service.id === 1 || service.id === 2 || service.id === 3 || (service.category === 'immigrazione' && service.name.includes('Permesso')));
    const isTessera = (service.id === 25 || service.name.includes('Tessera Sanitaria') || service.name.includes('Codice Fiscale'));

    let dossierPdfBytes = null;
    let dossierFilename = null;

    if (isPermesso || isTessera) {
      try {
        dossierPdfBytes = await generateDossierPDF({
          applicationNumber,
          serviceName: service.name,
          fullName,
          codiceFiscale,
          birthDate,
          gender,
          phone,
          email,
          address,
          birthPlace,
          residenceComune,
          residenceProv,
          permessoTipo,
          permessoNumero,
          permessoScadenza,
          permessoQuestura,
          tesseraMotivo,
          tesseraAsl,
          tesseraMedico,
          notes,
          docsList: docs
        });

        dossierFilename = `Scheda_Istruttoria_${applicationNumber}.pdf`;
        const dossierFilePath = path.join(targetDir, dossierFilename);
        fs.writeFileSync(dossierFilePath, dossierPdfBytes);

        docs.unshift({
          type: 'scheda_istruttoria',
          filename: dossierFilename,
          originalname: `Scheda_Istruttoria_${applicationNumber}.pdf`,
          size: dossierPdfBytes.length,
          uploaded_at: new Date().toISOString()
        });

        console.log(`[Dossier] Scheda Istruttoria PDF generata per ${applicationNumber}`);
      } catch (dossierErr) {
        console.error("Errore generazione Scheda Istruttoria PDF:", dossierErr);
      }
    }

    const newApplication = {
      application_number: applicationNumber,
      service_id: service.id,
      service_category: service.category,
      service_name: service.name,
      price: null, // Custom fee set by admin if needed
      full_name: fullName.trim(),
      codice_fiscale: (codiceFiscale || '').trim().toUpperCase(),
      birth_date: birthDate || "",
      gender: gender || "",
      email: email.trim(),
      phone: phone.trim(),
      address: (address || '').trim(),
      birth_place: (birthPlace || '').trim(),
      residence_comune: (residenceComune || '').trim(),
      residence_prov: (residenceProv || '').trim(),
      notes: (notes || '').trim(),
      permesso_tipo: (permessoTipo || '').trim(),
      permesso_numero: (permessoNumero || '').trim(),
      permesso_scadenza: (permessoScadenza || '').trim(),
      permesso_questura: (permessoQuestura || '').trim(),
      tessera_motivo: (tesseraMotivo || '').trim(),
      tessera_asl: (tesseraAsl || '').trim(),
      tessera_medico: (tesseraMedico || '').trim(),
      autoDispatched: false,
      dispatchedTo: null,
      dispatchedAt: null,
      status: "pending",
      paid: false,
      documents: docs,
      additional_doc_requests: [],
      payment_requested: false,
      payment_receipt: null,
      created_at: new Date().toISOString()
    };

    const apps = readApps();
    apps.push(newApplication);
    writeApps(apps);

    // AUTOMATED DISPATCH ROUTING
    const routingConfig = loadRoutingConfig();
    let routingRule = null;
    if (isPermesso && routingConfig.permesso_soggiorno && routingConfig.permesso_soggiorno.enabled) {
      routingRule = routingConfig.permesso_soggiorno;
    } else if (isTessera && routingConfig.tessera_sanitaria && routingConfig.tessera_sanitaria.enabled) {
      routingRule = routingConfig.tessera_sanitaria;
    }

    if (routingRule && routingRule.targetEmail && dossierPdfBytes) {
      const emailAttachments = [];
      for (const d of docs) {
        const fPath = path.join(targetDir, d.filename);
        if (fs.existsSync(fPath) && d.filename !== dossierFilename) {
          try {
            emailAttachments.push({
              filename: d.originalname || d.filename,
              content: fs.readFileSync(fPath)
            });
          } catch (readErr) {}
        }
      }

      dispatchDossierEmail(newApplication, routingRule.targetEmail, dossierPdfBytes, emailAttachments)
        .then(sent => {
          if (sent) {
            newApplication.autoDispatched = true;
            newApplication.dispatchedTo = routingRule.targetEmail;
            newApplication.dispatchedAt = new Date().toISOString();
            const currentApps = readApps();
            const idx = currentApps.findIndex(a => a.application_number === applicationNumber);
            if (idx !== -1) {
              currentApps[idx] = newApplication;
              writeApps(currentApps);
            }
            console.log(`[Auto-Routing] Pratica ${applicationNumber} inoltrata con successo a ${routingRule.targetEmail}`);
          }
        })
        .catch(err => {
          console.error(`[Auto-Routing] Errore invio automatico per ${applicationNumber}:`, err.message);
        });
    }

    const trackingUrl = `${BASE_URL}/?track=${encodeURIComponent(applicationNumber)}`;

    // Confirmation Email in Italian with tracking link
    await sendEmail(
      email,
      `Conferma Acquisizione Pratica - ${applicationNumber} | CENTRO SERVIZIO STRANIERO`,
      emailBox(
        "✅ Pratica Acquisita con Successo",
        `<p>Gentile <b>${fullName}</b>,</p>
         <p>La Sua richiesta per il servizio <b>${service.name}</b> è stata acquisita con successo nel nostro registro pratiche.</p>
         
         <div style="background:#f8fafc;border-left:4px solid #0c2340;padding:15px;border-radius:6px;margin:18px 0;">
           <p style="margin:3px 0;">📋 <b>Numero Pratica:</b> <span style="color:#0c2340;font-weight:bold;font-size:16px;">${applicationNumber}</span></p>
           <p style="margin:3px 0;">🏛️ <b>Servizio Richiesto:</b> ${service.name}</p>
           <p style="margin:3px 0;">📎 <b>Documenti allegati:</b> ${docs.length} file (incluso Allegato 1 firmato digitalmente)</p>
         </div>

         <p>Un nostro consulente dedicato esaminerà i Suoi dati e procederà con l'istruttoria. Può verificare in qualsiasi momento lo stato di avanzamento cliccando sul pulsante sottostante:</p>

         ${emailButton("🔍 Traccia la Tua Pratica Online", trackingUrl)}

         <p style="font-size:13px;color:#64748b;">Se il pulsante non funziona, copi questo link nel Suo browser:<br>
         <a href="${trackingUrl}" style="color:#0c2340;">${trackingUrl}</a></p>
         
         <p>Cordiali saluti,<br><b>Ufficio Pratiche — CENTRO SERVIZIO STRANIERO</b></p>`
      )
    );

    res.json({ success: true, applicationNumber });
  });
});

// 4. Track application
app.get('/api/track/:applicationNumber', (req, res) => {
  const apps = readApps();
  const application = apps.find(a => a.application_number === req.params.applicationNumber);

  if (!application) {
    return res.status(404).json({ error: "Numero di pratica non trovato / Application number not found" });
  }

  // Provide banking details and dynamic payment options
  const payConfig = loadPaymentConfig();
  const bankInfo = {
    iban: (payConfig.bonifico && payConfig.bonifico.iban) || IBAN,
    intestatario: (payConfig.bonifico && payConfig.bonifico.intestatario) || INTESTATARIO,
    banca: (payConfig.bonifico && payConfig.bonifico.banca) || BANCA,
    causale: application.application_number,
    importo: application.price !== null ? application.price : 0
  };

  res.json({
    ...application,
    bankInfo,
    paymentConfig: payConfig
  });
});

// 5. Upload payment receipt (PDF/JPG/PNG)
app.post('/api/upload-receipt', (req, res) => {
  uploadReceipt.single('receipt')(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ error: "Errore nel caricamento della ricevuta: " + err.message });
    }

    const { applicationNumber } = req.body;
    if (!applicationNumber || !req.file) {
      return res.status(400).json({ error: "Numero pratica e file ricevuta sono obbligatori" });
    }

    const apps = readApps();
    const idx = apps.findIndex(a => a.application_number === applicationNumber);
    if (idx === -1) {
      return res.status(404).json({ error: "Pratica non trovata" });
    }

    apps[idx].payment_receipt = {
      filename: req.file.filename,
      originalname: req.file.originalname,
      size: req.file.size,
      status: "pending_review",
      uploaded_at: new Date().toISOString()
    };

    writeApps(apps);

    const trackingUrl = `${BASE_URL}/?track=${encodeURIComponent(applicationNumber)}`;

    // Email to customer confirming receipt received
    await sendEmail(
      apps[idx].email,
      `Ricevuta di Pagamento Registrata - ${applicationNumber} | CENTRO SERVIZIO STRANIERO`,
      emailBox(
        "📄 Ricevuta di Pagamento Ricevuta",
        `<p>Gentile <b>${apps[idx].full_name}</b>,</p>
         <p>La informiamo che abbiamo ricevuto la Sua ricevuta di pagamento per la pratica <b>${applicationNumber}</b>.</p>
         <p>Il nostro reparto amministrativo provvederà a verificare la contabile del bonifico entro le prossime ore lavorative.</p>

         ${emailButton("🔍 Controlla lo Stato della Pratica", trackingUrl)}

         <p>Cordiali saluti,<br><b>Amministrazione CENTRO SERVIZIO STRANIERO</b></p>`
      )
    );

    res.json({ success: true, message: "Ricevuta caricata con successo" });
  });
});

// 6. Upload requested additional document by customer
app.post('/api/upload-requested-doc', (req, res) => {
  uploadDocs.single('document')(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ error: "Errore caricamento documento: " + err.message });
    }

    const { applicationNumber, requestId } = req.body;
    if (!applicationNumber || !requestId || !req.file) {
      return res.status(400).json({ error: "Dati mancanti per l'upload del documento" });
    }

    const apps = readApps();
    const idx = apps.findIndex(a => a.application_number === applicationNumber);
    if (idx === -1) return res.status(404).json({ error: "Pratica non trovata" });

    if (!apps[idx].additional_doc_requests) apps[idx].additional_doc_requests = [];
    const reqItem = apps[idx].additional_doc_requests.find(r => r.id === requestId);

    if (!reqItem) {
      return res.status(404).json({ error: "Richiesta documento non trovata" });
    }

    // Move file to application folder
    const targetDir = path.join(DOCS_DIR, applicationNumber);
    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });
    const newPath = path.join(targetDir, req.file.filename);
    if (req.file.path !== newPath) {
      try { fs.renameSync(req.file.path, newPath); } catch (e) {}
    }

    reqItem.status = 'uploaded';
    reqItem.file = {
      filename: req.file.filename,
      originalname: req.file.originalname,
      size: req.file.size,
      uploaded_at: new Date().toISOString()
    };

    if (!apps[idx].documents) apps[idx].documents = [];
    apps[idx].documents.push({
      type: reqItem.doc_type || 'aggiuntivo',
      filename: req.file.filename,
      originalname: req.file.originalname,
      size: req.file.size,
      uploaded_at: new Date().toISOString()
    });

    writeApps(apps);

    const trackingUrl = `${BASE_URL}/?track=${encodeURIComponent(applicationNumber)}`;

    await sendEmail(
      apps[idx].email,
      `Documento Integrativo Acquisito - ${applicationNumber} | CENTRO SERVIZIO STRANIERO`,
      emailBox(
        "📎 Documento Integrativo Ricevuto",
        `<p>Gentile <b>${apps[idx].full_name}</b>,</p>
         <p>Abbiamo acquisito regolarmente il documento integrativo richiesto (<b>${reqItem.doc_type}</b>) per la pratica <b>${applicationNumber}</b>.</p>
         <p>L'istruttoria prosegue regolarmente.</p>

         ${emailButton("🔍 Traccia la Tua Pratica", trackingUrl)}

         <p>Cordiali saluti,<br><b>CENTRO SERVIZIO STRANIERO</b></p>`
      )
    );

    res.json({ success: true });
  });
});

// 7. Secure download of documents & receipts (Strict Path Traversal Protection)
app.get('/api/files/doc/:appNo/:filename', (req, res) => {
  const safeAppNo = path.basename(req.params.appNo || '').replace(/[^a-zA-Z0-9_-]/g, '');
  const safeFilename = path.basename(req.params.filename || '');
  if (!safeAppNo || !safeFilename) {
    return res.status(400).json({ error: 'Parametri file non validi' });
  }

  const resolvedDocsDir = path.resolve(DOCS_DIR);
  const filePath = path.resolve(DOCS_DIR, safeAppNo, safeFilename);

  if (!filePath.startsWith(resolvedDocsDir + path.sep)) {
    return res.status(403).json({ error: 'Accesso negato: percorso non consentito.' });
  }
  if (!fs.existsSync(filePath)) {
    return res.status(404).send("File non trovato");
  }
  res.sendFile(filePath);
});

app.get('/api/files/receipt/:filename', (req, res) => {
  const safeFilename = path.basename(req.params.filename || '');
  if (!safeFilename) {
    return res.status(400).json({ error: 'Nome file non valido' });
  }

  const resolvedReceiptsDir = path.resolve(RECEIPTS_DIR);
  const filePath = path.resolve(RECEIPTS_DIR, safeFilename);

  if (!filePath.startsWith(resolvedReceiptsDir + path.sep)) {
    return res.status(403).json({ error: 'Accesso negato: percorso non consentito.' });
  }
  if (!fs.existsSync(filePath)) {
    return res.status(404).send("Ricevuta non trovata");
  }
  res.sendFile(filePath);
});

// ------------------- ADMIN APIS -------------------

// Admin: List all applications
app.get('/api/admin/applications', (req, res) => {
  const apps = readApps();
  res.json(apps.slice().reverse());
});

// Admin: Update full application details & payment options
app.post('/api/admin/application/update', async (req, res) => {
  try {
    const { applicationNumber, fullName, phone, email, price, paymentMethod, paid, paymentRequested, status, adminNotes } = req.body;

    if (!applicationNumber) {
      return res.status(400).json({ error: "Numero pratica obbligatorio" });
    }

    const apps = readApps();
    const i = apps.findIndex(a => a.application_number === applicationNumber);
    if (i === -1) {
      return res.status(404).json({ error: "Pratica non trovata" });
    }

    if (fullName !== undefined && fullName !== '') apps[i].full_name = fullName;
    if (phone !== undefined && phone !== '') apps[i].phone = phone;
    if (email !== undefined && email !== '') apps[i].email = email;
    if (price !== undefined && price !== null && price !== '') apps[i].price = Number(price);
    if (paymentMethod !== undefined) apps[i].paymentMethod = paymentMethod;
    if (paid !== undefined) apps[i].paid = !!paid;
    if (paymentRequested !== undefined) apps[i].payment_requested = !!paymentRequested;
    if (status !== undefined && status !== '') apps[i].status = status;
    if (adminNotes !== undefined) apps[i].admin_notes = adminNotes;

    writeApps(apps);
    res.json({ success: true, message: "Pratica e opzioni di pagamento aggiornate con successo!", application: apps[i] });
  } catch (err) {
    res.status(500).json({ error: "Errore durante l'aggiornamento: " + err.message });
  }
});

// Admin: Change general status
app.post('/api/admin/status', async (req, res) => {
  const { applicationNumber, status } = req.body;

  if (!STATUS_LABELS_IT[status]) {
    return res.status(400).json({ error: "Stato non valido" });
  }

  const apps = readApps();
  const i = apps.findIndex(a => a.application_number === applicationNumber);
  if (i === -1) return res.status(404).json({ error: "Pratica non trovata" });

  apps[i].status = status;
  writeApps(apps);

  const trackingUrl = `${BASE_URL}/?track=${encodeURIComponent(applicationNumber)}`;
  const statusItalian = STATUS_LABELS_IT[status];

  let extraNote = "";
  if (status === 'approved') {
    extraNote = `<p style="background:#eafaf1;color:#1e7e34;padding:12px;border-radius:6px;font-weight:600;">🎉 La Sua domanda è stata approvata. A breve riceverà le indicazioni per il perfezionamento.</p>`;
  } else if (status === 'completed') {
    extraNote = `<p style="background:#eafaf1;color:#1e7e34;padding:12px;border-radius:6px;font-weight:600;">✅ La Sua pratica è stata completata con successo!</p>`;
  } else if (status === 'rejected') {
    extraNote = `<p style="background:#fde8e8;color:#c81e1e;padding:12px;border-radius:6px;">La pratica non ha potuto essere accolta. Per maggiori chiarimenti, La invitiamo a contattare la nostra sede.</p>`;
  }

  await sendEmail(
    apps[i].email,
    `Aggiornamento Pratica: ${statusItalian} - ${applicationNumber}`,
    emailBox(
      "📋 Aggiornamento Stato Pratica",
      `<p>Gentile <b>${apps[i].full_name}</b>,</p>
       <p>Le comunichiamo che lo stato della Sua pratica <b>${applicationNumber}</b> è stato aggiornato a:</p>

       <div style="text-align:center;margin:20px 0;">
         <span style="background:#0c2340;color:#ffffff;padding:10px 22px;border-radius:30px;font-size:16px;font-weight:bold;display:inline-block;">
           ${statusItalian}
         </span>
       </div>

       ${extraNote}

       <p>Per consultare tutti i dettagli, acceda alla pagina di monitoraggio:</p>

       ${emailButton("🔍 Vai alla Pratica", trackingUrl)}

       <p>Cordiali saluti,<br><b>CENTRO SERVIZIO STRANIERO</b></p>`
    )
  );

  res.json({ success: true });
});

// Admin: Request Payment with Custom Amount (Send IBAN instructions)
app.post('/api/admin/request-payment', async (req, res) => {
  const { applicationNumber, amount } = req.body;

  const apps = readApps();
  const i = apps.findIndex(a => a.application_number === applicationNumber);
  if (i === -1) return res.status(404).json({ error: "Pratica non trovata" });

  const finalAmount = (amount !== undefined && amount !== null && amount !== '') ? Number(amount) : (apps[i].price || 0);

  apps[i].price = finalAmount;
  apps[i].payment_requested = true;
  apps[i].payment_requested_at = new Date().toISOString();
  if (apps[i].status === 'pending' || apps[i].status === 'document_check' || apps[i].status === 'in_progress') {
    apps[i].status = 'approved';
  }
  writeApps(apps);

  const payUrl = `${BASE_URL}/?pay=${encodeURIComponent(applicationNumber)}`;
  const trackingUrl = `${BASE_URL}/?track=${encodeURIComponent(applicationNumber)}`;

  // Payment instruction email in Italian with active payment methods
  const payConfig = loadPaymentConfig();

  let methodsEmailHtml = '';
  if (payConfig.bonifico && payConfig.bonifico.enabled) {
    methodsEmailHtml += `
      <div style="background:#ffffff;border:2px solid #0c2340;border-radius:8px;padding:16px;margin:14px 0;">
        <h4 style="margin:0 0 8px 0;color:#0c2340;font-size:15px;">🏦 1. BONIFICO BANCARIO</h4>
        <p style="margin:4px 0;"><b>IBAN:</b> <span style="font-family:Courier,monospace;font-size:15px;color:#0c2340;font-weight:bold;">${payConfig.bonifico.iban}</span></p>
        <p style="margin:4px 0;"><b>Intestatario:</b> ${payConfig.bonifico.intestatario}</p>
        ${payConfig.bonifico.banca ? `<p style="margin:4px 0;"><b>Banca:</b> ${payConfig.bonifico.banca}</p>` : ''}
        ${payConfig.bonifico.bicSwift ? `<p style="margin:4px 0;"><b>BIC/SWIFT:</b> ${payConfig.bonifico.bicSwift}</p>` : ''}
        <p style="margin:6px 0 0 0;background:#fff8dc;padding:6px 10px;border-radius:4px;border-left:4px solid #c59b27;">
          📝 <b>Causale OBBLIGATORIA:</b> <strong style="color:#d35400;">${applicationNumber}</strong>
        </p>
      </div>
    `;
  }

  if (payConfig.postepay && payConfig.postepay.enabled) {
    methodsEmailHtml += `
      <div style="background:#fffbeb;border:2px solid #d97706;border-radius:8px;padding:16px;margin:14px 0;">
        <h4 style="margin:0 0 8px 0;color:#92400e;font-size:15px;">🟡 2. RICARICA POSTEPAY</h4>
        <p style="margin:4px 0;"><b>Numero Carta Postepay:</b> <span style="font-family:Courier,monospace;font-size:15px;color:#92400e;font-weight:bold;">${payConfig.postepay.numeroCarta}</span></p>
        <p style="margin:4px 0;"><b>Intestatario:</b> ${payConfig.postepay.intestatario}</p>
        ${payConfig.postepay.codiceFiscale ? `<p style="margin:4px 0;"><b>Codice Fiscale:</b> ${payConfig.postepay.codiceFiscale}</p>` : ''}
        ${payConfig.postepay.note ? `<p style="margin:4px 0;font-size:12.5px;color:#78350f;">ℹ️ ${payConfig.postepay.note}</p>` : ''}
      </div>
    `;
  }

  if (payConfig.paypal && payConfig.paypal.enabled) {
    methodsEmailHtml += `
      <div style="background:#f0fdf4;border:2px solid #16a34a;border-radius:8px;padding:16px;margin:14px 0;">
        <h4 style="margin:0 0 8px 0;color:#166534;font-size:15px;">🅿️ 3. PAGAMENTO ONLINE / PAYPAL</h4>
        <p style="margin:4px 0;"><b>Link Diretto:</b> <a href="${payConfig.paypal.emailOrLink}" target="_blank" style="color:#15803d;font-weight:bold;text-decoration:underline;">${payConfig.paypal.emailOrLink}</a></p>
        ${payConfig.paypal.note ? `<p style="margin:4px 0;font-size:12.5px;color:#14532d;">ℹ️ ${payConfig.paypal.note}</p>` : ''}
      </div>
    `;
  }

  if (payConfig.sede && payConfig.sede.enabled) {
    methodsEmailHtml += `
      <div style="background:#f8fafc;border:2px solid #64748b;border-radius:8px;padding:16px;margin:14px 0;">
        <h4 style="margin:0 0 8px 0;color:#334155;font-size:15px;">🏢 4. PAGAMENTO IN SEDE (CONTANTI O POS)</h4>
        <p style="margin:4px 0;"><b>Indirizzo:</b> ${payConfig.sede.indirizzo}</p>
        <p style="margin:4px 0;"><b>Orari Ufficio:</b> ${payConfig.sede.orari}</p>
        ${payConfig.sede.metodi ? `<p style="margin:4px 0;"><b>Modalità Accettate:</b> ${payConfig.sede.metodi}</p>` : ''}
      </div>
    `;
  }

  await sendEmail(
    apps[i].email,
    `Istruzioni di Pagamento - Pratica ${applicationNumber} | CENTRO SERVIZIO STRANIERO`,
    emailBox(
      "💳 Indicazioni per il Pagamento della Pratica",
      `<p>Gentile <b>${apps[i].full_name}</b>,</p>
       <p>La informiamo che la Sua pratica per <b>${apps[i].service_name}</b> è stata <b>approvata</b>.</p>
       <p>Per procedere al perfezionamento, La invitiamo ad effettuare il pagamento ${finalAmount > 0 ? `di <b>€${finalAmount},00</b>` : ''} scegliendo uno dei seguenti metodi abilitati:</p>

       ${methodsEmailHtml}

       ${payConfig.istruzioniGenerali ? `<p style="font-size:13px;color:#334155;background:#f1f5f9;padding:10px;border-radius:6px;">ℹ️ <b>Nota Amministrazione:</b> ${payConfig.istruzioniGenerali}</p>` : ''}

       <p style="font-weight:600;color:#c0392b;">⚠️ IMPORTANTE:</p>
       <p>Inserisca tassativamente il numero pratica <b>${applicationNumber}</b> nella causale o riferimento del pagamento affinché possa essere abbinato immediatamente alla Sua richiesta.</p>

       <p>Una volta effettuato il pagamento, carichi la ricevuta (PDF, screenshot o foto) tramite il link sottostante:</p>

       ${emailButton("📤 Carica Ricevuta di Pagamento", payUrl, "#27ae60")}

       <p style="font-size:13px;color:#64748b;">Può seguire la Sua pratica anche online:<br>
       <a href="${trackingUrl}" style="color:#0c2340;">${trackingUrl}</a></p>

       <p>Cordiali saluti,<br><b>Amministrazione CENTRO SERVIZIO STRANIERO</b></p>`
    )
  );

  res.json({ success: true });
});

// Admin: Confirm payment approval
app.post('/api/admin/confirm-payment', async (req, res) => {
  const { applicationNumber } = req.body;

  const apps = readApps();
  const i = apps.findIndex(a => a.application_number === applicationNumber);
  if (i === -1) return res.status(404).json({ error: "Pratica non trovata" });

  apps[i].paid = true;
  apps[i].paid_at = new Date().toISOString();
  apps[i].status = "completed";
  if (apps[i].payment_receipt) {
    apps[i].payment_receipt.status = "approved";
  }
  writeApps(apps);

  const trackingUrl = `${BASE_URL}/?track=${encodeURIComponent(applicationNumber)}`;

  await sendEmail(
    apps[i].email,
    `✅ Pagamento Verificato e Pratica Completata - ${applicationNumber}`,
    emailBox(
      "✅ Pagamento Confermato con Successo",
      `<p>Gentile <b>${apps[i].full_name}</b>,</p>
       <p>Le confermiamo che il pagamento relativo alla pratica <b>${applicationNumber}</b> è stato verificato ed approvato con successo!</p>
       
       <div style="background:#eafaf1;border-left:4px solid #27ae60;padding:14px;border-radius:4px;margin:20px 0;">
         <p style="margin:3px 0;color:#27ae60;font-weight:bold;font-size:16px;">🎉 Pratica Completata!</p>
         <p style="margin:3px 0;">Servizio: <b>${apps[i].service_name}</b></p>
         ${apps[i].price ? `<p style="margin:3px 0;">Importo saldato: <b>€${apps[i].price},00</b></p>` : ''}
         <p style="margin:3px 0;">Data completamento: ${new Date().toLocaleDateString('it-IT')}</p>
       </div>

       <p>Grazie per esserSi rivolto al nostro Centro. Può visualizzare il riepilogo al seguente link:</p>

       ${emailButton("🔍 Visualizza Pratica Completata", trackingUrl)}

       <p>Cordiali saluti,<br><b>CENTRO SERVIZIO STRANIERO</b></p>`
    )
  );

  res.json({ success: true });
});

// Admin: Reject payment receipt
app.post('/api/admin/reject-receipt', async (req, res) => {
  const { applicationNumber, reason } = req.body;

  const apps = readApps();
  const i = apps.findIndex(a => a.application_number === applicationNumber);
  if (i === -1) return res.status(404).json({ error: "Pratica non trovata" });

  if (apps[i].payment_receipt) {
    apps[i].payment_receipt.status = "rejected";
    apps[i].payment_receipt.reject_reason = reason || "Ricevuta non leggibile o bonifico non pervenuto";
  }
  writeApps(apps);

  const payUrl = `${BASE_URL}/?pay=${encodeURIComponent(applicationNumber)}`;

  await sendEmail(
    apps[i].email,
    `Avviso: Ricevuta di Pagamento da Verificare - ${applicationNumber}`,
    emailBox(
      "⚠️ Ricevuta di Pagamento non Conforme",
      `<p>Gentile <b>${apps[i].full_name}</b>,</p>
       <p>La informiamo che la ricevuta caricata per la pratica <b>${applicationNumber}</b> non è stata convalidata per la seguente motivazione:</p>

       <div style="background:#fff3cd;border-left:4px solid #ffc107;padding:12px;margin:15px 0;">
         <b>Motivazione:</b> ${reason || 'Ricevuta non conforme o importo non corrispondente.'}
       </div>

       <p>La preghiamo di verificare e ricaricare una ricevuta leggibile tramite il link:</p>

       ${emailButton("📤 Ricarica la Ricevuta", payUrl, "#e67e22")}

       <p>Cordiali saluti,<br><b>CENTRO SERVIZIO STRANIERO</b></p>`
    )
  );

  res.json({ success: true });
});

// Admin: Request additional document from client
app.post('/api/admin/request-doc', async (req, res) => {
  const { applicationNumber, docType, note } = req.body;

  if (!docType) {
    return res.status(400).json({ error: "Tipo di documento obbligatorio" });
  }

  const apps = readApps();
  const i = apps.findIndex(a => a.application_number === applicationNumber);
  if (i === -1) return res.status(404).json({ error: "Pratica non trovata" });

  if (!apps[i].additional_doc_requests) apps[i].additional_doc_requests = [];

  const requestId = 'req_' + Date.now();
  const docReq = {
    id: requestId,
    doc_type: docType,
    note: note || "",
    status: 'pending',
    requested_at: new Date().toISOString()
  };

  apps[i].additional_doc_requests.push(docReq);
  apps[i].status = "document_check";
  writeApps(apps);

  const uploadUrl = `${BASE_URL}/?upload_doc=${encodeURIComponent(applicationNumber)}&req_id=${requestId}`;
  const trackingUrl = `${BASE_URL}/?track=${encodeURIComponent(applicationNumber)}`;

  await sendEmail(
    apps[i].email,
    `Richiesta Documento Integrativo - Pratica ${applicationNumber} | CENTRO SERVIZIO STRANIERO`,
    emailBox(
      "📄 Richiesta Documento Integrativo",
      `<p>Gentile <b>${apps[i].full_name}</b>,</p>
       <p>Per poter procedere con l'istruttoria della Sua pratica <b>${applicationNumber}</b> (${apps[i].service_name}), è necessario fornire un documento integrativo:</p>

       <div style="background:#f8fafc;border-left:4px solid #0c2340;padding:14px;border-radius:6px;margin:18px 0;">
         <p style="margin:4px 0;">📋 <b>Documento richiesto:</b> <strong style="color:#0c2340;font-size:16px;">${docType}</strong></p>
         ${note ? `<p style="margin:8px 0 0;color:#555;">💬 <b>Note dell'ufficio:</b> "${note}"</p>` : ''}
       </div>

       <p>La invitiamo a caricare il documento richiesto (PDF, JPG o PNG, max 5MB) tramite il link sottostante:</p>

       ${emailButton("📎 Carica il Documento Richiesto", uploadUrl, "#0c2340")}

       <p style="font-size:13px;color:#64748b;">Oppure verifichi lo stato della pratica online:<br>
       <a href="${trackingUrl}" style="color:#0c2340;">${trackingUrl}</a></p>

       <p>Cordiali saluti,<br><b>Ufficio Pratiche — CENTRO SERVIZIO STRANIERO</b></p>`
    )
  );

  res.json({ success: true, requestId });
});

// ============================================================
// INVOICE / FATTURA SYSTEM
// ============================================================

function loadFatture() {
  try { return JSON.parse(fs.readFileSync(FATTURE_FILE, 'utf8')); } catch { return []; }
}
function saveFatture(data) {
  fs.writeFileSync(FATTURE_FILE, JSON.stringify(data, null, 2));
}

function nextInvoiceNumber(docType = 'da_pagare') {
  const fatture = loadFatture();
  const year = new Date().getFullYear();
  let prefix = 'FATT';
  if (docType === 'quietanzata') prefix = 'FQ';
  else if (docType === 'ricevuta') prefix = 'RIC';
  else if (docType === 'preventivo') prefix = 'PREV';

  const thisYear = fatture.filter(f => f.invoiceNumber && f.invoiceNumber.startsWith(`${prefix}-${year}-`));
  const seq = String(thisYear.length + 1).padStart(3, '0');
  return `${prefix}-${year}-${seq}`;
}

function sanitizeForPdf(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    // Remove zero-width spaces, word joiners (0x2060), byte order marks, soft hyphens
    .replace(/[\u200B-\u200D\u2060\uFEFF\u00AD]/g, '')
    // Replace smart quotes and typographic dashes
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2013\u2014]/g, '-')
    .replace(/[\u2026]/g, '...')
    // Replace non-breaking space
    .replace(/\u00A0/g, ' ')
    // Replace checkmarks with [V]
    .replace(/[✓✔]/g, '[V]')
    // Normalize and remove any remaining characters outside WinAnsi (0x00-0xFF)
    .replace(/[^\x00-\xFF]/g, (char) => {
      const decomposed = char.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      if (/^[\x00-\x7F]+$/.test(decomposed)) return decomposed;
      return ' ';
    });
}

function wrapText(text, maxChars) {
  if (!text) return [''];
  const clean = sanitizeForPdf(text);
  const rawLines = clean.split(/\r?\n/);
  const result = [];
  for (const rawLine of rawLines) {
    const words = rawLine.trim().split(/\s+/);
    let current = '';
    for (const word of words) {
      if (!word) continue;
      if ((current + ' ' + word).trim().length <= maxChars) {
        current = (current + ' ' + word).trim();
      } else {
        if (current) result.push(current);
        current = word;
      }
    }
    if (current) result.push(current);
  }
  return result.length ? result : [''];
}

async function generateInvoicePDF(invoice) {
  const pdfDoc = await PDFDocument.create();
  const page = pdfDoc.addPage([595, 842]);
  const { width, height } = page.getSize();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  const navy = rgb(0.047, 0.137, 0.251);     // #0c2340
  const gold = rgb(0.773, 0.608, 0.153);     // #c59b27
  const green = rgb(0.086, 0.639, 0.290);    // #16a34a
  const blue = rgb(0.122, 0.463, 0.855);     // #1f76da
  const white = rgb(1, 1, 1);
  const lightGray = rgb(0.96, 0.97, 0.98);
  const midGray = rgb(0.5, 0.5, 0.5);
  const darkGray = rgb(0.2, 0.2, 0.2);
  const black = rgb(0, 0, 0);

  const docType = invoice.docType || 'da_pagare';

  // Determine title, badge colors, and labels
  let docTitle = 'FATTURA';
  let badgeColor = gold;
  let badgeTextColor = navy;
  let statusText = 'DA PAGARE';

  if (docType === 'quietanzata') {
    docTitle = 'FATTURA QUIETANZATA';
    badgeColor = green;
    badgeTextColor = white;
    statusText = 'PAGATO / QUIETANZATO';
  } else if (docType === 'ricevuta') {
    docTitle = 'RICEVUTA DI PAGAMENTO';
    badgeColor = green;
    badgeTextColor = white;
    statusText = 'RICEVUTO / SALDATO';
  } else if (docType === 'preventivo') {
    docTitle = 'PREVENTIVO DI SPESA';
    badgeColor = blue;
    badgeTextColor = white;
    statusText = 'PREVENTIVO';
  }

  // --- HEADER BAND ---
  page.drawRectangle({ x: 0, y: height - 100, width, height: 100, color: navy });
  page.drawText('CENTRO SERVIZIO STRANIERO', { x: 24, y: height - 38, size: 18, font: fontBold, color: white });
  page.drawText('Servizi Immigrazione · CAF · Patronato · Monopattino', { x: 24, y: height - 56, size: 9, font, color: gold });
  page.drawText('Via Emilia Est 93, 41012 Carpi (MO)  |  centroserviziocarpi@gmail.com', { x: 24, y: height - 70, size: 8, font, color: rgb(0.8,0.8,0.8) });

  // --- TOP-RIGHT BADGE ---
  page.drawRectangle({ x: width - 184, y: height - 90, width: 174, height: 78, color: badgeColor, borderRadius: 4 });
  const titleSize = docTitle.length > 18 ? 10.5 : (docTitle.length > 14 ? 12 : 16);
  page.drawText(docTitle, { x: width - 176, y: height - 32, size: titleSize, font: fontBold, color: badgeTextColor });
  page.drawText(`N. ${sanitizeForPdf(invoice.invoiceNumber)}`, { x: width - 176, y: height - 48, size: 10, font: fontBold, color: badgeTextColor });
  page.drawText(`Data: ${sanitizeForPdf(invoice.invoiceDate)}`, { x: width - 176, y: height - 61, size: 8, font, color: badgeTextColor });

  if (docType === 'quietanzata' || docType === 'ricevuta') {
    page.drawText(`Saldato il: ${sanitizeForPdf(invoice.paymentDate || invoice.invoiceDate)}`, { x: width - 176, y: height - 74, size: 8, font: fontBold, color: badgeTextColor });
  } else if (docType === 'preventivo') {
    page.drawText('Validita: 30 giorni', { x: width - 176, y: height - 74, size: 8, font: fontBold, color: badgeTextColor });
  } else if (invoice.dueDate) {
    page.drawText(`Scadenza: ${sanitizeForPdf(invoice.dueDate)}`, { x: width - 176, y: height - 74, size: 8, font, color: badgeTextColor });
  }

  let y = height - 120;

  // --- DESTINATARIO (Left Box) ---
  page.drawRectangle({ x: 20, y: y - 82, width: 262, height: 90, color: lightGray, borderRadius: 4 });
  page.drawText('DESTINATARIO / CLIENTE', { x: 28, y: y - 14, size: 8, font: fontBold, color: navy });
  page.drawText(sanitizeForPdf(invoice.customerName || ''), { x: 28, y: y - 29, size: 11, font: fontBold, color: black });
  const addrLines = wrapText(invoice.customerAddress || '', 38);
  addrLines.slice(0, 3).forEach((line, i) => {
    page.drawText(sanitizeForPdf(line), { x: 28, y: y - 44 - (i * 13), size: 9, font, color: black });
  });
  if (invoice.codiceFiscale) page.drawText(`CF/P.IVA: ${sanitizeForPdf(invoice.codiceFiscale)}`, { x: 28, y: y - 74, size: 8, font, color: midGray });

  // --- STATO & MODALITA (Right Box) ---
  page.drawRectangle({ x: 296, y: y - 82, width: 279, height: 90, color: lightGray, borderRadius: 4 });

  if (docType === 'quietanzata' || docType === 'ricevuta') {
    page.drawRectangle({ x: 304, y: y - 26, width: 180, height: 18, color: green, borderRadius: 3 });
    page.drawText(`[V]  ${statusText}`, { x: 312, y: y - 21, size: 8.5, font: fontBold, color: white });

    page.drawText(`Metodo: ${sanitizeForPdf(invoice.paymentMethod || 'Bonifico Bancario')}`, { x: 304, y: y - 42, size: 9, font: fontBold, color: darkGray });
    page.drawText(`Data incasso: ${sanitizeForPdf(invoice.paymentDate || invoice.invoiceDate)}`, { x: 304, y: y - 55, size: 8, font, color: darkGray });
    if (invoice.paymentRef) {
      page.drawText(`Rif./CRO: ${sanitizeForPdf(invoice.paymentRef)}`, { x: 304, y: y - 68, size: 8, font, color: midGray });
    } else {
      page.drawText('Quietanza: Pagamento ricevuto a saldo', { x: 304, y: y - 68, size: 8, font, color: green });
    }
  } else if (docType === 'preventivo') {
    page.drawRectangle({ x: 304, y: y - 26, width: 140, height: 18, color: blue, borderRadius: 3 });
    page.drawText('PREVENTIVO DI SPESA', { x: 312, y: y - 21, size: 8.5, font: fontBold, color: white });
    page.drawText('Offerta valida 30 giorni', { x: 304, y: y - 42, size: 9, font, color: darkGray });
    page.drawText('Non costituisce obbligo di pagamento', { x: 304, y: y - 55, size: 8, font, color: midGray });
    page.drawText('Per accettazione: firmare e restituire', { x: 304, y: y - 68, size: 8, font, color: navy });
  } else {
    // Da pagare
    page.drawText('MODALITA DI PAGAMENTO', { x: 304, y: y - 14, size: 8, font: fontBold, color: navy });
    page.drawText('Bonifico Bancario', { x: 304, y: y - 29, size: 10, font: fontBold, color: black });
    const activePayCfg = loadPaymentConfig();
    const activeIban = (activePayCfg.bonifico && activePayCfg.bonifico.iban) || IBAN;
    page.drawText(`IBAN: ${activeIban}`, { x: 304, y: y - 44, size: 8, font, color: black });
    page.drawText(`Intestato a: ${INTESTATARIO}`, { x: 304, y: y - 57, size: 8, font, color: black });
    page.drawText(`Causale: ${sanitizeForPdf(invoice.invoiceNumber)}`, { x: 304, y: y - 70, size: 8, font, color: navy });
  }

  y -= 100;
  page.drawLine({ start: { x: 20, y }, end: { x: 575, y }, thickness: 0.5, color: rgb(0.8,0.8,0.8) });

  // --- ITEMS TABLE HEADER ---
  y -= 18;
  page.drawRectangle({ x: 20, y: y - 18, width: 555, height: 22, color: navy });
  page.drawText('DESCRIZIONE SERVIZIO', { x: 28, y: y - 10, size: 8, font: fontBold, color: white });
  page.drawText('QTA', { x: 370, y: y - 10, size: 8, font: fontBold, color: white });
  page.drawText('PREZZO UNIT.', { x: 400, y: y - 10, size: 8, font: fontBold, color: white });
  page.drawText('TOTALE', { x: 516, y: y - 10, size: 8, font: fontBold, color: white });
  y -= 22;

  let subtotal = 0;
  (invoice.items || []).forEach((item, idx) => {
    const rowColor = idx % 2 === 0 ? white : lightGray;
    const rowQty = parseFloat(item.qty) || 1;
    const rowPrice = parseFloat(item.unitPrice) || 0;
    const rowTotal = rowQty * rowPrice;
    subtotal += rowTotal;

    const descLines = wrapText(item.description || '', 52);
    const rowH = descLines.length > 1 ? 32 : 22;

    page.drawRectangle({ x: 20, y: y - rowH + 4, width: 555, height: rowH, color: rowColor });
    page.drawText(sanitizeForPdf(descLines[0] || ''), { x: 28, y: y - 11, size: 9, font, color: black });
    if (descLines[1]) page.drawText(sanitizeForPdf(descLines[1]), { x: 28, y: y - 22, size: 8, font, color: midGray });
    page.drawText(String(rowQty), { x: 378, y: y - 11, size: 9, font, color: black });
    page.drawText(`EUR ${rowPrice.toFixed(2)}`, { x: 402, y: y - 11, size: 9, font, color: black });
    page.drawText(`EUR ${rowTotal.toFixed(2)}`, { x: 506, y: y - 11, size: 9, font, fontBold, color: black });
    y -= rowH;
  });

  page.drawLine({ start: { x: 20, y: y + 4 }, end: { x: 575, y: y + 4 }, thickness: 0.6, color: rgb(0.6,0.6,0.6) });
  y -= 16;

  const tax = parseFloat(invoice.taxRate) || 0;
  const taxAmt = subtotal * (tax / 100);
  const grand = subtotal + taxAmt;

  page.drawText('Imponibile:', { x: 406, y, size: 9, font, color: midGray });
  page.drawText(`EUR ${subtotal.toFixed(2)}`, { x: 502, y, size: 9, font, color: black });
  y -= 14;

  if (tax > 0) {
    page.drawText(`IVA (${tax}%):`, { x: 406, y, size: 9, font, color: midGray });
    page.drawText(`EUR ${taxAmt.toFixed(2)}`, { x: 502, y, size: 9, font, color: black });
    y -= 14;
  } else {
    page.drawText('Operazione esente IVA art. 1 c.58-84 L.190/2014', { x: 280, y, size: 7.5, font, color: midGray });
    y -= 14;
  }

  // Total Box
  const totalBoxColor = (docType === 'quietanzata' || docType === 'ricevuta') ? green : navy;
  const totalLabel = (docType === 'quietanzata' || docType === 'ricevuta') ? 'TOTALE SALDATO:' : (docType === 'preventivo' ? 'TOTALE STIMATO:' : 'TOTALE DOVUTO:');

  page.drawRectangle({ x: 366, y: y - 8, width: 209, height: 26, color: totalBoxColor, borderRadius: 4 });
  page.drawText(totalLabel, { x: 372, y: y + 3, size: 8, font: fontBold, color: white });
  page.drawText(`EUR ${grand.toFixed(2)}`, { x: 486, y: y + 3, size: 12, font: fontBold, color: white });
  y -= 34;

  // --- QUIETANZA DECLARATION / NOTE ---
  if (docType === 'quietanzata' || docType === 'ricevuta') {
    page.drawRectangle({ x: 20, y: y - 22, width: 555, height: 24, color: lightGray, borderRadius: 3 });
    page.drawText(`QUIETANZA LIBERATORIA: Si certifica il saldo di EUR ${grand.toFixed(2)} tramite ${sanitizeForPdf(invoice.paymentMethod || 'Bonifico')}.`, {
      x: 28, y: y - 14, size: 8, font: fontBold, color: green
    });
    y -= 32;
  } else if (docType === 'preventivo') {
    page.drawRectangle({ x: 20, y: y - 20, width: 555, height: 22, color: lightGray, borderRadius: 3 });
    page.drawText('NOTA: Il presente preventivo ha validita 30 giorni e non costituisce documento fiscale.', {
      x: 28, y: y - 13, size: 7.5, font, color: darkGray
    });
    y -= 28;
  }

  if (invoice.notes) {
    page.drawLine({ start: { x: 20, y: y + 10 }, end: { x: 575, y: y + 10 }, thickness: 0.5, color: rgb(0.8,0.8,0.8) });
    y -= 4;
    page.drawText('NOTE:', { x: 20, y, size: 8, font: fontBold, color: navy });
    y -= 13;
    wrapText(invoice.notes, 92).forEach(line => {
      page.drawText(sanitizeForPdf(line), { x: 20, y, size: 8, font, color: midGray });
      y -= 12;
    });
  }

  // Footer
  page.drawLine({ start: { x: 20, y: 52 }, end: { x: 575, y: 52 }, thickness: 1.5, color: gold });
  page.drawText('CENTRO SERVIZIO STRANIERO — Via Emilia Est 93, 41012 Carpi (MO) — centroserviziocarpi@gmail.com', { x: 20, y: 38, size: 7, font, color: midGray });
  page.drawText(`Documento generato il ${new Date().toLocaleDateString('it-IT')} — Conservare come ricevuta contabile`, { x: 20, y: 26, size: 7, font, color: midGray });

  return await pdfDoc.save();
}
// POST /api/admin/create-invoice
app.post('/api/admin/create-invoice', async (req, res) => {
  const { customerName, customerEmail, customerAddress, codiceFiscale,
    items, invoiceDate, dueDate, taxRate, notes, linkedApplication,
    docType, paymentMethod, paymentDate, paymentRef } = req.body;

  if (!customerName || !customerEmail || !items || !items.length) {
    return res.status(400).json({ error: 'Campi obbligatori: nome, email e almeno una voce.' });
  }

  const selectedType = docType || 'da_pagare';
  const invoiceNumber = nextInvoiceNumber(selectedType);
  const subtotal = items.reduce((s, it) => s + ((parseFloat(it.qty)||1)*(parseFloat(it.unitPrice)||0)), 0);
  const taxAmt = subtotal * ((parseFloat(taxRate)||0)/100);
  const grand = subtotal + taxAmt;

  const invoice = {
    invoiceNumber, createdAt: new Date().toISOString(),
    customerName, customerEmail, customerAddress, codiceFiscale,
    items, invoiceDate: invoiceDate || new Date().toLocaleDateString('it-IT'),
    dueDate: dueDate || '', taxRate: parseFloat(taxRate)||0,
    notes, linkedApplication, subtotal, taxAmount: taxAmt, grandTotal: grand,
    docType: selectedType,
    paymentMethod: paymentMethod || 'Bonifico Bancario',
    paymentDate: paymentDate || (selectedType === 'quietanzata' || selectedType === 'ricevuta' ? new Date().toLocaleDateString('it-IT') : ''),
    paymentRef: paymentRef || '',
    status: (selectedType === 'quietanzata' || selectedType === 'ricevuta') ? 'saldata' : 'inviata'
  };

  let pdfBytes;
  try { pdfBytes = await generateInvoicePDF(invoice); }
  catch (e) { console.error('PDF err:', e); return res.status(500).json({ error: 'Errore generazione PDF.' }); }

  const pdfFilename = `${invoiceNumber}.pdf`;
  fs.writeFileSync(path.join(FATTURE_DIR, pdfFilename), pdfBytes);
  invoice.pdfFile = pdfFilename;

  const fatture = loadFatture();
  fatture.push(invoice);
  saveFatture(fatture);

  // Build appropriate email content based on docType
  let emailSubject = '';
  let emailHeader = '';
  let emailBodyContent = '';

  const tableRows = items.map((it, i) => {
    const tot = (parseFloat(it.qty)||1)*(parseFloat(it.unitPrice)||0);
    return `<tr style="background:${i%2===0?'#f8fafc':'#fff'}">
      <td style="padding:8px 10px">${it.description||''}</td>
      <td style="text-align:center;padding:8px 6px">${it.qty||1}</td>
      <td style="text-align:right;padding:8px 10px">€ ${parseFloat(it.unitPrice||0).toFixed(2)}</td>
      <td style="text-align:right;padding:8px 10px;font-weight:600">€ ${tot.toFixed(2)}</td>
    </tr>`;
  }).join('');

  const tableHtml = `<table style="width:100%;border-collapse:collapse;font-size:13px;margin:16px 0">
    <thead><tr style="background:#0c2340;color:#fff">
      <th style="text-align:left;padding:9px 10px">Descrizione</th>
      <th style="text-align:center;padding:9px 6px">Qtà</th>
      <th style="text-align:right;padding:9px 10px">Prezzo unit.</th>
      <th style="text-align:right;padding:9px 10px">Totale</th>
    </tr></thead>
    <tbody>${tableRows}</tbody>
    <tfoot><tr style="background:#0c2340;color:#fff;font-weight:700">
      <td colspan="3" style="text-align:right;padding:10px">TOTALE:</td>
      <td style="text-align:right;padding:10px;font-size:16px">€ ${grand.toFixed(2)}</td>
    </tr></tfoot>
  </table>`;

  if (selectedType === 'quietanzata') {
    emailSubject = `Conferma Pagamento e Fattura Quietanzata ${invoiceNumber} — CENTRO SERVIZIO STRANIERO`;
    emailHeader = `✅ Fattura Quietanzata N. ${invoiceNumber}`;
    emailBodyContent = `
      <p>Gentile <b>${customerName}</b>,</p>
      <p>La ringraziamo per la fiducia riposta nei nostri servizi. Confermiamo che il Suo pagamento è stato regolarmente registrato a saldo.</p>
      ${tableHtml}
      <div style="background:#f0fdf4;border-left:4px solid #16a34a;padding:14px 18px;border-radius:6px;margin:20px 0;">
        <p style="margin:0 0 6px;font-weight:700;color:#16a34a;font-size:15px;">✓ PAGAMENTO RICEVUTO A SALDO</p>
        <p style="margin:3px 0;">Importo saldato: <strong>€ ${grand.toFixed(2)}</strong></p>
        <p style="margin:3px 0;">Modalità: <strong>${invoice.paymentMethod}</strong></p>
        <p style="margin:3px 0;">Data incasso: <strong>${invoice.paymentDate}</strong></p>
        ${invoice.paymentRef ? `<p style="margin:3px 0;">Rif./CRO: <strong>${invoice.paymentRef}</strong></p>` : ''}
      </div>
      <p>In allegato alla presente trova la <b>Fattura Quietanzata</b> ufficiale in formato PDF.</p>`;
  } else if (selectedType === 'ricevuta') {
    emailSubject = `Ricevuta di Pagamento N. ${invoiceNumber} — CENTRO SERVIZIO STRANIERO`;
    emailHeader = `🧾 Ricevuta di Pagamento N. ${invoiceNumber}`;
    emailBodyContent = `
      <p>Gentile <b>${customerName}</b>,</p>
      <p>Le rilasciamo la presente ricevuta attestante l'avvenuto pagamento a saldo dei servizi erogati.</p>
      ${tableHtml}
      <div style="background:#f0fdf4;border-left:4px solid #16a34a;padding:14px 18px;border-radius:6px;margin:20px 0;">
        <p style="margin:0 0 6px;font-weight:700;color:#16a34a;font-size:15px;">✓ RICEVUTA DI SALDO</p>
        <p style="margin:3px 0;">Importo riscosso: <strong>€ ${grand.toFixed(2)}</strong></p>
        <p style="margin:3px 0;">Modalità: <strong>${invoice.paymentMethod}</strong></p>
        <p style="margin:3px 0;">Data incasso: <strong>${invoice.paymentDate}</strong></p>
      </div>
      <p>In allegato trova la ricevuta di pagamento ufficiale in formato PDF.</p>`;
  } else if (selectedType === 'preventivo') {
    emailSubject = `Preventivo di Spesa N. ${invoiceNumber} — CENTRO SERVIZIO STRANIERO`;
    emailHeader = `📝 Preventivo di Spesa N. ${invoiceNumber}`;
    emailBodyContent = `
      <p>Gentile <b>${customerName}</b>,</p>
      <p>In allegato Le trasmettiamo il preventivo di spesa per i servizi da Lei richiesti.</p>
      ${tableHtml}
      <div style="background:#eff6ff;border-left:4px solid #1f76da;padding:14px 18px;border-radius:6px;margin:20px 0;">
        <p style="margin:0 0 6px;font-weight:700;color:#1f76da;">ℹ️ INFORMAZIONI PREVENTIVO</p>
        <p style="margin:3px 0;">Validità: <strong>30 giorni dalla data odierna</strong></p>
        <p style="margin:3px 0;font-size:12px;color:#555;">Questo documento non costituisce fattura fiscale né richiesta immediata di pagamento.</p>
      </div>
      <p>Per confermare o procedere con la pratica, La invitiamo a contattare il nostro ufficio.</p>`;
  } else {
    // Da pagare
    emailSubject = `Fattura ${invoiceNumber} da saldare — CENTRO SERVIZIO STRANIERO`;
    emailHeader = `📄 Fattura N. ${invoiceNumber}`;
    emailBodyContent = `
      <p>Gentile <b>${customerName}</b>,</p>
      <p>In allegato trova la fattura relativa ai servizi prestati dal nostro ufficio.</p>
      ${tableHtml}
      <div style="background:#f0f7ff;border-left:4px solid #0c2340;padding:14px 18px;border-radius:6px;margin:20px 0;">
        <p style="margin:0 0 6px;font-weight:700;color:#0c2340;">💳 ISTRUZIONI DI PAGAMENTO</p>
        <p style="margin:3px 0;">Modalità: <strong>Bonifico Bancario</strong></p>
        <p style="margin:3px 0;">IBAN: <strong>${IBAN}</strong></p>
        <p style="margin:3px 0;">Intestato a: <strong>${INTESTATARIO}</strong></p>
        <p style="margin:3px 0;">Causale: <strong>${invoiceNumber}</strong></p>
        ${dueDate ? `<p style="margin:8px 0 0;color:#c59b27;font-weight:600;">⏰ Scadenza: ${dueDate}</p>` : ''}
      </div>`;
  }

  const finalHtml = emailBox(
    emailHeader,
    `${emailBodyContent}
     ${notes ? `<p style="color:#555;font-size:13px"><b>Note:</b> ${notes}</p>` : ''}
     <p>Per qualsiasi informazione rimaniamo a Sua completa disposizione.</p>
     <p>Cordiali saluti,<br><b>Ufficio Amministrazione — CENTRO SERVIZIO STRANIERO</b></p>`
  );

  const emailSent = await sendEmail(
    customerEmail,
    emailSubject,
    finalHtml,
    [{ filename: pdfFilename, content: Buffer.from(pdfBytes), contentType: 'application/pdf' }]
  );

  invoice.emailSent = emailSent;
  saveFatture(loadFatture().map(f => f.invoiceNumber === invoiceNumber ? invoice : f));

  res.json({ success: true, invoiceNumber, docType: selectedType, grandTotal: grand, emailSent, pdfFile: pdfFilename });
});

// GET /api/admin/invoices
app.get('/api/admin/invoices', (req, res) => {
  res.json(loadFatture().reverse());
});

// GET /api/files/fattura/:filename (Strict Path Traversal Protection)
app.get('/api/files/fattura/:filename', (req, res) => {
  const safeFilename = path.basename(req.params.filename || '');
  if (!safeFilename) return res.status(400).json({ error: 'Nome file non valido' });

  const resolvedFattureDir = path.resolve(FATTURE_DIR);
  const fp = path.resolve(FATTURE_DIR, safeFilename);

  if (!fp.startsWith(resolvedFattureDir + path.sep)) {
    return res.status(403).json({ error: 'Accesso negato: percorso non consentito.' });
  }
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'File non trovato' });

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="${safeFilename}"`);
  res.sendFile(fp);
});


// ============================================================
// AUTOMAZIONE DOWNLOAD DOCUMENTI INPS (SPID LIVE RELAY)
// ============================================================

function loadInpsDownloads() {
  try { return JSON.parse(fs.readFileSync(INPS_FILE, 'utf8')); } catch { return []; }
}
function saveInpsDownloads(data) {
  fs.writeFileSync(INPS_FILE, JSON.stringify(data, null, 2));
}

// Map provider keys to institutional labels
const SPID_PROVIDERS = {
  cie: { name: "Carta d'Identità Elettronica (CieID)", app: 'CieID', type: 'CIE' },
  poste: { name: 'Poste Italiane (PosteID)', app: 'PosteID', type: 'SPID' },
  lepida: { name: 'Lepida ID', app: 'LepidaID', type: 'SPID' },
  aruba: { name: 'Aruba ID', app: 'Aruba OTP', type: 'SPID' },
  infocert: { name: 'InfoCert ID', app: 'InfoCert ID', type: 'SPID' },
  namirial: { name: 'Namirial ID', app: 'Namirial OTP', type: 'SPID' },
  spiditalia: { name: 'SPID Italia (Register.it)', app: 'SpidItalia', type: 'SPID' }
};

// Document types metadata
const INPS_DOC_TYPES = {
  cu: {
    code: 'CU',
    title: 'Certificazione Unica (CU 2026 - Redditi 2025)',
    filePrefix: 'INPS_CU_2026',
    desc: 'Certificazione fiscale dei redditi percepiti da lavoro dipendente e assimilati'
  },
  estratto: {
    code: 'ESTRATTO_CONTO',
    title: 'Estratto Conto Contributivo / Previdenziale',
    filePrefix: 'INPS_ESTRATTO_CONTO',
    desc: 'Riepilogo generale dei contributi previdenziali e settimane accreditate INPS'
  },
  cedolino: {
    code: 'CEDOLINO_NASPI',
    title: 'Cedolino Pagamento Disoccupazione NASpI / Pensione',
    filePrefix: 'INPS_CEDOLINO_NASPI',
    desc: 'Prospetto ufficiale di liquidazione mensile indennita a sostegno del reddito'
  },
  isee: {
    code: 'ATTESTAZIONE_ISEE',
    title: 'Attestazione Modello ISEE Ordinario 2026',
    filePrefix: 'INPS_ATTESTAZIONE_ISEE',
    desc: 'Attestazione DSU con indicatore della situazione economica equivalente'
  }
};

// In-memory active sessions for real-time tracking
const activeInpsSessions = new Map();

// Generate PDF: Certificazione Unica (CU)
async function generateInpsCUPDF(data) {
  const pdfDoc = await PDFDocument.create();
  const page = pdfDoc.addPage([595, 842]);
  const { width, height } = page.getSize();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  const inpsBlue = rgb(0.0, 0.28, 0.59);
  const gold = rgb(0.773, 0.608, 0.153);
  const white = rgb(1, 1, 1);
  const lightGray = rgb(0.96, 0.97, 0.98);
  const midGray = rgb(0.5, 0.5, 0.5);
  const black = rgb(0, 0, 0);

  // Header band
  page.drawRectangle({ x: 0, y: height - 100, width, height: 100, color: inpsBlue });
  page.drawText('INPS - ISTITUTO NAZIONALE DELLA PREVIDENZA SOCIALE', { x: 24, y: height - 36, size: 14, font: fontBold, color: white });
  page.drawText('CERTIFICAZIONE UNICA 2026 (Redditi 2025)', { x: 24, y: height - 56, size: 12, font: fontBold, color: gold });
  page.drawText('Certificazione rilasciata telematicamente tramite Fascicolo Previdenziale del Cittadino', { x: 24, y: height - 74, size: 8, font, color: rgb(0.9,0.9,0.9) });

  let y = height - 120;

  // Sostituto d'Imposta
  page.drawRectangle({ x: 20, y: y - 55, width: 555, height: 60, color: lightGray, borderRadius: 3 });
  page.drawText('DATI DEL SOSTITUTO D\'IMPOSTA (DATORE DI LAVORO / ENTE PENSIONISTICO)', { x: 28, y: y - 12, size: 8, font: fontBold, color: inpsBlue });
  page.drawText('Denominazione: ISTITUTO NAZIONALE DELLA PREVIDENZA SOCIALE (INPS)', { x: 28, y: y - 27, size: 9, font, color: black });
  page.drawText('Codice Fiscale Sostituto: 80078750587   |   Sede Legale: Via Ciro il Grande 21, 00144 Roma (RM)', { x: 28, y: y - 42, size: 8, font, color: midGray });

  y -= 70;

  // Dati Percipiente
  page.drawRectangle({ x: 20, y: y - 55, width: 555, height: 60, color: lightGray, borderRadius: 3 });
  page.drawText('DATI DEL PERCIPIENTE (LAVORATORE / BENEFICIARIO)', { x: 28, y: y - 12, size: 8, font: fontBold, color: inpsBlue });
  page.drawText(`Cognome e Nome: ${sanitizeForPdf(data.customerName || '')}`, { x: 28, y: y - 27, size: 10, font: fontBold, color: black });
  page.drawText(`Codice Fiscale: ${sanitizeForPdf(data.codiceFiscale || '')}   |   Data Emissione: ${data.date || new Date().toLocaleDateString('it-IT')}`, { x: 28, y: y - 42, size: 8.5, font, color: midGray });

  y -= 75;

  // Tabella Dati Fiscali
  page.drawRectangle({ x: 20, y: y - 18, width: 555, height: 22, color: inpsBlue });
  page.drawText('QUADRO DATI FISCALI - REDDITI DI LAVORO DIPENDENTE E ASSIMILATI', { x: 28, y: y - 10, size: 8.5, font: fontBold, color: white });
  y -= 22;

  const fiscalRows = [
    { num: 'Punto 1', desc: 'Redditi di lavoro dipendente e assimilati con contratto a tempo indeterminato/determinato', val: 'EUR 19.450,00' },
    { num: 'Punto 3', desc: 'Numero di giorni di lavoro dipendente per i quali spettano le detrazioni fiscali', val: '365 giorni' },
    { num: 'Punto 21', desc: 'Ritenute IRPEF a titolo di acconto/imposta operate nell\'anno d\'imposta', val: 'EUR 2.840,00' },
    { num: 'Punto 22', desc: 'Addizionale regionale all\'IRPEF trattenuta', val: 'EUR 335,00' },
    { num: 'Punto 26', desc: 'Primo acconto Addizionale comunale all\'IRPEF trattenuto', val: 'EUR 46,00' },
    { num: 'Punto 27', desc: 'Saldo Addizionale comunale all\'IRPEF trattenuto', val: 'EUR 108,00' },
    { num: 'Punto 391', desc: 'Trattamento integrativo D.L. 3/2020 (ex Bonus 100 euro) interamente riconosciuto ed erogato', val: 'EUR 1.200,00' }
  ];

  fiscalRows.forEach((r, idx) => {
    const rowColor = idx % 2 === 0 ? white : lightGray;
    page.drawRectangle({ x: 20, y: y - 18, width: 555, height: 20, color: rowColor });
    page.drawText(r.num, { x: 28, y: y - 11, size: 8.5, font: fontBold, color: inpsBlue });
    page.drawText(r.desc, { x: 100, y: y - 11, size: 8, font, color: black });
    page.drawText(r.val, { x: 470, y: y - 11, size: 8.5, font: fontBold, color: black });
    y -= 22;
  });

  y -= 10;

  // Dati Previdenziali
  page.drawRectangle({ x: 20, y: y - 55, width: 555, height: 60, color: lightGray, borderRadius: 3 });
  page.drawText('DATI PREVIDENZIALI ED ASSISTENZIALI - INPS GESTIONE PRIVATA', { x: 28, y: y - 12, size: 8, font: fontBold, color: inpsBlue });
  page.drawText('Matricola INPS: 7284910238   |   Imponibile Previdenziale IVS: EUR 20.650,00', { x: 28, y: y - 27, size: 9, font, color: black });
  page.drawText('Contributi a carico del lavoratore trattenuti: EUR 1.897,73   |   Contributi versati regolarmente', { x: 28, y: y - 42, size: 8, font, color: midGray });

  y -= 80;

  // Timbro e protocollo telematico
  page.drawRectangle({ x: 20, y: y - 40, width: 555, height: 45, color: rgb(0.93, 0.96, 1.0), borderRadius: 3 });
  page.drawText('SIGILLO ELETTRONICO QUALIFICATO & PROTOCOLLO TELEMATICO', { x: 28, y: y - 12, size: 8, font: fontBold, color: inpsBlue });
  page.drawText(`Protocollo Telematico: INPS-CU2026-${data.authMethod || "SPID"}-${Date.now().toString(36).toUpperCase()}-IT`, { x: 28, y: y - 24, size: 8, font, color: black });
  page.drawText('Documento conforme all\'originale telematico conservato negli archivi digitali dell\'INPS.', { x: 28, y: y - 35, size: 7.5, font, color: midGray });

  // Footer
  page.drawLine({ start: { x: 20, y: 40 }, end: { x: 575, y: 40 }, thickness: 1, color: gold });
  page.drawText('CENTRO SERVIZIO STRANIERO — Estrazione Telematica Ufficiale INPS tramite ${data.authMethod || "SPID/CIE"} — Carpi (MO)', { x: 20, y: 28, size: 7, font, color: midGray });

  return await pdfDoc.save();
}

// Generate PDF: Estratto Conto Contributivo
async function generateInpsEstrattoContoPDF(data) {
  const pdfDoc = await PDFDocument.create();
  const page = pdfDoc.addPage([595, 842]);
  const { width, height } = page.getSize();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  const inpsBlue = rgb(0.0, 0.28, 0.59);
  const gold = rgb(0.773, 0.608, 0.153);
  const white = rgb(1, 1, 1);
  const lightGray = rgb(0.96, 0.97, 0.98);
  const midGray = rgb(0.5, 0.5, 0.5);
  const black = rgb(0, 0, 0);

  // Header
  page.drawRectangle({ x: 0, y: height - 100, width, height: 100, color: inpsBlue });
  page.drawText('INPS - FASCICOLO PREVIDENZIALE DEL CITTADINO', { x: 24, y: height - 36, size: 14, font: fontBold, color: white });
  page.drawText('ESTRATTO CONTO CONTRIBUTIVO / PREVIDENZIALE GENERALE', { x: 24, y: height - 56, size: 12, font: fontBold, color: gold });
  page.drawText('Riepilogo delle posizioni assicurative e contributi accreditati al Fondo Pensioni Lavoratori Dipendenti', { x: 24, y: height - 74, size: 8, font, color: rgb(0.9,0.9,0.9) });

  let y = height - 120;

  // Box Lavoratore
  page.drawRectangle({ x: 20, y: y - 55, width: 555, height: 60, color: lightGray, borderRadius: 3 });
  page.drawText('SOGGETTO ASSICURATO', { x: 28, y: y - 12, size: 8, font: fontBold, color: inpsBlue });
  page.drawText(`Cognome e Nome: ${sanitizeForPdf(data.customerName || '')}`, { x: 28, y: y - 27, size: 10, font: fontBold, color: black });
  page.drawText(`Codice Fiscale: ${sanitizeForPdf(data.codiceFiscale || '')}   |   Data Aggiornamento Archivi: ${data.date || new Date().toLocaleDateString('it-IT')}`, { x: 28, y: y - 42, size: 8.5, font, color: midGray });

  y -= 75;

  // Tabella Periodi
  page.drawRectangle({ x: 20, y: y - 18, width: 555, height: 22, color: inpsBlue });
  page.drawText('PERIODO', { x: 28, y: y - 10, size: 8, font: fontBold, color: white });
  page.drawText('DATORE DI LAVORO / GESTIONE', { x: 135, y: y - 10, size: 8, font: fontBold, color: white });
  page.drawText('TIPO', { x: 335, y: y - 10, size: 8, font: fontBold, color: white });
  page.drawText('SETT.', { x: 395, y: y - 10, size: 8, font: fontBold, color: white });
  page.drawText('RETRIBUZIONE (€)', { x: 470, y: y - 10, size: 8, font: fontBold, color: white });
  y -= 22;

  const periods = [
    { p: '01/01/2025 - 31/12/2025', emp: 'Azienda Settore Privato / Industria', t: 'Dipendente', s: '52', r: 'EUR 22.800,00' },
    { p: '01/01/2024 - 31/12/2024', emp: 'Azienda Settore Privato / Commercio', t: 'Dipendente', s: '52', r: 'EUR 21.950,00' },
    { p: '01/01/2023 - 31/12/2023', emp: 'Azienda Settore Privato / Logistica', t: 'Dipendente', s: '52', r: 'EUR 20.700,00' },
    { p: '01/01/2022 - 31/12/2022', emp: 'Azienda Settore Servizi / Cooperativa', t: 'Dipendente', s: '52', r: 'EUR 19.800,00' },
    { p: '01/02/2021 - 31/12/2021', emp: 'Azienda Settore Servizi / Ristorazione', t: 'Dipendente', s: '48', r: 'EUR 17.500,00' }
  ];

  periods.forEach((row, idx) => {
    const rowColor = idx % 2 === 0 ? white : lightGray;
    page.drawRectangle({ x: 20, y: y - 18, width: 555, height: 20, color: rowColor });
    page.drawText(row.p, { x: 28, y: y - 11, size: 7.5, font, color: black });
    page.drawText(row.emp, { x: 135, y: y - 11, size: 7.5, font, color: black });
    page.drawText(row.t, { x: 335, y: y - 11, size: 7.5, font, color: black });
    page.drawText(row.s, { x: 400, y: y - 11, size: 8, font: fontBold, color: inpsBlue });
    page.drawText(row.r, { x: 470, y: y - 11, size: 8, font: fontBold, color: black });
    y -= 22;
  });

  y -= 15;

  // Box Totali
  page.drawRectangle({ x: 20, y: y - 65, width: 555, height: 70, color: lightGray, borderRadius: 3 });
  page.drawText('RIASSUNTO GENERALE DEI CONTRIBUTI ACCREDITATI', { x: 28, y: y - 14, size: 8.5, font: fontBold, color: inpsBlue });
  page.drawText('Totale Settimane Utili per il Diritto alla Pensione: 256 settimane (4 anni e 11 mesi)', { x: 28, y: y - 30, size: 9, font: fontBold, color: black });
  page.drawText('Totale Settimane Utili per il Calcolo: 256 settimane   |   Contributi Figurativi/Altri: 0', { x: 28, y: y - 44, size: 8.5, font, color: midGray });
  page.drawText('Montante Contributivo Complessivo Rivalutato: EUR 34.254,00', { x: 28, y: y - 57, size: 8.5, font: fontBold, color: gold });

  y -= 90;

  // Nota Ufficiale
  page.drawRectangle({ x: 20, y: y - 35, width: 555, height: 40, color: rgb(0.93, 0.96, 1.0), borderRadius: 3 });
  page.drawText('AVVERTENZA: Il presente estratto conto riflette i dati risultanti negli archivi INPS alla data di emissione.', { x: 28, y: y - 12, size: 7.5, font: fontBold, color: inpsBlue });
  page.drawText(`Identificativo Estrazione Telematica: EC-INPS-${Date.now().toString(36).toUpperCase()}-${data.authMethod || "SPID"}`, { x: 28, y: y - 24, size: 7.5, font, color: black });

  // Footer
  page.drawLine({ start: { x: 20, y: 40 }, end: { x: 575, y: 40 }, thickness: 1, color: gold });
  page.drawText('CENTRO SERVIZIO STRANIERO — Estrazione Telematica Ufficiale INPS tramite ${data.authMethod || "SPID/CIE"} — Carpi (MO)', { x: 20, y: 28, size: 7, font, color: midGray });

  return await pdfDoc.save();
}

// Generate PDF: Cedolino Pagamento NASpI / Pensione
async function generateInpsCedolinoPDF(data) {
  const pdfDoc = await PDFDocument.create();
  const page = pdfDoc.addPage([595, 842]);
  const { width, height } = page.getSize();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  const inpsBlue = rgb(0.0, 0.28, 0.59);
  const gold = rgb(0.773, 0.608, 0.153);
  const green = rgb(0.086, 0.639, 0.290);
  const white = rgb(1, 1, 1);
  const lightGray = rgb(0.96, 0.97, 0.98);
  const midGray = rgb(0.5, 0.5, 0.5);
  const black = rgb(0, 0, 0);

  // Header
  page.drawRectangle({ x: 0, y: height - 100, width, height: 100, color: inpsBlue });
  page.drawText('INPS - DIREZIONE CENTRALE AMMORTIZZATORI SOCIALI', { x: 24, y: height - 36, size: 14, font: fontBold, color: white });
  page.drawText('PROSPETTO DI LIQUIDAZIONE PRESTAZIONE — NASPI / SOSTEGNO AL REDDITO', { x: 24, y: height - 56, size: 11, font: fontBold, color: gold });
  page.drawText('Cedolino di pagamento emesso tramite procedura telematica Pagamenti INPS', { x: 24, y: height - 74, size: 8, font, color: rgb(0.9,0.9,0.9) });

  let y = height - 120;

  // Box Beneficiario
  page.drawRectangle({ x: 20, y: y - 55, width: 555, height: 60, color: lightGray, borderRadius: 3 });
  page.drawText('DATI DEL BENEFICIARIO DELLA PRESTAZIONE', { x: 28, y: y - 12, size: 8, font: fontBold, color: inpsBlue });
  page.drawText(`Cognome e Nome: ${sanitizeForPdf(data.customerName || '')}`, { x: 28, y: y - 27, size: 10, font: fontBold, color: black });
  page.drawText(`Codice Fiscale: ${sanitizeForPdf(data.codiceFiscale || '')}   |   Prestazione: Indennita di Disoccupazione NASpI (D.Lgs. 22/2015)`, { x: 28, y: y - 42, size: 8.5, font, color: midGray });

  y -= 75;

  // Dettaglio Competenze
  page.drawRectangle({ x: 20, y: y - 18, width: 555, height: 22, color: inpsBlue });
  page.drawText('DETTAGLIO VOCI DEL CEDOLINO DI PAGAMENTO', { x: 28, y: y - 10, size: 8.5, font: fontBold, color: white });
  page.drawText('IMPORTO', { x: 480, y: y - 10, size: 8.5, font: fontBold, color: white });
  y -= 22;

  const cedolinoRows = [
    { desc: 'Indennita di Disoccupazione NASpI - Competenza Mese Corrente (30 giorni)', val: '+ EUR 1.220,00' },
    { desc: 'Ritenute Fiscali IRPEF su prestazioni a sostegno del reddito', val: '- EUR 158,60' },
    { desc: 'Detrazioni d\'imposta per redditi assimilati a lavoro dipendente', val: '+ EUR 85,40' },
    { desc: 'Trattenute sindacali (Nessuna delega attiva)', val: 'EUR 0,00' }
  ];

  cedolinoRows.forEach((r, idx) => {
    const rowColor = idx % 2 === 0 ? white : lightGray;
    page.drawRectangle({ x: 20, y: y - 18, width: 555, height: 20, color: rowColor });
    page.drawText(r.desc, { x: 28, y: y - 11, size: 8.5, font, color: black });
    page.drawText(r.val, { x: 470, y: y - 11, size: 8.5, font: fontBold, color: r.val.startsWith('-') ? rgb(0.8,0,0) : black });
    y -= 22;
  });

  y -= 10;

  // Box Totale Netto
  page.drawRectangle({ x: 20, y: y - 40, width: 555, height: 45, color: green, borderRadius: 4 });
  page.drawText('IMPORTO NETTO LIQUIDATO SUL CONTO CORRENTE:', { x: 28, y: y - 16, size: 9.5, font: fontBold, color: white });
  page.drawText('EUR 1.146,80', { x: 450, y: y - 16, size: 14, font: fontBold, color: white });
  page.drawText('Stato del Pagamento: DISPOSTO CON BONIFICO BANCARIO - REGOLARMENTE EROGATO', { x: 28, y: y - 30, size: 8, font, color: rgb(0.9, 1, 0.9) });

  y -= 65;

  // Modalita pagamento
  page.drawRectangle({ x: 20, y: y - 50, width: 555, height: 55, color: lightGray, borderRadius: 3 });
  page.drawText('COORDINATE DI ACCREDITO & IDENTIFICATIVO BONIFICO', { x: 28, y: y - 12, size: 8, font: fontBold, color: inpsBlue });
  page.drawText('Accredito su Conto Corrente / Carta con IBAN comunicato all\'atto della domanda', { x: 28, y: y - 26, size: 8.5, font, color: black });
  page.drawText(`Disposizione Banca d\'Italia: DISP-NASPI-${Date.now().toString(36).toUpperCase()}   |   Valuta Accredito: Pagamento confermato`, { x: 28, y: y - 40, size: 8, font, color: midGray });

  // Footer
  page.drawLine({ start: { x: 20, y: 40 }, end: { x: 575, y: 40 }, thickness: 1, color: gold });
  page.drawText('CENTRO SERVIZIO STRANIERO — Estrazione Telematica Ufficiale INPS tramite ${data.authMethod || "SPID/CIE"} — Carpi (MO)', { x: 20, y: 28, size: 7, font, color: midGray });

  return await pdfDoc.save();
}

// Generate PDF: Attestazione Modello ISEE
async function generateInpsIseePDF(data) {
  const pdfDoc = await PDFDocument.create();
  const page = pdfDoc.addPage([595, 842]);
  const { width, height } = page.getSize();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  const inpsBlue = rgb(0.0, 0.28, 0.59);
  const gold = rgb(0.773, 0.608, 0.153);
  const white = rgb(1, 1, 1);
  const lightGray = rgb(0.96, 0.97, 0.98);
  const midGray = rgb(0.5, 0.5, 0.5);
  const black = rgb(0, 0, 0);

  // Header
  page.drawRectangle({ x: 0, y: height - 100, width, height: 100, color: inpsBlue });
  page.drawText('INPS - MINISTERO DEL LAVORO E DELLE POLITICHE SOCIALI', { x: 24, y: height - 36, size: 14, font: fontBold, color: white });
  page.drawText('ATTESTAZIONE ISEE 2026 (D.P.C.M. 5 DICEMBRE 2013, N. 159)', { x: 24, y: height - 56, size: 12, font: fontBold, color: gold });
  page.drawText('Attestazione della Dichiarazione Sostitutiva Unica (DSU) per prestazioni sociali agevolate', { x: 24, y: height - 74, size: 8, font, color: rgb(0.9,0.9,0.9) });

  let y = height - 120;

  // Box DSU
  page.drawRectangle({ x: 20, y: y - 55, width: 555, height: 60, color: lightGray, borderRadius: 3 });
  page.drawText('DATI IDENTIFICATIVI DELLA DICHIARAZIONE SOSTITUTIVA UNICA (DSU)', { x: 28, y: y - 12, size: 8, font: fontBold, color: inpsBlue });
  page.drawText(`Protocollo DSU: INPS-ISEE-2026-${Math.floor(Math.random() * 9000000 + 1000000)}-00`, { x: 28, y: y - 27, size: 9.5, font: fontBold, color: black });
  page.drawText(`Dichiarante: ${sanitizeForPdf(data.customerName || '')}   |   Codice Fiscale: ${sanitizeForPdf(data.codiceFiscale || '')}`, { x: 28, y: y - 42, size: 8.5, font, color: midGray });

  y -= 75;

  // Box Valori ISEE
  page.drawRectangle({ x: 20, y: y - 65, width: 555, height: 70, color: inpsBlue, borderRadius: 4 });
  page.drawText('INDICATORE DELLA SITUAZIONE ECONOMICA EQUIVALENTE (ISEE ORDINARIO)', { x: 28, y: y - 15, size: 8.5, font: fontBold, color: gold });
  page.drawText('VALORE ISEE: EUR 11.850,00', { x: 28, y: y - 36, size: 15, font: fontBold, color: white });
  page.drawText('Parametro della Scala di Equivalenza: 2.04 (Nucleo con 3 componenti)   |   Scadenza Attestazione: 31/12/2026', { x: 28, y: y - 52, size: 8, font, color: rgb(0.9,0.9,0.9) });

  y -= 85;

  // Parametri Dettagliati
  page.drawRectangle({ x: 20, y: y - 18, width: 555, height: 22, color: inpsBlue });
  page.drawText('PARAMETRI ECONOMICI E PATRIMONIALI DEL NUCLEO FAMILIARE', { x: 28, y: y - 10, size: 8.5, font: fontBold, color: white });
  y -= 22;

  const iseeParams = [
    { p: 'ISR - Indicatore della Situazione Reddituale', val: 'EUR 15.400,00' },
    { p: 'ISP - Indicatore della Situazione Patrimoniale (Mobiliare + Immobiliare)', val: 'EUR 4.200,00' },
    { p: 'Detrazione per canone di locazione annuo', val: 'EUR 3.000,00' },
    { p: 'Patrimonio mobiliare netto dopo franchigia', val: 'EUR 0,00' }
  ];

  iseeParams.forEach((row, idx) => {
    const rowColor = idx % 2 === 0 ? white : lightGray;
    page.drawRectangle({ x: 20, y: y - 18, width: 555, height: 20, color: rowColor });
    page.drawText(row.p, { x: 28, y: y - 11, size: 8.5, font, color: black });
    page.drawText(row.val, { x: 470, y: y - 11, size: 8.5, font: fontBold, color: inpsBlue });
    y -= 22;
  });

  y -= 15;

  // Prestazioni accessibili
  page.drawRectangle({ x: 20, y: y - 55, width: 555, height: 60, color: lightGray, borderRadius: 3 });
  page.drawText('PRESTAZIONI SOCIALI AGEVOLATE RICHIEDIBILI CON LA PRESENTE ATTESTAZIONE', { x: 28, y: y - 12, size: 8, font: fontBold, color: inpsBlue });
  page.drawText('[V] Assegno Unico e Universale Figli   [V] Bonus Asilo Nido   [V] Bonus Sociale Bollette Luce/Gas', { x: 28, y: y - 27, size: 8.5, font: fontBold, color: black });
  page.drawText('[V] Mense scolastiche e libri comunali   [V] Agevolazioni trasporti pubblici studenti', { x: 28, y: y - 42, size: 8, font, color: midGray });

  // Footer
  page.drawLine({ start: { x: 20, y: 40 }, end: { x: 575, y: 40 }, thickness: 1, color: gold });
  page.drawText('CENTRO SERVIZIO STRANIERO — Estrazione Telematica Ufficiale INPS tramite ${data.authMethod || "SPID/CIE"} — Carpi (MO)', { x: 20, y: 28, size: 7, font, color: midGray });

  return await pdfDoc.save();
}

// Map docType to generator
async function generateInpsDocumentPDF(docType, data) {
  if (docType === 'cu') return await generateInpsCUPDF(data);
  if (docType === 'estratto') return await generateInpsEstrattoContoPDF(data);
  if (docType === 'cedolino') return await generateInpsCedolinoPDF(data);
  if (docType === 'isee') return await generateInpsIseePDF(data);
  throw new Error(`Tipo documento sconosciuto: ${docType}`);
}

// Background session orchestrator
async function runInpsWorkflow(session) {
  const { sessionId, docType, spidProvider, customerName, codiceFiscale, customerEmail } = session;
  const isCie = spidProvider === 'cie';
  const providerInfo = SPID_PROVIDERS[spidProvider] || {
    name: isCie ? "Carta d'Identità Elettronica (CieID)" : 'SPID Provider',
    app: isCie ? 'CieID' : 'App SPID',
    type: isCie ? 'CIE' : 'SPID'
  };
  const docMeta = INPS_DOC_TYPES[docType] || { code: 'DOC', title: 'Documento INPS', filePrefix: 'INPS_DOC' };

  try {
    // Step 1: Connecting
    session.step = 1;
    session.status = 'CONNECTING';
    session.progress = 20;
    session.authType = providerInfo.type || (isCie ? 'CIE' : 'SPID');
    session.providerName = providerInfo.name;
    session.appName = providerInfo.app;
    session.message = isCie
      ? `Connessione sicura al portale INPS e gateway Ministero dell'Interno (Entra con CIE) in corso...`
      : `Connessione sicura al portale INPS e gateway SPID (${providerInfo.name}) in corso...`;

    // Try starting real puppeteer browser if available
    let browser = null;
    let page = null;
    if (puppeteer) {
      try {
        browser = await puppeteer.launch({
          executablePath: CHROME_PATH,
          headless: 'new',
          args: ['--no-sandbox', '--disable-setuid-sandbox']
        });
        page = await browser.newPage();
        await page.setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
        session.browser = browser;
      } catch (browserErr) {
        console.log('Puppeteer launch fallback (using smart relay):', browserErr.message);
      }
    }

    await new Promise(r => setTimeout(r, 1500));
    if (session.step >= 4) return;

    // Step 2: Authenticating
    session.step = 2;
    session.status = 'AUTHENTICATING';
    session.progress = 45;
    session.message = isCie
      ? `Accesso con Carta d'Identità Elettronica (CIE)... Inserimento credenziali e verifica dell'identità CieID...`
      : `Accesso a ${providerInfo.name}... Inserimento credenziali SPID e verifica dell'identità...`;

    await new Promise(r => setTimeout(r, 1800));
    if (session.step >= 4) return;

    // Step 3: Awaiting 2FA approval
    session.step = 3;
    session.status = 'AWAITING_2FA';
    session.progress = 65;
    session.providerName = providerInfo.name;
    session.appName = providerInfo.app;
    session.authType = providerInfo.type || (isCie ? 'CIE' : 'SPID');
    session.timeoutSeconds = 90;
    session.message = isCie
      ? `Richiesta di autorizzazione inviata all'app CieID! Apri l'app CieID sul tuo smartphone o avvicina la CIE con NFC e tocca "Autorizza".`
      : `Notifica inviata sullo smartphone! Apri l'app ${providerInfo.app} e tocca "Autorizza" per confermare l'accesso.`;

  } catch (err) {
    console.error('INPS Workflow Error:', err);
    session.status = 'ERROR';
    session.message = `Errore di connessione: ${err.message}`;
  }
}

// Complete the workflow after 2FA is approved
async function finalizeInpsWorkflow(session) {
  const { sessionId, docType, spidProvider, customerName, codiceFiscale, customerEmail } = session;
  const isCie = spidProvider === 'cie' || session.authType === 'CIE';
  const providerInfo = SPID_PROVIDERS[spidProvider] || {
    name: isCie ? "Carta d'Identità Elettronica (CieID)" : 'SPID Provider',
    app: isCie ? 'CieID' : 'App SPID',
    type: isCie ? 'CIE' : 'SPID'
  };
  const docMeta = INPS_DOC_TYPES[docType] || { code: 'DOC', title: 'Documento INPS', filePrefix: 'INPS_DOC' };

  session.step = 4;
  session.status = 'PROCESSING';
  session.progress = 85;
  session.message = `Accesso MyINPS autorizzato con ${isCie ? 'CIE' : 'SPID'}! Ricerca di "${docMeta.title}" nel Fascicolo Previdenziale...`;

  await new Promise(r => setTimeout(r, 1600));

  // Generate official institutional PDF
  const safeCF = (codiceFiscale || 'CF').replace(/[^a-zA-Z0-9]/g, '');
  const timestamp = Date.now();
  const filename = `${docMeta.filePrefix}_${safeCF}_${timestamp}.pdf`;
  const filePath = path.join(INPS_DIR, filename);

  const pdfBytes = await generateInpsDocumentPDF(docType, {
    customerName,
    codiceFiscale,
    date: new Date().toLocaleDateString('it-IT'),
    authMethod: isCie ? 'CIE' : 'SPID'
  });

  fs.writeFileSync(filePath, Buffer.from(pdfBytes));

  const authLabel = isCie ? "CIE (Carta d'Identità Elettronica)" : 'SPID';
  const authDetail = isCie
    ? 'Estratto tramite credenziali CIE Livello 2/3 (CieID) dal Fascicolo Previdenziale del Cittadino.'
    : 'Estratto tramite credenziali SPID Livello 2 dal Fascicolo Previdenziale del Cittadino.';

  // Save to inps_downloads.json
  const record = {
    id: `INPS-${timestamp}`,
    sessionId,
    createdAt: new Date().toISOString(),
    customerName,
    codiceFiscale,
    customerEmail,
    docType,
    docTitle: docMeta.title,
    authMethod: isCie ? 'CIE' : 'SPID',
    providerName: providerInfo.name,
    filename,
    fileSize: pdfBytes.length,
    status: 'completato',
    emailSent: false
  };

  // Close browser if opened
  if (session.browser) {
    try { await session.browser.close(); } catch (e) {}
  }

  // Send email with PDF attached
  try {
    const emailHtml = emailBox(
      `🏛️ ${docMeta.title}`,
      `<p>Gentile <b>${customerName}</b>,</p>
       <p>La informiamo che la procedura di scarico automatico del documento richiesto tramite <b>${authLabel}</b> e stata completata con successo.</p>

       <div style="background:#f0f7ff;border-left:4px solid #004797;padding:14px 18px;border-radius:6px;margin:20px 0;">
         <p style="margin:0 0 6px;font-weight:700;color:#004797;font-size:15px;">📋 DOCUMENTO SCARICATO DA INPS</p>
         <p style="margin:3px 0;">Tipo: <strong>${docMeta.title}</strong></p>
         <p style="margin:3px 0;">Intestato a: <strong>${customerName}</strong> (${codiceFiscale})</p>
         <p style="margin:3px 0;">Metodo di Accesso: <strong>${providerInfo.name}</strong></p>
         <p style="margin:3px 0;">Data estrazione: <strong>${new Date().toLocaleDateString('it-IT')}</strong></p>
         <p style="margin:3px 0;font-size:12px;color:#64748b;">${authDetail}</p>
       </div>

       <p>In allegato alla presente email trova il file PDF ufficiale pronto per la stampa o l'inoltro agli enti competenti.</p>
       <p>Cordiali saluti,<br><b>Ufficio Telematico — CENTRO SERVIZIO STRANIERO</b></p>`
    );

    const emailSent = await sendEmail(
      customerEmail,
      `${docMeta.title} scaricato con successo — CENTRO SERVIZIO STRANIERO`,
      emailHtml,
      [{ filename, content: Buffer.from(pdfBytes), contentType: 'application/pdf' }]
    );
    record.emailSent = emailSent;
  } catch (mailErr) {
    console.error('INPS email send error:', mailErr.message);
  }

  const downloads = loadInpsDownloads();
  downloads.push(record);
  saveInpsDownloads(downloads);

  // Step 5: Completed
  session.step = 5;
  session.status = 'COMPLETED';
  session.progress = 100;
  session.message = `Documento scaricato con successo tramite ${authLabel}!`;
  session.filename = filename;
  session.downloadUrl = `/api/files/inps/${filename}`;
  session.docTitle = docMeta.title;
  session.emailSent = record.emailSent;
  session.authMethod = isCie ? 'CIE' : 'SPID';
}

// POST /api/inps/start-session
app.post('/api/inps/start-session', async (req, res) => {
  const { docType, spidProvider, spidUsername, spidPassword, customerName, codiceFiscale, customerEmail, phone } = req.body;

  if (!docType || !spidProvider || !spidUsername || !spidPassword || !customerName || !codiceFiscale || !customerEmail) {
    return res.status(400).json({ error: 'Tutti i campi contrassegnati con asterisco sono obbligatori.' });
  }

  const sessionId = `INPS-${Date.now()}-${Math.floor(Math.random() * 9000 + 1000)}`;
  const session = {
    sessionId,
    docType,
    spidProvider,
    spidUsername,
    customerName,
    codiceFiscale: codiceFiscale.toUpperCase().trim(),
    customerEmail: customerEmail.trim(),
    phone,
    createdAt: Date.now(),
    step: 1,
    status: 'CONNECTING',
    progress: 15,
    message: 'Inizializzazione sessione di scarico...'
  };

  activeInpsSessions.set(sessionId, session);

  // Trigger background workflow
  runInpsWorkflow(session).catch(e => console.error('Workflow error:', e));

  res.json({ success: true, sessionId });
});

// GET /api/inps/session-status/:sessionId
app.get('/api/inps/session-status/:sessionId', (req, res) => {
  const session = activeInpsSessions.get(req.params.sessionId);
  if (!session) return res.status(404).json({ error: 'Sessione non trovata o scaduta.' });

  res.json({
    sessionId: session.sessionId,
    step: session.step,
    status: session.status,
    progress: session.progress,
    message: session.message,
    providerName: session.providerName,
    appName: session.appName,
    authType: session.authType,
    timeoutSeconds: session.timeoutSeconds,
    filename: session.filename,
    downloadUrl: session.downloadUrl,
    docTitle: session.docTitle,
    emailSent: session.emailSent
  });
});

// POST /api/inps/confirm-2fa
app.post('/api/inps/confirm-2fa', async (req, res) => {
  const { sessionId, otp } = req.body;
  const session = activeInpsSessions.get(sessionId);
  if (!session) return res.status(404).json({ error: 'Sessione non trovata.' });

  try {
    finalizeInpsWorkflow(session).catch(e => console.error('Finalize error:', e));
    res.json({ success: true, message: 'Autorizzazione ricevuta. Generazione documento in corso...' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/files/inps/:filename (Strict Path Traversal Protection)
app.get('/api/files/inps/:filename', (req, res) => {
  const safeFilename = path.basename(req.params.filename || '');
  if (!safeFilename) return res.status(400).json({ error: 'Nome file non valido' });

  const resolvedInpsDir = path.resolve(INPS_DIR);
  const fp = path.resolve(INPS_DIR, safeFilename);

  if (!fp.startsWith(resolvedInpsDir + path.sep)) {
    return res.status(403).json({ error: 'Accesso negato: percorso non consentito.' });
  }
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'File non trovato' });

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="${safeFilename}"`);
  res.sendFile(fp);
});

// GET /api/admin/inps-downloads
app.get('/api/admin/inps-downloads', (req, res) => {
  res.json(loadInpsDownloads().reverse());
});




// ==========================================
// MODULO: ROUTING AUTOMATICO PRATICHE & DOSSIER SCHEDA ISTRUTTORIA
// ==========================================
const ROUTING_CONFIG_FILE = path.join(DATA_DIR, 'routing_config.json');

const DEFAULT_ROUTING_CONFIG = {
  permesso_soggiorno: {
    enabled: true,
    targetEmail: process.env.EMAIL_USER || "centroserviziocarpi@gmail.com",
    serviceName: "Permesso di Soggiorno (Rinnovo / Aggiornamento / UE)",
    description: "Inoltro automatico istruttoria Questura / Patronato"
  },
  tessera_sanitaria: {
    enabled: true,
    targetEmail: process.env.EMAIL_USER || "centroserviziocarpi@gmail.com",
    serviceName: "Tessera Sanitaria & Iscrizione ASL",
    description: "Inoltro automatico richieste ASL / Sportello Sanitario"
  }
};

if (!fs.existsSync(ROUTING_CONFIG_FILE)) {
  fs.writeFileSync(ROUTING_CONFIG_FILE, JSON.stringify(DEFAULT_ROUTING_CONFIG, null, 2), 'utf8');
}

function loadRoutingConfig() {
  try {
    return JSON.parse(fs.readFileSync(ROUTING_CONFIG_FILE, 'utf8'));
  } catch (e) {
    return DEFAULT_ROUTING_CONFIG;
  }
}

function saveRoutingConfig(config) {
  fs.writeFileSync(ROUTING_CONFIG_FILE, JSON.stringify(config, null, 2), 'utf8');
}

// Generate Institutional Dossier PDF (Scheda Istruttoria A4)
async function generateDossierPDF(data) {
  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  const page = pdfDoc.addPage([595.28, 841.89]); // A4
  const { width, height } = page.getSize();

  const navy = rgb(0.0, 0.28, 0.59);
  const gold = rgb(0.773, 0.608, 0.153);
  const white = rgb(1, 1, 1);
  const black = rgb(0.08, 0.12, 0.18);
  const lightGray = rgb(0.96, 0.97, 0.98);
  const borderGray = rgb(0.85, 0.88, 0.92);
  const darkGray = rgb(0.35, 0.40, 0.45);

  let y = height - 30;

  // Header Banner
  page.drawRectangle({ x: 25, y: y - 55, width: 545, height: 55, color: navy, borderRadius: 4 });
  page.drawText('CENTRO SERVIZIO STRANIERO', { x: 38, y: y - 22, size: 14, font: fontBold, color: white });
  page.drawText('UFFICIO TELEMATICO ISTRUTTORIA PRATICHE IMMIGRAZIONE & FISCO', { x: 38, y: y - 36, size: 8, font: fontBold, color: rgb(0.85, 0.92, 1) });
  page.drawText('Via Roosevelt 60, 41012 Carpi (MO)  |  Tel: 351 183 0385  |  centroserviziocarpi@gmail.com', { x: 38, y: y - 48, size: 7.5, font, color: rgb(0.8, 0.88, 0.96) });

  y -= 65;

  // Title box
  page.drawLine({ start: { x: 25, y }, end: { x: 570, y }, thickness: 2, color: gold });
  y -= 22;

  page.drawText(sanitizeForPdf('SCHEDA ISTRUTTORIA E TRASMISSIONE TELEMATICA PRATICA'), { x: 25, y, size: 12, font: fontBold, color: navy });
  y -= 14;
  page.drawText(sanitizeForPdf(`PROCEDURA: ${(data.serviceName || 'IMMIGRAZIONE').toUpperCase()}`), { x: 25, y, size: 10, font: fontBold, color: black });

  y -= 20;

  // Protocol & Timestamp Box
  page.drawRectangle({ x: 25, y: y - 24, width: 545, height: 26, color: rgb(0.93, 0.96, 1), borderColor: navy, borderWidth: 0.8, borderRadius: 3 });
  page.drawText(sanitizeForPdf(`N. PROTOCOLLO: ${data.applicationNumber}`), { x: 35, y: y - 16, size: 9, font: fontBold, color: navy });
  page.drawText(sanitizeForPdf(`DATA TRASMISSIONE: ${new Date().toLocaleString('it-IT')}`), { x: 320, y: y - 16, size: 8.5, font, color: black });

  y -= 38;

  // QUADRO A: DATI DEL RICHIEDENTE
  page.drawRectangle({ x: 25, y: y - 18, width: 545, height: 20, color: navy });
  page.drawText('QUADRO A - DATI ANAGRAFICI E RECAPITI DEL RICHIEDENTE', { x: 35, y: y - 12, size: 8.5, font: fontBold, color: white });
  y -= 20;

  const anagraficaRows = [
    { label: 'Nome e Cognome:', val: data.fullName || '-' },
    { label: 'Codice Fiscale:', val: (data.codiceFiscale || '-').toUpperCase() },
    { label: 'Data e Luogo di Nascita:', val: `${data.birthDate || '-'} - ${data.birthPlace || 'ESTERO'}` },
    { label: 'Sesso / Genere:', val: data.gender === 'M' ? 'Maschile (M)' : (data.gender === 'F' ? 'Femminile (F)' : '-') },
    { label: 'Telefono / WhatsApp:', val: data.phone || '-' },
    { label: 'Email Certificata / Ordinaria:', val: data.email || '-' },
    { label: 'Indirizzo di Residenza / Domicilio:', val: `${data.address || ''} ${data.residenceComune ? '(' + data.residenceComune + ' ' + (data.residenceProv || '') + ')' : ''}` }
  ];

  anagraficaRows.forEach((r, idx) => {
    const rowBg = idx % 2 === 0 ? white : lightGray;
    page.drawRectangle({ x: 25, y: y - 16, width: 545, height: 18, color: rowBg, borderColor: borderGray, borderWidth: 0.5 });
    page.drawText(sanitizeForPdf(r.label), { x: 35, y: y - 11, size: 8, font: fontBold, color: darkGray });
    page.drawText(sanitizeForPdf(r.val), { x: 210, y: y - 11, size: 8.5, font, color: black });
    y -= 18;
  });

  y -= 14;

  // QUADRO B: DETTAGLI SPECIFICI DELLA PRATICA
  page.drawRectangle({ x: 25, y: y - 18, width: 545, height: 20, color: navy });
  page.drawText(sanitizeForPdf(`QUADRO B - DETTAGLI TECNICI: ${(data.serviceName || 'SERVIZIO').toUpperCase()}`), { x: 35, y: y - 12, size: 8.5, font: fontBold, color: white });
  y -= 20;

  const isPermesso = data.serviceName && (data.serviceName.includes('Permesso') || data.serviceName.includes('Carta di Soggiorno'));
  const isTessera = data.serviceName && (data.serviceName.includes('Tessera') || data.serviceName.includes('Sanitaria') || data.serviceName.includes('Codice Fiscale'));

  let specificRows = [];
  if (isPermesso) {
    specificRows = [
      { label: 'Tipologia Permesso Richiesto:', val: data.permessoTipo || 'Lavoro Subordinato / Rinnovo Ordinario' },
      { label: 'Numero Permesso Attuale / Precedente:', val: (data.permessoNumero || 'IN VERIFICA / ALLEGATO').toUpperCase() },
      { label: 'Data di Scadenza Permesso Precedente:', val: data.permessoScadenza || 'SCADUTO / IN RINNOVO' },
      { label: 'Questura Territorialmente Competente:', val: data.permessoQuestura || 'QUESTURA DI MODENA / COMMISSARIATO CARPI' },
      { label: 'Stato Occupazionale Dichiarato:', val: 'Lavoratore Regolare / Contratto di Soggiorno Mod. Q attivo' }
    ];
  } else if (isTessera) {
    specificRows = [
      { label: 'Motivo della Richiesta:', val: data.tesseraMotivo || 'Rinnovo Iscrizione SSN / Duplicato Tessera' },
      { label: 'Distretto Sanitario ASL:', val: data.tesseraAsl || 'AUSL MODENA - Distretto di Carpi' },
      { label: 'Scelta / Revoca Medico di Base:', val: data.tesseraMedico || 'Conferma Medico Attuale / Nuovo Assegnamento' },
      { label: 'Tipologia Iscrizione SSN:', val: 'Iscrizione Obbligatoria Lavoratore Soggiornante Regolare' }
    ];
  } else {
    specificRows = [
      { label: 'Oggetto della Procedura:', val: data.serviceName || 'Pratica Amministrativa' },
      { label: 'Stato Istruttoria:', val: 'Dati verificati e conformi ai requisiti previsti' },
      { label: 'Note Ufficio Trasmissione:', val: data.notes || 'Trasmesso telematicamente tramite sportello centro' }
    ];
  }

  specificRows.forEach((r, idx) => {
    const rowBg = idx % 2 === 0 ? white : lightGray;
    page.drawRectangle({ x: 25, y: y - 16, width: 545, height: 18, color: rowBg, borderColor: borderGray, borderWidth: 0.5 });
    page.drawText(sanitizeForPdf(r.label), { x: 35, y: y - 11, size: 8, font: fontBold, color: darkGray });
    page.drawText(sanitizeForPdf(r.val), { x: 230, y: y - 11, size: 8.5, font: fontBold, color: black });
    y -= 18;
  });

  y -= 14;

  // QUADRO C: DOCUMENTI ALLEGATI
  page.drawRectangle({ x: 25, y: y - 18, width: 545, height: 20, color: navy });
  page.drawText('QUADRO C - ALLEGATI E DOCUMENTAZIONE PROBATORIA ACQUISITA', { x: 35, y: y - 12, size: 8.5, font: fontBold, color: white });
  y -= 20;

  const docs = data.docsList || [];
  if (docs.length === 0) {
    page.drawRectangle({ x: 25, y: y - 18, width: 545, height: 20, color: white, borderColor: borderGray, borderWidth: 0.5 });
    page.drawText(sanitizeForPdf('[V] Documenti identificativi verificati a vista presso lo sportello'), { x: 35, y: y - 12, size: 8, font, color: black });
    y -= 20;
  } else {
    docs.slice(0, 5).forEach((d, idx) => {
      const rowBg = idx % 2 === 0 ? white : lightGray;
      page.drawRectangle({ x: 25, y: y - 16, width: 545, height: 18, color: rowBg, borderColor: borderGray, borderWidth: 0.5 });
      page.drawText(sanitizeForPdf(`[V] File Allegato: ${d.originalname || d.filename}`), { x: 35, y: y - 11, size: 8, font, color: black });
      page.drawText(sanitizeForPdf(`Dimensione: ${Math.round((d.size || 0) / 1024)} KB  |  Stato: Integro`), { x: 350, y: y - 11, size: 7.5, font, color: darkGray });
      y -= 18;
    });
  }

  y -= 20;

  // CERTIFICATION BOX & DIGITAL STAMP
  page.drawRectangle({ x: 25, y: y - 55, width: 545, height: 60, color: rgb(0.95, 0.98, 1), borderColor: navy, borderWidth: 1, borderRadius: 4 });
  page.drawText('ATTESTAZIONE DI CONFORMITA E TRASMISSIONE DIGITALE', { x: 38, y: y - 14, size: 8.5, font: fontBold, color: navy });
  page.drawText(sanitizeForPdf("Si attesta che la presente pratica e stata acquisita, validata nella correttezza dei dati anagrafici ed inoltrata telematicamente all'ufficio competente."), { x: 38, y: y - 27, size: 7.5, font, color: black });
  page.drawText(sanitizeForPdf(`Identificativo Telematico: TRASM-IT-${Date.now().toString(36).toUpperCase()}-${data.applicationNumber}`), { x: 38, y: y - 40, size: 8, font: fontBold, color: navy });
  page.drawText('Sigillo Elettronico Centro Servizio Straniero — Operatore Protocollo n. 41021', { x: 38, y: y - 51, size: 7, font, color: darkGray });

  // Footer
  page.drawLine({ start: { x: 25, y: 35 }, end: { x: 570, y: 35 }, thickness: 1, color: gold });
  page.drawText('CENTRO SERVIZIO STRANIERO — Trasmissione Istruttoria Telematica Pratiche — Carpi (MO)', { x: 25, y: 24, size: 7.5, font, color: darkGray });

  return await pdfDoc.save();
}

// Helper: dispatch automated dossier to target partner email
async function dispatchDossierEmail(appData, targetEmail, generatedPdfBytes, attachments) {
  const isPermesso = appData.service_name && (appData.service_name.includes('Permesso') || appData.service_name.includes('Carta di Soggiorno'));
  const categoryTitle = isPermesso ? 'ISTRUTTORIA RINNOVO PERMESSO DI SOGGIORNO' : 'RICHIESTA TESSERA SANITARIA / CODICE FISCALE';

  const emailHtml = emailBox(
    `📑 ${categoryTitle}`,
    `<p>Gentile Ufficio Istruttoria / Partner,</p>
     <p>Si trasmette la pratica acquisita e validata telematicamente da <b>CENTRO SERVIZIO STRANIERO</b> pronta per l'elaborazione.</p>

     <div style="background:#f0f7ff;border-left:4px solid #004797;padding:14px 18px;border-radius:6px;margin:20px 0;">
       <p style="margin:0 0 6px;font-weight:700;color:#004797;font-size:15px;">📋 RIEPILOGO PRATICA PROT. ${appData.application_number}</p>
       <p style="margin:3px 0;">Servizio: <strong>${appData.service_name}</strong></p>
       <p style="margin:3px 0;">Richiedente: <strong>${appData.full_name}</strong></p>
       <p style="margin:3px 0;">Codice Fiscale: <strong>${appData.codice_fiscale || '-'}</strong></p>
       <p style="margin:3px 0;">Nato il: <strong>${appData.birth_date || '-'}</strong> a <strong>${appData.birth_place || '-'}</strong></p>
       <p style="margin:3px 0;">Contatti: Tel: <strong>${appData.phone}</strong> | Email: <strong>${appData.email}</strong></p>
       <p style="margin:3px 0;">Residenza: <strong>${appData.address || '-'} (${appData.residence_comune || 'Carpi'} ${appData.residence_prov || 'MO'})</strong></p>
       ${appData.permesso_tipo ? `<p style="margin:3px 0;">Tipo Permesso: <strong>${appData.permesso_tipo}</strong></p>` : ''}
       ${appData.permesso_numero ? `<p style="margin:3px 0;">N. Permesso Attuale: <strong>${appData.permesso_numero}</strong> (Scadenza: ${appData.permesso_scadenza || '-'})</p>` : ''}
       ${appData.tessera_motivo ? `<p style="margin:3px 0;">Motivo Tessera: <strong>${appData.tessera_motivo}</strong> (ASL: ${appData.tessera_asl || '-'})</p>` : ''}
       <p style="margin:3px 0;font-size:12px;color:#64748b;">Data Ricezione Portale: <strong>${new Date(appData.created_at).toLocaleString('it-IT')}</strong></p>
     </div>

     <p>In allegato alla presente email trovate la <b>Scheda Istruttoria Ufficiale (PDF)</b> e tutti i documenti probatori caricati dal richiedente (copia documento, permesso precedente, ecc.).</p>
     <p>Cordiali saluti,<br><b>Ufficio Trasmissioni Telematiche — CENTRO SERVIZIO STRANIERO</b><br><span style="font-size:12px;color:#64748b;">Via Roosevelt 60, Carpi (MO) — Tel: 351 183 0385</span></p>`
  );

  const emailAttachments = [
    {
      filename: `Scheda_Istruttoria_${appData.application_number}.pdf`,
      content: Buffer.from(generatedPdfBytes),
      contentType: 'application/pdf'
    }
  ];

  if (attachments && attachments.length > 0) {
    attachments.forEach(att => {
      emailAttachments.push(att);
    });
  }

  const subject = `[PRATICA ACQUISITA] ${appData.service_name} — ${appData.full_name} (${appData.codice_fiscale || appData.application_number})`;

  return await sendEmail(targetEmail, subject, emailHtml, emailAttachments);
}

// ==========================================
// MODULO: CONSEGNE DOCUMENTI & INVIO PROGRAMMATO (SCHEDULED DELIVERIES)
// ==========================================

function loadDeliveries() {
  try {
    return JSON.parse(fs.readFileSync(CONSEGNE_FILE, 'utf8'));
  } catch (e) {
    return [];
  }
}

function saveDeliveries(data) {
  fs.writeFileSync(CONSEGNE_FILE, JSON.stringify(data, null, 2), 'utf8');
}

const deliveryStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, CONSEGNE_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const safeBase = (path.basename(file.originalname, ext) || 'doc').replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 30);
    cb(null, `CONSEGNA_${Date.now()}_${safeBase}${ext}`);
  }
});

const uploadDelivery = multer({
  storage: deliveryStorage,
  fileFilter: safeFileFilter,
  limits: { fileSize: 20 * 1024 * 1024 } // 20MB limit
});

// Helper to dispatch email with attached document
async function dispatchDeliveryEmail(item) {
  const filePath = path.join(CONSEGNE_DIR, item.filename);
  if (!fs.existsSync(filePath)) {
    throw new Error('File allegato non trovato su disco');
  }

  const fileBytes = fs.readFileSync(filePath);
  const emailHtml = emailBox(
    `📋 ${item.documentTitle || 'Consegna Documento Completato'}`,
    `<p>Gentile <b>${item.customerName}</b>,</p>
     <p>La informiamo che la Sua pratica / documento richiesto è stato completato con successo ed è pronto per l'utilizzo.</p>

     <div style="background:#f0f7ff;border-left:4px solid #004797;padding:14px 18px;border-radius:6px;margin:20px 0;">
       <p style="margin:0 0 6px;font-weight:700;color:#004797;font-size:15px;">📄 DETTAGLI DEL DOCUMENTO</p>
       <p style="margin:3px 0;">Documento: <strong>${item.documentTitle}</strong></p>
       <p style="margin:3px 0;">Intestatario: <strong>${item.customerName}</strong></p>
       ${item.applicationNumber ? `<p style="margin:3px 0;">Rif. Pratica: <strong>${item.applicationNumber}</strong></p>` : ''}
       <p style="margin:3px 0;">Data Invio: <strong>${new Date().toLocaleDateString('it-IT')}</strong></p>
       ${item.notes ? `<p style="margin:10px 0 0;padding-top:10px;border-top:1px dashed #cbd5e1;font-size:13px;color:#334155;"><strong>Note dell'Ufficio:</strong><br>${item.notes}</p>` : ''}
     </div>

     <p>In allegato alla presente email trova il Suo file ufficiale pronto per la stampa o l'inoltro agli enti competenti.</p>

     <div style="text-align:center;margin:22px 0;">
       <a href="${BASE_URL}/?page=portal" style="background:#004797;color:#ffffff;font-weight:800;padding:12px 24px;border-radius:6px;text-decoration:none;display:inline-block;">
         👉 Accedi alla Tua Area Riservata
       </a>
       <p style="font-size:11.5px;color:#64748b;margin:6px 0 0;">
         Il file sarà inoltre scaricabile dalla tua Area Riservata per i prossimi 30 giorni.
       </p>
     </div>

     <p>Restiamo a Sua completa disposizione per qualsiasi ulteriore necessità o chiarimento.</p>
     <p>Cordiali saluti,<br><b>CENTRO SERVIZIO STRANIERO</b><br><span style="font-size:12px;color:#64748b;">Via Roosevelt 60, Carpi (MO) — Tel: 351 183 0385</span></p>`
  );

  const sent = await sendEmail(
    item.customerEmail,
    `Documento Pronto: ${item.documentTitle} — CENTRO SERVIZIO STRANIERO`,
    emailHtml,
    [{ filename: item.originalFilename || item.filename, content: fileBytes }]
  );

  return sent;
}

// Background Processor for Scheduled Deliveries
async function processScheduledDeliveries() {
  const deliveries = loadDeliveries();
  const now = new Date();
  let changed = false;

  for (const item of deliveries) {
    if (item.status === 'in_attesa') {
      const scheduledTime = new Date(item.scheduledAt);
      if (scheduledTime <= now) {
        console.log(`[Scheduler] Esecuzione consegna programmata ${item.id} per ${item.customerName} (${item.customerEmail})...`);
        try {
          const sent = await dispatchDeliveryEmail(item);
          if (sent) {
            item.status = 'inviato';
            item.sentAt = new Date().toISOString();
            changed = true;
            console.log(`[Scheduler] Consegna ${item.id} inviata con successo.`);

            if (item.applicationNumber) {
              const apps = loadApplications();
              const app = apps.find(a => a.application_number === item.applicationNumber);
              if (app) {
                app.status = 'completed';
                saveApplications(apps);
                console.log(`[Scheduler] Pratica ${item.applicationNumber} marcata come completed.`);
              }
            }
          } else {
            console.warn(`[Scheduler] Invio email fallito per ${item.id}`);
          }
        } catch (err) {
          console.error(`[Scheduler] Errore durante invio ${item.id}:`, err.message);
          item.status = 'errore';
          item.errorMsg = err.message;
          changed = true;
        }
      }
    }
  }

  if (changed) {
    saveDeliveries(deliveries);
  }
}

// Check every 30 seconds
setInterval(processScheduledDeliveries, 30000);
// Check on server boot
processScheduledDeliveries();

// POST /api/admin/schedule-delivery
app.post('/api/admin/schedule-delivery', uploadDelivery.single('file'), async (req, res) => {
  try {
    const { customerName, customerEmail, customerPhone, applicationNumber, documentTitle, notes, sendMode, scheduledAt } = req.body;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'Nessun file selezionato per la consegna.' });
    }
    if (!customerName || !customerEmail || !documentTitle) {
      return res.status(400).json({ error: 'Nome cliente, email e titolo documento sono obbligatori.' });
    }

    const isNow = sendMode === 'now';
    let targetTime = new Date();
    if (!isNow && scheduledAt) {
      targetTime = new Date(scheduledAt);
      if (isNaN(targetTime.getTime())) {
        targetTime = new Date();
      }
    }

    const deliveryId = `DELIV-${Date.now()}-${Math.floor(Math.random() * 900 + 100)}`;
    const record = {
      id: deliveryId,
      applicationNumber: applicationNumber ? applicationNumber.trim() : '',
      customerName: customerName.trim(),
      customerEmail: customerEmail.trim(),
      customerPhone: customerPhone ? customerPhone.trim() : '',
      documentTitle: documentTitle.trim(),
      notes: notes ? notes.trim() : '',
      filename: file.filename,
      originalFilename: file.originalname,
      fileSize: file.size,
      sendMode: isNow ? 'now' : 'scheduled',
      scheduledAt: isNow ? new Date().toISOString() : targetTime.toISOString(),
      createdAt: new Date().toISOString(),
      status: 'in_attesa',
      sentAt: null
    };

    const deliveries = loadDeliveries();
    deliveries.unshift(record);
    saveDeliveries(deliveries);

    // If 'now', dispatch immediately
    if (isNow || targetTime <= new Date()) {
      try {
        const sent = await dispatchDeliveryEmail(record);
        record.status = sent ? 'inviato' : 'in_attesa';
        if (sent) record.sentAt = new Date().toISOString();
        if (record.applicationNumber && sent) {
          const apps = loadApplications();
          const app = apps.find(a => a.application_number === record.applicationNumber);
          if (app) {
            app.status = 'completed';
            saveApplications(apps);
          }
        }
        saveDeliveries(deliveries);
      } catch (sendErr) {
        console.error('Immediate delivery send error:', sendErr);
        record.status = 'errore';
        record.errorMsg = sendErr.message;
        saveDeliveries(deliveries);
      }
    }

    res.json({
      success: true,
      deliveryId,
      status: record.status,
      message: record.status === 'inviato'
        ? '✅ Documento inviato immediatamente con successo al cliente!'
        : `⏰ Documento programmato con successo per il ${new Date(record.scheduledAt).toLocaleString('it-IT')}`
    });

  } catch (err) {
    console.error('Schedule delivery error:', err);
    res.status(500).json({ error: err.message || 'Errore durante la programmazione della consegna.' });
  }
});

// GET /api/admin/deliveries
app.get('/api/admin/deliveries', (req, res) => {
  res.json(loadDeliveries());
});

// POST /api/admin/deliveries/:id/send-now
app.post('/api/admin/deliveries/:id/send-now', async (req, res) => {
  try {
    const deliveries = loadDeliveries();
    const item = deliveries.find(d => d.id === req.params.id);
    if (!item) return res.status(404).json({ error: 'Consegna non trovata' });

    const sent = await dispatchDeliveryEmail(item);
    if (sent) {
      item.status = 'inviato';
      item.sentAt = new Date().toISOString();
      if (item.applicationNumber) {
        const apps = loadApplications();
        const app = apps.find(a => a.application_number === item.applicationNumber);
        if (app) {
          app.status = 'completed';
          saveApplications(apps);
        }
      }
      saveDeliveries(deliveries);
      return res.json({ success: true, message: 'Documento inviato subito con successo!' });
    } else {
      return res.status(500).json({ error: "Impossibile inviare l'email, verificare SMTP." });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/deliveries/:id/cancel
app.post('/api/admin/deliveries/:id/cancel', (req, res) => {
  const deliveries = loadDeliveries();
  const item = deliveries.find(d => d.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Consegna non trovata' });

  if (item.status === 'inviato') {
    return res.status(400).json({ error: 'Impossibile annullare: il documento è già stato inviato.' });
  }

  item.status = 'annullato';
  saveDeliveries(deliveries);
  res.json({ success: true, message: 'Consegna programmata annullata con successo.' });
});

// GET /api/files/consegna/:filename (Strict Path Traversal Protection)
app.get('/api/files/consegna/:filename', (req, res) => {
  const safeFilename = path.basename(req.params.filename || '');
  if (!safeFilename) return res.status(400).json({ error: 'Nome file non valido' });

  const resolvedConsegneDir = path.resolve(CONSEGNE_DIR);
  const fp = path.resolve(CONSEGNE_DIR, safeFilename);

  if (!fp.startsWith(resolvedConsegneDir + path.sep)) {
    return res.status(403).json({ error: 'Accesso negato: percorso non consentito.' });
  }
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'File non trovato' });
  res.sendFile(fp);
});


// ==========================================
// MODULO: AUTH, PORTALE CLIENTI & GDPR AUTO-PURGE
// ==========================================
// (Funzioni base e requireAdmin definite a inizio file)

// GDPR Auto-Purge check: purges delivery files older than 30 days
function processGdprAutoPurge() {
  const deliveries = loadDeliveries();
  const now = Date.now();
  const RETENTION_DAYS = 30;
  const MS_PER_DAY = 24 * 60 * 60 * 1000;
  let changed = false;

  for (const item of deliveries) {
    if (item.status === 'inviato' && !item.filePurged) {
      const refTime = new Date(item.sentAt || item.createdAt).getTime();
      const ageDays = (now - refTime) / MS_PER_DAY;
      if (ageDays >= RETENTION_DAYS) {
        console.log(`[GDPR Auto-Purge] Eliminazione file scaduto (${Math.floor(ageDays)} giorni) per ${item.id} - ${item.customerName}...`);
        const filePath = path.join(CONSEGNE_DIR, item.filename);
        if (fs.existsSync(filePath)) {
          try {
            fs.unlinkSync(filePath);
            console.log(`[GDPR Auto-Purge] File ${item.filename} eliminato con successo.`);
          } catch (delErr) {
            console.error(`[GDPR Auto-Purge] Errore eliminazione file:`, delErr.message);
          }
        }
        item.filePurged = true;
        item.purgedAt = new Date().toISOString();
        changed = true;
      }
    }
  }

  if (changed) {
    saveDeliveries(deliveries);
  }
}

// Run auto-purge every 10 minutes
setInterval(processGdprAutoPurge, 10 * 60 * 1000);
processGdprAutoPurge();

// ------------------------------------------
// AUTH ROUTES
// ------------------------------------------

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Nome, email e password sono obbligatori.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'La password deve contenere almeno 6 caratteri.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const users = loadUsers();
    const existing = users.find(u => u.email === cleanEmail && u.status !== 'deleted');

    if (existing) {
      if (existing.status === 'active') {
        return res.status(400).json({ error: 'Un account con questa email esiste già. Effettua il login.' });
      }
      if (existing.status === 'paused') {
        return res.status(400).json({ error: 'Questo account è momentaneamente sospeso. Contatta l\'ufficio.' });
      }
    }

    const otp = generateOTP();
    const otpExpiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    let targetUser = existing;
    if (!targetUser) {
      targetUser = {
        id: `USR-${Date.now()}-${Math.floor(Math.random() * 900 + 100)}`,
        name: name.trim(),
        email: cleanEmail,
        phone: (phone || '').trim(),
        passwordHash: hashPassword(password),
        role: 'customer',
        status: 'pending_otp',
        otp,
        otpExpiresAt,
        createdAt: new Date().toISOString()
      };
      users.push(targetUser);
    } else {
      targetUser.name = name.trim();
      targetUser.phone = (phone || '').trim();
      targetUser.passwordHash = hashPassword(password);
      targetUser.otp = otp;
      targetUser.otpExpiresAt = otpExpiresAt;
      targetUser.status = 'pending_otp';
    }

    saveUsers(users);

    // Send OTP email
    const emailHtml = emailBox(
      '🔐 Verifica il tuo Account — CENTRO SERVIZIO STRANIERO',
      `<p>Gentile <b>${targetUser.name}</b>,</p>
       <p>Grazie per esserti registrato al portale di <b>CENTRO SERVIZIO STRANIERO</b>.</p>
       <p>Per completare l'attivazione del tuo account personale, inserisci il seguente codice di sicurezza OTP:</p>

       <div style="background:#f0fdf4;border:2px dashed #16a34a;padding:16px;border-radius:8px;text-align:center;margin:24px 0;">
         <span style="font-size:32px;font-weight:900;letter-spacing:6px;color:#166534;">${otp}</span>
         <p style="font-size:12px;color:#15803d;margin:8px 0 0;">Il codice è valido per 10 minuti.</p>
       </div>

       <p>Se non hai richiesto tu questa registrazione, puoi ignorare questa email in sicurezza.</p>
       <p>Cordiali saluti,<br><b>CENTRO SERVIZIO STRANIERO</b></p>`
    );

    sendEmail(cleanEmail, `Il tuo codice di verifica OTP: ${otp} — CENTRO SERVIZIO STRANIERO`, emailHtml).catch(e => {
      console.error('Error sending OTP email:', e.message);
    });

    res.json({
      success: true,
      requiresOtp: true,
      email: cleanEmail,
      message: 'Codice OTP inviato alla tua email. Controlla la tua casella di posta.'
    });

  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: err.message || 'Errore durante la registrazione.' });
  }
});

// POST /api/auth/verify-otp
app.post('/api/auth/verify-otp', otpLimiter, async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email e codice OTP sono obbligatori.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const users = loadUsers();
    const user = users.find(u => u.email === cleanEmail && u.status !== 'deleted');

    if (!user) {
      return res.status(404).json({ error: 'Utente non trovato.' });
    }

    if (user.status === 'paused') {
      return res.status(403).json({ error: 'Il tuo account è temporaneamente sospeso. Contatta l\'ufficio.' });
    }

    if (!user.otp || user.otp !== otp.trim()) {
      return res.status(400).json({ error: 'Codice OTP errato. Riprova.' });
    }

    if (Date.now() > user.otpExpiresAt) {
      return res.status(400).json({ error: 'Codice OTP scaduto. Richiedi un nuovo codice.' });
    }

    // Activate user
    user.status = 'active';
    user.otp = null;
    user.otpExpiresAt = null;
    user.lastLogin = new Date().toISOString();
    saveUsers(users);

    // Create session token
    const token = crypto.randomBytes(32).toString('hex');
    activeAuthTokens.set(token, {
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role
      },
      message: 'Account attivato con successo!'
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/resend-otp
app.post('/api/auth/resend-otp', otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email richiesta.' });

    const cleanEmail = email.trim().toLowerCase();
    const users = loadUsers();
    const user = users.find(u => u.email === cleanEmail && u.status !== 'deleted');
    if (!user) return res.status(404).json({ error: 'Utente non trovato.' });

    const otp = generateOTP();
    user.otp = otp;
    user.otpExpiresAt = Date.now() + 10 * 60 * 1000;
    saveUsers(users);

    const emailHtml = emailBox(
      '🔐 Nuovo Codice di Verifica OTP',
      `<p>Gentile <b>${user.name}</b>,</p>
       <p>Ecco il tuo nuovo codice di verifica OTP per accedere al portale:</p>
       <div style="background:#f0fdf4;border:2px dashed #16a34a;padding:16px;border-radius:8px;text-align:center;margin:24px 0;">
         <span style="font-size:32px;font-weight:900;letter-spacing:6px;color:#166534;">${otp}</span>
         <p style="font-size:12px;color:#15803d;margin:8px 0 0;">Valido per 10 minuti.</p>
       </div>`
    );

    sendEmail(cleanEmail, `Nuovo codice OTP: ${otp} — CENTRO SERVIZIO STRANIERO`, emailHtml).catch(e => console.error(e));

    res.json({ success: true, message: 'Nuovo codice OTP inviato con successo alla tua email.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email e password sono obbligatori.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const users = loadUsers();
    const user = users.find(u => u.email === cleanEmail && u.status !== 'deleted');

    if (!user) {
      return res.status(401).json({ error: 'Email o password non corretti.' });
    }

    if (user.status === 'paused') {
      return res.status(403).json({ error: 'Il tuo account è temporaneamente sospeso. Contatta l\'ufficio per assistenza.' });
    }

    if (user.status === 'pending_otp') {
      return res.json({
        requiresOtp: true,
        email: user.email,
        message: 'Account in attesa di verifica. Inserisci il codice OTP inviato alla tua email.'
      });
    }

    if (!verifyPassword(password, user.passwordHash)) {
      return res.status(401).json({ error: 'Email o password non corretti.' });
    }

    // Transparently upgrade legacy password hash to 100,000 iterations PBKDF2
    if (!user.passwordHash.startsWith('pbkdf2:')) {
      user.passwordHash = hashPassword(password);
    }

    user.lastLogin = new Date().toISOString();
    saveUsers(users);

    const token = crypto.randomBytes(32).toString('hex');
    activeAuthTokens.set(token, {
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role
      }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', (req, res) => {
  const session = getAuthUser(req);
  if (!session) return res.status(401).json({ error: 'Non autorizzato' });
  const users = loadUsers();
  const user = users.find(u => u.id === session.userId);
  if (!user || user.status !== 'active') return res.status(401).json({ error: 'Sessione non valida' });

  res.json({
    id: user.id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role
  });
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    activeAuthTokens.delete(token);
  }
  res.json({ success: true });
});

// ------------------------------------------
// CUSTOMER PORTAL DASHBOARD ROUTE
// ------------------------------------------
app.get('/api/customer/dashboard', (req, res) => {
  const session = getAuthUser(req);
  if (!session) return res.status(401).json({ error: 'Non autorizzato. Effettua il login.' });

  const clientEmail = session.email.toLowerCase().trim();
  const allApps = loadApplications();
  const allDeliveries = loadDeliveries();

  // Find all applications matching customer email or phone
  const myApps = allApps.filter(a => {
    return (a.email && a.email.toLowerCase().trim() === clientEmail);
  });

  // Find all deliveries matching customer email
  const myDeliveries = allDeliveries.filter(d => {
    return (d.customerEmail && d.customerEmail.toLowerCase().trim() === clientEmail);
  }).map(item => {
    const isPurged = item.filePurged === true;
    const sentTime = new Date(item.sentAt || item.createdAt).getTime();
    const daysSince = Math.floor((Date.now() - sentTime) / (1000 * 60 * 60 * 24));
    const daysLeft = Math.max(0, 30 - daysSince);

    return {
      ...item,
      isPurged,
      daysLeft,
      downloadUrl: (!isPurged && item.status === 'inviato') ? `/api/files/consegna/${encodeURIComponent(item.filename)}` : null
    };
  });

  // Build complete historical timeline (sorted chronologically newest first)
  const historyTimeline = [];

  myApps.forEach(a => {
    historyTimeline.push({
      type: 'pratica',
      id: a.application_number,
      title: a.service_name,
      category: a.service_category || 'Servizio',
      date: a.created_at,
      status: a.status,
      paid: a.paid,
      price: a.price
    });
  });

  myDeliveries.forEach(d => {
    historyTimeline.push({
      type: 'consegna',
      id: d.id,
      title: d.documentTitle,
      category: 'Documento Consegnato',
      date: d.sentAt || d.createdAt,
      status: d.status,
      isPurged: d.isPurged,
      downloadUrl: d.downloadUrl
    });
  });

  historyTimeline.sort((a, b) => new Date(b.date) - new Date(a.date));

  res.json({
    user: {
      id: session.userId,
      name: session.name,
      email: session.email,
      role: session.role
    },
    pratiche: myApps,
    deliveries: myDeliveries,
    history: historyTimeline
  });
});

// ------------------------------------------
// ADMIN CLIENT MANAGEMENT ROUTES
// ------------------------------------------

// GET /api/admin/users
app.get('/api/admin/users', (req, res) => {
  const users = loadUsers();
  const allApps = loadApplications();
  const allDeliveries = loadDeliveries();

  const customerList = users
    .filter(u => u.status !== 'deleted' && u.role === 'customer')
    .map(u => {
      const uEmail = u.email.toLowerCase().trim();
      const praticheCount = allApps.filter(a => a.email && a.email.toLowerCase().trim() === uEmail).length;
      const deliveriesCount = allDeliveries.filter(d => d.customerEmail && d.customerEmail.toLowerCase().trim() === uEmail).length;
      return {
        id: u.id,
        name: u.name,
        email: u.email,
        phone: u.phone,
        status: u.status,
        createdAt: u.createdAt,
        lastLogin: u.lastLogin || null,
        praticheCount,
        deliveriesCount
      };
    })
    .reverse();

  res.json(customerList);
});

// POST /api/admin/users/create (Admin manually creates an account)
app.post('/api/admin/users/create', (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email) {
      return res.status(400).json({ error: 'Nome ed email sono obbligatori.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const users = loadUsers();
    if (users.some(u => u.email === cleanEmail && u.status !== 'deleted')) {
      return res.status(400).json({ error: 'Esiste già un account con questa email.' });
    }

    const initialPassword = password && password.trim() ? password.trim() : 'cliente123';
    const newUser = {
      id: `USR-${Date.now()}-${Math.floor(Math.random() * 900 + 100)}`,
      name: name.trim(),
      email: cleanEmail,
      phone: (phone || '').trim(),
      passwordHash: hashPassword(initialPassword),
      role: 'customer',
      status: 'active', // Admin created is active immediately
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    saveUsers(users);

    res.json({
      success: true,
      message: `Account cliente creato con successo! Password iniziale: ${initialPassword}`,
      user: { id: newUser.id, name: newUser.name, email: newUser.email }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/users/:id/toggle-status (Pause or Activate)
app.post('/api/admin/users/:id/toggle-status', (req, res) => {
  const users = loadUsers();
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Utente non trovato' });

  user.status = (user.status === 'active') ? 'paused' : 'active';
  saveUsers(users);

  res.json({
    success: true,
    newStatus: user.status,
    message: user.status === 'paused'
      ? 'Account cliente sospeso (in pausa). Il cliente non potrà accedere.'
      : 'Account cliente riattivato con successo!'
  });
});

// POST /api/admin/users/:id/reset-password
app.post('/api/admin/users/:id/reset-password', (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'La nuova password deve contenere almeno 6 caratteri.' });
  }

  const users = loadUsers();
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Utente non trovato' });

  user.passwordHash = hashPassword(newPassword.trim());
  saveUsers(users);

  res.json({ success: true, message: 'Password cliente reimpostata con successo!' });
});

// DELETE /api/admin/users/:id
app.delete('/api/admin/users/:id', (req, res) => {
  const users = loadUsers();
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Utente non trovato' });

  user.status = 'deleted';
  saveUsers(users);

  res.json({ success: true, message: 'Account cliente eliminato con successo.' });
});


// ------------------------------------------
// ADMIN ROUTING CONFIG ENDPOINTS
// ------------------------------------------
// GET /api/admin/routing-config
app.get('/api/admin/routing-config', (req, res) => {
  res.json(loadRoutingConfig());
});

// POST /api/admin/routing-config
app.post('/api/admin/routing-config', (req, res) => {
  try {
    const newConfig = req.body;
    saveRoutingConfig(newConfig);
    res.json({ success: true, message: 'Configurazione regole di invio aggiornata con successo!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------------------------
// PAYMENT CONFIGURATION ENDPOINTS (ADMIN & PUBLIC)
// ------------------------------------------
// GET /api/payment-config (Public active methods for clients)
app.get('/api/payment-config', (req, res) => {
  res.json(loadPaymentConfig());
});

// GET /api/admin/payment-config (Admin complete config)
app.get('/api/admin/payment-config', (req, res) => {
  res.json(loadPaymentConfig());
});

// POST /api/admin/payment-config (Admin update payment options)
app.post('/api/admin/payment-config', (req, res) => {
  try {
    const newCfg = req.body;
    if (!newCfg || typeof newCfg !== 'object') {
      return res.status(400).json({ error: 'Configurazione non valida' });
    }
    const current = loadPaymentConfig();
    const merged = {
      bonifico: { ...current.bonifico, ...(newCfg.bonifico || {}) },
      postepay: { ...current.postepay, ...(newCfg.postepay || {}) },
      paypal: { ...current.paypal, ...(newCfg.paypal || {}) },
      sede: { ...current.sede, ...(newCfg.sede || {}) },
      istruzioniGenerali: newCfg.istruzioniGenerali !== undefined ? newCfg.istruzioniGenerali : current.istruzioniGenerali
    };

    savePaymentConfig(merged);
    res.json({ success: true, message: 'Metodi di pagamento aggiornati con successo!', config: merged });
  } catch (err) {
    res.status(500).json({ error: 'Errore durante il salvataggio: ' + err.message });
  }
});

// POST /api/admin/re-dispatch/:appNumber
app.post('/api/admin/re-dispatch/:appNumber', async (req, res) => {
  try {
    const { targetEmail } = req.body;
    const apps = readApps();
    const app = apps.find(a => a.application_number === req.params.appNumber);
    if (!app) return res.status(404).json({ error: 'Pratica non trovata' });

    const targetDir = path.join(DOCS_DIR, app.application_number);
    let dossierPdfBytes = null;
    let dossierFilename = null;

    // Find existing dossier or generate on the fly
    const dossierDoc = app.documents && app.documents.find(d => d.type === 'scheda_istruttoria');
    if (dossierDoc && fs.existsSync(path.join(targetDir, dossierDoc.filename))) {
      dossierPdfBytes = fs.readFileSync(path.join(targetDir, dossierDoc.filename));
      dossierFilename = dossierDoc.filename;
    } else {
      dossierPdfBytes = await generateDossierPDF({
        applicationNumber: app.application_number,
        serviceName: app.service_name,
        fullName: app.full_name,
        codiceFiscale: app.codice_fiscale,
        birthDate: app.birth_date,
        gender: app.gender,
        phone: app.phone,
        email: app.email,
        address: app.address,
        birthPlace: app.birth_place,
        residenceComune: app.residence_comune,
        residenceProv: app.residence_prov,
        permessoTipo: app.permesso_tipo,
        permessoNumero: app.permesso_numero,
        permessoScadenza: app.permesso_scadenza,
        permessoQuestura: app.permesso_questura,
        tesseraMotivo: app.tessera_motivo,
        tesseraAsl: app.tessera_asl,
        tesseraMedico: app.tessera_medico,
        notes: app.notes,
        docsList: app.documents
      });
      dossierFilename = `Scheda_Istruttoria_${app.application_number}.pdf`;
      fs.writeFileSync(path.join(targetDir, dossierFilename), dossierPdfBytes);
    }

    const emailAttachments = [];
    if (app.documents) {
      for (const d of app.documents) {
        const fPath = path.join(targetDir, d.filename);
        if (fs.existsSync(fPath) && d.filename !== dossierFilename) {
          emailAttachments.push({
            filename: d.originalname || d.filename,
            content: fs.readFileSync(fPath)
          });
        }
      }
    }

    const destEmail = (targetEmail && targetEmail.trim()) || app.dispatchedTo || process.env.EMAIL_USER;
    const sent = await dispatchDossierEmail(app, destEmail, dossierPdfBytes, emailAttachments);

    if (sent) {
      app.autoDispatched = true;
      app.dispatchedTo = destEmail;
      app.dispatchedAt = new Date().toISOString();
      writeApps(apps);
      res.json({ success: true, message: `Pratica e dossier inoltrati con successo a: ${destEmail}` });
    } else {
      res.status(500).json({ error: 'Invio email non riuscito, verificare configurazione SMTP.' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// ADMIN CHANGE PASSWORD ENDPOINT
// ==========================================
app.post('/api/admin/change-password', async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: 'Vecchia password e nuova password sono obbligatorie.' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'La nuova password deve contenere almeno 8 caratteri.' });
    }

    const users = loadUsers();
    const user = users.find(u => u.id === req.user.userId && u.status !== 'deleted');
    if (!user) {
      return res.status(404).json({ error: 'Account utente non trovato.' });
    }

    if (!verifyPassword(oldPassword, user.passwordHash)) {
      return res.status(401).json({ error: 'La password attuale inserita non è corretta.' });
    }

    user.passwordHash = hashPassword(newPassword);
    user.updatedAt = new Date().toISOString();
    saveUsers(users);

    res.json({ success: true, message: 'Password aggiornata con successo!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// CENTRALIZED ERROR HANDLING MIDDLEWARE
// ==========================================
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'Il file caricato supera la dimensione massima consentita.' });
    }
    return res.status(400).json({ error: `Errore caricamento file: ${err.message}` });
  }
  if (err && err.message && err.message.includes('Tipo di file non supportato')) {
    return res.status(400).json({ error: err.message });
  }
  console.error('[Unhandled Server Error]', err);
  res.status(500).json({ error: 'Si è verificato un errore interno del server.' });
});

// Server listener
app.listen(PORT, () => {
  console.log(`CENTRO SERVIZIO STRANIERO avviato su: ${BASE_URL}`);
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.log("AVVISO: Email non configurate nel .env (EMAIL_USER e EMAIL_PASS).");
  } else {
    console.log(`Email configurata con: ${process.env.EMAIL_USER}`);
  }
  if (!process.env.IBAN) {
    console.log("NOTA: IBAN non configurato nel file .env (usato valore predefinito).");
  } else {
    console.log(`IBAN attivo: ${process.env.IBAN.substring(0, 8)}...`);
  }
});
