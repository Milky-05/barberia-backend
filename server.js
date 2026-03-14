const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();
const cron = require('node-cron');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// ==========================================
// CONFIGURAZIONE DATABASE
// ==========================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

app.listen(process.env.PORT, () => {
    console.log(`Server avviato sulla porta ${process.env.PORT}`);
});

// ==========================================
// MIDDLEWARE AUTH
// ==========================================
const verificaToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Accesso non autorizzato" });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.utente = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: "Token non valido o scaduto" });
    }
};

const soloAdmin = (req, res, next) => {
    if (req.utente.ruolo !== 'barbiere') {
        return res.status(403).json({ error: "Accesso riservato ai barbieri" });
    }
    next();
};

// ==========================================
// CRON JOB - Pulizia ogni 10 minuti
// ==========================================
cron.schedule('*/10 * * * *', async () => {
    try {
        const cancellati = await pool.query("DELETE FROM prenotazioni WHERE stato = 'cancellato'");
        const passati = await pool.query("DELETE FROM prenotazioni WHERE data < CURRENT_DATE AND stato = 'attivo'");
        const scaduti = await pool.query("DELETE FROM prenotazioni WHERE data = CURRENT_DATE AND ora < CURRENT_TIME AND stato = 'attivo'");
        const totale = (cancellati.rowCount || 0) + (passati.rowCount || 0) + (scaduti.rowCount || 0);
        if (totale > 0) console.log(`Pulizia: eliminati ${totale} appuntamenti`);
    } catch (err) {
        console.error('Errore pulizia:', err);
    }
});

// ==========================================
// AUTH: REGISTRAZIONE + LOGIN UNIFICATO
// ==========================================

// Registrazione cliente
app.post('/api/auth/registrazione', async (req, res) => {
    const { nome, cognome, email, telefono, password } = req.body;

    if (!nome || !email || !password) {
        return res.status(400).json({ error: "Nome, email e password sono obbligatori" });
    }

    try {
        // Controlla che l'email non esista già tra clienti
        const esistente = await pool.query('SELECT id FROM clienti WHERE email = $1', [email]);
        if (esistente.rows.length > 0) {
            return res.status(409).json({ error: "Questa email è già registrata" });
        }

        // Controlla che non sia un'email barbiere
        const barbiere = await pool.query('SELECT id FROM barbieri WHERE email = $1', [email]);
        if (barbiere.rows.length > 0) {
            return res.status(409).json({ error: "Questa email è riservata" });
        }

        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            `INSERT INTO clienti (nome, cognome, email, telefono, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id, nome, cognome, email`,
            [nome, cognome || null, email, telefono || null, hash]
        );

        const cliente = result.rows[0];
        const token = jwt.sign(
            { id: cliente.id, nome: cliente.nome, email: cliente.email, ruolo: 'cliente' },
            process.env.JWT_SECRET, { expiresIn: '30d' }
        );

        res.json({ success: true, token, utente: { ...cliente, ruolo: 'cliente' } });
    } catch (err) {
        console.error("Errore registrazione:", err);
        res.status(500).json({ error: "Errore durante la registrazione" });
    }
});

// Login unificato (clienti + barbieri)
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Inserisci email e password" });

    try {
        // 1. Cerca tra i barbieri
        const barbiereResult = await pool.query('SELECT * FROM barbieri WHERE email = $1', [email]);
        if (barbiereResult.rows.length > 0) {
            const barbiere = barbiereResult.rows[0];
            if (!barbiere.password_hash) return res.status(401).json({ error: "Password non configurata" });

            const valida = await bcrypt.compare(password, barbiere.password_hash);
            if (!valida) return res.status(401).json({ error: "Password errata" });

            const token = jwt.sign(
                { id: barbiere.id, nome: barbiere.nome, email: barbiere.email, tipo: barbiere.tipo, ruolo: 'barbiere' },
                process.env.JWT_SECRET, { expiresIn: '30d' }
            );
            return res.json({ success: true, token, utente: { id: barbiere.id, nome: barbiere.nome, ruolo: 'barbiere', tipo: barbiere.tipo } });
        }

        // 2. Cerca tra i clienti
        const clienteResult = await pool.query('SELECT * FROM clienti WHERE email = $1', [email]);
        if (clienteResult.rows.length > 0) {
            const cliente = clienteResult.rows[0];
            if (!cliente.password_hash) return res.status(401).json({ error: "Password non configurata" });

            const valida = await bcrypt.compare(password, cliente.password_hash);
            if (!valida) return res.status(401).json({ error: "Password errata" });

            const token = jwt.sign(
                { id: cliente.id, nome: cliente.nome, email: cliente.email, ruolo: 'cliente' },
                process.env.JWT_SECRET, { expiresIn: '30d' }
            );
            return res.json({ success: true, token, utente: { id: cliente.id, nome: cliente.nome, cognome: cliente.cognome, ruolo: 'cliente' } });
        }

        return res.status(401).json({ error: "Email non trovata" });
    } catch (err) {
        console.error("Errore login:", err);
        res.status(500).json({ error: "Errore durante il login" });
    }
});

// Verifica token (per auto-login)
app.get('/api/auth/me', verificaToken, async (req, res) => {
    try {
        if (req.utente.ruolo === 'barbiere') {
            const sedi = await pool.query(
                `SELECT DISTINCT s.id, s.nome FROM sedi s JOIN turni_rotazione t ON s.id = t.sede_id WHERE t.barbiere_id = $1 ORDER BY s.id`,
                [req.utente.id]
            );
            return res.json({ utente: req.utente, sedi: sedi.rows });
        }
        res.json({ utente: req.utente });
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Setup password barbieri (chiamare UNA VOLTA)
app.get('/api/admin/setup-passwords', async (req, res) => {
    try {
        const barbieri = await pool.query('SELECT id, nome FROM barbieri');
        for (const b of barbieri.rows) {
            const hash = await bcrypt.hash('barberia2024', 10);
            await pool.query('UPDATE barbieri SET password_hash = $1 WHERE id = $2', [hash, b.id]);
        }
        res.json({ success: true, message: "Password impostate per tutti (password: barberia2024)" });
    } catch (err) {
        console.error("IL VERO ERRORE È:", err);
        res.status(500).json({ error: "Errore setup" });
    }
});

// Modifica profilo cliente
app.patch('/api/auth/profilo', verificaToken, async (req, res) => {
    const { nome, cognome, telefono } = req.body;
    try {
        if (req.utente.ruolo === 'cliente') {
            await pool.query('UPDATE clienti SET nome=$1, cognome=$2, telefono=$3 WHERE id=$4', [nome, cognome, telefono, req.utente.id]);
            // Aggiorna anche il nome nelle prenotazioni future
            await pool.query('UPDATE prenotazioni SET cliente_nome=$1 WHERE cliente_id=$2 AND stato=\'attivo\'', [nome, req.utente.id]);
        } else {
            await pool.query('UPDATE barbieri SET nome=$1 WHERE id=$2', [nome, req.utente.id]);
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Errore aggiornamento profilo" });
    }
});

// Cambia password
app.patch('/api/auth/cambia-password', verificaToken, async (req, res) => {
    const { vecchia_password, nuova_password } = req.body;
    if (!vecchia_password || !nuova_password) return res.status(400).json({ error: "Compila tutti i campi" });
    if (nuova_password.length < 6) return res.status(400).json({ error: "Minimo 6 caratteri" });

    try {
        let result;
        if (req.utente.ruolo === 'cliente') {
            result = await pool.query('SELECT password_hash FROM clienti WHERE id=$1', [req.utente.id]);
        } else {
            result = await pool.query('SELECT password_hash FROM barbieri WHERE id=$1', [req.utente.id]);
        }
        if (result.rows.length === 0) return res.status(404).json({ error: "Utente non trovato" });

        const valida = await bcrypt.compare(vecchia_password, result.rows[0].password_hash);
        if (!valida) return res.status(401).json({ error: "Password attuale errata" });

        const hash = await bcrypt.hash(nuova_password, 10);
        if (req.utente.ruolo === 'cliente') {
            await pool.query('UPDATE clienti SET password_hash=$1 WHERE id=$2', [hash, req.utente.id]);
        } else {
            await pool.query('UPDATE barbieri SET password_hash=$1 WHERE id=$2', [hash, req.utente.id]);
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Errore cambio password" });
    }
});

// ==========================================
// API: SEDI
// ==========================================
app.get('/api/sedi', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM sedi');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore del server" });
    }
});

// ==========================================
// API: SERVIZI
// ==========================================
app.get('/api/servizi', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM servizi ORDER BY prezzo ASC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore nel recupero servizi" });
    }
});

// ==========================================
// API: BARBIERI
// ==========================================
app.get('/api/barbieri/:sede_id', async (req, res) => {
    const { sede_id } = req.params;
    try {
        const result = await pool.query(
            `SELECT DISTINCT b.id, b.nome FROM barbieri b
             JOIN turni_rotazione t ON b.id = t.barbiere_id
             WHERE t.sede_id = $1 AND b.assente = false`,
            [sede_id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore nel recupero barbieri" });
    }
});

app.get('/api/barbieri-disponibili', async (req, res) => {
    const { sede_id, data } = req.query;
    if (!sede_id || !data) return res.status(400).json({ error: "Mancano parametri" });

    try {
        const dateObj = new Date(data);
        const giorno_settimana = dateObj.getDay();
        if (giorno_settimana === 0) return res.json({ messaggio: "Il negozio è chiuso di Domenica", barbieri: [] });

        const result = await pool.query(
            `SELECT b.id, b.nome FROM barbieri b
             JOIN turni_rotazione t ON b.id = t.barbiere_id
             WHERE t.sede_id = $1 AND t.giorno_settimana = $2 AND b.assente = false`,
            [sede_id, giorno_settimana]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore durante la ricerca dei barbieri" });
    }
});

// ==========================================
// API: ORARI DISPONIBILI
// ==========================================
app.get('/api/orari-disponibili', async (req, res) => {
    const { barbiere_id, data } = req.query;
    if (!barbiere_id || !data) return res.status(400).json({ error: "Mancano parametri" });

    const orariBase = [
        "09:00", "09:40", "10:20", "11:00", "11:40",
        "15:00", "15:40", "16:20", "17:00", "17:40", "18:20"
    ];

    try {
        const occupati = await pool.query(
            "SELECT ora FROM prenotazioni WHERE barbiere_id = $1 AND data = $2 AND stato = 'attivo'",
            [barbiere_id, data]
        );
        const listaOccupati = occupati.rows.map(row => row.ora.split(':').slice(0, 2).join(':'));
        let disponibili = orariBase.filter(ora => !listaOccupati.includes(ora));

        const oggi = new Date().toISOString().split('T')[0];
        if (data === oggi) {
            const oraAttuale = new Date().getHours() * 60 + new Date().getMinutes();
            disponibili = disponibili.filter(ora => {
                const [h, m] = ora.split(':').map(Number);
                return (h * 60 + m) > oraAttuale;
            });
        }
        res.json(disponibili);
    } catch (err) {
        res.status(500).json({ error: "Errore nel recupero orari" });
    }
});

// ==========================================
// API: PRENOTAZIONI (CLIENTI)
// ==========================================

// Crea prenotazione (ora richiede auth)
app.post('/api/prenotazioni', verificaToken, async (req, res) => {
    const { sede_id, barbiere_id, data, ora, servizio_id } = req.body;
    const cliente_nome = req.utente.nome;

    if (!sede_id || !barbiere_id || !data || !ora || !servizio_id) {
        return res.status(400).json({ error: "Mancano campi obbligatori" });
    }

    try {
        const check = await pool.query(
            "SELECT id FROM prenotazioni WHERE barbiere_id = $1 AND data = $2 AND ora = $3 AND stato = 'attivo'",
            [barbiere_id, data, ora]
        );
        if (check.rows.length > 0) return res.status(409).json({ error: "Questo orario è già prenotato!" });

        const result = await pool.query(
            `INSERT INTO prenotazioni (sede_id, barbiere_id, cliente_nome, cliente_id, data, ora, servizio_id) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
            [sede_id, barbiere_id, cliente_nome, req.utente.ruolo === 'cliente' ? req.utente.id : null, data, ora, servizio_id]
        );
        res.json({ success: true, prenotazione: result.rows[0] });
    } catch (err) {
        console.error("Errore salvataggio:", err);
        res.status(500).json({ error: "Errore nel salvataggio della prenotazione" });
    }
});

// I miei appuntamenti
app.get('/api/prenotazioni/miei', verificaToken, async (req, res) => {
    const { sede_id } = req.query;
    const cliente_id = req.utente.id; // <-- ORA USIAMO L'ID

    try {
        // Pulizia basata sull'ID
        await pool.query("DELETE FROM prenotazioni WHERE cliente_id = $1 AND stato = 'cancellato'", [cliente_id]);
        await pool.query(
            "DELETE FROM prenotazioni WHERE cliente_id = $1 AND stato = 'attivo' AND (data < CURRENT_DATE OR (data = CURRENT_DATE AND ora < CURRENT_TIME))",
            [cliente_id]
        );

        let query = `
            SELECT p.id, p.data, p.ora, p.stato, p.sede_id,
                    s.nome AS sede_nome, b.nome AS barbiere_nome,
                    sv.nome AS servizio_nome, sv.prezzo AS servizio_prezzo
             FROM prenotazioni p
             JOIN sedi s ON p.sede_id = s.id
             JOIN barbieri b ON p.barbiere_id = b.id
             JOIN servizi sv ON p.servizio_id = sv.id
             WHERE p.cliente_id = $1 AND p.stato = 'attivo'`; // <-- CERCA PER ID
        const params = [cliente_id];

        if (sede_id) { query += ` AND p.sede_id = $2`; params.push(sede_id); }
        query += ` ORDER BY p.data ASC, p.ora ASC`;

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore nel recupero delle prenotazioni" });
    }
});

// Cancella prenotazione (cliente)
app.delete('/api/prenotazioni/:id', verificaToken, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(
            "DELETE FROM prenotazioni WHERE id = $1 AND stato = 'attivo' RETURNING *", [id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: "Non trovata o già cancellata" });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Errore nella cancellazione" });
    }
});

// Notifiche cliente
app.get('/api/notifiche', verificaToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM notifiche WHERE cliente_id = $1 ORDER BY created_at DESC LIMIT 20',
            [req.utente.id] // <-- CERCA PER ID
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

app.patch('/api/notifiche/lette', verificaToken, async (req, res) => {
    try {
        await pool.query('UPDATE notifiche SET letta = true WHERE cliente_id = $1', [req.utente.id]); // <-- AGGIORNA PER ID
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// ==========================================
// API: ADMIN (BARBIERI)
// ==========================================

// Tutte le prenotazioni per sede + data
app.get('/api/admin/prenotazioni', verificaToken, soloAdmin, async (req, res) => {
    const { sede_id, data, barbiere_id } = req.query;
    const dataQuery = data || new Date().toISOString().split('T')[0];
    if (!sede_id) return res.status(400).json({ error: "Manca sede_id" });

    try {
        let query = `
            SELECT p.id, p.data, p.ora, p.stato, p.cliente_nome,
                    b.nome AS barbiere_nome, b.id AS barbiere_id,
                    sv.nome AS servizio_nome, sv.prezzo AS servizio_prezzo, sv.durata_minuti
             FROM prenotazioni p
             JOIN barbieri b ON p.barbiere_id = b.id
             JOIN servizi sv ON p.servizio_id = sv.id
             WHERE p.sede_id = $1 AND p.data = $2`;
        const params = [sede_id, dataQuery];

        if (barbiere_id) {
            query += ` AND p.barbiere_id = $3`;
            params.push(barbiere_id);
        }
        query += ` ORDER BY p.ora ASC`;

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Prenotazioni settimana
app.get('/api/admin/prenotazioni/settimana', verificaToken, soloAdmin, async (req, res) => {
    const { sede_id, data_inizio } = req.query;
    if (!sede_id) return res.status(400).json({ error: "Manca sede_id" });

    let inizio;
    if (data_inizio) { inizio = new Date(data_inizio); }
    else { inizio = new Date(); const day = inizio.getDay(); inizio.setDate(inizio.getDate() - (day === 0 ? 6 : day - 1)); }
    const fine = new Date(inizio); fine.setDate(fine.getDate() + 6);

    try {
        const result = await pool.query(
            `SELECT p.id, p.data, p.ora, p.stato, p.cliente_nome,
                    b.nome AS barbiere_nome, b.id AS barbiere_id,
                    sv.nome AS servizio_nome, sv.prezzo AS servizio_prezzo, sv.durata_minuti
             FROM prenotazioni p JOIN barbieri b ON p.barbiere_id = b.id JOIN servizi sv ON p.servizio_id = sv.id
             WHERE p.sede_id = $1 AND p.data BETWEEN $2 AND $3 ORDER BY p.data ASC, p.ora ASC`,
            [sede_id, inizio.toISOString().split('T')[0], fine.toISOString().split('T')[0]]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Aggiungi prenotazione (admin)
app.post('/api/admin/prenotazioni', verificaToken, soloAdmin, async (req, res) => {
    const { sede_id, barbiere_id, cliente_nome, data, ora, servizio_id } = req.body;
    if (!sede_id || !barbiere_id || !cliente_nome || !data || !ora || !servizio_id) {
        return res.status(400).json({ error: "Mancano campi obbligatori" });
    }
    try {
        const check = await pool.query(
            "SELECT id FROM prenotazioni WHERE barbiere_id = $1 AND data = $2 AND ora = $3 AND stato = 'attivo'",
            [barbiere_id, data, ora]
        );
        if (check.rows.length > 0) return res.status(409).json({ error: "Orario già prenotato!" });

        const result = await pool.query(
            `INSERT INTO prenotazioni (sede_id, barbiere_id, cliente_nome, data, ora, servizio_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
            [sede_id, barbiere_id, cliente_nome, data, ora, servizio_id]
        );
        res.json({ success: true, prenotazione: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: "Errore nel salvataggio" });
    }
});

// Modifica prenotazione (admin)
app.patch('/api/admin/prenotazioni/:id', verificaToken, soloAdmin, async (req, res) => {
    const { id } = req.params;
    const { ora, barbiere_id, data } = req.body;
    try {
        const pren = await pool.query('SELECT * FROM prenotazioni WHERE id = $1', [id]);
        if (pren.rows.length === 0) return res.status(404).json({ error: "Non trovata" });
        const p = pren.rows[0];
        const newOra = ora || p.ora, newBarbiere = barbiere_id || p.barbiere_id, newData = data || p.data;

        const check = await pool.query(
            "SELECT id FROM prenotazioni WHERE barbiere_id=$1 AND data=$2 AND ora=$3 AND stato='attivo' AND id!=$4",
            [newBarbiere, newData, newOra, id]
        );
        if (check.rows.length > 0) return res.status(409).json({ error: "Nuovo orario già occupato!" });

        const result = await pool.query(
            `UPDATE prenotazioni SET ora=$1, barbiere_id=$2, data=$3 WHERE id=$4 AND stato='attivo' RETURNING *`,
            [newOra, newBarbiere, newData, id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: "Non modificabile" });
        res.json({ success: true, prenotazione: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: "Errore nella modifica" });
    }
});

// Cancella prenotazione (admin)
app.delete('/api/admin/prenotazioni/:id', verificaToken, soloAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query("DELETE FROM prenotazioni WHERE id = $1 RETURNING *", [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: "Non trovata" });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Lista barbieri (admin)
app.get('/api/admin/barbieri', verificaToken, soloAdmin, async (req, res) => {
    const { sede_id } = req.query;
    try {
        let result;
        if (sede_id) {
            result = await pool.query(
                `SELECT DISTINCT b.id, b.nome, b.tipo, b.assente FROM barbieri b 
                 JOIN turni_rotazione t ON b.id=t.barbiere_id WHERE t.sede_id=$1 ORDER BY b.nome`, [sede_id]
            );
        } else {
            result = await pool.query('SELECT id, nome, tipo, assente FROM barbieri ORDER BY nome');
        }
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// SEGNA BARBIERE COME ASSENTE
// Cancella tutti i suoi appuntamenti futuri e notifica i clienti
app.post('/api/admin/barbiere-assente', verificaToken, soloAdmin, async (req, res) => {
    const { barbiere_id, motivo } = req.body;
    if (!barbiere_id) return res.status(400).json({ error: "Manca barbiere_id" });

    try {
        // 1. Segna il barbiere come assente
        await pool.query(
            'UPDATE barbieri SET assente = true, motivo_assenza = $1 WHERE id = $2',
            [motivo || 'Assente per cause di forza maggiore', barbiere_id]
        );

        // 2. Trova tutti gli appuntamenti futuri di questo barbiere
        const appuntamenti = await pool.query(
            `SELECT p.id, p.cliente_id, p.data, p.ora, b.nome AS barbiere_nome, sv.nome AS servizio_nome
             FROM prenotazioni p
             JOIN barbieri b ON p.barbiere_id = b.id
             JOIN servizi sv ON p.servizio_id = sv.id
             WHERE p.barbiere_id = $1 AND p.stato = 'attivo' 
             AND (p.data > CURRENT_DATE OR (p.data = CURRENT_DATE AND p.ora > CURRENT_TIME))`,
            [barbiere_id]
        );

        // 3. Per ogni appuntamento, crea una notifica per il cliente (SE HA L'APP)
        let notificheInviate = 0;
        for (const app of appuntamenti.rows) {
            // Se cliente_id è presente, significa che si è registrato dall'app e non aggiunto a mano
            if (app.cliente_id) {
                const dateObj = new Date(app.data);
                const giorni = ['Dom', 'Lun', 'Mar', 'Mer', 'Gio', 'Ven', 'Sab'];
                const mesi = ['Gennaio', 'Febbraio', 'Marzo', 'Aprile', 'Maggio', 'Giugno', 'Luglio', 'Agosto', 'Settembre', 'Ottobre', 'Novembre', 'Dicembre'];
                const dataFormattata = `${giorni[dateObj.getDay()]} ${dateObj.getDate()} ${mesi[dateObj.getMonth()]}`;

                const messaggio = `Ci scusiamo per il disagio. Il tuo appuntamento di **${dataFormattata}** alle **${app.ora.slice(0,5)}** con **${app.barbiere_nome}** per il servizio di **${app.servizio_nome}** è stato cancellato perché il barbiere non è disponibile.\n\nTi invitiamo a prenotare un nuovo appuntamento.`;
                
                // SALVIAMO USANDO IL CLIENTE_ID INVECE DEL NOME
                await pool.query(
                    'INSERT INTO notifiche (cliente_id, messaggio) VALUES ($1, $2)',
                    [app.cliente_id, messaggio]
                );
                notificheInviate++;
            }
        }
        
        // 4. Elimina tutti gli appuntamenti del barbiere
        const eliminati = await pool.query(
            `DELETE FROM prenotazioni WHERE barbiere_id = $1 AND stato = 'attivo'
             AND (data > CURRENT_DATE OR (data = CURRENT_DATE AND ora > CURRENT_TIME))`,
            [barbiere_id]
        );

        res.json({ 
            success: true, 
            eliminati: eliminati.rowCount,
            notifiche_inviate: notificheInviate,
            messaggio: `Barbiere segnato come assente. ${eliminati.rowCount} appuntamenti cancellati e ${notificheInviate} clienti su app notificati.`
        });
    } catch (err) {
        console.error("Errore assenza:", err);
        res.status(500).json({ error: "Errore nella gestione dell'assenza" });
    }
});

// RIATTIVA BARBIERE
app.post('/api/admin/barbiere-presente', verificaToken, soloAdmin, async (req, res) => {
    const { barbiere_id } = req.body;
    if (!barbiere_id) return res.status(400).json({ error: "Manca barbiere_id" });
    try {
        await pool.query('UPDATE barbieri SET assente = false, motivo_assenza = NULL WHERE id = $1', [barbiere_id]);
        res.json({ success: true, messaggio: "Barbiere riattivato" });
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});