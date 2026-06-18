const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // Zaštita za lozinke

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/ednevnik';
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ Uspešno povezan sa MongoDB bazom!'))
  .catch(err => console.error('❌ Greška pri povezivanju sa bazom:', err));

// --- MONGODB ŠEME ---

const PredmetSchema = new mongoose.Schema({
    id: String,      
    naziv: String    
});
const Predmet = mongoose.model('Predmet', PredmetSchema);

const OcenaSchema = new mongoose.Schema({
    ucenikId: String,
    predmet: String,
    vrednost: String, 
    jeZakljucna: Boolean,
    period: String,
    ulaziUProsek: Boolean, 
    napomena: String,
    datum: { type: Date, default: Date.now }
});
const Ocena = mongoose.model('Ocena', OcenaSchema);

const OdeljenjeSchema = new mongoose.Schema({
    naziv: String    
});
const Odeljenje = mongoose.model('Odeljenje', OdeljenjeSchema);

const NastavnikSchema = new mongoose.Schema({
    ime: String,
    uloga: String,
    username: String,
    password: { type: String, default: "admin123", select: false }, // Ignoriše se pri običnoj pretrazi
    odeljenja: [String],
    predmeti: [String]
});

// Middleware koji automatski hesira lozinku pre nego što se nastavnik sačuva u bazu
NastavnikSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (err) {
        next(err);
    }
});

const Nastavnik = mongoose.model('Nastavnik', NastavnikSchema);

const CasSchema = new mongoose.Schema({
    lekcija: String,
    rbr: String,
    type: String,
    odeljenje: String,
    predmetId: String,
    datum: String
});
const Cas = mongoose.model('Cas', CasSchema);

const UcenikSchema = new mongoose.Schema({
    ime: String,
    odeljenje: String,
    ocena_vladanja: { type: String, default: "5" }, 
    ocene: [{ 
        id: Number, 
        tip: String,        
        vrednost: String,   
        vrsta: String,      
        predmet: String, 
        datum: String       
    }],
    izostanci: [{ 
        lekcija: String, 
        predmet: String, 
        datum: String, 
        status: { type: String, default: "нерегулисано" } 
    }],
    vladanje_lista: [{ 
        id: Number, 
        tip_zapisa: String, 
        vrsta: String,      
        tekst: String,      
        datum: String, 
        predmet: String,    
        cas: String,        
        posledica: String   
    }]
});
const Ucenik = mongoose.model('Ucenik', UcenikSchema);


// --- API RUTE ---

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// Безбедан Login преко bcrypt-а
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const nastavnik = await Nastavnik.findOne({ username: username.trim() }).select('+password');

        if (!nastavnik) {
            return res.status(401).json({ success: false, message: "Pogrešni podaci" });
        }

        if (nastavnik.password === password.trim()) {
            const korisnikObjekat = nastavnik.toObject();
            delete korisnikObjekat.password;
            return res.json({ success: true, user: korisnikObjekat });
        }

        const isMatch = await bcrypt.compare(password.trim(), nastavnik.password);

        if (isMatch) {
            const korisnikObjekat = nastavnik.toObject();
            delete korisnikObjekat.password;
            res.json({ success: true, user: korisnikObjekat });
        } else {
            res.status(401).json({ success: false, message: "Pogrešni podaci" });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/podaci', async (req, res) => {
    try {
        const ucenici = await Ucenik.find();
        const casovi = await Cas.find();
        const predmeti = await Predmet.find();
        const odeljenja = await Odeljenje.find();
        
        const siroviNastavnici = await Nastavnik.find();
        const nastavnici = siroviNastavnici.map(n => {
            const nastavnikObj = n.toObject();
            delete nastavnikObj.password; 
            return nastavnikObj;
        });

        res.json({ ucenici, casovi, nastavnici, predmeti, odeljenja });
        
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.post('/api/nastavnici/promena-lozinke', async (req, res) => {
    try {
        const { username, novaLozinka } = req.body;
        let korisnik = await Nastavnik.findOne({ username: username });
        if (!korisnik && username === 'admin') {
            korisnik = new Nastavnik({ ime: "Стефан Михајловић", uloga: "Администратор", username: "admin" });
        }
        if (korisnik) {
            korisnik.password = novaLozinka; 
            await korisnik.save();
            return res.json({ success: true, message: "Lozinka promenjena!" });
        }
        res.status(404).json({ success: false });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/predmeti', async (req, res) => {
    try { const nov = await Predmet.create(req.body); res.status(200).json(nov); } catch (err) { res.status(400).json(err); }
});

app.post('/api/sacuvaj', async (req, res) => {
    try {
        const { ucenikId, predmet, vrednost, jeZakljucna, period, ulaziUProsek, napomena } = req.body;
        const novaOcena = new Ocena({ ucenikId, predmet, vrednost, jeZakljucna, period, ulaziUProsek, napomena });
        await novaOcena.save();
        res.status(201).json({ poruka: 'Ocena uspešno sačuvana' });
    } catch (error) { res.status(500).json({ poruka: 'Greška pri čuvanju', error }); }
});

app.delete('/api/predmeti/:id', async (req, res) => {
    try { await Predmet.deleteOne({ id: req.params.id }); res.json({ success: true }); } catch (err) { res.status(400).json(err); }
});

app.post('/api/odeljenja', async (req, res) => {
    try { const nov = await Odeljenje.create(req.body); res.status(200).json(nov); } catch (err) { res.status(400).json(err); }
});

app.delete('/api/odeljenja/:naziv', async (req, res) => {
    try { await Odeljenje.deleteOne({ naziv: req.params.naziv }); res.json({ success: true }); } catch (err) { res.status(400).json(err); }
});

app.post('/api/sacuvaj-ocenu', async (req, res) => {
    try {
        const ucenikData = req.body; 
        await Ucenik.findByIdAndUpdate(ucenikData._id, { $set: { ocene: ucenikData.ocene } });
        res.status(200).json({ poruka: 'Sačuvano u profil učenika' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/nastavnici', async (req, res) => {
    try { const nov = await Nastavnik.create(req.body); res.status(200).json(nov); } catch (err) { res.status(400).json(err); }
});

app.delete('/api/nastavnici/:id', async (req, res) => {
    try { await Nastavnik.findByIdAndDelete(req.params.id); res.json({ success: true }); } catch (err) { res.status(400).json(err); }
});

app.post('/api/casovi', async (req, res) => {
    try { const nov = await Cas.create(req.body); res.status(200).json(nov); } catch (err) { res.status(400).json(err); }
});

app.put('/api/casovi/:id', async (req, res) => {
    try { const azur = await Cas.findByIdAndUpdate(req.params.id, req.body, { new: true }); res.json(azur); } catch (err) { res.status(400).json(err); }
});

app.delete('/api/casovi/:id', async (req, res) => {
    try { await Cas.findByIdAndDelete(req.params.id); res.json({ success: true }); } catch (err) { res.status(400).json(err); }
});

app.post('/api/ucenici', async (req, res) => {
    try { 
        const nov = await Ucenik.create(req.body); 
        res.status(200).json({ success: true, ucenik: nov }); 
    } catch (err) { res.status(400).json({ success: false, error: err.message }); }
});

// POPRAVLJENO: Сада креира АКТИВНОГ корисника унутар Nastavnik колекције
app.post('/api/registracija', async (req, res) => {
    try {
        const { korisnickoIme, lozinka } = req.body;

        // 1. Provera preko ispravnog modela (Nastavnik) i polja (username)
        const postojeciKorisnik = await Nastavnik.findOne({ username: korisnickoIme.trim() });
        if (postojeciKorisnik) {
            return res.status(400).json({ poruka: "Корисничко име је већ заузето!" });
        }

        // 2. Pravimo novog aktivnog nastavnika sa praznim podacima za njegovu školu
        const noviNastavnik = new Nastavnik({
            ime: korisnickoIme.trim(), // Privremeno ime dok sami ne promene
            uloga: "Наставник",         // Podrazumevana uloga
            username: korisnickoIme.trim(),
            password: lozinka.trim(),   // Ovo će Mongoose 'pre-save' kuka automatski bezbedno da hesira!
            odeljenja: [],              // Prazan dnevnik u startu
            predmeti: []                // Prazan dnevnik u startu
        });

        await noviNastavnik.save();

        res.status(201).json({ poruka: "Успешна регистрација!" });

    } catch (error) {
        console.error(error);
        res.status(500).json({ poruka: "Грешка на серверу приликом регистрације." });
    }
});

app.put('/api/ucenici/:id', async (req, res) => {
    try { 
        const azur = await Ucenie.findByIdAndUpdate(req.params.id, req.body, { new: true }); 
        res.json({ success: true, data: azur }); 
    } catch (err) { res.status(400).json({ success: false, error: err.message }); }
});

app.delete('/api/ucenici/:id', async (req, res) => {
    try { await Ucenik.findByIdAndDelete(req.params.id); res.json({ success: true }); } catch (err) { res.status(400).json({ success: false, error: err.message }); }
});

app.post('/api/obrisi-ocenu', async (req, res) => {
    try {
        const { ucenikId, ocenaId } = req.body;
        await Ucenik.findByIdAndUpdate(ucenikId, { $pull: { ocene: { id: Number(ocenaId) } } });
        res.status(200).json({ poruka: 'Ocena uspešno obrisana' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Сервер је успешно покренут на порту ${PORT}`);
});
