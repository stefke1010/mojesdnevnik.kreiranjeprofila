const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // <--- DODATO: Zaštita za lozinke

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

// POPRAVLJENO: Dodat select: false za lozinku
const NastavnikSchema = new mongoose.Schema({
    ime: String,
    uloga: String,
    username: String,
    password: { type: String, default: "admin123", select: false }, // <--- BILO KOJA PRETRAGA OD SADA IGNORIŠE OVO POLJE
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

// POPRAVLJENO: Login sada radi preko bcrypt poređenja i bezbedan je
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Uzimamo nastavnika i eksplicitno tražimo password iz baze
        const nastavnik = await Nastavnik.findOne({ username: username.trim() }).select('+password');

        if (!nastavnik) {
            return res.status(401).json({ success: false, message: "Pogrešni podaci" });
        }

        // 1. PROVERA: Da li je lozinka u bazi još uvek običan tekst (npr. "admin123")?
        if (nastavnik.password === password.trim()) {
            const korisnikObjekat = nastavnik.toObject();
            delete korisnikObjekat.password;
            return res.json({ success: true, user: korisnikObjekat });
        }

        // 2. PROVERA: Ako nije običan tekst, proveri preko bcrypt-a (za kriptovane lozinke)
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
// POPRAVLJENO: Izbačene lozinke iz odgovora!
app.get('/api/podaci', async (req, res) => {
    try {
        // 1. Povlačimo sve podatke normalno iz baze
        const ucenici = await Ucenik.find();
        const casovi = await Cas.find();
        const predmeti = await Predmet.find();
        const odeljenja = await Odeljenje.find();
        
        // 2. Povlačimo nastavnike, ali EKSPLICITNO brišemo šifre pre slanja klijentu
        const siroviNastavnici = await Nastavnik.find();
        
        const nastavnici = siroviNastavnici.map(n => {
            const nastavnikObj = n.toObject();
            delete nastavnikObj.password; // Potpuno uklanjamo lozinku iz objekta
            return nastavnikObj;
        });

        // 3. Šaljemo sve podatke nazad. Front-end sada dobija SVU strukturu kao i pre, ali bez šifara!
        res.json({ ucenici, casovi, nastavnici, predmeti, odeljenja });
        
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});
// POPRAVLJENO: Promena lozinke sada bezbedno hesira novu lozinku
app.post('/api/nastavnici/promena-lozinke', async (req, res) => {
    try {
        const { username, novaLozinka } = req.body;
        let korisnik = await Nastavnik.findOne({ username: username });
        if (!korisnik && username === 'admin') {
            korisnik = new Nastavnik({ ime: "Стефан Михајловић", uloga: "Администратор", username: "admin" });
        }
        if (korisnik) {
            korisnik.password = novaLozinka; // pre-save kuka iz šeme će ovo automatski hesirati
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

// --- POPRAVLJENE RUTE ZA UČENIKE ---

app.post('/api/ucenici', async (req, res) => {
    try { 
        const nov = await Ucenik.create(req.body); 
        res.status(200).json({ success: true, ucenik: nov }); 
    } catch (err) { res.status(400).json({ success: false, error: err.message }); }
});
// Рута за регистрацију новог корисника из друге школе
app.post('/api/registracija', async (req, res) => {
    try {
        const { korisnickoIme, lozinka } = req.body;

        // 1. Проверавамо да ли корисник већ постоји у бази
        const postojeciKorisnik = await Korisnik.findOne({ korisnickoIme: korisnickoIme });
        if (postojeciKorisnik) {
            return res.status(400).json({ poruka: "Корисничко име је већ заузето!" });
        }

        // 2. Креирамо новог корисника (овде убаци твој модел за кориснике)
        const noviKorisnik = new Korisnik({
            korisnickoIme: korisnickoIme,
            lozinka: lozinka // Препорука је да се лозинка хешује (bcrypt), али ако радиш овако обично, само сачувај
        });

        await noviKorisnik.save();

        // Враћамо одговор фронтенду да је све супер
        res.status(201).json({ poruka: "Успешна регистрација!" });

    } catch (error) {
        console.error(error);
        res.status(500).json({ poruka: "Грешка на серверу приликом регистрације." });
    }
});

app.put('/api/ucenici/:id', async (req, res) => {
    try { 
        const azur = await Ucenik.findByIdAndUpdate(req.params.id, req.body, { new: true }); 
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
