# code share - Code Sharing Platform

Platform cepat untuk berbagi paste, kode, dan thread diskusi yang terinspirasi dari Lunox.io.

## Fitur

✅ **Rich text editor** - Bold, list, code block, dan formatting lainnya
✅ **Paste & code-friendly** - Link publik/pribadi dengan proteksi password  
✅ **Thread diskusi** - Sistem komentar untuk setiap paste
✅ **Sistem badge & views** - Tracking popularitas dan engagement
✅ **UI modern** - Interface yang nyaman dengan dark theme
✅ **Cepat & mudah** - Buka, tulis, bagikan. Selesai!

## Teknologi

- **Backend**: FastAPI (Python)
- **Database**: Apache Cassandra
- **Frontend**: HTML, CSS (Tailwind), JavaScript
- **Authentication**: JWT tokens
- **Syntax Highlighting**: Prism.js

## Instalasi

1. **Install dependencies**:
\`\`\`bash
pip install -r requirements.txt
\`\`\`

2. **Setup Cassandra**:
   - Install Apache Cassandra
   - Start Cassandra service
   - Database akan dibuat otomatis saat aplikasi pertama kali dijalankan

3. **Setup environment**:
\`\`\`bash
cp .env.example .env
# Edit .env dengan konfigurasi yang sesuai
\`\`\`

4. **Jalankan aplikasi**:
\`\`\`bash
python run.py
\`\`\`

Aplikasi akan berjalan di `http://localhost:8000`

## Struktur Database

### Users Table
- `id` (UUID) - Primary key
- `username` (TEXT) - Username unik
- `email` (TEXT) - Email user
- `password_hash` (TEXT) - Password yang di-hash
- `created_at` (TIMESTAMP) - Waktu registrasi
- `badges` (SET<TEXT>) - Badge yang dimiliki user

### Pastes Table
- `id` (UUID) - Primary key
- `title` (TEXT) - Judul paste
- `content` (TEXT) - Isi paste
- `language` (TEXT) - Bahasa pemrograman
- `author_id` (UUID) - ID pembuat
- `author_username` (TEXT) - Username pembuat
- `is_private` (BOOLEAN) - Status privasi
- `password_hash` (TEXT) - Password proteksi (opsional)
- `views` (COUNTER) - Jumlah views
- `created_at` (TIMESTAMP) - Waktu dibuat
- `expires_at` (TIMESTAMP) - Waktu kadaluarsa (opsional)

### Threads Table
- `id` (UUID) - Primary key
- `paste_id` (UUID) - ID paste yang dikomentari
- `author_id` (UUID) - ID pembuat komentar
- `author_username` (TEXT) - Username pembuat komentar
- `content` (TEXT) - Isi komentar
- `created_at` (TIMESTAMP) - Waktu dibuat

## API Endpoints

### Authentication
- `POST /api/signup` - Registrasi user baru
- `POST /api/login` - Login user

### Pastes
- `POST /api/paste` - Buat paste baru
- `GET /paste/{paste_id}` - Lihat paste
- `GET /api/paste/{paste_id}/stats` - Statistik paste

### Threads
- `POST /api/thread` - Buat komentar baru

### Pages
- `GET /` - Homepage
- `GET /login` - Halaman login
- `GET /signup` - Halaman registrasi
- `GET /create` - Halaman buat paste
- `GET /dashboard` - Dashboard user

## Penggunaan

1. **Registrasi/Login** - Buat akun atau login
2. **Buat Paste** - Klik "Create Paste", isi konten
3. **Atur Privasi** - Pilih publik/privat, tambah password jika perlu
4. **Bagikan** - Copy link dan bagikan
5. **Diskusi** - Gunakan thread untuk diskusi di setiap paste

## Keamanan

- Password di-hash menggunakan bcrypt
- JWT tokens untuk authentication
- Password protection untuk paste sensitif
- Input validation dan sanitization

## Kontribusi

1. Fork repository
2. Buat feature branch
3. Commit changes
4. Push ke branch
5. Buat Pull Request

## Lisensi

MIT License - Silakan gunakan untuk proyek pribadi atau komersial.
