-- 1. Tabla de Usuarios con roles estrictos (RBAC)
CREATE TABLE usuarios (
    id_usuario SERIAL PRIMARY KEY,
    nombre_completo VARCHAR(150) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Siempre almacenado con Bcrypt/Argon2
    rol VARCHAR(30) DEFAULT 'asistente' CHECK (rol IN ('administrador', 'expositor', 'asistente', 'alumno')),
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Tabla de Simposios Normalizada (Evita redundancias)
CREATE TABLE simposios (
    id_simposio SERIAL PRIMARY KEY,
    nombre_simposio VARCHAR(150) NOT NULL,
    descripcion TEXT
);

-- 3. Tabla de Trabajos Académicos (Gestión Criptográfica de Archivos)
CREATE TABLE trabajos_academicos (
    id_trabajo SERIAL PRIMARY KEY,
    id_usuario INT REFERENCES usuarios(id_usuario) ON DELETE CASCADE,
    id_simposio INT REFERENCES simposios(id_simposio) ON DELETE SET NULL,
    titulo_trabajo VARCHAR(255) NOT NULL,
    eje_tematico VARCHAR(100) NOT NULL,
    archivo_url VARCHAR(255) NOT NULL,
    archivo_hash_sha256 CHAR(64) NOT NULL, -- Control de integridad estricto (ISO 27001)
    estado_evaluacion VARCHAR(20) DEFAULT 'pendiente' CHECK (estado_evaluacion IN ('pendiente', 'aprobado', 'rechazado')),
    subido_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
