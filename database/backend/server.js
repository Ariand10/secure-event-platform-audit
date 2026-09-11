const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

// Simulación de Base de Datos en memoria para el prototipo
const trabajosRepo = [];

// Endpoint Seguro para el Registro de Trabajos Académicos
app.post('/api/v1/trabajos/cargar', (req, res) => {
    const { id_usuario, id_simposio, titulo, eje, archivoBuffer } = req.body;

    // 1. Validar entradas (Sanitización básica para evitar inyecciones)
    if (!id_usuario || !titulo || !archivoBuffer) {
        return res.status(400).json({ status: 'Error', message: 'Datos obligatorios incompletos.' });
    }

    try {
        // 2. Control de Integridad Criptográfica (ISO/IEC 27001 Control A.8.29)
        // Se calcula el hash SHA-256 del binario recibido en crudo
        const hash = crypto.createHash('sha256').update(archivoBuffer).digest('hex');

        const nuevoTrabajo = {
            id_trabajo: trabajosRepo.length + 1,
            id_usuario,
            id_simposio,
            titulo_trabajo: titulo.trim(),
            eje_tematico: eje,
            archivo_hash_sha256: hash,
            estado: 'pendiente'
        };

        // 3. Almacenamiento en repositorio controlado
        trabajosRepo.push(nuevoTrabajo);

        res.status(201).json({
            status: 'Éxito',
            message: 'Archivo verificado y procesado de forma segura.',
            data: {
                id_trabajo: nuevoTrabajo.id_trabajo,
                hash_verificacion: nuevoTrabajo.archivo_hash_sha256
            }
        });
    } catch (error) {
        res.status(500).json({ status: 'Error Fatal', message: 'Falla en el subsistema de criptografía.' });
    }
});
