## 📌 Descripción del Proyecto
Este repositorio contiene el prototipo y la arquitectura base de **Secure-Event Platform**, una solución robusta, desacoplada y nativamente segura diseñada para la gestión federal de congresos académicos y simulaciones técnicas de alta criticidad. 

El diseño de este sistema no surge de un planteo teórico abstracto, sino de una **ingeniería inversa y auditoría pasiva (OSINT)** ejecutada sobre plataformas institucionales activas en el sector público de ciberdefensa. A partir de los vectores de riesgo detectados en dichas plataformas, se implementaron controles técnicos alineados con el estándar internacional **ISO/IEC 27001:2022** y los lineamientos de gestión de riesgos del **Project Management Institute (PMI)**.

---

## 🔍 Caso de Estudio: Auditoría Pasiva y Relevamiento OSINT
Para establecer las bases funcionales y de seguridad de este desarrollo, se realizó un ejercicio de recopilación de inteligencia de fuentes abiertas (sin credenciales, sin registros previos y de manera estrictamente pasiva) sobre el portal de un congreso nacional de ciberdefensa activo.

### Hechos Comprobados (Evidencia Documental en el Origen):
1. **Riesgos de Configuración y Código Fuente:** Se detectó la persistencia de bucles redundantes de datos en el backend expuestos de cara al cliente (duplicación en espejo de matrices de sponsors/auspiciantes) y la presencia de metadatos de entornos de desarrollo locales (`TeXstudio v4.8.9`) incrustados en las plantillas LaTeX distribuidas a los usuarios.
2. **Vectores de Inyección de Malware:** La plataforma origen exige de forma obligatoria la carga y descarga de archivos binarios modificables (`.docx` y `.tex`) a través de un gestor externo (Microsoft CMT) sin proveer firmas ni *hashes* criptográficos de verificación.
3. **Ausencia de Políticas de Privacidad:** El procesamiento de formularios de preinscripción y suscripción a boletines operaba sin módulos explícitos de términos de uso ni avisos de privacidad para el tratamiento de Datos de Identificación Personal (PII).
4. **Anacronismos en la Infraestructura:** Restricciones estéticas retro y excusas técnicas del servidor que delegaban en el navegador del usuario la incapacidad de renderizar documentos embebidos de manera segura (fallas de configuración en la Content Security Policy).

### El Enfoque Estratégico:
En lugar de centrar el esfuerzo en la explotación de vulnerabilidades de un sitio ajeno, **se procedió a la exfiltración pasiva de la estructura de datos** (cronogramas de simposios, agendas, precios y bases presupuestarias corporativas) utilizando funciones nativas de impresión del navegador (`Ctrl + P`). Con esta base documental aislada en un repositorio local PDF, se diseñaron los requerimientos funcionales para construir esta plataforma superadora.

---

## 🏗️ Arquitectura del Sistema (Mitigación ISO 27001:2022)

La arquitectura de este proyecto implementa de manera nativa soluciones técnicas para anular los vectores identificados en la auditoría pasiva:

*   **Mitigación de Inyección de Malware (Control A.8.23 y A.8.26):** El microservicio de carga no almacena binarios en crudo. Todo archivo ingresado se deposita en una zona de memoria volátil aislada (*Sandbox*), calcula automáticamente su firma criptográfica **SHA-256** para validar su integridad y se somete a un escaneo antivirus automatizado antes de su persistencia en buckets inmutables.
*   **Normalización de Datos y Optimización de Rendimiento:** La persistencia basada en PostgreSQL elimina la redundancia mediante una separación estricta entre las entidades de usuarios (esquema RBAC), simposios y trabajos académicos, evitando loops en el renderizado del lado del cliente.
*   **Privacidad Nativa (Control A.5.34):** Cumplimiento estricto de tratamiento de PII mediante cifrado de columnas sensibles en base de datos y un sistema dinámico de *Opt-In* que bloquea scripts de seguimiento externos hasta el consentimiento del usuario.
*   **Visualización Segura en Contenedores (Control A.8.27):** Configuración explícita de cabeceras de seguridad (**CORS / CSP**) en el servidor para forzar el renderizado seguro de documentos mediante *sandboxed iframes* locales, eliminando redirecciones externas innecesarias.

---

## 🛠️ Tecnologías Utilizadas
*   **Backend:** Node.js, Express, JavaScript Criptográfico Nativo.
*   **Base de Datos:** PostgreSQL (Normalización Relacional y Control Estricto de Claves Foráneas).
*   **Frontend:** HTML5 semántico y CSS3 responsivo (Sin dependencias externas vulnerables, carga acelerada en < 1.5s).

---

## 📈 Matriz de Gestión de Riesgos Operacionales (Marco PMI)

| ID | Riesgo Identificado | Impacto (1-5) | Probabilidad (1-5) | Estrategia de Respuesta (Mitigación) |
| :--- | :--- | :--- | :--- | :--- |
| **R1** | Inyección de macros o código embebido en archivos `.docx`/`.tex`. | 5 | 3 | **Evitar:** Validación forzada de *hashes* en sandbox y aislamiento de almacenamiento secundario inmutable. |
| **R2** | Exposición o fuga de PII de usuarios inscritos. | 5 | 2 | **Mitigar:** Cifrado asimétrico a nivel de base de datos y logs de auditoría inmutables no modificables por administradores. |
| **R3** | Degradación del servicio o redundancia en loops de renderizado. | 3 | 4 | **Mitigar:** Normalización relacional estricta en base de datos y pipelines automáticos de CI/CD para limpieza de assets. |

---

## 🚀 Instrucciones de Despliegue Local

### 1. Inicialización de la Base de Datos
Cargar el esquema estructurado en una instancia local de PostgreSQL:
```bash
psql -U tu_usuario -d base_segura -f database/schema.sql
```

### 2. Configuración e Inicio del Backend
Instalar dependencias y levantar el servidor seguro de validación criptográfica:
```bash
cd backend
npm install
npm start
```

### 3. Acceso a la Interfaz del Cronograma
Abrir el archivo `frontend/index.html` de manera directa en cualquier navegador web para comprobar el renderizado responsivo optimizado sin bucles repetitivos de información.

---
*Nota: Este proyecto demuestra cómo la ciberseguridad profesional y la administración de riesgos se ejecutan desde el silencio metodológico de la ingeniería, priorizando la solidez de los procesos por encima de la narrativa cosmética de las redes.*
