import os
import requests
import hashlib
from PyPDF2 import PdfReader
from datetime import datetime

class PassiveAuditor:
    def __init__(self, target_url):
        self.url = target_url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Passive-OSINT-Auditor/1.0'
        }
        # Repositorio interno para estructurar los hallazgos del reporte
        self.report_data = {
            'target': target_url,
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'alerts': []
        }

    def _add_alert(self, control_iso, titulo, descripcion, nivel_riesgo, evidencia="N/A"):
        """Estructura internamente un hallazgo de seguridad."""
        self.report_data['alerts'].append({
            'iso': control_iso,
            'titulo': titulo,
            'desc': descripcion,
            'riesgo': nivel_riesgo,
            'evidencia': evidencia
        })

    def auditar_cabeceras_servidor(self):
        print(f"[+] Auditando cabeceras de respuesta HTTP...")
        try:
            respuesta = requests.head(self.url, headers=self.headers, timeout=10)
            cabeceras = respuesta.headers

            servidor = cabeceras.get('Server', 'No expuesto')
            powered_by = cabeceras.get('X-Powered-By', None)
            csp = cabeceras.get('Content-Security-Policy', None)

            if powered_by:
                self._add_alert(
                    "Control A.8.9 (Gestión de la Configuración)",
                    "Exposición de tecnología en Backend (X-Powered-By)",
                    f"El servidor revela explícitamente el software de ejecución: {powered_by}.",
                    "Bajo",
                    f"Header expuesto: X-Powered-By: {powered_by}"
                )

            if not csp:
                self._add_alert(
                    "Control A.8.27 (Control de Navegación)",
                    "Ausencia de Content-Security-Policy (CSP)",
                    "La falta de directivas CSP expone la aplicación a vectores de inyección de scripts (XSS) y redirecciones no controladas.",
                    "Alto"
                )
        except requests.exceptions.RequestException as e:
            print(f"[X] Error al auditar cabeceras: {e}")

    def extraer_usuarios_rest_api(self):
        print(f"[+] Verificando exposición de API REST de usuarios...")
        endpoint_usuarios = self.url.rstrip('/') + "/wp-json/wp/v2/users"
        try:
            respuesta = requests.get(endpoint_usuarios, headers=self.headers, timeout=10)
            if respuesta.status_code == 200:
                usuarios_json = respuesta.json()
                if usuarios_json:
                    evidencia_lista = []
                    for u in usuarios_json[:5]:
                        evidencia_lista.append(f"ID: {u.get('id')} | Slug: {u.get('slug')} | Nombre: {u.get('name')}")
                    
                    evidencia_str = "\n".join(evidencia_lista)
                    self._add_alert(
                        "Control A.5.34 (Privacidad de PII)",
                        "Exposición Pública de Identidades (WordPress API REST)",
                        f"El servidor tiene el endpoint de enumeración abierto, filtrando {len(usuarios_json)} nombres de usuario reales.",
                        "Crítico",
                        evidencia_str
                    )
        except Exception as e:
            print(f"[X] Error en análisis de API: {e}")

    def generar_reporte_markdown(self, filename="reporte_cumplimiento_osint.md"):
        """Genera y escribe de forma local el archivo Markdown listo para el cliente."""
        print(f"[+] Exportando reporte final a formato Markdown en: {filename}...")
        
        with open(filename, 'w', encoding='utf-8') as f:
            # Encabezado del Informe
            f.write(f"# 🛡️ Informe de Auditoría de Ciberseguridad Pasiva (OSINT)\n\n")
            f.write(f"## 📋 Resumen Ejecutivo\n")
            f.write(f"Este informe técnico contiene los resultados del análisis pasivo de vulnerabilidades y cumplimiento normativo ejecutado sobre la infraestructura expuesta del cliente. No se realizaron técnicas de intrusión activa.\n\n")
            f.write(f"* **Objetivo Auditado:** {self.report_data['target']}\n")
            f.write(f"* **Fecha y Hora de Ejecución:** {self.report_data['date']}\n")
            f.write(f"* **Estándar de Referencia:** ISO/IEC 27001:2022\n\n")
            f.write(f"---\n\n")
            
            f.write(f"## 📊 Hallazgos Técnicos y Diagnóstico de Riesgo\n\n")
            
            if not self.report_data['alerts']:
                f.write(f"✅ **No se detectaron alertas críticas en los módulos pasivos evaluados.** El sitio demuestra un nivel adecuado de hardening inicial.\n")
                return

            # Renderizado dinámico de alertas encontradas
            for idx, alerta in enumerate(self.report_data['alerts'], 1):
                color_riesgo = "🔴" if alerta['riesgo'] in ["Crítico", "Alto"] else "🟡"
                f.write(f"### {color_riesgo} Hallazgo {idx}: {alerta['titulo']}\n\n")
                f.write(f"* **Control ISO/IEC 27001:** {alerta['iso']}\n")
                f.write(f"* **Nivel de Riesgo Asignado:** **{alerta['riesgo']}**\n\n")
                f.write(f"#### 📝 Descripción:\n{alerta['desc']}\n\n")
                
                if alerta['evidencia'] != "N/A":
                    f.write(f"#### 🔍 Evidencia Empírica de Fuentes Abiertas:\n")
                    f.write(f"```text\n{alerta['evidencia']}\n```\n\n")
                f.write(f"#### 🚀 Recomendación de Mitigación (Mejora Continua):\n")
                if "A.8.27" in alerta['iso']:
                    f.write(f"Configurar las cabeceras de respuesta del servidor web (Nginx/Apache) para incluir la cabecera `Content-Security-Policy`, restringiendo los orígenes de ejecución legítimos.\n\n")
                elif "A.5.34" in alerta['iso']:
                    f.write(f"Restringir el acceso público al endpoint `/wp-json/wp/v2/users` mediante reglas de denegación en las funciones del backend o aplicando un firewall de aplicación (WAF).\n\n")
                else:
                    f.write(f"Ocultar la firma del servidor modificando las directivas por defecto para evitar la fuga de información sobre la versión exacta de las herramientas.\n\n")
                f.write(f"---\n\n")
            
            f.write(f"📄 *Fin del documento técnico de auditoría pasiva. Propiedad del consultor de ciberseguridad.*")

# ==========================================
# ÁREA DE PRUEBA LOCAL
# ==========================================
if __name__ == "__main__":
    # URL de simulación (reemplazar por el dominio real a auditar)
    url_auditoria = "https://example.com" 
    
    auditor = PassiveAuditor(url_auditoria)
    
    # Ejecución secuencial de los módulos analíticos
    auditor.auditar_cabeceras_servidor()
    auditor.extraer_usuarios_rest_api()
    
    # Exportación automática del entregable comercial (.md)
    auditor.generar_reporte_markdown()
