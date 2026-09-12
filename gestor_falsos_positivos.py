"""
Sistema de gestión de falsos positivos para reportes de errores.

Permite marcar reportes como falsos positivos y evita sobre-revisión,
pero limpia el estado si el archivo presenta un error diferente.
"""

import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class Reporte:
    """Representa un reporte de error."""
    archivo: str
    linea: int
    columna: int
    tipo_error: str
    mensaje: str
    
    def generar_id(self) -> str:
        """Genera un identificador único para este reporte."""
        contenido = f"{self.archivo}:{self.linea}:{self.columna}:{self.tipo_error}:{self.mensaje}"
        return hashlib.sha256(contenido.encode()).hexdigest()[:16]
    
    def generar_id_archivo(self) -> str:
        """Genera un identificador basado solo en el archivo."""
        return hashlib.sha256(self.archivo.encode()).hexdigest()[:16]


@dataclass
class FalsoPositivo:
    """Representa un falso positivo registrado."""
    reporte_id: str
    archivo: str
    archivo_id: str
    tipo_error: str
    mensaje: str
    fecha_marcaje: str
    razon: str = ""


class GestorFalsosPositivos:
    """
    Gestiona el almacenamiento y verificación de falsos positivos.
    
    - Almacena reportes marcados como falsos positivos
    - Si un archivo tiene un nuevo error diferente, limpia todos sus falsos positivos
    - Permite consultar si un reporte ya fue marcado como seguro
    """
    
    def __init__(self, archivo_db: str = "falsos_positivos.json"):
        self.archivo_db = Path(archivo_db)
        self.falsos_positivos: Dict[str, FalsoPositivo] = {}
        self._cargar_db()
    
    def _cargar_db(self):
        """Carga la base de datos de falsos positivos desde el archivo JSON."""
        if self.archivo_db.exists():
            try:
                with open(self.archivo_db, 'r', encoding='utf-8') as f:
                    datos = json.load(f)
                    for key, value in datos.items():
                        self.falsos_positivos[key] = FalsoPositivo(**value)
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Advertencia: Error al cargar la DB de falsos positivos: {e}")
                self.falsos_positivos = {}
    
    def _guardar_db(self):
        """Guarda la base de datos de falsos positivos en el archivo JSON."""
        datos = {key: asdict(value) for key, value in self.falsos_positivos.items()}
        with open(self.archivo_db, 'w', encoding='utf-8') as f:
            json.dump(datos, f, indent=2, ensure_ascii=False)
    
    def marcar_como_falso_positivo(self, reporte: Reporte, razon: str = "") -> bool:
        """
        Marca un reporte como falso positivo.
        
        Args:
            reporte: El reporte a marcar como falso positivo
            razon: Razón opcional por la que se marca como falso positivo
            
        Returns:
            True si se marcó exitosamente, False si ya existía
        """
        reporte_id = reporte.generar_id()
        
        if reporte_id in self.falsos_positivos:
            return False
        
        falso_positivo = FalsoPositivo(
            reporte_id=reporte_id,
            archivo=reporte.archivo,
            archivo_id=reporte.generar_id_archivo(),
            tipo_error=reporte.tipo_error,
            mensaje=reporte.mensaje,
            fecha_marcaje=datetime.now().isoformat(),
            razon=razon
        )
        
        self.falsos_positivos[reporte_id] = falso_positivo
        self._guardar_db()
        return True
    
    def es_falso_positivo(self, reporte: Reporte) -> bool:
        """
        Verifica si un reporte ya está marcado como falso positivo.
        
        Args:
            reporte: El reporte a verificar
            
        Returns:
            True si es un falso positivo conocido, False en caso contrario
        """
        reporte_id = reporte.generar_id()
        return reporte_id in self.falsos_positivos
    
    def procesar_reportes(self, reportes: List[Reporte]) -> List[Reporte]:
        """
        Procesa una lista de reportes y filtra los falsos positivos conocidos.
        
        Si un archivo tiene un error NUEVO (no marcado como falso positivo),
        se limpian TODOS los falsos positivos de ese archivo y se retornan
        todos sus reportes para revisión.
        
        Args:
            reportes: Lista de reportes a procesar
            
        Returns:
            Lista de reportes que requieren revisión (no son falsos positivos)
        """
        # Agrupar reportes por archivo
        reportes_por_archivo: Dict[str, List[Reporte]] = {}
        for reporte in reportes:
            archivo_id = reporte.generar_id_archivo()
            if archivo_id not in reportes_por_archivo:
                reportes_por_archivo[archivo_id] = []
            reportes_por_archivo[archivo_id].append(reporte)
        
        reportes_a_revisar: List[Reporte] = []
        archivos_con_nuevos_errores: Set[str] = set()
        
        # Primero, identificar qué archivos tienen errores nuevos
        for archivo_id, lista_reportes in reportes_por_archivo.items():
            tiene_error_nuevo = False
            
            for reporte in lista_reportes:
                if not self.es_falso_positivo(reporte):
                    tiene_error_nuevo = True
                    break
            
            if tiene_error_nuevo:
                archivos_con_nuevos_errores.add(archivo_id)
        
        # Limpiar falsos positivos de archivos con errores nuevos
        for archivo_id in archivos_con_nuevos_errores:
            self._limpiar_falsos_positivos_por_archivo_id(archivo_id)
        
        # Ahora procesar todos los reportes
        for reporte in reportes:
            if not self.es_falso_positivo(reporte):
                reportes_a_revisar.append(reporte)
        
        return reportes_a_revisar
    
    def _limpiar_falsos_positivos_por_archivo_id(self, archivo_id: str):
        """Elimina todos los falsos positivos asociados a un archivo específico."""
        ids_a_eliminar = [
            key for key, fp in self.falsos_positivos.items()
            if fp.archivo_id == archivo_id
        ]
        
        for id_a_eliminar in ids_a_eliminar:
            del self.falsos_positivos[id_a_eliminar]
        
        if ids_a_eliminar:
            self._guardar_db()
    
    def limpiar_falsos_positivos_por_archivo(self, archivo: str):
        """
        Limpia manualmente todos los falsos positivos de un archivo específico.
        
        Args:
            archivo: Ruta del archivo cuyos falsos positivos se eliminarán
        """
        reporte_ejemplo = Reporte(
            archivo=archivo,
            linea=0,
            columna=0,
            tipo_error="",
            mensaje=""
        )
        archivo_id = reporte_ejemplo.generar_id_archivo()
        self._limpiar_falsos_positivos_por_archivo_id(archivo_id)
    
    def obtener_estadisticas(self) -> Dict:
        """
        Obtiene estadísticas sobre los falsos positivos registrados.
        
        Returns:
            Diccionario con estadísticas útiles
        """
        archivos_unicos = set(fp.archivo for fp in self.falsos_positivos.values())
        tipos_error = {}
        
        for fp in self.falsos_positivos.values():
            tipos_error[fp.tipo_error] = tipos_error.get(fp.tipo_error, 0) + 1
        
        return {
            "total_falsos_positivos": len(self.falsos_positivos),
            "archivos_afectados": len(archivos_unicos),
            "tipos_error": tipos_error
        }
    
    def listar_falsos_positivos(self, archivo: Optional[str] = None) -> List[FalsoPositivo]:
        """
        Lista los falsos positivos registrados, opcionalmente filtrados por archivo.
        
        Args:
            archivo: Ruta del archivo para filtrar (None para todos)
            
        Returns:
            Lista de falsos positivos
        """
        if archivo is None:
            return list(self.falsos_positivos.values())
        
        reporte_ejemplo = Reporte(
            archivo=archivo,
            linea=0,
            columna=0,
            tipo_error="",
            mensaje=""
        )
        archivo_id = reporte_ejemplo.generar_id_archivo()
        
        return [
            fp for fp in self.falsos_positivos.values()
            if fp.archivo_id == archivo_id
        ]


# Ejemplo de uso
if __name__ == "__main__":
    # Inicializar el gestor
    gestor = GestorFalsosPositivos()
    
    # Crear algunos reportes de ejemplo
    reporte1 = Reporte(
        archivo="src/utils.py",
        linea=10,
        columna=5,
        tipo_error="W0613",
        mensaje="Unused argument 'args'"
    )
    
    reporte2 = Reporte(
        archivo="src/utils.py",
        linea=15,
        columna=8,
        tipo_error="E1101",
        mensaje="Module has no member 'foo'"
    )
    
    reporte3 = Reporte(
        archivo="src/main.py",
        linea=20,
        columna=3,
        tipo_error="W0613",
        mensaje="Unused argument 'kwargs'"
    )
    
    print("=== Marcando reporte1 como falso positivo ===")
    gestor.marcar_como_falso_positivo(reporte1, "Es un argumento requerido por la interfaz")
    
    print("\n=== Verificando si reporte1 es falso positivo ===")
    print(f"¿reporte1 es falso positivo? {gestor.es_falso_positivo(reporte1)}")
    
    print("\n=== Procesando reportes (solo reporte1 debería filtrarse) ===")
    reportes_pendientes = gestor.procesar_reportes([reporte1, reporte2, reporte3])
    print(f"Reportes pendientes de revisión: {len(reportes_pendientes)}")
    for r in reportes_pendientes:
        print(f"  - {r.archivo}:{r.linea} - {r.tipo_error}: {r.mensaje}")
    
    print("\n=== Ahora agregamos un NUEVO error en src/utils.py ===")
    reporte4 = Reporte(
        archivo="src/utils.py",
        linea=25,
        columna=10,
        tipo_error="E0401",
        mensaje="Unable to import 'numpy'"
    )
    
    print("Al detectar un error nuevo en src/utils.py, se limpian TODOS sus falsos positivos")
    reportes_pendientes = gestor.procesar_reportes([reporte1, reporte2, reporte3, reporte4])
    print(f"Reportes pendientes de revisión: {len(reportes_pendientes)}")
    for r in reportes_pendientes:
        print(f"  - {r.archivo}:{r.linea} - {r.tipo_error}: {r.mensaje}")
    
    print("\n=== Estadísticas ===")
    stats = gestor.obtener_estadisticas()
    print(f"Total falsos positivos: {stats['total_falsos_positivos']}")
    print(f"Archivos afectados: {stats['archivos_afectados']}")
