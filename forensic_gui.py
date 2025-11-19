import sys
import os
import subprocess
import hashlib
import datetime
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFileDialog, QPushButton, QLabel,
    QVBoxLayout, QHBoxLayout, QMessageBox, QSplitter, QTreeView, QTabWidget,
    QListWidget, QPlainTextEdit
)
from PyQt5.QtCore import Qt, QModelIndex
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QStyleFactory
from PyQt5.QtWidgets import QFileSystemModel


# --- RUTAS BASE ---
BASE_DIR = Path(__file__).resolve().parent
TOOLS_DIR = BASE_DIR / "tools"
WINPMEM_EXE = TOOLS_DIR / "winpmem.exe"
SYSINTERNALS_DIR = TOOLS_DIR / "sysinternals"
VOLATILITY_DIR = TOOLS_DIR / "volatility3"

# --- COMANDOS A EJECUTAR ---

COMMAND_SPECS = [
    # --- Volatility 3 ---
    {
        "id": "vol_info",
        "label": "Volatility: windows.info",
        "kind": "volatility",
        "plugin": "windows.info"
    },
    {
        "id": "vol_pslist",
        "label": "Volatility: windows.pslist",
        "kind": "volatility",
        "plugin": "windows.pslist"
    },
    {
        "id": "vol_netscan",
        "label": "Volatility: windows.netscan",
        "kind": "volatility",
        "plugin": "windows.netscan"
    },
    {
        "id": "vol_dlllist",
        "label": "Volatility: windows.dlllist",
        "kind": "volatility",
        "plugin": "windows.dlllist"
    },

    # --- Sysinternals (ejemplos de comandos CLI) ---
    {
        "id": "sys_pslist",
        "label": "Sysinternals: pslist.exe (procesos)",
        "kind": "sysinternals",
        "exe": "pslist.exe",
        "args": ["-accepteula"]
    },
    {
        "id": "sys_psloggedon",
        "label": "Sysinternals: psloggedon.exe (sesiones)",
        "kind": "sysinternals",
        "exe": "psloggedon.exe",
        "args": ["-accepteula"]
    },
]



def check_admin():
    """
    En Windows, verifica si el proceso tiene privilegios de administrador.
    Si no, muestra un mensaje (recomendado ejecutar como admin para el dump).
    """
    if os.name == "nt":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
        if not is_admin:
            QMessageBox.warning(
                None,
                "Permisos insuficientes",
                "Es recomendable ejecutar la herramienta como Administrador\n"
                "para poder realizar el volcado de memoria correctamente."
            )


def calcular_sha256(path: Path) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


# ---------------------- VENTANA ANALIZADOR ---------------------- #
class AnalyzerWindow(QMainWindow):
    """
    Ventana que aparece después de terminar el dump:
    - Panel izquierdo: Árbol de archivos + lista de comandos.
    - Panel derecho superior: Hex viewer.
    - Panel derecho inferior: Detalles (hash, tamaño, salida comandos, etc.).
    """

    def __init__(self, base_output_dir: Path, dump_path: Path, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Analizador de memoria - Herramienta Forense")
        self.resize(1100, 650)

        self.base_output_dir = base_output_dir
        self.dump_path = dump_path

        # Splitter principal horizontal (izquierda / derecha)
        main_splitter = QSplitter(Qt.Horizontal)

        # --- Panel izquierdo: Tabs con Árbol y Comandos ---
        left_tabs = QTabWidget()

        # 1) Árbol de archivos
        self.fs_model = QFileSystemModel()
        self.fs_model.setRootPath(str(self.base_output_dir))

        self.tree_view = QTreeView()
        self.tree_view.setModel(self.fs_model)
        self.tree_view.setRootIndex(self.fs_model.index(str(self.base_output_dir)))
        self.tree_view.setColumnWidth(0, 250)
        self.tree_view.clicked.connect(self.on_tree_item_clicked)

        left_tabs.addTab(self.tree_view, "Archivos")

        # 2) Lista de comandos (simulando comandos tipo Volatility/autopsy-like)
        self.commands_list = QListWidget()
        # Ejemplo de comandos / plugins (tú los conectas con Volatility si quieres)
        comandos = [
            "windows.info",
            "windows.pslist",
            "windows.netscan",
            "windows.dlllist"
        ]
        self.commands_list.addItems(comandos)
        self.commands_list.itemDoubleClicked.connect(self.on_command_double_clicked)
        left_tabs.addTab(self.commands_list, "Comandos")

        main_splitter.addWidget(left_tabs)

        # --- Panel derecho: splitter vertical (hex arriba, detalles abajo) ---
        right_splitter = QSplitter(Qt.Vertical)

        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setPlaceholderText("Aquí se mostrará el contenido en hexadecimal del archivo seleccionado.")
        right_splitter.addWidget(self.hex_view)

        self.details_view = QPlainTextEdit()
        self.details_view.setReadOnly(True)
        self.details_view.setPlaceholderText(
            "Aquí se mostrarán detalles del archivo (tamaño, hash, etc.)\n"
            "o la salida de un comando (por ejemplo, plugins de Volatility)."
        )
        right_splitter.addWidget(self.details_view)

        main_splitter.addWidget(right_splitter)
        main_splitter.setStretchFactor(0, 1)  # izquierda
        main_splitter.setStretchFactor(1, 2)  # derecha

        self.setCentralWidget(main_splitter)

        # Si ya tenemos un dump, lo mostramos por defecto
        if self.dump_path.exists():
            self.mostrar_archivo_en_hex(self.dump_path)

    # ----------------- Eventos del Árbol de archivos ----------------- #
    def on_tree_item_clicked(self, index: QModelIndex):
        path = self.fs_model.filePath(index)
        file_path = Path(path)
        if file_path.is_file():
            self.mostrar_archivo_en_hex(file_path)

    def mostrar_archivo_en_hex(self, file_path: Path, max_bytes: int = 4096):
        """
        Carga los primeros 'max_bytes' del archivo y los muestra en formato hex.
        También muestra detalles (tamaño, hash) en el panel inferior.
        """
        try:
            data = b""
            with open(file_path, "rb") as f:
                data = f.read(max_bytes)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"No se pudo leer el archivo:\n{e}")
            return

        # Hex dump simple
        lines = []
        offset = 0
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_bytes = " ".join(f"{b:02X}" for b in chunk)
            ascii_bytes = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset:08X}  {hex_bytes:<48}  {ascii_bytes}")
            offset += 16

        self.hex_view.setPlainText("\n".join(lines))

        # Detalles del archivo
        try:
            size = file_path.stat().st_size
            sha256 = calcular_sha256(file_path)
        except Exception:
            size = 0
            sha256 = "Error calculando hash"

        detalles = (
            f"Archivo: {file_path}\n"
            f"Tamaño: {size} bytes\n"
            f"SHA256: {sha256}\n"
            f"Fecha análisis: {datetime.datetime.now().isoformat()}\n"
        )
        self.details_view.setPlainText(detalles)

    # ----------------- Eventos de la lista de comandos ----------------- #
    def on_command_double_clicked(self, item):
        comando = item.text()
        # Aquí es donde podrías integrar Volatility.
        # Por ejemplo:
        #
        #   subprocess.run([
        #       "python", "vol.py", "-f", str(self.dump_path), comando
        #   ], stdout=..., stderr=...)
        #
        # Para efectos de la materia, mostramos un texto simulando la salida.
        simulated_output = (
            f"Ejecutando comando '{comando}' sobre el dump:\n"
            f"  {self.dump_path}\n\n"
            ">> Aquí se mostraría la salida real de Volatility u otra herramienta.\n"
            ">> En el proyecto final, puedes reemplazar este texto por la salida real\n"
            "   capturada con subprocess.run(...).\n"
        )
        self.details_view.setPlainText(simulated_output)


# ---------------------- VENTANA PRINCIPAL ---------------------- #
class MainWindow(QMainWindow):
    """
    Ventana principal:
    - Botón para seleccionar carpeta de salida.
    - Botón para ejecutar el dump de memoria.
    - Cuando termina el dump, muestra popup y abre AnalyzerWindow.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Herramienta Forense - Dump y Análisis de Memoria")
        self.resize(600, 200)

        self.output_dir = None  # carpeta seleccionada por el usuario
        self.last_dump_path = None

        # Widgets
        main_widget = QWidget()
        layout = QVBoxLayout(main_widget)

        self.label_output = QLabel("Carpeta de salida: (no seleccionada)")
        layout.addWidget(self.label_output)

        btn_select_folder = QPushButton("Seleccionar carpeta de reportes")
        btn_select_folder.clicked.connect(self.select_output_folder)
        layout.addWidget(btn_select_folder)

        self.btn_dump = QPushButton("Ejecutar dump de memoria")
        self.btn_dump.setEnabled(False)
        self.btn_dump.clicked.connect(self.run_memory_dump)
        layout.addWidget(self.btn_dump)

        self.btn_skip_dump = QPushButton("Excluir dump de memoria (usar dump existente)")
        self.btn_skip_dump.clicked.connect(self.use_existing_dump)
        layout.addWidget(self.btn_skip_dump)

        # Nota / ayuda
        help_label = QLabel(
            "Flujo sugerido:\n"
            "1. Selecciona la carpeta donde se guardarán el dump y los reportes.\n"
            "2. Ejecuta el dump de memoria.\n"
            "3. Cuando finalice, se abrirá la ventana de análisis con los 3 paneles."
        )
        help_label.setWordWrap(True)
        layout.addWidget(help_label)

        self.setCentralWidget(main_widget)

    def select_output_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self,
            "Seleccionar carpeta para reportes y dumps",
            str(BASE_DIR)
        )
        if folder:
            self.output_dir = Path(folder)
            self.label_output.setText(f"Carpeta de salida: {self.output_dir}")
            self.btn_dump.setEnabled(True)

    def run_memory_dump(self):
        if not self.output_dir:
            QMessageBox.warning(self, "Carpeta no seleccionada",
                                "Primero selecciona la carpeta de salida.")
            return

        # Verificar winpmem
        if not WINPMEM_EXE.exists():
            QMessageBox.critical(
                self, "winpmem.exe no encontrado",
                f"No se encontró {WINPMEM_EXE}\n"
                "Copia winpmem.exe en la carpeta 'tools' junto al script."
            )
            return

        check_admin()

        # Definimos ruta para el dump
        dump_name = f"memdump_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.raw"
        dump_path = self.output_dir / dump_name
        self.last_dump_path = dump_path

        # Ejecutar winpmem (bloqueante, pero simple para el ejemplo)
        cmd = [
            str(WINPMEM_EXE),
            "-o", str(dump_path),
            "--format", "raw"
        ]

        reply = QMessageBox.question(
            self,
            "Confirmar dump de memoria",
            f"Se realizará un volcado de memoria en:\n{dump_path}\n\n"
            "¿Deseas continuar?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        try:
            # Aquí se hace el dump real
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(
                self, "Error en winpmem",
                f"Ocurrió un error ejecutando winpmem:\n{e}"
            )
            return

        # Calculamos hash y registramos cadena de custodia
        try:
            sha256 = calcular_sha256(dump_path)
            log_path = self.output_dir / "chain_of_custody.txt"
            with open(log_path, "a", encoding="utf-8") as log:
                log.write(
                    f"{datetime.datetime.utcnow().isoformat()}Z | "
                    f"{dump_path.name} | SHA256={sha256}\n"
                )
        except Exception as e:
            QMessageBox.warning(
                self, "Advertencia",
                f"El dump se generó, pero hubo un problema registrando la cadena de custodia:\n{e}"
            )

        # Popup indicando que finalizó el dump
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle("Dump completado")
        msg.setText("El volcado de memoria ha finalizado correctamente.")
        msg.setInformativeText(
            f"Archivo generado:\n{dump_path}\n\n"
            "Al cerrar esta ventana se abrirá el analizador."
        )
        msg.exec_()

        # Al cerrar el popup, abrimos la ventana de análisis
        self.open_analyzer_window()


    def use_existing_dump(self):
        """
        Permite saltar el paso de winpmem y usar un dump de memoria ya existente.
        - El usuario selecciona el archivo de dump.
        - Se toma la carpeta del dump como output_dir.
        - Se calcula el hash y se registra en chain_of_custody.txt.
        - Se abre directamente la ventana de análisis.
        """
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar dump de memoria existente",
            str(BASE_DIR),
            "Volcados de memoria (*.raw *.mem *.dmp);;Todos los archivos (*.*)"
        )

        if not file_path:
            # Usuario canceló
            return

        dump_path = Path(file_path)

        if not dump_path.is_file():
            QMessageBox.warning(
                self,
                "Archivo no válido",
                "El archivo seleccionado no es válido."
            )
            return

        # Usamos la carpeta del dump seleccionado como carpeta base
        self.output_dir = dump_path.parent
        self.last_dump_path = dump_path
        self.label_output.setText(f"Carpeta de salida (auto): {self.output_dir}")

        # Intentamos registrar cadena de custodia del dump existente
        try:
            sha256 = calcular_sha256(dump_path)
            log_path = self.output_dir / "chain_of_custody.txt"
            with open(log_path, "a", encoding="utf-8") as log:
                log.write(
                    f"{datetime.datetime.utcnow().isoformat()}Z | "
                    f"{dump_path.name} | SHA256={sha256} | [DUMP EXISTENTE]\n"
                )
        except Exception as e:
            QMessageBox.warning(
                self,
                "Advertencia",
                f"Se utilizará el dump existente, pero no se pudo registrar la cadena de custodia:\n{e}"
            )

        QMessageBox.information(
            self,
            "Dump existente seleccionado",
            f"Se utilizará el siguiente dump de memoria:\n{dump_path}\n\n"
            "Ahora se abrirá el analizador."
        )

        self.open_analyzer_window()


    def open_analyzer_window(self):
        if not self.output_dir or not self.last_dump_path:
            QMessageBox.warning(
                self, "Sin dump",
                "No se encontró información del dump para analizar."
            )
            return

        self.analyzer = AnalyzerWindow(self.output_dir, self.last_dump_path, self)
        self.analyzer.show()


# ---------------------- MAIN ---------------------- #
def main():
    app = QApplication(sys.argv)
    # Un estilo un poco más moderno
    app.setStyle(QStyleFactory.create("Fusion"))
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
